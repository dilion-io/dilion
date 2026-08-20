package auth

// POST /admin/generate_link — mint an email action link without sending mail.
//
// Reproduces adminGenerateLink from
// github.com/supabase/auth/internal/api/mail.go.
//
//	POST /admin/generate_link {type, email, new_email?, password?, data?, redirect_to?}
//	-> 200 {<user fields...>, action_link, email_otp, hashed_token, verification_type, redirect_to}
//
// It is the escape hatch for deployments that deliver their own email: the
// server does all the token bookkeeping (the same columns and the same
// auth.one_time_tokens rows the built-in mailer writes) and hands the caller the
// link, the OTP and the hash, but never contacts a mailer.
//
// Because it returns a live credential for an arbitrary account, it is
// admin-gated and every call that CREATES a user is audited.
//
// Supported types (upstream's full set for email):
//
//	signup                — creates the account when absent (password honoured)
//	invite                — creates the account when absent, stamps invited_at
//	magiclink             — falls back to `signup` when the address is unknown
//	recovery              — 404 when the address is unknown
//	email_change_current  — requires Mailer.SecureEmailChangeEnabled
//	email_change_new

import (
	"context"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/ports"
)

func init() {
	registerFeature("generate_link", func(a *api, r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(a.requireAdmin)
			r.Post("/admin/generate_link", a.handle(a.adminGenerateLink))
		})
	})
}

// GenerateLinkParams is the POST /admin/generate_link body (upstream
// api.GenerateLinkParams).
type GenerateLinkParams struct {
	Type       string         `json:"type"`
	Email      string         `json:"email"`
	NewEmail   string         `json:"new_email"`
	Password   string         `json:"password"`
	Data       map[string]any `json:"data"`
	RedirectTo string         `json:"redirect_to"`
}

// GenerateLinkResponse is upstream's GenerateLinkResponse: the user object
// FLATTENED (User is embedded, not nested) plus the link material.
type GenerateLinkResponse struct {
	User
	ActionLink       string `json:"action_link"`
	EmailOtp         string `json:"email_otp"`
	HashedToken      string `json:"hashed_token"`
	VerificationType string `json:"verification_type"`
	RedirectTo       string `json:"redirect_to"`
}

func (a *api) adminGenerateLink(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	params := &GenerateLinkParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	params.Email = strings.ToLower(strings.TrimSpace(params.Email))
	if params.Email == "" {
		return badRequestError(ErrorCodeValidationFailed, "An email address is required")
	}
	if _, err := mail.ParseAddress(params.Email); err != nil {
		return badRequestError(ErrorCodeValidationFailed, "Unable to validate email address: invalid format")
	}
	switch params.Type {
	case mailSignup, mailInvite, mailMagicLink, mailRecovery, mailEmailChangeCurrent, mailEmailChangeNew:
	default:
		return badRequestError(ErrorCodeValidationFailed, "Invalid email action link type requested: %v", params.Type)
	}

	aud := requestAud(r)
	referrer := a.referrerFor(r, params.RedirectTo)

	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	user, err := findUserByEmail(ctx, pool, params.Email, aud)
	if err != nil && !isNoRows(err) {
		return internalServerError("Database error finding user").withInternal(err)
	}

	if user == nil {
		switch params.Type {
		case mailMagicLink:
			// Upstream turns a magic link for an unknown address into a signup
			// with a generated password.
			params.Type = mailSignup
			params.Password = ""
		case mailRecovery, mailEmailChangeCurrent, mailEmailChangeNew:
			return notFoundError(ErrorCodeUserNotFound, "User with this email not found")
		}
	}

	// Account creation needs the validating hook and password hashing outside
	// the transaction.
	var hashed string
	if user == nil && (params.Type == mailSignup || params.Type == mailInvite) {
		if params.Type == mailSignup && params.Password != "" {
			if herr := a.checkPasswordStrength(ctx, params.Password); herr != nil {
				return herr
			}
		}
		h, data, herr := a.prepareEmailUser(ctx, params.Email, params.Data)
		if herr != nil {
			return herr
		}
		params.Data = data
		hashed = h
		if params.Type == mailSignup && params.Password != "" {
			hashed, err = HashPassword(params.Password)
			if err != nil {
				return internalServerError("Error hashing password").withInternal(err)
			}
		}
	}

	now := a.now()
	created := false
	var tok *mailToken

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		if user == nil {
			var cerr error
			user, cerr = a.insertEmailUser(ctx, tx, params.Email, aud, hashed, params.Data, false, now)
			if cerr != nil {
				return cerr
			}
			created = true
		} else if params.Type == mailSignup || params.Type == mailInvite {
			if user.EmailConfirmedAt != nil {
				return unprocessableEntityError(ErrorCodeEmailExists,
					"A user with this email address has already been registered")
			}
		}

		var terr error
		tok, terr = a.generateActionToken(ctx, tx, r, params, user, referrer, now)
		if terr != nil {
			return terr
		}

		refreshed, rerr := a.loadUserWithIdentities(ctx, tx, user.ID)
		if rerr != nil {
			return internalServerError("Error refetching user").withInternal(rerr)
		}
		user = refreshed
		return nil
	}); err != nil {
		return err
	}

	if created {
		a.observeHook(ctx, ports.AfterSignup, map[string]any{
			"user_id":  user.ID,
			"email":    user.Email,
			"provider": ProviderEmail,
		})
		a.emitAudit(r, auditOpts{
			Action:      audit.ActionUserCreated,
			Resource:    auditResourceUser(user.ID),
			AccessLevel: audit.AccessNA,
			SubjectIDs:  []string{user.ID},
		})
	}

	return sendJSON(w, http.StatusOK, GenerateLinkResponse{
		User:             *user,
		ActionLink:       tok.Link,
		EmailOtp:         tok.OTP,
		HashedToken:      tok.Hash,
		VerificationType: params.Type,
		RedirectTo:       referrer,
	})
}

// generateActionToken persists the token for one action type and builds its
// link. It is the send path of mailflow.go with the delivery step removed —
// deliberately duplicated rather than parameterised, because "which columns does
// this action touch" is the part that must stay readable against upstream.
func (a *api) generateActionToken(ctx context.Context, tx querier, r *http.Request,
	params *GenerateLinkParams, user *User, referrer string, now time.Time) (*mailToken, error) {

	otp, err := generateOTP(a.cfg.Mailer.OTPLength)
	if err != nil {
		return nil, internalServerError("Error generating one-time token").withInternal(err)
	}

	var (
		hash      string
		linkType  string
		tokenType string
		set       map[string]any
		relatesTo = params.Email
	)

	switch params.Type {
	case mailMagicLink, mailRecovery:
		hash = generateTokenHash(params.Email, otp)
		linkType, tokenType = params.Type, tokenTypeRecovery
		set = map[string]any{"recovery_token": hash, "recovery_sent_at": now}

	case mailInvite:
		hash = generateTokenHash(params.Email, otp)
		linkType, tokenType = mailInvite, tokenTypeConfirmation
		set = map[string]any{"confirmation_token": hash, "confirmation_sent_at": now, "invited_at": now}

	case mailSignup:
		hash = generateTokenHash(params.Email, otp)
		linkType, tokenType = mailSignup, tokenTypeConfirmation
		set = map[string]any{"confirmation_token": hash, "confirmation_sent_at": now}
		if params.Data != nil {
			merged := JSONMap{}
			for k, v := range user.UserMetaData {
				merged[k] = v
			}
			for k, v := range params.Data {
				merged[k] = v
			}
			set["raw_user_meta_data"] = merged
		}

	case mailEmailChangeCurrent, mailEmailChangeNew:
		if params.Type == mailEmailChangeCurrent && !a.cfg.Mailer.SecureEmailChangeEnabled {
			return nil, badRequestError(ErrorCodeValidationFailed,
				"Enable secure email change to generate link for current email")
		}
		newEmail := strings.ToLower(strings.TrimSpace(params.NewEmail))
		if newEmail == "" {
			return nil, badRequestError(ErrorCodeValidationFailed, "An email address is required")
		}
		if _, perr := mail.ParseAddress(newEmail); perr != nil {
			return nil, badRequestError(ErrorCodeValidationFailed, "Unable to validate email address: invalid format")
		}
		dup, derr := findUserByEmail(ctx, tx, newEmail, user.Aud)
		if derr != nil && !isNoRows(derr) {
			return nil, internalServerError("Database error checking email").withInternal(derr)
		}
		if dup != nil && dup.ID != user.ID {
			return nil, unprocessableEntityError(ErrorCodeEmailExists,
				"A user with this email address has already been registered")
		}

		linkType = mailEmailChange
		set = map[string]any{
			"email_change":                newEmail,
			"email_change_sent_at":        now,
			"email_change_confirm_status": zeroConfirmation,
		}
		if params.Type == mailEmailChangeCurrent {
			hash = generateTokenHash(user.Email, otp)
			tokenType = tokenTypeEmailChangeCurrent
			relatesTo = user.Email
			set["email_change_token_current"] = hash
		} else {
			hash = generateTokenHash(newEmail, otp)
			tokenType = tokenTypeEmailChangeNew
			relatesTo = newEmail
			set["email_change_token_new"] = hash
		}
	}

	if _, err := updateUserFields(ctx, tx, user.ID, now, set); err != nil {
		if isUniqueViolation(err) {
			return nil, unprocessableEntityError(ErrorCodeEmailExists,
				"A user with this email address has already been registered")
		}
		return nil, internalServerError("Database error updating user").withInternal(err)
	}
	if err := issueOneTimeToken(ctx, tx, user.ID, relatesTo, hash, tokenType, now); err != nil {
		return nil, internalServerError("Database error creating one-time token").withInternal(err)
	}

	link, err := a.actionLink(r, params.Type, hash, linkType, referrer)
	if err != nil {
		return nil, internalServerError("Error building email action link").withInternal(err)
	}
	return &mailToken{OTP: otp, Hash: hash, Link: link, RedirectTo: referrer}, nil
}

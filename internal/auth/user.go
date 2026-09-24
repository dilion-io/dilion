package auth

import (
	"context"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// UserUpdateParams is the PUT /user body.
type UserUpdateParams struct {
	Email    *string        `json:"email"`
	Phone    *string        `json:"phone"`
	Password *string        `json:"password"`
	Nonce    string         `json:"nonce"`
	Data     map[string]any `json:"data"`
	// AppMetaData is accepted upstream but only honoured for admin callers; a
	// self-service user may not escalate their own app_metadata.
	AppMetaData map[string]any `json:"app_metadata"`
	Channel     string         `json:"channel"`

	// CodeChallenge / CodeChallengeMethod make the email-change confirmation a
	// PKCE flow (pkce.go), exactly as they do on /signup and /otp.
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`

	// RedirectTo is where /verify sends the browser after the change is
	// confirmed. Validated against Config.URIAllowList like every other
	// redirect.
	RedirectTo string `json:"redirect_to"`
}

// reauthRecencyWindow is upstream's grace period: a session younger than this
// counts as recent enough proof of identity, so no nonce is demanded even with
// Security.UpdatePasswordRequireReauth on.
const reauthRecencyWindow = 24 * time.Hour

// getUser implements GET /user.
func (a *api) getUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	u := userFrom(ctx)
	pool, err := a.db(ctx)
	if err != nil {
		return internalServerError("Database unavailable").withInternal(err)
	}
	if err := a.loadFactors(ctx, pool, u); err != nil {
		return internalServerError("Error loading factors").withInternal(err)
	}
	return sendJSON(w, http.StatusOK, u)
}

// updateUser implements PUT /user.
//
// # Email change
//
// With Mailer.Autoconfirm OFF, a new address is NOT applied here. It is parked
// in auth.users.email_change, a token is mailed, and the change only lands when
// /verify is followed (verify.go emailChangeVerify):
//
//	SecureEmailChangeEnabled = true   both the OLD and the NEW address are
//	                                  mailed, and BOTH links must be followed
//	                                  (email_change_confirm_status)
//	SecureEmailChangeEnabled = false  only the new address is mailed
//
// DILION DEVIATION: with Mailer.Autoconfirm ON (the Dilion default) the address
// is applied immediately and the old one notified, which is the behaviour every
// existing embedder relies on. Upstream would mail even then — but upstream also
// treats autoconfirm as "skip the double confirmation" inside emailChangeVerify,
// so the two agree on what autoconfirm means; they differ only on whether a mail
// is sent at all. Operators who want confirmed email changes turn autoconfirm
// off, which is the same switch upstream uses.
//
// # Phone change
//
// The phone twin of the above, switched by SMS.Autoconfirm instead:
//
//	SMS.Autoconfirm = false  the number is parked in auth.users.phone_change, an
//	                         OTP is texted to it, and the change lands through
//	                         POST /verify {type:"phone_change", phone, token}
//	SMS.Autoconfirm = true   the number is applied immediately (upstream does
//	                         exactly this, by running its own phone_change
//	                         verification against a synthetic token)
//
// Unlike the email path this matches upstream in BOTH settings, because upstream
// itself short-circuits the OTP when SMS.Autoconfirm is on.
//
// # Password change
//
// With Security.UpdatePasswordRequireReauth on, a password change needs a fresh
// proof of identity: either a session created within the last 24 hours, or a
// nonce obtained from GET /reauthenticate (reauth.go). Without one the answer is
// upstream's 400 reauthentication_needed.
func (a *api) updateUser(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := userFrom(ctx)
	claims := claimsFrom(ctx)

	params := &UserUpdateParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}

	set := map[string]any{}
	now := a.now()

	var newEmail string
	if params.Email != nil {
		newEmail = strings.ToLower(strings.TrimSpace(*params.Email))
		if newEmail == "" {
			return badRequestError(ErrorCodeValidationFailed, "An email address is required")
		}
		if _, err := mail.ParseAddress(newEmail); err != nil {
			return badRequestError(ErrorCodeValidationFailed, "Unable to validate email address: invalid format")
		}
		if newEmail == user.Email {
			newEmail = "" // no-op
		}
	}
	if err := validatePKCEParams(params.CodeChallengeMethod, params.CodeChallenge); err != nil {
		return err
	}

	// A phone change mirrors the email change one-for-one, with SMS.Autoconfirm
	// standing in for Mailer.Autoconfirm. An absent field and an empty string
	// are both no-ops (upstream ignores an empty phone).
	var newPhone string
	if params.Phone != nil && strings.TrimSpace(*params.Phone) != "" {
		if !a.phoneProviderEnabled() {
			return badRequestError(ErrorCodePhoneProviderDisabled, "Phone logins are disabled")
		}
		normalized, perr := validatePhone(*params.Phone)
		if perr != nil {
			return perr
		}
		if normalized != user.Phone {
			newPhone = normalized
		}
	}
	params.Channel = defaultChannel(params.Channel)
	if newPhone != "" && !a.isValidMessageChannel(params.Channel) {
		return badRequestError(ErrorCodeValidationFailed, "%s", invalidChannelError)
	}

	// Upstream: with MFA enabled, changing the email, phone or password needs
	// an aal2 session — otherwise a stolen password alone could replace the
	// credentials the second factor protects.
	if (params.Password != nil && *params.Password != "") || newEmail != "" || newPhone != "" {
		pool, perr := a.db(ctx)
		if perr != nil {
			return perr
		}
		needed, serr := a.stepUpRequired(ctx, pool, user)
		if serr != nil {
			return serr
		}
		if needed {
			return httpError(http.StatusUnauthorized, ErrorCodeInsufficientAAL,
				"AAL2 session is required to update email or password when MFA is enabled.")
		}
	}

	sessionID := sessionIDFrom(claims)

	passwordChanged := false
	if params.Password != nil {
		if rerr := a.requireReauthentication(ctx, params.Nonce, user, sessionID); rerr != nil {
			return rerr
		}
		if herr := a.checkPasswordStrength(ctx, *params.Password); herr != nil {
			return herr
		}
		if user.EncryptedPassword != nil && ComparePassword(*user.EncryptedPassword, *params.Password) == nil {
			return unprocessableEntityError(ErrorCodeSamePassword,
				"New password should be different from the old password.")
		}
		hashed, err := HashPassword(*params.Password)
		if err != nil {
			return internalServerError("Error hashing password").withInternal(err)
		}
		set["encrypted_password"] = hashed
		passwordChanged = true
	}

	if params.Data != nil {
		merged := JSONMap{}
		for k, v := range user.UserMetaData {
			merged[k] = v
		}
		for k, v := range params.Data {
			if v == nil {
				delete(merged, k)
				continue
			}
			merged[k] = v
		}
		set["raw_user_meta_data"] = merged
	}

	// A confirmed email change is a two-step flow (see the doc comment): the new
	// address is parked and mailed, not applied.
	confirmEmailChange := newEmail != "" && !a.cfg.Mailer.Autoconfirm
	if newEmail != "" && !confirmEmailChange {
		set["email"] = newEmail
		set["email_confirmed_at"] = now
	}

	if len(set) == 0 && !confirmEmailChange && newPhone == "" {
		return sendJSON(w, http.StatusOK, user)
	}

	if newEmail != "" {
		// Fail fast on a taken address; the unique index is the backstop.
		pool, perr := a.db(ctx)
		if perr != nil {
			return perr
		}
		dup, derr := findUserByEmail(ctx, pool, newEmail, user.Aud)
		if derr != nil && !isNoRows(derr) {
			return internalServerError("Database error checking email").withInternal(derr)
		}
		if dup != nil && dup.ID != user.ID {
			return unprocessableEntityError(ErrorCodeEmailExists,
				"A user with this email address has already been registered")
		}
	}

	if newPhone != "" {
		// Fail fast on a taken number; the unique index is the backstop.
		pool, perr := a.db(ctx)
		if perr != nil {
			return perr
		}
		taken, derr := isDuplicatePhone(ctx, pool, newPhone, user.Aud, user.ID)
		if derr != nil {
			return internalServerError("Database error checking phone").withInternal(derr)
		}
		if taken {
			return unprocessableEntityError(ErrorCodePhoneExists, "%s", duplicatePhoneMsg)
		}
	}

	oldEmail := user.Email
	pkce := isPKCERequest(params.CodeChallenge)

	var updated *User
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		// The nonce is burned in the SAME transaction that applies the change it
		// authorized: a failed update must not spend it, a successful one must
		// not leave it reusable.
		if passwordChanged && params.Nonce != "" {
			if verr := a.verifyReauthentication(ctx, tx, params.Nonce, user); verr != nil {
				return verr
			}
		}

		var uerr error
		updated, uerr = updateUserFields(ctx, tx, user.ID, now, set)
		if uerr != nil {
			if isUniqueViolation(uerr) {
				return unprocessableEntityError(ErrorCodeEmailExists,
					"A user with this email address has already been registered")
			}
			return internalServerError("Database error updating user").withInternal(uerr)
		}

		if confirmEmailChange {
			if pkce {
				if ferr := a.startEmailChangeFlowState(ctx, tx, params, user.ID, now); ferr != nil {
					return ferr
				}
			}
			if _, _, serr := a.sendEmailChange(ctx, tx, r, user, newEmail, params.RedirectTo, pkce); serr != nil {
				return serr
			}
			refreshed, rerr := a.loadUserWithIdentities(ctx, tx, user.ID)
			if rerr != nil {
				return internalServerError("Error refetching user").withInternal(rerr)
			}
			updated = refreshed
		}

		if newPhone != "" {
			if a.cfg.SMS.Autoconfirm {
				// Upstream parks the number and runs the phone_change effect on
				// the spot (api/user.go: smsVerify with a synthetic
				// VerifyParams), so no OTP is ever texted.
				parked, uerr := updateUserFields(ctx, tx, user.ID, now, map[string]any{"phone_change": newPhone})
				if uerr != nil {
					if isUniqueViolation(uerr) {
						return unprocessableEntityError(ErrorCodePhoneExists, "%s", duplicatePhoneMsg)
					}
					return internalServerError("Database error updating user").withInternal(uerr)
				}
				applied, verr := a.smsVerify(ctx, tx, r,
					&VerifyParams{Type: phoneChangeVerification, Phone: newPhone}, parked)
				if verr != nil {
					return verr
				}
				updated = applied
			} else {
				// Confirmation required: the number is parked in
				// auth.users.phone_change and only lands through
				// POST /verify {type:"phone_change", phone, token}.
				if _, serr := a.sendPhoneConfirmation(ctx, tx, r, user, newPhone,
					phoneChangeVerification, params.Channel); serr != nil {
					return serr
				}
				refreshed, rerr := a.loadUserWithIdentities(ctx, tx, user.ID)
				if rerr != nil {
					return internalServerError("Error refetching user").withInternal(rerr)
				}
				updated = refreshed
			}
		}

		if newEmail != "" && !confirmEmailChange {
			// Keep the email identity's identity_data in sync — supabase-js and
			// RLS policies read the identity, not just auth.users.
			if ierr := updateIdentityData(ctx, tx, user.ID, ProviderEmail, JSONMap{
				"sub":            user.ID,
				"email":          newEmail,
				"email_verified": true,
				"phone_verified": false,
			}, now); ierr != nil {
				return internalServerError("Error updating identity").withInternal(ierr)
			}
		}

		if passwordChanged {
			// A password change invalidates every OTHER session (project.md
			// §2.3): the current caller stays signed in.
			if sessionID != "" {
				if derr := deleteOtherUserSessions(ctx, tx, user.ID, sessionID); derr != nil {
					return internalServerError("Error revoking sessions").withInternal(derr)
				}
			} else if derr := deleteUserSessions(ctx, tx, user.ID); derr != nil {
				return internalServerError("Error revoking sessions").withInternal(derr)
			}
		}

		ids, ierr := findIdentitiesByUserID(ctx, tx, user.ID)
		if ierr != nil {
			return internalServerError("Error loading identities").withInternal(ierr)
		}
		updated.Identities = ids
		return nil
	}); err != nil {
		return err
	}

	if newEmail != "" && !confirmEmailChange {
		a.notify(ctx, oldEmail, "Your email address was changed",
			"The email address on your account was changed to "+newEmail+".")
	}
	if passwordChanged {
		a.notify(ctx, updated.Email, "Your password was changed",
			"The password on your account was changed. Other sessions have been signed out.")
	}

	return sendJSON(w, http.StatusOK, updated)
}

// requireReauthentication enforces Security.UpdatePasswordRequireReauth.
//
// Upstream's rule: a session created within the last 24 hours is proof enough;
// otherwise a nonce from GET /reauthenticate is required. The nonce itself is
// only VERIFIED later, inside the transaction that applies the password change.
func (a *api) requireReauthentication(ctx context.Context, nonce string, user *User, sessionID string) error {
	if !a.cfg.Security.UpdatePasswordRequireReauth {
		return nil
	}

	recent := false
	if sessionID != "" {
		pool, perr := a.db(ctx)
		if perr != nil {
			return perr
		}
		sess, serr := findSessionByID(ctx, pool, sessionID)
		if serr != nil && !isNoRows(serr) {
			return internalServerError("Error loading session").withInternal(serr)
		}
		if sess != nil && !a.now().After(sess.CreatedAt.Add(reauthRecencyWindow)) {
			recent = true
		}
	}
	if recent {
		return nil
	}
	if nonce == "" {
		return badRequestError(ErrorCodeReauthenticationNeeded, "Password update requires reauthentication")
	}
	return nil
}

// startEmailChangeFlowState creates the PKCE flow state an email-change
// confirmation redeems (pkce.go).
func (a *api) startEmailChangeFlowState(ctx context.Context, tx querier, params *UserUpdateParams, userID string, now time.Time) error {
	if _, err := createFlowState(ctx, tx, authMethodEmailChange, authMethodEmailChange,
		params.CodeChallengeMethod, params.CodeChallenge, userID, now); err != nil {
		return internalServerError("Error creating flow state").withInternal(err)
	}
	return nil
}

// logout implements POST /logout. Upstream supports ?scope=global|local|others
// and always answers 204.
func (a *api) logout(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := userFrom(ctx)
	sessionID := sessionIDFrom(claimsFrom(ctx))

	scope := r.URL.Query().Get("scope")
	switch scope {
	case "", "global", "local", "others":
	default:
		return badRequestError(ErrorCodeValidationFailed, "Unsupported logout scope %q", scope)
	}

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		now := a.now()

		if sessionID != "" {
			switch scope {
			case "local":
				if err := deleteSession(ctx, tx, sessionID); err != nil {
					return internalServerError("Error logging out user").withInternal(err)
				}
				return nil
			case "others":
				if err := deleteOtherUserSessions(ctx, tx, user.ID, sessionID); err != nil {
					return internalServerError("Error logging out user").withInternal(err)
				}
				return nil
			}
		}

		// Default (global): every session and refresh token of the user dies.
		if err := deleteUserSessions(ctx, tx, user.ID); err != nil {
			return internalServerError("Error logging out user").withInternal(err)
		}
		if err := revokeUserRefreshTokens(ctx, tx, user.ID, now); err != nil {
			return internalServerError("Error logging out user").withInternal(err)
		}
		return nil
	}); err != nil {
		return err
	}

	w.WriteHeader(http.StatusNoContent)
	return nil
}

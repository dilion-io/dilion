package auth

// POST /invite — an admin creates an account and mails an invitation.
//
// Reproduces github.com/supabase/auth/internal/api/invite.go.
//
//	POST /invite {email, data?}      (service_role, or users.admin via RBAC)
//	-> 200 <user>
//
// The invited account exists immediately but is UNCONFIRMED and has no password
// the invitee knows; following the mailed link (GET /verify?type=invite)
// confirms it, sets a random password and signs them in, at which point the
// application is expected to walk them through PUT /user.
//
// Unlike the self-service endpoints this one is deliberately NOT
// enumeration-safe: an admin inviting an already-registered, confirmed address
// gets upstream's 422 email_exists, because an admin is entitled to know.

import (
	"net/http"
	"net/mail"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/ports"
)

func init() {
	registerFeature("invite", func(a *api, r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(a.requireAdmin)
			r.With(a.limit(LimiterOTP)).Post("/invite", a.handle(a.invite))
		})
	})
}

// InviteParams is the POST /invite body (upstream api.InviteParams).
type InviteParams struct {
	Email      string         `json:"email"`
	Data       map[string]any `json:"data"`
	RedirectTo string         `json:"redirect_to"`
}

func (a *api) invite(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	params := &InviteParams{}
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

	aud := requestAud(r)
	redirectTo := params.RedirectTo
	if redirectTo == "" {
		redirectTo = redirectToOf(r)
	}

	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	existing, err := findUserByEmail(ctx, pool, params.Email, aud)
	if err != nil && !isNoRows(err) {
		return internalServerError("Database error finding user").withInternal(err)
	}
	if existing != nil && existing.EmailConfirmedAt != nil {
		return unprocessableEntityError(ErrorCodeEmailExists,
			"A user with this email address has already been registered")
	}

	// The invited account gets a random password it will never be told; the
	// invite link is the only way in until PUT /user sets a real one.
	var hashed string
	if existing == nil {
		h, data, herr := a.prepareEmailUser(ctx, params.Email, params.Data)
		if herr != nil {
			return herr
		}
		hashed, params.Data = h, data
	}

	now := a.now()
	created := false
	var user *User

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		user = existing
		if user == nil {
			var cerr error
			user, cerr = a.insertEmailUser(ctx, tx, params.Email, aud, hashed, params.Data, false, now)
			if cerr != nil {
				return cerr
			}
			created = true
		}
		if _, serr := a.sendInvite(ctx, tx, r, user, redirectTo); serr != nil {
			return serr
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
		// An admin-actor account creation is a graded change (project.md §5.2).
		// Only the FACT and the subject's UUID are recorded — never the address.
		a.emitAudit(r, auditOpts{
			Action:      audit.ActionUserCreated,
			Resource:    auditResourceUser(user.ID),
			AccessLevel: audit.AccessNA,
			SubjectIDs:  []string{user.ID},
		})
	}

	return sendJSON(w, http.StatusOK, user)
}

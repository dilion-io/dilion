package auth

// POST /recover — send a password-reset link.
//
// Reproduces github.com/supabase/auth/internal/api/recover.go.
//
//	POST /recover {email, code_challenge?, code_challenge_method?}
//	-> 200 {}
//
// The answer is `{}` for a known and for an unknown address alike: a password
// reset form must not double as an account-existence oracle. Following the
// mailed link (GET /verify?type=recovery) signs the user in, which is what lets
// the client show a "choose a new password" form and finish with PUT /user.

import (
	"net/http"
	"net/mail"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

func init() {
	registerFeature("recover", func(a *api, r chi.Router) {
		r.With(a.limit(LimiterRecover)).Post("/recover", a.handle(a.recover))
	})
}

// RecoverParams is the POST /recover body (upstream api.RecoverParams).
type RecoverParams struct {
	Email               string `json:"email"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	RedirectTo          string `json:"redirect_to"`
}

func (a *api) recover(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	// CAPTCHA first (captcha.go): /recover makes the server send mail to an
	// address the caller names.
	if cerr := a.verifyCaptcha(r); cerr != nil {
		return cerr
	}

	params := &RecoverParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	params.Email = strings.ToLower(strings.TrimSpace(params.Email))
	if params.Email == "" {
		return badRequestError(ErrorCodeValidationFailed, "Password recovery requires an email")
	}
	if _, err := mail.ParseAddress(params.Email); err != nil {
		return badRequestError(ErrorCodeValidationFailed, "Unable to validate email address: invalid format")
	}
	if err := validatePKCEParams(params.CodeChallengeMethod, params.CodeChallenge); err != nil {
		return err
	}
	pkce := isPKCERequest(params.CodeChallenge)

	redirectTo := params.RedirectTo
	if redirectTo == "" {
		redirectTo = redirectToOf(r)
	}

	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	user, err := findUserByEmail(ctx, pool, params.Email, requestAud(r))
	if err != nil {
		if isNoRows(err) {
			// Unknown address: same body, same status, no mail.
			return sendJSON(w, http.StatusOK, map[string]string{})
		}
		return internalServerError("Unable to process request").withInternal(err)
	}

	now := a.now()
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		if pkce {
			if _, ferr := createFlowState(ctx, tx, authMethodRecovery, authMethodRecovery,
				params.CodeChallengeMethod, params.CodeChallenge, user.ID, now); ferr != nil {
				return internalServerError("Error creating flow state").withInternal(ferr)
			}
		}
		_, serr := a.sendPasswordRecovery(ctx, tx, r, user, redirectTo, pkce)
		return serr
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, map[string]string{})
}

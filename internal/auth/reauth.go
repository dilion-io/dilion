package auth

// GET /reauthenticate — mail a one-time nonce so a sensitive change can be
// re-authorized.
//
// Reproduces github.com/supabase/auth/internal/api/reauthenticate.go.
//
//	GET /reauthenticate            (Bearer access token)
//	-> 200 {}   and a mail (or, for a phone-only account, an SMS) containing a
//	            6-digit code
//
//	PUT /user {"password": "...", "nonce": "123456"}
//
// The nonce is stored the same way every other email token is (ott.go): the mail
// carries the OTP, auth.users.reauthentication_token and
// auth.one_time_tokens hold sha224(email+otp). It is consumed by
// verifyReauthentication (user.go) and, like every successful redemption,
// retires every other pending one-time token on the account.

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

func init() {
	registerFeature("reauthenticate", func(a *api, r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(a.requireAuthentication)
			r.With(a.limit(LimiterOTP)).Get("/reauthenticate", a.handle(a.reauthenticate))
		})
	})
}

// invalidNonceMessage is upstream's InvalidNonceMessage.
const invalidNonceMessage = "Nonce has expired or is invalid"

func (a *api) reauthenticate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	user := userFrom(ctx)

	if user.Email == "" && user.Phone == "" {
		return badRequestError(ErrorCodeValidationFailed,
			"Reauthentication requires the user to have an email or a phone number")
	}
	// Upstream prefers the EMAIL when an account has both.
	if user.Email == "" {
		if !a.phoneProviderEnabled() {
			return badRequestError(ErrorCodePhoneProviderDisabled, "Unsupported phone provider")
		}
		if user.PhoneConfirmedAt == nil {
			return unprocessableEntityError(ErrorCodePhoneNotConfirmed, "Please verify your phone first.")
		}
		if err := a.inTx(ctx, func(tx pgx.Tx) error {
			_, serr := a.sendPhoneConfirmation(ctx, tx, r, user, user.Phone, phoneReauthenticationOTP, channelSMS)
			return serr
		}); err != nil {
			return err
		}
		return sendJSON(w, http.StatusOK, map[string]any{})
	}
	if user.EmailConfirmedAt == nil {
		return unprocessableEntityError(ErrorCodeEmailNotConfirmed, "Please verify your email first.")
	}

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		return a.sendReauthentication(ctx, tx, user)
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, map[string]any{})
}

// verifyReauthentication is upstream's verifyReauthentication: check the nonce
// against reauthentication_token, then burn it.
//
// It must run inside the transaction that applies the change it authorizes, so a
// failed password update cannot leave the nonce spent (or a successful one leave
// it reusable).
func (a *api) verifyReauthentication(ctx context.Context, tx querier, nonce string, user *User) error {
	if user.Email == "" && user.Phone == "" {
		return unprocessableEntityError(ErrorCodeReauthenticationNotValid,
			"Reauthentication requires an email or a phone number")
	}
	tokens, err := findUserTokens(ctx, tx, user.ID)
	if err != nil {
		return internalServerError("Error during reauthentication").withInternal(err)
	}
	if tokens.ReauthenticationToken == "" || user.ReauthenticationSentAt == nil {
		return unprocessableEntityError(ErrorCodeReauthenticationNotValid, "%s", invalidNonceMessage)
	}
	// The nonce was hashed against whichever identifier it was sent to, and a
	// phone nonce expires on the (much shorter) SMS clock.
	valid := false
	if user.Email != "" {
		valid = a.isOTPValid(generateTokenHash(user.Email, nonce),
			tokens.ReauthenticationToken, user.ReauthenticationSentAt)
	} else {
		valid = a.isSMSOTPValid(generateTokenHash(user.Phone, nonce),
			tokens.ReauthenticationToken, user.ReauthenticationSentAt)
	}
	if !valid {
		return unprocessableEntityError(ErrorCodeReauthenticationNotValid, "%s", invalidNonceMessage)
	}

	if _, err := updateUserFields(ctx, tx, user.ID, a.now(), map[string]any{
		"reauthentication_token": "",
	}); err != nil {
		return internalServerError("Error during reauthentication").withInternal(err)
	}
	if err := clearAllOneTimeTokens(ctx, tx, user.ID); err != nil {
		return internalServerError("Error during reauthentication").withInternal(err)
	}
	return nil
}

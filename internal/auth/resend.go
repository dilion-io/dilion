package auth

// POST /resend — re-send a pending confirmation or email-change link.
//
// Reproduces github.com/supabase/auth/internal/api/resend.go.
//
//	POST /resend {type: "signup"|"email_change", email, code_challenge?, code_challenge_method?}
//	-> 200 {}
//
//	POST /resend {type: "sms"|"phone_change", phone}
//	-> 200 {"message_id": "..."}
//
// Every terminal case answers `{}` with 200 — unknown address or number, already
// confirmed, nothing pending — so /resend cannot be used to probe account state.

import (
	"net/http"
	"net/mail"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

func init() {
	registerFeature("resend", func(a *api, r chi.Router) {
		r.With(a.limit(LimiterResend)).Post("/resend", a.handle(a.resend))
	})
}

// ResendConfirmationParams is the POST /resend body (upstream
// api.ResendConfirmationParams).
type ResendConfirmationParams struct {
	Type                string `json:"type"`
	Email               string `json:"email"`
	Phone               string `json:"phone"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	RedirectTo          string `json:"redirect_to"`
}

func (a *api) resend(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	// CAPTCHA first (captcha.go): /resend is a mail-sending endpoint.
	if cerr := a.verifyCaptcha(r); cerr != nil {
		return cerr
	}

	params := &ResendConfirmationParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	params.Email = strings.ToLower(strings.TrimSpace(params.Email))
	params.Phone = strings.TrimSpace(params.Phone)

	switch params.Type {
	case mailSignup, mailEmailChange:
		if err := validatePKCEParams(params.CodeChallengeMethod, params.CodeChallenge); err != nil {
			return err
		}
	case smsVerification, phoneChangeVerification:
		return a.resendSMS(w, r, params)
	default:
		return badRequestError(ErrorCodeValidationFailed,
			"Missing one of these types: signup, email_change, sms, phone_change")
	}

	if params.Email == "" && params.Type == mailSignup {
		return badRequestError(ErrorCodeValidationFailed, "Type provided requires an email address")
	}
	switch {
	case params.Email != "" && params.Phone != "":
		return badRequestError(ErrorCodeValidationFailed, "Only an email address or phone number should be provided.")
	case params.Phone != "":
		// An email `type` with a phone number: the two disagree.
		return badRequestError(ErrorCodeValidationFailed, "Only an email address or phone number should be provided.")
	case params.Email == "":
		return badRequestError(ErrorCodeValidationFailed, "Missing email address or phone number")
	}
	if !a.cfg.External[ProviderEmail].Enabled {
		return badRequestError(ErrorCodeEmailProviderDisabled, "Email logins are disabled")
	}
	if _, err := mail.ParseAddress(params.Email); err != nil {
		return badRequestError(ErrorCodeValidationFailed, "Unable to validate email address: invalid format")
	}

	pkce := isPKCERequest(params.CodeChallenge)
	redirectTo := params.RedirectTo
	if redirectTo == "" {
		redirectTo = redirectToOf(r)
	}
	empty := map[string]string{}

	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	user, err := findUserByEmail(ctx, pool, params.Email, requestAud(r))
	if err != nil {
		if isNoRows(err) {
			return sendJSON(w, http.StatusOK, empty)
		}
		return internalServerError("Unable to process request").withInternal(err)
	}

	// Nothing left to confirm: answer as if the mail went out.
	switch params.Type {
	case mailSignup:
		if user.EmailConfirmedAt != nil {
			return sendJSON(w, http.StatusOK, empty)
		}
	case mailEmailChange:
		if user.EmailChange == "" {
			return sendJSON(w, http.StatusOK, empty)
		}
	}

	now := a.now()
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		switch params.Type {
		case mailSignup:
			if pkce {
				if _, ferr := createFlowState(ctx, tx, ProviderEmail, authMethodEmailSignup,
					params.CodeChallengeMethod, params.CodeChallenge, user.ID, now); ferr != nil {
					return internalServerError("Error creating flow state").withInternal(ferr)
				}
			}
			_, serr := a.sendConfirmation(ctx, tx, r, user, redirectTo, pkce)
			return serr
		default: // mailEmailChange
			if pkce {
				if _, ferr := createFlowState(ctx, tx, authMethodEmailChange, authMethodEmailChange,
					params.CodeChallengeMethod, params.CodeChallenge, user.ID, now); ferr != nil {
					return internalServerError("Error creating flow state").withInternal(ferr)
				}
			}
			_, _, serr := a.sendEmailChange(ctx, tx, r, user, user.EmailChange, redirectTo, pkce)
			return serr
		}
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, empty)
}

// resendSMS is the phone half of POST /resend (upstream's smsVerification /
// phoneChangeVerification cases).
//
//	type "sms"           re-text the SIGNUP confirmation OTP
//	type "phone_change"  re-text the OTP for the number parked in phone_change
//
// In both cases `phone` is the account's CURRENT number — that is how upstream
// resolves the user — and for a phone change the message goes to the PENDING
// one. Like the email half, every terminal case answers 200.
//
// Upstream hard-codes the SMS channel here (there is no `channel` field on the
// resend body), and so does Dilion.
func (a *api) resendSMS(w http.ResponseWriter, r *http.Request, params *ResendConfirmationParams) error {
	ctx := r.Context()

	if params.Email != "" {
		return badRequestError(ErrorCodeValidationFailed, "Only an email address or phone number should be provided.")
	}
	if params.Phone == "" {
		if params.Type == smsVerification {
			return badRequestError(ErrorCodeValidationFailed, "Type provided requires a phone number")
		}
		return badRequestError(ErrorCodeValidationFailed, "Missing email address or phone number")
	}
	if !a.phoneProviderEnabled() {
		return badRequestError(ErrorCodePhoneProviderDisabled, "Phone logins are disabled")
	}
	phone, perr := validatePhone(params.Phone)
	if perr != nil {
		return perr
	}

	empty := map[string]any{}

	pool, dberr := a.db(ctx)
	if dberr != nil {
		return dberr
	}
	user, err := findUserByPhone(ctx, pool, phone, requestAud(r))
	if err != nil {
		if isNoRows(err) {
			return sendJSON(w, http.StatusOK, empty)
		}
		return internalServerError("Unable to process request").withInternal(err)
	}

	// Nothing left to confirm: answer as if the message went out.
	target, otpType := phone, phoneConfirmationOTP
	switch params.Type {
	case smsVerification:
		if user.PhoneConfirmedAt != nil {
			return sendJSON(w, http.StatusOK, empty)
		}
	default: // phoneChangeVerification
		if user.PhoneChange == "" {
			return sendJSON(w, http.StatusOK, empty)
		}
		target, otpType = user.PhoneChange, phoneChangeVerification
	}

	messageID := ""
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		mID, serr := a.sendPhoneConfirmation(ctx, tx, r, user, target, otpType, channelSMS)
		if serr != nil {
			return serr
		}
		messageID = mID
		return nil
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, smsResponse(messageID))
}

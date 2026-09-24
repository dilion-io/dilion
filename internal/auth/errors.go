package auth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
)

// Error codes mirror github.com/supabase/auth/internal/api/apierrors/errorcode.go
// verbatim. Only the wave-1 subset is declared; add upstream names as features land.
const (
	ErrorCodeUnexpectedFailure = "unexpected_failure"
	ErrorCodeValidationFailed  = "validation_failed"
	ErrorCodeBadJSON           = "bad_json"
	ErrorCodeBadJWT            = "bad_jwt"
	ErrorCodeNotAdmin          = "not_admin"
	ErrorCodeNoAuthorization   = "no_authorization"
	ErrorCodeEmailExists       = "email_exists"
	ErrorCodePhoneExists       = "phone_exists"
	ErrorCodeUserNotFound      = "user_not_found"
	ErrorCodeUserAlreadyExists = "user_already_exists"
	ErrorCodeUserBanned        = "user_banned"
	ErrorCodeSessionNotFound   = "session_not_found"
	// ErrorCodeOAuthClientToken: an OAuth application's token on a route only
	// the user's own sign-in may use (Dilion extension).
	ErrorCodeOAuthClientToken        = "oauth_client_token_not_allowed"
	ErrorCodeSessionExpired          = "session_expired"
	ErrorCodeRefreshTokenNotFound    = "refresh_token_not_found"
	ErrorCodeRefreshTokenAlreadyUsed = "refresh_token_already_used"
	ErrorCodeSignupDisabled          = "signup_disabled"
	ErrorCodeInvalidCredentials      = "invalid_credentials"
	ErrorCodeSamePassword            = "same_password"
	ErrorCodeWeakPassword            = "weak_password"
	ErrorCodeConflict                = "conflict"
	ErrorCodeEmailNotConfirmed       = "email_not_confirmed"

	// ErrorCodeOverRequestRateLimit is the 429 of every rate-limited endpoint.
	ErrorCodeOverRequestRateLimit = "over_request_rate_limit"
	// ErrorCodeRequestTimeout is upstream's 504 when a request exceeds
	// GOTRUE_API_MAX_REQUEST_DURATION.
	ErrorCodeRequestTimeout = "request_timeout"
	// ErrorCodeAnonymousProviderDisabled is POST /signup without email/phone
	// while anonymous sign-ins are off.
	ErrorCodeAnonymousProviderDisabled = "anonymous_provider_disabled"
	// ErrorCodeEmailProviderDisabled is a password/email flow while the email
	// provider is disabled.
	ErrorCodeEmailProviderDisabled = "email_provider_disabled"
	// ErrorCodePhoneProviderDisabled is a phone flow while the phone provider is
	// disabled.
	ErrorCodePhoneProviderDisabled = "phone_provider_disabled"

	// ---- email lifecycle (verify / otp / recover / resend / invite) --------

	// ErrorCodeOTPExpired is /verify's answer for a token that is unknown,
	// already consumed, or past Mailer.OTPExp. The three cases deliberately
	// share one code and one message so /verify is not an oracle for which
	// links exist.
	ErrorCodeOTPExpired = "otp_expired"
	// ErrorCodeOTPDisabled is POST /otp with create_user=false for an address
	// that has no account.
	ErrorCodeOTPDisabled = "otp_disabled"
	// ErrorCodeOverEmailSendRateLimit is the 429 of the mail-sending endpoints.
	ErrorCodeOverEmailSendRateLimit = "over_email_send_rate_limit"
	// ErrorCodePhoneNotConfirmed is a phone flow on an unverified number.
	ErrorCodePhoneNotConfirmed = "phone_not_confirmed"
	// ErrorCodeUserSSOManaged is an attempt to change the email, phone or
	// password of an account whose identity is owned by an SSO provider.
	ErrorCodeUserSSOManaged = "user_sso_managed"

	// ---- reauthentication -------------------------------------------------

	// ErrorCodeReauthenticationNeeded is PUT /user with a new password while
	// Security.UpdatePasswordRequireReauth is on and no nonce was supplied.
	ErrorCodeReauthenticationNeeded = "reauthentication_needed"
	// ErrorCodeReauthenticationNotValid is a nonce that is wrong or expired.
	ErrorCodeReauthenticationNotValid = "reauthentication_not_valid"

	// ---- PKCE -------------------------------------------------------------

	// ErrorCodeFlowStateNotFound is an auth code that never existed, was already
	// redeemed, or belongs to a flow with no user.
	ErrorCodeFlowStateNotFound = "flow_state_not_found"
	// ErrorCodeFlowStateExpired is an auth code older than FlowStateExpiry.
	ErrorCodeFlowStateExpired = "flow_state_expired"
	// ErrorCodeBadCodeVerifier is a code_verifier that does not hash to the
	// challenge the flow was created with.
	ErrorCodeBadCodeVerifier = "bad_code_verifier"
)

// InvalidLoginMessage is upstream's constant message for a failed password grant.
// It is deliberately identical for "no such user" and "wrong password" so the
// endpoint does not become a user-enumeration oracle.
const InvalidLoginMessage = "Invalid login credentials"

// HTTPError is the gotrue error body. The JSON tags are part of the compatibility
// contract — do not rename them.
//
//	{"code": 400, "error_code": "validation_failed", "msg": "..."}
type HTTPError struct {
	HTTPStatus int    `json:"code"`                 // do not rename the JSON tags!
	ErrorCode  string `json:"error_code,omitempty"` // do not rename the JSON tags!
	Message    string `json:"msg"`                  // do not rename the JSON tags!

	// internal is never serialized; it carries the cause for server-side logs.
	internal error
}

func (e *HTTPError) Error() string {
	if e.internal != nil {
		return fmt.Sprintf("%d %s: %s: %v", e.HTTPStatus, e.ErrorCode, e.Message, e.internal)
	}
	return fmt.Sprintf("%d %s: %s", e.HTTPStatus, e.ErrorCode, e.Message)
}

func (e *HTTPError) Unwrap() error { return e.internal }

// withInternal attaches a cause that is logged but never returned to the client.
func (e *HTTPError) withInternal(err error) *HTTPError {
	e.internal = err
	return e
}

func httpError(status int, code, format string, args ...any) *HTTPError {
	return &HTTPError{HTTPStatus: status, ErrorCode: code, Message: fmt.Sprintf(format, args...)}
}

func badRequestError(code, format string, args ...any) *HTTPError {
	return httpError(http.StatusBadRequest, code, format, args...)
}

func unauthorizedError(code, format string, args ...any) *HTTPError {
	return httpError(http.StatusUnauthorized, code, format, args...)
}

func forbiddenError(code, format string, args ...any) *HTTPError {
	return httpError(http.StatusForbidden, code, format, args...)
}

func notFoundError(code, format string, args ...any) *HTTPError {
	return httpError(http.StatusNotFound, code, format, args...)
}

func conflictError(format string, args ...any) *HTTPError {
	return httpError(http.StatusConflict, ErrorCodeConflict, format, args...)
}

func unprocessableEntityError(code, format string, args ...any) *HTTPError {
	return httpError(http.StatusUnprocessableEntity, code, format, args...)
}

// tooManyRequestsError is gotrue's 429 body.
func tooManyRequestsError(format string, args ...any) *HTTPError {
	return httpError(http.StatusTooManyRequests, ErrorCodeOverRequestRateLimit, format, args...)
}

func internalServerError(format string, args ...any) *HTTPError {
	return httpError(http.StatusInternalServerError, ErrorCodeUnexpectedFailure, format, args...)
}

// sendJSON writes obj as the response body. Errors are reported to the caller
// rather than swallowed so the handler chain can log them.
func sendJSON(w http.ResponseWriter, status int, obj any) error {
	b, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("auth: marshal response: %w", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(b)
	return err
}

// handlerFunc lets handlers return errors; writeError renders them in gotrue's
// error format.
type handlerFunc func(w http.ResponseWriter, r *http.Request) error

func (a *api) handle(fn handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			a.writeError(r, w, err)
		}
	}
}

func (a *api) writeError(r *http.Request, w http.ResponseWriter, err error) {
	he, ok := err.(*HTTPError)
	if !ok {
		he = internalServerError("Unexpected failure, please check server logs for more information").withInternal(err)
	}

	level := slog.LevelWarn
	if he.HTTPStatus >= 500 {
		level = slog.LevelError
	}
	a.log.LogAttrs(r.Context(), level, "auth: request failed",
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.Int("status", he.HTTPStatus),
		slog.String("error_code", he.ErrorCode),
		slog.String("error", he.Error()),
	)

	if sendErr := sendJSON(w, he.HTTPStatus, he); sendErr != nil {
		a.log.ErrorContext(r.Context(), "auth: failed to write error response", slog.String("error", sendErr.Error()))
	}
}

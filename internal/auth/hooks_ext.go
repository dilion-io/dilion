package auth

// External auth hooks: the Supabase-compatible extension points invoked at fixed
// lifecycle moments and configured by URI (Config.Hooks, conf.go).
//
// These are DISTINCT from Dilion's in-process ports.Hooks (a.runHook /
// a.observeHook in auth.go), which are compiled-in collaborators. An external
// hook is out-of-process: the URI scheme selects the transport —
//
//	https?://                     -> HTTP webhook, HMAC-signed (hooks_http.go,
//	                                 Standard Webhooks spec)
//	pg-functions://<db>/<schema>/<func>
//	                              -> a Postgres function called in the request's
//	                                 transaction (hooks_pg.go)
//
// # Naming
//
// The runner is a.runExtHook, NOT a.runHook: a.runHook already exists in auth.go
// for the in-process ports hook points, and the two must not collide. Every
// external call site therefore reads runExtHook, which keeps the two hook systems
// visibly separate.
//
// # Error semantics (upstream v0hooks.Manager.dispatch)
//
// A hook error is returned to the caller as an *HTTPError: a validating hook
// (before_user_created, custom_access_token, the verification hooks) that fails
// aborts the request, and the error the hook communicated — via a JSON
// `{"error":{"http_code","message"}}` object or a webhook HTTP status — becomes
// the response. Observing hooks (after_user_created) are run through the
// fire-and-forget wrappers at their call sites, so their failures are logged, not
// surfaced.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// checkHookError is upstream's hookserrors.Check: both drivers run the hook's
// JSON response body through it before decoding the response into the output
// struct. A body carrying a non-empty `{"error":{"http_code","message"}}` object
// is turned into an *HTTPError that aborts the request; anything else (no error
// object, or an error object with an empty message — upstream tolerates that as
// "no error") returns nil.
func checkHookError(body []byte) error {
	if len(body) == 0 {
		return nil
	}
	var dst struct {
		Error *struct {
			HTTPCode int    `json:"http_code"`
			Message  string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &dst); err != nil {
		// Not decodable as the error envelope: leave it to the caller's decode.
		return nil
	}
	if dst.Error == nil || dst.Error.Message == "" {
		return nil
	}
	code := dst.Error.HTTPCode
	if code == 0 {
		code = http.StatusInternalServerError
	}
	return httpError(code, "", "%s", dst.Error.Message)
}

// Hook error codes. Upstream declares these in apierrors/errorcode.go; they live
// here because errors.go is shared and this file owns the external-hook surface.
const (
	// ErrorCodeHookTimeout is the 422 when a webhook does not answer within the
	// per-call timeout (upstream ErrorCodeHookTimeout).
	ErrorCodeHookTimeout = "hook_timeout"
	// ErrorCodeHookTimeoutAfterRetry is the 422 after every retry timed out.
	ErrorCodeHookTimeoutAfterRetry = "hook_timeout_after_retry"
	// ErrorCodeHookPayloadOverSizeLimit is the 422 when a webhook response body
	// exceeds the read limit.
	ErrorCodeHookPayloadOverSizeLimit = "hook_payload_over_size_limit"
	// ErrorCodeHookPayloadInvalidContentType is the 400 when a webhook answers
	// 200/202 without an application/json Content-Type.
	ErrorCodeHookPayloadInvalidContentType = "hook_payload_invalid_content_type"
)

// ErrorCodeMFAVerificationRejected (the 403 an mfa_verification_attempt hook
// raises on a "reject" decision) is declared by the MFA factor code
// (mfa_models.go); runMFAVerificationHook reuses it.

// runExtHook invokes one external hook and decodes its response into out. It is
// upstream's v0hooks.Manager.invokeHook + dispatch collapsed onto Dilion's api:
//
//   - a disabled hook is a no-op (out is left untouched), so a call site guarded
//     by cfg.<hook>.Enabled and one that always calls behave identically;
//   - the URI scheme selects the driver;
//   - tx is the caller's transaction. It is threaded to the pg-functions driver
//     so a custom_access_token or before_user_created hook runs inside the very
//     transaction that is issuing the token / creating the user (upstream passes
//     the same conn to avoid pool-exhaustion deadlocks). The HTTP driver ignores
//     it. Pass nil when no transaction is open; the pg driver then opens its own.
//
// r may be nil (issueAccessToken has no request); it only supplies the metadata
// IP address, which is omitempty.
func (a *api) runExtHook(ctx context.Context, cfg HookEndpointConfig, tx querier, in, out any) error {
	if !cfg.Enabled {
		return nil
	}
	uri := strings.TrimSpace(cfg.URI)
	switch {
	case strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://"):
		return a.dispatchHTTPHook(ctx, cfg, in, out)
	case strings.HasPrefix(uri, "pg-functions:"):
		return a.dispatchPGHook(ctx, cfg, tx, in, out)
	default:
		// Upstream returns a plain error here; wrap it as a 500 so it flows
		// through the same envelope every other hook failure does.
		return internalServerError(
			"unsupported hook protocol in URI %q: only http(s) and pg-functions are supported", uri)
	}
}

// ---- user-creation hooks (wired in signup.go) ------------------------------

// runBeforeUserCreated runs the before_user_created hook for the user about to
// be inserted. It is validating: a hook error (its `{"error":...}` object or a
// webhook rejection status) is returned as-is so the signup fails with the
// status and message the hook chose. tx is the signup transaction, threaded so a
// pg-functions hook sees the in-progress row context. A no-op when disabled.
func (a *api) runBeforeUserCreated(ctx context.Context, tx querier, u *User) error {
	cfg := a.cfg.Hooks.BeforeUserCreated
	if !cfg.Enabled {
		return nil
	}
	in := &BeforeUserCreatedInput{
		Metadata: newHookMetadata(nil, HookNameBeforeUserCreated),
		User:     u,
	}
	return a.runExtHook(ctx, cfg, tx, in, &BeforeUserCreatedOutput{})
}

// observeAfterUserCreated runs the after_user_created hook for a freshly created
// user. It is observing: it runs AFTER the signup transaction commits (with no
// transaction of its own — the pg driver opens a short one), and a failure is
// logged, never surfaced, so an observer cannot break signup. A no-op when
// disabled.
func (a *api) observeAfterUserCreated(ctx context.Context, u *User) {
	cfg := a.cfg.Hooks.AfterUserCreated
	if !cfg.Enabled {
		return
	}
	in := &AfterUserCreatedInput{
		Metadata: newHookMetadata(nil, HookNameAfterUserCreated),
		User:     u,
	}
	if err := a.runExtHook(ctx, cfg, nil, in, &AfterUserCreatedOutput{}); err != nil {
		a.log.WarnContext(ctx, "auth: after_user_created hook failed",
			"error", err.Error())
	}
}

// ---- delivery-override hooks (wired in mailflow.go / smsflow.go) ------------

// sendEmailViaHook delivers an email through the send_email hook when it is
// enabled. It returns handled=true whenever the hook is enabled — the hook then
// OWNS delivery and the built-in mailer must be skipped, whether the hook
// succeeded or failed. A hook failure is returned so the send (and its
// transaction) fails, exactly as a broken SMTP setup would. When the hook is
// disabled it returns handled=false and the caller proceeds with the built-in
// mailer.
func (a *api) sendEmailViaHook(ctx context.Context, u *User, data EmailData) (handled bool, err error) {
	cfg := a.cfg.Hooks.SendEmail
	if !cfg.Enabled {
		return false, nil
	}
	in := &SendEmailInput{
		Metadata:  newHookMetadata(nil, HookNameSendEmail),
		User:      u,
		EmailData: data,
	}
	if herr := a.runExtHook(ctx, cfg, nil, in, &SendEmailOutput{}); herr != nil {
		return true, herr
	}
	return true, nil
}

// sendSMSViaHook is sendEmailViaHook's twin for the send_sms hook. When enabled
// the hook OWNS SMS delivery and the built-in provider is skipped.
func (a *api) sendSMSViaHook(ctx context.Context, u *User, sms SMS) (handled bool, err error) {
	cfg := a.cfg.Hooks.SendSMS
	if !cfg.Enabled {
		return false, nil
	}
	in := &SendSMSInput{
		Metadata: newHookMetadata(nil, HookNameSendSMS),
		User:     u,
		SMS:      sms,
	}
	if herr := a.runExtHook(ctx, cfg, nil, in, &SendSMSOutput{}); herr != nil {
		return true, herr
	}
	return true, nil
}

// ---- verification-hook seams (owned by other agents) -----------------------
//
// The MFA and grant/password owners call these two methods; this file only
// DEFINES them so those agents have a stable seam. Both are fail-closed on a hook
// error and return (allowed, error): allowed=false means the hook decided
// "reject", err!=nil means the hook could not be reached or misbehaved.

// runMFAVerificationHook runs the mfa_verification_attempt hook for a factor
// verification whose local outcome is `valid`. It returns whether the attempt
// may proceed: false when the hook's decision is "reject".
//
// SEAM FOR THE MFA AGENT: call this from the factor-challenge verification path
// (factors*.go / mfa verify) immediately AFTER the local code/secret check and
// BEFORE a session is upgraded to aal2, passing the just-computed `valid`. On a
// reject, surface the returned error (a 403 carrying the hook's message) instead
// of completing the challenge. userID/factorID are the UUIDs of the user and the
// factor; factorType is "totp" | "phone" | "webauthn".
func (a *api) runMFAVerificationHook(ctx context.Context, userID, factorID, factorType string, valid bool) (bool, error) {
	cfg := a.cfg.Hooks.MFAVerificationAttempt
	if !cfg.Enabled {
		return true, nil
	}
	in := &MFAVerificationAttemptInput{
		Metadata:   newHookMetadata(nil, HookNameMFAVerification),
		UserID:     userID,
		FactorID:   factorID,
		FactorType: factorType,
		Valid:      valid,
	}
	out := &MFAVerificationAttemptOutput{}
	if err := a.runExtHook(ctx, cfg, nil, in, out); err != nil {
		return false, err
	}
	if out.Decision == HookRejection {
		msg := out.Message
		if msg == "" {
			msg = DefaultMFAHookRejectionMessage
		}
		return false, forbiddenError(ErrorCodeMFAVerificationRejected, "%s", msg)
	}
	return true, nil
}

// runPasswordVerificationHook runs the password_verification_attempt hook for a
// password check whose local outcome is `valid`. It returns whether the caller
// may proceed: false when the hook's decision is "reject".
//
// SEAM FOR THE GRANT AGENT: call this from the password grant (grant.go /
// token.go password path) immediately AFTER comparing the password hash, passing
// the boolean result. On a reject, surface the returned error instead of issuing
// a session. Upstream also honours ShouldLogoutUser (terminating existing
// sessions on repeated failures); that side effect is left to the grant owner —
// this seam returns only the allow/deny decision and the message.
func (a *api) runPasswordVerificationHook(ctx context.Context, userID string, valid bool) (bool, error) {
	cfg := a.cfg.Hooks.PasswordVerificationAttempt
	if !cfg.Enabled {
		return true, nil
	}
	in := &PasswordVerificationAttemptInput{
		Metadata: newHookMetadata(nil, HookNamePasswordVerification),
		UserID:   userID,
		Valid:    valid,
	}
	out := &PasswordVerificationAttemptOutput{}
	if err := a.runExtHook(ctx, cfg, nil, in, out); err != nil {
		return false, err
	}
	if out.Decision == HookRejection {
		msg := out.Message
		if msg == "" {
			msg = DefaultPasswordHookRejectionMessage
		}
		// Upstream answers a password-hook rejection with 400 invalid_credentials
		// (the ShouldLogoutUser side effect is the grant owner's to honour).
		return false, badRequestError(ErrorCodeInvalidCredentials, "%s", msg)
	}
	return true, nil
}

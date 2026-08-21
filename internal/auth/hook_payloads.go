package auth

// Typed payloads for the Supabase-compatible external auth hooks.
//
// These structs and their JSON tags are copied field-for-field from
// github.com/supabase/auth/internal/hooks/v0hooks/v0hooks.go, so a hook written
// for GoTrue receives exactly the bytes it expects and its response is decoded
// exactly the way upstream decodes it. Deviations are called out inline.
//
// The seven extension points are the fields of Config.Hooks (conf.go):
//
//	custom_access_token          rewrites the access-token claims before signing
//	send_email                   takes over confirmation/recovery/... delivery
//	send_sms                     takes over SMS OTP delivery
//	before_user_created          may reject a signup before the row is written
//	after_user_created           observes a new user post-commit
//	mfa_verification_attempt     may reject an MFA challenge verification
//	password_verification_attempt observes / limits a password check
//
// Both the HTTP webhook driver (hooks_http.go) and the pg-functions driver
// (hooks_pg.go) marshal these to JSON, so the wire shape is identical whichever
// transport a deployment configures.

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Hook names. The strings are upstream's v0hooks.Name values and travel in the
// `metadata.name` field of every payload.
const (
	HookNameSendSMS              = "send-sms"
	HookNameSendEmail            = "send-email"
	HookNameCustomAccessToken    = "customize-access-token"
	HookNameMFAVerification      = "mfa-verification"
	HookNamePasswordVerification = "password-verification"
	HookNameBeforeUserCreated    = "before-user-created"
	HookNameAfterUserCreated     = "after-user-created"
)

// HookRejection is the `decision` value an MFA / password verification hook
// returns to abort the attempt (upstream v0hooks.HookRejection).
const HookRejection = "reject"

// Default rejection messages upstream substitutes when a hook rejects without
// supplying one (v0hooks.Default*HookRejectionMessage).
const (
	DefaultMFAHookRejectionMessage      = "Further MFA verification attempts will be rejected."
	DefaultPasswordHookRejectionMessage = "Further password verification attempts will be rejected."
)

// hookMetadata is upstream v0hooks.Metadata: the envelope every hook payload
// carries. IPAddress is omitempty because the token-issuance call site has no
// *http.Request to read it from (see the deviation note on newHookMetadata).
type hookMetadata struct {
	UUID      string    `json:"uuid"`
	Time      time.Time `json:"time"`
	Name      string    `json:"name,omitempty"`
	IPAddress string    `json:"ip_address,omitempty"`
}

// newHookMetadata builds the metadata envelope. r may be nil: unlike upstream —
// which always threads the *http.Request into NewMetadata — Dilion issues access
// tokens from call sites (issueAccessToken) that carry no request, so the IP is
// simply omitted there. The UUID and time are always present.
func newHookMetadata(r *http.Request, name string) *hookMetadata {
	m := &hookMetadata{
		UUID: uuid.NewString(),
		Time: time.Now().UTC(),
		Name: name,
	}
	if r != nil {
		m.IPAddress = clientIP(r)
	}
	return m
}

// ---- custom_access_token ---------------------------------------------------

// CustomAccessTokenInput is upstream v0hooks.CustomAccessTokenInput. Claims is
// the full claim view of the token about to be signed (a superset of the JWT
// registered claims plus gotrue's email/phone/app_metadata/... members), exactly
// what upstream's AccessTokenClaims marshals to.
type CustomAccessTokenInput struct {
	Metadata             *hookMetadata  `json:"metadata"`
	UserID               string         `json:"user_id"`
	Claims               map[string]any `json:"claims"`
	AuthenticationMethod string         `json:"authentication_method"`
}

// CustomAccessTokenOutput is upstream v0hooks.CustomAccessTokenOutput. The
// returned Claims map becomes the token's claims. Upstream fails when the field
// is missing; UnmarshalJSON reproduces that so a hook that returns `{}` is a hard
// error rather than a silently empty token.
type CustomAccessTokenOutput struct {
	Claims map[string]any `json:"claims"`
}

// UnmarshalJSON mirrors upstream's CustomAccessTokenOutput.UnmarshalJSON: a
// response missing the `claims` field is an internal error.
func (o *CustomAccessTokenOutput) UnmarshalJSON(b []byte) error {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	raw, ok := m["claims"]
	if !ok {
		return internalServerError("output claims field is missing")
	}
	claims, ok := raw.(map[string]any)
	if !ok {
		return internalServerError("output claims field must be an object")
	}
	o.Claims = claims
	return nil
}

// ---- send_email ------------------------------------------------------------

// EmailData is upstream mailer.EmailData: everything a send_email hook needs to
// render and deliver the message itself. Field order and tags are upstream's.
type EmailData struct {
	Token           string `json:"token"`
	TokenHash       string `json:"token_hash"`
	RedirectTo      string `json:"redirect_to"`
	EmailActionType string `json:"email_action_type"`
	SiteURL         string `json:"site_url"`
	TokenNew        string `json:"token_new"`
	TokenHashNew    string `json:"token_hash_new"`
	OldEmail        string `json:"old_email,omitempty"`
	OldPhone        string `json:"old_phone,omitempty"`
	Provider        string `json:"provider,omitempty"`
	FactorType      string `json:"factor_type,omitempty"`
}

// SendEmailInput is upstream v0hooks.SendEmailInput.
type SendEmailInput struct {
	Metadata  *hookMetadata `json:"metadata"`
	User      *User         `json:"user"`
	EmailData EmailData     `json:"email_data"`
}

// SendEmailOutput is upstream v0hooks.SendEmailOutput (empty — success is the
// absence of an error object in the body).
type SendEmailOutput struct{}

// ---- send_sms --------------------------------------------------------------

// SMS is upstream v0hooks.SMS: the OTP payload handed to a send_sms hook.
type SMS struct {
	OTP     string `json:"otp,omitempty"`
	SMSType string `json:"sms_type,omitempty"`
	Phone   string `json:"phone,omitempty"`
}

// SendSMSInput is upstream v0hooks.SendSMSInput.
type SendSMSInput struct {
	Metadata *hookMetadata `json:"metadata"`
	User     *User         `json:"user,omitempty"`
	SMS      SMS           `json:"sms,omitempty"`
}

// SendSMSOutput is upstream v0hooks.SendSMSOutput (empty).
type SendSMSOutput struct{}

// ---- before_user_created / after_user_created ------------------------------

// BeforeUserCreatedInput is upstream v0hooks.BeforeUserCreatedInput.
type BeforeUserCreatedInput struct {
	Metadata *hookMetadata `json:"metadata"`
	User     *User         `json:"user"`
}

// BeforeUserCreatedOutput is upstream v0hooks.BeforeUserCreatedOutput (empty;
// a rejection travels as the `error` object, not as a field here).
type BeforeUserCreatedOutput struct{}

// AfterUserCreatedInput is upstream v0hooks.AfterUserCreatedInput.
type AfterUserCreatedInput struct {
	Metadata *hookMetadata `json:"metadata"`
	User     *User         `json:"user"`
}

// AfterUserCreatedOutput is upstream v0hooks.AfterUserCreatedOutput (empty).
type AfterUserCreatedOutput struct{}

// ---- mfa_verification_attempt ----------------------------------------------

// MFAVerificationAttemptInput is upstream v0hooks.MFAVerificationAttemptInput.
type MFAVerificationAttemptInput struct {
	Metadata   *hookMetadata `json:"metadata"`
	UserID     string        `json:"user_id"`
	FactorID   string        `json:"factor_id"`
	FactorType string        `json:"factor_type"`
	Valid      bool          `json:"valid"`
}

// MFAVerificationAttemptOutput is upstream v0hooks.MFAVerificationAttemptOutput.
type MFAVerificationAttemptOutput struct {
	Decision string `json:"decision"`
	Message  string `json:"message"`
}

// ---- password_verification_attempt -----------------------------------------

// PasswordVerificationAttemptInput is upstream
// v0hooks.PasswordVerificationAttemptInput.
type PasswordVerificationAttemptInput struct {
	Metadata *hookMetadata `json:"metadata"`
	UserID   string        `json:"user_id"`
	Valid    bool          `json:"valid"`
}

// PasswordVerificationAttemptOutput is upstream
// v0hooks.PasswordVerificationAttemptOutput.
type PasswordVerificationAttemptOutput struct {
	Decision         string `json:"decision"`
	Message          string `json:"message"`
	ShouldLogoutUser bool   `json:"should_logout_user"`
}

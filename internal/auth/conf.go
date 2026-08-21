package auth

// Config is the /auth/v1 configuration contract.
//
// It mirrors github.com/supabase/auth/internal/conf.GlobalConfiguration field
// for field (only the parts that are meaningful for Dilion), so that an
// operator who knows GoTrue can configure Dilion from muscle memory. Every
// field carries the upstream environment variable it mirrors.
//
// # Environment variables
//
// LoadConfig reads DILION_AUTH_<NAME> first and falls back to the upstream
// GOTRUE_<NAME> spelling, so an existing gotrue .env keeps working while a
// deployment migrates. <NAME> is always the upstream suffix, e.g.
//
//	DILION_AUTH_SITE_URL   (preferred)
//	GOTRUE_SITE_URL        (accepted fallback)
//
// # Stability
//
// This struct is THE shared contract of the /auth/v1 feature work: feature
// packages READ it, they never extend it. Fields for features that are not
// implemented yet are defined here already and documented as "fields only" —
// adding a field later is a breaking change for everyone reading it.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/dilion-io/dilion/ports"
)

// Defaults that are referenced from more than one place.
const (
	// DefaultSiteURL is used when neither DILION_AUTH_SITE_URL nor
	// GOTRUE_SITE_URL is set. Upstream requires SITE_URL; Dilion defaults it so
	// the zero-config developer path works.
	DefaultSiteURL = "http://localhost:5173"

	// DefaultJWTExp mirrors GOTRUE_JWT_EXP (seconds).
	DefaultJWTExp = 3600

	// DefaultOTPLength mirrors GOTRUE_MAILER_OTP_LENGTH / GOTRUE_SMS_OTP_LENGTH.
	DefaultOTPLength = 6

	// DefaultSMSTemplate is upstream's fallback GOTRUE_SMS_TEMPLATE.
	DefaultSMSTemplate = "Your code is {{ .Code }}"

	// DefaultMailerURLPath is the URL path every emailed action link is built
	// on top of (GOTRUE_MAILER_URLPATHS_*).
	//
	// DEVIATION: upstream's default is "/verify" because its API owns the root
	// of its host. Dilion mounts the compatible surface under /auth/v1, so the
	// default carries that prefix; the env overrides still work.
	DefaultMailerURLPath = "/auth/v1/verify"

	// DefaultCaptchaTimeout mirrors upstream's captcha verifier default: the
	// HTTP timeout of one hcaptcha/turnstile siteverify call.
	DefaultCaptchaTimeout = 10 * time.Second

	// DefaultRefreshTokenReuseInterval mirrors
	// GOTRUE_SECURITY_REFRESH_TOKEN_REUSE_INTERVAL (seconds). Upstream ships 0;
	// Dilion defaults to 10s because every supported client (gotrue-js and the
	// Supabase CLI) can issue concurrent refreshes.
	DefaultRefreshTokenReuseInterval = 10
)

// ---- provider names --------------------------------------------------------

// ExternalProviders is the fixed set of provider keys reported by GET /settings.
// The order is the order of upstream's api.ProviderSettings struct; the strings
// are its json tags. `anonymous_users` is reported from
// Config.AnonymousUsersEnabled, not from this map.
var ExternalProviders = []string{
	"apple", "azure", "bitbucket", "discord", "facebook", "snapchat", "figma",
	"fly", "github", "gitlab", "google", "keycloak", "kakao", "linkedin",
	"linkedin_oidc", "notion", "spotify", "slack", "slack_oidc", "workos",
	"twitch", "twitter", "email", "phone", "zoom",
}

// providerEnvName maps a provider key to the env-var infix upstream uses
// (GOTRUE_EXTERNAL_<INFIX>_ENABLED).
func providerEnvName(p string) string { return strings.ToUpper(p) }

// ---- sub-configurations ----------------------------------------------------

// ProviderConfig is one external identity provider
// (upstream conf.OAuthProviderConfiguration). Env prefix:
// GOTRUE_EXTERNAL_<PROVIDER>_*.
type ProviderConfig struct {
	// Enabled mirrors GOTRUE_EXTERNAL_<PROVIDER>_ENABLED.
	Enabled bool `json:"enabled"`
	// ClientID mirrors GOTRUE_EXTERNAL_<PROVIDER>_CLIENT_ID. It is a LIST
	// upstream (comma separated in the env) because Apple/Azure accept several
	// audiences; the first entry is the primary client id.
	ClientID []string `json:"client_id"`
	// Secret mirrors GOTRUE_EXTERNAL_<PROVIDER>_SECRET.
	Secret string `json:"-"`
	// RedirectURI mirrors GOTRUE_EXTERNAL_<PROVIDER>_REDIRECT_URI.
	RedirectURI string `json:"redirect_uri"`
	// URL mirrors GOTRUE_EXTERNAL_<PROVIDER>_URL (self-hosted GitLab/Keycloak).
	URL string `json:"url"`
	// SkipNonceCheck mirrors GOTRUE_EXTERNAL_<PROVIDER>_SKIP_NONCE_CHECK.
	SkipNonceCheck bool `json:"skip_nonce_check"`
}

// JWK is one JSON Web Key of GOTRUE_JWT_KEYS. Only the fields Dilion needs to
// route a key are decoded; Raw keeps the original JSON so the signing
// implementation can parse it with whatever library it wants without losing
// members (`aws:kms:arn`, `x5c`, ...).
type JWK struct {
	KeyType   string   `json:"kty"`
	KeyID     string   `json:"kid"`
	Algorithm string   `json:"alg"`
	Use       string   `json:"use"`
	KeyOps    []string `json:"key_ops"`

	// EC (ES256) members.
	Curve string `json:"crv,omitempty"`
	X     string `json:"x,omitempty"`
	Y     string `json:"y,omitempty"`
	D     string `json:"d,omitempty"`

	// RSA / oct members, decoded so a foreign key set round-trips.
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	K string `json:"k,omitempty"`

	// Raw is the key exactly as it appeared in GOTRUE_JWT_KEYS.
	Raw json.RawMessage `json:"-"`
}

// CanSign reports whether key_ops contains "sign" (upstream's signing-key rule).
func (k JWK) CanSign() bool {
	for _, op := range k.KeyOps {
		if op == "sign" {
			return true
		}
	}
	return false
}

// JWKSet is the parsed GOTRUE_JWT_KEYS: a JSON ARRAY of private JWKs, indexed
// here by `kid`. Order preserves the array order so /.well-known/jwks.json can
// be emitted deterministically.
type JWKSet struct {
	Keys  map[string]JWK
	Order []string
}

// Len reports how many keys were configured.
func (s JWKSet) Len() int { return len(s.Keys) }

// SigningKey returns the single private key whose key_ops contains "sign" —
// upstream's active `kid`. Absent when no key set is configured (HS256 mode).
func (s JWKSet) SigningKey() (JWK, bool) {
	for _, kid := range s.Order {
		if k := s.Keys[kid]; k.CanSign() {
			return k, true
		}
	}
	return JWK{}, false
}

// JWTConfig mirrors upstream conf.JWTConfiguration.
type JWTConfig struct {
	// Exp mirrors GOTRUE_JWT_EXP: access-token lifetime in seconds (default 3600).
	Exp int `json:"exp"`
	// Aud mirrors GOTRUE_JWT_AUD (default "authenticated").
	Aud string `json:"aud"`
	// AdminRoles mirrors GOTRUE_JWT_ADMIN_ROLES; roles admitted to /admin/*
	// unconditionally (default ["service_role", "supabase_admin"]).
	AdminRoles []string `json:"admin_roles"`
	// Issuer mirrors GOTRUE_JWT_ISSUER; empty means no `iss` claim.
	Issuer string `json:"issuer"`
	// KeyID mirrors GOTRUE_JWT_KEY_ID. Advisory: the active key is the one whose
	// key_ops contains "sign" (see JWKSet.SigningKey).
	KeyID string `json:"key_id"`
	// Keys mirrors GOTRUE_JWT_KEYS — a JSON array of PRIVATE JWKs. Dilion signs
	// with ES256 (NOT RS256) when a key set is configured.
	//
	// FIELDS + PARSING ONLY here: asymmetric signing itself is implemented by
	// the JWT/ES256 feature work, which reads this field.
	Keys JWKSet `json:"-"`
	// Secret mirrors GOTRUE_JWT_SECRET: the legacy HS256 shared secret. It stays
	// a valid VERIFY key even after ES256 signing is enabled, so tokens issued
	// before a key rotation keep working.
	Secret string `json:"-"`
}

// ExpDuration returns Exp as a duration.
func (j JWTConfig) ExpDuration() time.Duration { return time.Duration(j.Exp) * time.Second }

// EmailContentConfig mirrors upstream conf.EmailContentConfiguration; used for
// both Subjects (GOTRUE_MAILER_SUBJECTS_*) and URLPaths (GOTRUE_MAILER_URLPATHS_*).
type EmailContentConfig struct {
	Invite           string `json:"invite"`
	Confirmation     string `json:"confirmation"`
	Recovery         string `json:"recovery"`
	EmailChange      string `json:"email_change"`
	MagicLink        string `json:"magic_link"`
	Reauthentication string `json:"reauthentication"`
}

// MailerConfig mirrors upstream conf.MailerConfiguration.
type MailerConfig struct {
	// Autoconfirm mirrors GOTRUE_MAILER_AUTOCONFIRM.
	//
	// DILION DEFAULT: true (upstream defaults to false). Dilion has no email
	// confirmation flow wired yet, so signups must remain immediately usable.
	// The email-flows work flips this default to false once /verify, /recover
	// and /resend are in place.
	Autoconfirm bool `json:"autoconfirm"`
	// SecureEmailChangeEnabled mirrors
	// GOTRUE_MAILER_SECURE_EMAIL_CHANGE_ENABLED (default true): an email change
	// must be confirmed from BOTH the old and the new address.
	SecureEmailChangeEnabled bool `json:"secure_email_change_enabled"`
	// OTPExp mirrors GOTRUE_MAILER_OTP_EXP, in seconds.
	//
	// DILION DEFAULT: 3600 (upstream defaults to 86400). A one-hour email OTP is
	// the tighter, and for 개인정보보호법 purposes the defensible, default.
	OTPExp int `json:"otp_exp"`
	// OTPLength mirrors GOTRUE_MAILER_OTP_LENGTH (default 6, clamped to 6..10).
	OTPLength int `json:"otp_length"`
	// Subjects mirrors GOTRUE_MAILER_SUBJECTS_*.
	Subjects EmailContentConfig `json:"subjects"`
	// URLPaths mirrors GOTRUE_MAILER_URLPATHS_* (defaults: "/verify").
	URLPaths EmailContentConfig `json:"url_paths"`
	// ExternalHosts mirrors GOTRUE_MAILER_EXTERNAL_HOSTS: extra Host values the
	// API answers on, used to build absolute links in emails.
	ExternalHosts []string `json:"external_hosts"`
	// MaxFrequency is the minimum interval between two mails of the SAME type
	// to the SAME user (upstream's validateSentWithinFrequencyLimit). Default
	// 1m, upstream's default too.
	//
	// UPSTREAM NAMING: gotrue houses this knob under its SMTP section
	// (GOTRUE_SMTP_MAX_FREQUENCY) because upstream owns the SMTP client;
	// Dilion delegates delivery to ports.Mailer and has no SMTP section, so the
	// knob lives on the mailer instead. BOTH env names are read:
	// DILION_AUTH_MAILER_MAX_FREQUENCY / GOTRUE_MAILER_MAX_FREQUENCY take
	// precedence, GOTRUE_SMTP_MAX_FREQUENCY (upstream's spelling) is the
	// fallback.
	//
	// A value <= 0 is replaced by the 1m default in Validate(); to switch the
	// suppression OFF entirely, set a negative-free tiny value (e.g. 1ns).
	MaxFrequency time.Duration `json:"max_frequency"`
}

// OTPExpDuration returns OTPExp as a duration.
func (m MailerConfig) OTPExpDuration() time.Duration { return time.Duration(m.OTPExp) * time.Second }

// SMSConfig mirrors upstream conf.SmsProviderConfiguration. It is consumed by
// the phone/SMS lifecycle (smsflow.go, sms_twilio.go).
type SMSConfig struct {
	// Autoconfirm mirrors GOTRUE_SMS_AUTOCONFIRM.
	Autoconfirm bool `json:"autoconfirm"`
	// OTPExp mirrors GOTRUE_SMS_OTP_EXP, in seconds (upstream default 60).
	OTPExp int `json:"otp_exp"`
	// OTPLength mirrors GOTRUE_SMS_OTP_LENGTH (default 6, clamped to 6..10).
	OTPLength int `json:"otp_length"`
	// Provider mirrors GOTRUE_SMS_PROVIDER; reported verbatim by GET /settings.
	// "twilio" selects the built-in Twilio REST sender (sms_twilio.go). Any
	// other non-empty value is reported to clients but has no built-in
	// transport — supply one through Sender.
	Provider string `json:"provider"`
	// MaxFrequency mirrors GOTRUE_SMS_MAX_FREQUENCY (default 1m).
	MaxFrequency time.Duration `json:"max_frequency"`

	// Template mirrors GOTRUE_SMS_TEMPLATE: the text/template rendered into the
	// message body, with `{{ .Code }}` bound to the OTP. Empty means upstream's
	// default, "Your code is {{ .Code }}".
	Template string `json:"template"`

	// Twilio mirrors GOTRUE_SMS_TWILIO_*.
	Twilio TwilioConfig `json:"twilio"`

	// Sender is the injected SMS transport (ports.SMSSender). When non-nil it
	// takes precedence over Provider, so an embedder can deliver SMS through
	// its own carrier without touching this configuration further.
	//
	// DILION-ONLY. Upstream has no equivalent because it owns its providers;
	// Dilion's SMS surface is a port. It is deliberately NOT read from the
	// environment and never serialized.
	//
	// NOTE: auth.Deps has no SMS field yet, so this is currently the ONLY way
	// to inject a sender into a mount. See the gap note in smsflow.go.
	Sender ports.SMSSender `json:"-"`
}

// OTPExpDuration returns SMS.OTPExp as a duration.
func (s SMSConfig) OTPExpDuration() time.Duration { return time.Duration(s.OTPExp) * time.Second }

// SMSTemplateOrDefault returns the configured message template, falling back to
// upstream's default when none is set.
func (s SMSConfig) SMSTemplateOrDefault() string {
	if strings.TrimSpace(s.Template) == "" {
		return DefaultSMSTemplate
	}
	return s.Template
}

// TwilioConfig mirrors upstream conf.TwilioProviderConfiguration
// (GOTRUE_SMS_TWILIO_*).
type TwilioConfig struct {
	// AccountSID mirrors GOTRUE_SMS_TWILIO_ACCOUNT_SID. It is both the HTTP
	// basic-auth username and a path segment of the Messages endpoint.
	AccountSID string `json:"account_sid"`
	// AuthToken mirrors GOTRUE_SMS_TWILIO_AUTH_TOKEN (basic-auth password).
	AuthToken string `json:"-"`
	// MessageServiceSID mirrors GOTRUE_SMS_TWILIO_MESSAGE_SERVICE_SID: the
	// `From` of the message (a Messaging Service SID or a sending number).
	MessageServiceSID string `json:"message_service_sid"`
	// ContentSID mirrors GOTRUE_SMS_TWILIO_CONTENT_SID: the WhatsApp
	// authentication template. When set, the OTP is passed as ContentVariables
	// instead of a rendered Body.
	ContentSID string `json:"content_sid"`

	// APIBase overrides https://api.twilio.com.
	//
	// DILION-ONLY (GOTRUE_SMS_TWILIO_API_BASE / DILION_AUTH_SMS_TWILIO_API_BASE):
	// upstream hard-codes the host, which leaves the provider untestable
	// without network access. Point it at an httptest server in tests, or at a
	// regional Twilio edge in production.
	APIBase string `json:"api_base"`
}

// SessionsConfig mirrors upstream conf.SessionsConfiguration.
type SessionsConfig struct {
	// Timebox mirrors GOTRUE_SESSIONS_TIMEBOX: absolute session lifetime measured
	// from sessions.created_at. Zero disables the check.
	Timebox time.Duration `json:"timebox"`
	// InactivityTimeout mirrors GOTRUE_SESSIONS_INACTIVITY_TIMEOUT: maximum age of
	// sessions.refreshed_at. Zero disables the check.
	InactivityTimeout time.Duration `json:"inactivity_timeout"`
	// SinglePerUser mirrors GOTRUE_SESSIONS_SINGLE_PER_USER. FIELD ONLY — the
	// "newest session wins" enforcement is the sessions feature work.
	SinglePerUser bool `json:"single_per_user"`
}

// CaptchaConfig mirrors upstream conf.CaptchaConfiguration. FIELDS ONLY.
type CaptchaConfig struct {
	// Enabled mirrors GOTRUE_SECURITY_CAPTCHA_ENABLED.
	Enabled bool `json:"enabled"`
	// Provider mirrors GOTRUE_SECURITY_CAPTCHA_PROVIDER: hcaptcha | turnstile.
	Provider string `json:"provider"`
	// Secret mirrors GOTRUE_SECURITY_CAPTCHA_SECRET.
	Secret string `json:"-"`
	// Timeout mirrors upstream conf.CaptchaConfiguration.Timeout
	// (GOTRUE_SECURITY_CAPTCHA_TIMEOUT, default 10s): the HTTP timeout of one
	// siteverify call.
	Timeout time.Duration `json:"-"`
	// VerifyURL has NO upstream equivalent: it overrides the provider's
	// siteverify endpoint. It exists so tests (and an operator fronting the
	// provider with a proxy) can point verification somewhere else; empty means
	// the provider's real endpoint.
	VerifyURL string `json:"-"`
}

// SecurityConfig mirrors upstream conf.SecurityConfiguration.
type SecurityConfig struct {
	// RefreshTokenRotationEnabled mirrors
	// GOTRUE_SECURITY_REFRESH_TOKEN_ROTATION_ENABLED (default true): a refresh
	// revokes the presented token and issues its child.
	RefreshTokenRotationEnabled bool `json:"refresh_token_rotation_enabled"`
	// RefreshTokenReuseInterval mirrors
	// GOTRUE_SECURITY_REFRESH_TOKEN_REUSE_INTERVAL, in SECONDS (Dilion default
	// 10, upstream 0): a revoked token presented within this many seconds of its
	// revocation is tolerated and answered with the session's current token
	// instead of being treated as abuse.
	RefreshTokenReuseInterval int `json:"refresh_token_reuse_interval"`
	// UpdatePasswordRequireReauth mirrors
	// GOTRUE_SECURITY_UPDATE_PASSWORD_REQUIRE_REAUTHENTICATION. FIELD ONLY —
	// enforced by the reauthentication feature work.
	UpdatePasswordRequireReauth bool `json:"update_password_require_reauthentication"`
	// ManualLinkingEnabled mirrors GOTRUE_SECURITY_MANUAL_LINKING_ENABLED.
	// FIELD ONLY — gates /user/identities in the identity-linking work.
	ManualLinkingEnabled bool `json:"manual_linking_enabled"`
	// Captcha mirrors GOTRUE_SECURITY_CAPTCHA_*.
	Captcha CaptchaConfig `json:"captcha"`
	// HIBPEnabled mirrors GOTRUE_PASSWORD_HIBP_ENABLED (upstream nests it under
	// Password; it is a security control, so it lives here): password strength
	// checks additionally query the HaveIBeenPwned range API (hibp.go).
	HIBPEnabled bool `json:"hibp_enabled"`
	// HIBPFailClosed mirrors GOTRUE_PASSWORD_HIBP_FAIL_CLOSED (default false):
	// when HaveIBeenPwned cannot be reached, false ACCEPTS the password (fail
	// open, with a WARN log — upstream's default) and true rejects the request
	// with a 500.
	HIBPFailClosed bool `json:"hibp_fail_closed"`
	// HIBPBaseURL has no upstream equivalent (upstream's hibp client hardcodes
	// the host): the base of the k-anonymity range API, without a trailing
	// slash. It exists so tests and air-gapped deployments can point the check
	// at their own mirror. Empty means api.pwnedpasswords.com.
	HIBPBaseURL string `json:"-"`
}

// ReuseIntervalDuration returns RefreshTokenReuseInterval as a duration.
func (s SecurityConfig) ReuseIntervalDuration() time.Duration {
	return time.Duration(s.RefreshTokenReuseInterval) * time.Second
}

// PasswordConfig mirrors upstream conf.PasswordConfiguration.
type PasswordConfig struct {
	// MinLength mirrors GOTRUE_PASSWORD_MIN_LENGTH (default 6).
	MinLength int `json:"min_length"`
	// RequiredCharacters mirrors GOTRUE_PASSWORD_REQUIRED_CHARACTERS: a
	// COLON-SEPARATED list of character-class sets, each of which the password
	// must draw at least one character from. A literal colon is escaped `\:`.
	//
	//	abcdefghijklmnopqrstuvwxyz:ABCDEFGHIJKLMNOPQRSTUVWXYZ:0123456789
	RequiredCharacters []string `json:"required_characters"`
}

// RateLimitConfig mirrors upstream's GOTRUE_RATE_LIMIT_* knobs. Unless noted,
// the number is "requests per 5 minutes per client IP" (upstream's window) and
// the burst is 30.
type RateLimitConfig struct {
	// EmailSent mirrors GOTRUE_RATE_LIMIT_EMAIL_SENT (default 30 / 5m).
	EmailSent float64 `json:"email_sent"`
	// SMSSent mirrors GOTRUE_RATE_LIMIT_SMS_SENT (default 30 / 5m).
	SMSSent float64 `json:"sms_sent"`
	// Verify mirrors GOTRUE_RATE_LIMIT_VERIFY (default 30 / 5m).
	Verify float64 `json:"verify"`
	// TokenRefresh mirrors GOTRUE_RATE_LIMIT_TOKEN_REFRESH (default 150 / 5m).
	TokenRefresh float64 `json:"token_refresh"`
	// SSO mirrors GOTRUE_RATE_LIMIT_SSO (default 30 / 5m).
	SSO float64 `json:"sso"`
	// AnonymousUsers mirrors GOTRUE_RATE_LIMIT_ANONYMOUS_USERS (default 30).
	// Upstream measures this one PER HOUR, and Dilion does the same.
	AnonymousUsers float64 `json:"anonymous_users"`
	// OTP mirrors GOTRUE_RATE_LIMIT_OTP (default 30 / 5m). Upstream applies it
	// to /otp, /magiclink, /recover, /resend, /signup and PUT /user.
	OTP float64 `json:"otp"`
	// Web3 mirrors GOTRUE_RATE_LIMIT_WEB3 (default 30 / 5m). FIELD ONLY.
	Web3 float64 `json:"web3"`
	// Passkey mirrors GOTRUE_RATE_LIMIT_PASSKEY (default 30 / 5m). FIELD ONLY.
	Passkey float64 `json:"passkey"`
}

// MFATOTPConfig mirrors upstream conf.TOTPFactorTypeConfiguration. FIELDS ONLY.
type MFATOTPConfig struct {
	// EnrollEnabled mirrors GOTRUE_MFA_TOTP_ENROLL_ENABLED (default true).
	EnrollEnabled bool `json:"enroll_enabled"`
	// VerifyEnabled mirrors GOTRUE_MFA_TOTP_VERIFY_ENABLED (default true).
	VerifyEnabled bool `json:"verify_enabled"`
}

// MFAFactorTypeConfig mirrors upstream's per-factor enroll/verify toggle
// (conf.MFAFactorTypeConfiguration), used by the phone and webauthn factors.
type MFAFactorTypeConfig struct {
	// EnrollEnabled mirrors GOTRUE_MFA_<TYPE>_ENROLL_ENABLED (default false).
	EnrollEnabled bool `json:"enroll_enabled"`
	// VerifyEnabled mirrors GOTRUE_MFA_<TYPE>_VERIFY_ENABLED (default false).
	VerifyEnabled bool `json:"verify_enabled"`
}

// MFAConfig mirrors upstream conf.MFAConfiguration. FIELDS ONLY.
type MFAConfig struct {
	// TOTP mirrors GOTRUE_MFA_TOTP_*.
	TOTP MFATOTPConfig `json:"totp"`
	// Phone mirrors GOTRUE_MFA_PHONE_* (SMS-delivered MFA factor). Default off.
	Phone MFAFactorTypeConfig `json:"phone"`
	// WebAuthn mirrors GOTRUE_MFA_WEB_AUTHN_* (WebAuthn as a second factor,
	// distinct from first-class Passkeys). Default off.
	WebAuthn MFAFactorTypeConfig `json:"web_authn"`
	// MaxEnrolledFactors mirrors GOTRUE_MFA_MAX_ENROLLED_FACTORS (default 10).
	MaxEnrolledFactors int `json:"max_enrolled_factors"`
	// PhoneOTPLength / PhoneOTPExp mirror the MFA phone challenge OTP shape
	// (default 6 / 300s).
	PhoneOTPLength int           `json:"phone_otp_length"`
	PhoneOTPExp    time.Duration `json:"phone_otp_exp"`
}

// HookEndpointConfig configures one Supabase-compatible auth hook. A hook is an
// external extension point invoked at a fixed lifecycle moment; the URI scheme
// selects the driver: https?:// -> HTTP webhook (HMAC-signed with Secrets),
// pg-functions://<db>/<schema>.<func> -> a Postgres function called in-tx.
// FIELDS ONLY (drivers implemented elsewhere).
type HookEndpointConfig struct {
	// Enabled mirrors GOTRUE_HOOK_<NAME>_ENABLED (default false).
	Enabled bool `json:"enabled"`
	// URI mirrors GOTRUE_HOOK_<NAME>_URI (http(s):// or pg-functions://...).
	URI string `json:"uri"`
	// Secrets mirrors GOTRUE_HOOK_<NAME>_SECRETS (v1,whsec_... — HMAC signing,
	// supports rotation as a comma list). HTTP driver only.
	Secrets []string `json:"-"`
}

// HooksConfig mirrors upstream conf.HookConfiguration. Each field is one hook
// point Supabase exposes to external code. FIELDS ONLY.
type HooksConfig struct {
	// CustomAccessToken mirrors GOTRUE_HOOK_CUSTOM_ACCESS_TOKEN_* — rewrites the
	// access-token claims before signing (in addition to the in-process
	// ports.TokenClaims hook).
	CustomAccessToken HookEndpointConfig `json:"custom_access_token"`
	// SendEmail mirrors GOTRUE_HOOK_SEND_EMAIL_* — overrides email delivery.
	SendEmail HookEndpointConfig `json:"send_email"`
	// SendSMS mirrors GOTRUE_HOOK_SEND_SMS_* — overrides SMS delivery.
	SendSMS HookEndpointConfig `json:"send_sms"`
	// BeforeUserCreated mirrors GOTRUE_HOOK_BEFORE_USER_CREATED_* — may reject a
	// signup before the row is written.
	BeforeUserCreated HookEndpointConfig `json:"before_user_created"`
	// AfterUserCreated mirrors GOTRUE_HOOK_AFTER_USER_CREATED_* — observes a new
	// user post-commit.
	AfterUserCreated HookEndpointConfig `json:"after_user_created"`
	// MFAVerificationAttempt mirrors GOTRUE_HOOK_MFA_VERIFICATION_ATTEMPT_* —
	// may reject an MFA challenge verification.
	MFAVerificationAttempt HookEndpointConfig `json:"mfa_verification_attempt"`
	// PasswordVerificationAttempt mirrors
	// GOTRUE_HOOK_PASSWORD_VERIFICATION_ATTEMPT_* — observes/limits a password
	// check.
	PasswordVerificationAttempt HookEndpointConfig `json:"password_verification_attempt"`
}

// PasskeyConfig mirrors upstream conf.PasskeyConfiguration +
// conf.WebAuthnConfiguration. FIELDS ONLY.
type PasskeyConfig struct {
	// Enabled mirrors GOTRUE_PASSKEY_ENABLED; reported by GET /settings.
	Enabled bool `json:"enabled"`
	// RPID mirrors GOTRUE_WEBAUTHN_RP_ID.
	RPID string `json:"rp_id"`
	// RPOrigins mirrors GOTRUE_WEBAUTHN_RP_ORIGINS.
	RPOrigins []string `json:"rp_origins"`
}

// SAMLConfig mirrors upstream conf.SAMLConfiguration. FIELDS ONLY.
type SAMLConfig struct {
	// Enabled mirrors GOTRUE_SAML_ENABLED; reported by GET /settings.
	Enabled bool `json:"enabled"`
	// PrivateKey mirrors GOTRUE_SAML_PRIVATE_KEY (base64 DER RSA key).
	PrivateKey string `json:"-"`
}

// OAuthServerConfig mirrors upstream conf.OAuthServerConfiguration. FIELDS ONLY.
type OAuthServerConfig struct {
	// Enabled mirrors GOTRUE_OAUTH_SERVER_ENABLED.
	Enabled bool `json:"enabled"`
}

// CORSConfig mirrors upstream conf.CORSConfiguration.
type CORSConfig struct {
	// AllowedHeaders mirrors GOTRUE_CORS_ALLOWED_HEADERS: EXTRA headers, added
	// to the built-in list (see corsAllowedHeaders in middleware.go).
	AllowedHeaders []string `json:"allowed_headers"`
}

// ---- Config ----------------------------------------------------------------

// Config is the whole /auth/v1 configuration. Construct it with LoadConfig (env)
// or DefaultConfig (defaults only) — never as a bare literal, or the compiled
// redirect allow-list will be empty.
type Config struct {
	// SiteURL mirrors GOTRUE_SITE_URL: the default redirect target and an
	// always-allowed redirect destination. Defaults to DefaultSiteURL.
	SiteURL string `json:"site_url"`
	// URIAllowList mirrors GOTRUE_URI_ALLOW_LIST: a comma-separated list of glob
	// patterns of additional allowed redirect URLs. See IsRedirectAllowed.
	URIAllowList []string `json:"uri_allow_list"`
	// DisableSignup mirrors GOTRUE_DISABLE_SIGNUP.
	DisableSignup bool `json:"disable_signup"`

	JWT      JWTConfig      `json:"jwt"`
	Mailer   MailerConfig   `json:"mailer"`
	SMS      SMSConfig      `json:"sms"`
	Sessions SessionsConfig `json:"sessions"`
	Security SecurityConfig `json:"security"`
	Password PasswordConfig `json:"password"`

	// RateLimits mirrors GOTRUE_RATE_LIMIT_*.
	RateLimits RateLimitConfig `json:"rate_limits"`

	// External mirrors GOTRUE_EXTERNAL_*, keyed by the provider names in
	// ExternalProviders. Every key of ExternalProviders is always present.
	External map[string]ProviderConfig `json:"external"`
	// FlowStateExpiry mirrors GOTRUE_EXTERNAL_FLOW_STATE_EXPIRY_DURATION
	// (default 5m). FIELD ONLY — consumed by the PKCE/OAuth work.
	FlowStateExpiry time.Duration `json:"flow_state_expiry"`

	MFA         MFAConfig         `json:"mfa"`
	Hooks       HooksConfig       `json:"hooks"`
	Passkeys    PasskeyConfig     `json:"passkeys"`
	SAML        SAMLConfig        `json:"saml"`
	OAuthServer OAuthServerConfig `json:"oauth_server"`
	CORS        CORSConfig        `json:"cors"`

	// CleanupEnabled mirrors GOTRUE_DB_CLEANUP_ENABLED (Dilion default TRUE;
	// upstream defaults to false because it piggybacks cleanup on requests).
	CleanupEnabled bool `json:"cleanup_enabled"`
	// CleanupInterval has no upstream equivalent (upstream runs cleanup from a
	// request middleware); Dilion runs a worker, default every 5m.
	CleanupInterval time.Duration `json:"cleanup_interval"`
	// APIMaxRequestDuration mirrors GOTRUE_API_MAX_REQUEST_DURATION (default 10s).
	APIMaxRequestDuration time.Duration `json:"api_max_request_duration"`
	// AnonymousUsersEnabled mirrors GOTRUE_EXTERNAL_ANONYMOUS_USERS_ENABLED
	// (default false): POST /signup with neither email nor phone.
	AnonymousUsersEnabled bool `json:"anonymous_users_enabled"`

	// allowGlobs are the compiled URIAllowList patterns, in list order.
	allowGlobs []*globPattern
}

// DefaultConfig returns the configuration used when the embedder supplies none:
// upstream defaults, with the Dilion deviations documented on each field.
func DefaultConfig() *Config {
	c := &Config{
		SiteURL:      DefaultSiteURL,
		URIAllowList: []string{},
		JWT: JWTConfig{
			Exp:        DefaultJWTExp,
			Aud:        AudienceAuthenticated,
			AdminRoles: []string{RoleServiceRole, "supabase_admin"},
		},
		Mailer: MailerConfig{
			Autoconfirm:              true,
			SecureEmailChangeEnabled: true,
			OTPExp:                   3600,
			OTPLength:                DefaultOTPLength,
			// DILION DEFAULT: "/auth/v1/verify" (upstream defaults to
			// "/verify"). Upstream's API is mounted at the ROOT of its own
			// host, so "/verify" resolves correctly there; Dilion mounts the
			// compatible surface under /auth/v1 (dilion.go), where "/verify"
			// would produce a dead link. GOTRUE_MAILER_URLPATHS_* /
			// DILION_AUTH_MAILER_URLPATHS_* still override, so a deployment
			// that reverse-proxies /verify can restore upstream's value.
			URLPaths: EmailContentConfig{
				Invite:           DefaultMailerURLPath,
				Confirmation:     DefaultMailerURLPath,
				Recovery:         DefaultMailerURLPath,
				EmailChange:      DefaultMailerURLPath,
				MagicLink:        DefaultMailerURLPath,
				Reauthentication: DefaultMailerURLPath,
			},
			ExternalHosts: []string{},
			MaxFrequency:  time.Minute,
		},
		SMS: SMSConfig{
			OTPExp:       60,
			OTPLength:    DefaultOTPLength,
			MaxFrequency: time.Minute,
		},
		Security: SecurityConfig{
			RefreshTokenRotationEnabled: true,
			RefreshTokenReuseInterval:   DefaultRefreshTokenReuseInterval,
			Captcha:                     CaptchaConfig{Provider: "hcaptcha", Timeout: DefaultCaptchaTimeout},
		},
		Password: PasswordConfig{
			MinLength:          MinPasswordLength,
			RequiredCharacters: []string{},
		},
		RateLimits: RateLimitConfig{
			EmailSent:      30,
			SMSSent:        30,
			Verify:         30,
			TokenRefresh:   150,
			SSO:            30,
			AnonymousUsers: 30,
			OTP:            30,
			Web3:           30,
			Passkey:        30,
		},
		External:        map[string]ProviderConfig{},
		FlowStateExpiry: 5 * time.Minute,
		MFA: MFAConfig{
			TOTP:               MFATOTPConfig{EnrollEnabled: true, VerifyEnabled: true},
			Phone:              MFAFactorTypeConfig{},
			WebAuthn:           MFAFactorTypeConfig{},
			MaxEnrolledFactors: 10,
			PhoneOTPLength:     6,
			PhoneOTPExp:        300 * time.Second,
		},
		CleanupEnabled:        true,
		CleanupInterval:       5 * time.Minute,
		APIMaxRequestDuration: 10 * time.Second,
	}
	for _, p := range ExternalProviders {
		c.External[p] = ProviderConfig{}
	}
	// Upstream enables the email provider by default; without it every password
	// signup would be rejected as "Email logins are disabled".
	c.External["email"] = ProviderConfig{Enabled: true}
	_ = c.compile()
	return c
}

// LoadConfig builds the configuration from the environment on top of
// DefaultConfig. Every parse or validation failure is returned as an error:
// a mis-typed auth configuration must be fatal at boot, never silently ignored.
func LoadConfig() (*Config, error) {
	c := DefaultConfig()
	var errs []string
	fail := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }

	c.SiteURL = envString("SITE_URL", c.SiteURL)
	c.URIAllowList = envStringSlice("URI_ALLOW_LIST", c.URIAllowList)
	c.DisableSignup = envBool("DISABLE_SIGNUP", c.DisableSignup, fail)

	// JWT.
	c.JWT.Exp = envInt("JWT_EXP", c.JWT.Exp, fail)
	c.JWT.Aud = envString("JWT_AUD", c.JWT.Aud)
	c.JWT.AdminRoles = envStringSlice("JWT_ADMIN_ROLES", c.JWT.AdminRoles)
	c.JWT.Issuer = envString("JWT_ISSUER", c.JWT.Issuer)
	c.JWT.KeyID = envString("JWT_KEY_ID", c.JWT.KeyID)
	c.JWT.Secret = envString("JWT_SECRET", c.JWT.Secret)
	if raw, ok := lookupEnv("JWT_KEYS"); ok && strings.TrimSpace(raw) != "" {
		keys, err := parseJWKSet(raw)
		if err != nil {
			fail("JWT_KEYS: %v", err)
		} else {
			c.JWT.Keys = keys
		}
	}

	// Mailer.
	c.Mailer.Autoconfirm = envBool("MAILER_AUTOCONFIRM", c.Mailer.Autoconfirm, fail)
	c.Mailer.SecureEmailChangeEnabled = envBool("MAILER_SECURE_EMAIL_CHANGE_ENABLED", c.Mailer.SecureEmailChangeEnabled, fail)
	c.Mailer.OTPExp = envInt("MAILER_OTP_EXP", c.Mailer.OTPExp, fail)
	c.Mailer.OTPLength = envInt("MAILER_OTP_LENGTH", c.Mailer.OTPLength, fail)
	c.Mailer.ExternalHosts = envStringSlice("MAILER_EXTERNAL_HOSTS", c.Mailer.ExternalHosts)
	loadEmailContent("MAILER_SUBJECTS_", &c.Mailer.Subjects)
	loadEmailContent("MAILER_URLPATHS_", &c.Mailer.URLPaths)
	// Upstream spells this GOTRUE_SMTP_MAX_FREQUENCY; the Dilion-native name
	// wins when both are set.
	c.Mailer.MaxFrequency = envDuration("SMTP_MAX_FREQUENCY", c.Mailer.MaxFrequency, fail)
	c.Mailer.MaxFrequency = envDuration("MAILER_MAX_FREQUENCY", c.Mailer.MaxFrequency, fail)

	// SMS.
	c.SMS.Autoconfirm = envBool("SMS_AUTOCONFIRM", c.SMS.Autoconfirm, fail)
	c.SMS.OTPExp = envInt("SMS_OTP_EXP", c.SMS.OTPExp, fail)
	c.SMS.OTPLength = envInt("SMS_OTP_LENGTH", c.SMS.OTPLength, fail)
	c.SMS.Provider = envString("SMS_PROVIDER", c.SMS.Provider)
	c.SMS.MaxFrequency = envDuration("SMS_MAX_FREQUENCY", c.SMS.MaxFrequency, fail)
	c.SMS.Template = envString("SMS_TEMPLATE", c.SMS.Template)
	c.SMS.Twilio.AccountSID = envString("SMS_TWILIO_ACCOUNT_SID", c.SMS.Twilio.AccountSID)
	c.SMS.Twilio.AuthToken = envString("SMS_TWILIO_AUTH_TOKEN", c.SMS.Twilio.AuthToken)
	c.SMS.Twilio.MessageServiceSID = envString("SMS_TWILIO_MESSAGE_SERVICE_SID", c.SMS.Twilio.MessageServiceSID)
	c.SMS.Twilio.ContentSID = envString("SMS_TWILIO_CONTENT_SID", c.SMS.Twilio.ContentSID)
	c.SMS.Twilio.APIBase = envString("SMS_TWILIO_API_BASE", c.SMS.Twilio.APIBase)

	// Sessions.
	c.Sessions.Timebox = envDuration("SESSIONS_TIMEBOX", c.Sessions.Timebox, fail)
	c.Sessions.InactivityTimeout = envDuration("SESSIONS_INACTIVITY_TIMEOUT", c.Sessions.InactivityTimeout, fail)
	c.Sessions.SinglePerUser = envBool("SESSIONS_SINGLE_PER_USER", c.Sessions.SinglePerUser, fail)

	// Security.
	c.Security.RefreshTokenRotationEnabled = envBool("SECURITY_REFRESH_TOKEN_ROTATION_ENABLED", c.Security.RefreshTokenRotationEnabled, fail)
	c.Security.RefreshTokenReuseInterval = envInt("SECURITY_REFRESH_TOKEN_REUSE_INTERVAL", c.Security.RefreshTokenReuseInterval, fail)
	c.Security.UpdatePasswordRequireReauth = envBool("SECURITY_UPDATE_PASSWORD_REQUIRE_REAUTHENTICATION", c.Security.UpdatePasswordRequireReauth, fail)
	c.Security.ManualLinkingEnabled = envBool("SECURITY_MANUAL_LINKING_ENABLED", c.Security.ManualLinkingEnabled, fail)
	c.Security.Captcha.Enabled = envBool("SECURITY_CAPTCHA_ENABLED", c.Security.Captcha.Enabled, fail)
	c.Security.Captcha.Provider = envString("SECURITY_CAPTCHA_PROVIDER", c.Security.Captcha.Provider)
	c.Security.Captcha.Secret = envString("SECURITY_CAPTCHA_SECRET", c.Security.Captcha.Secret)
	c.Security.Captcha.Timeout = envDuration("SECURITY_CAPTCHA_TIMEOUT", c.Security.Captcha.Timeout, fail)
	c.Security.Captcha.VerifyURL = envString("SECURITY_CAPTCHA_VERIFY_URL", c.Security.Captcha.VerifyURL)
	c.Security.HIBPEnabled = envBool("PASSWORD_HIBP_ENABLED", c.Security.HIBPEnabled, fail)
	c.Security.HIBPFailClosed = envBool("PASSWORD_HIBP_FAIL_CLOSED", c.Security.HIBPFailClosed, fail)
	c.Security.HIBPBaseURL = envString("PASSWORD_HIBP_BASE_URL", c.Security.HIBPBaseURL)

	// Password.
	c.Password.MinLength = envInt("PASSWORD_MIN_LENGTH", c.Password.MinLength, fail)
	if raw, ok := lookupEnv("PASSWORD_REQUIRED_CHARACTERS"); ok {
		c.Password.RequiredCharacters = parseRequiredCharacters(raw)
	}

	// Rate limits.
	c.RateLimits.EmailSent = envFloat("RATE_LIMIT_EMAIL_SENT", c.RateLimits.EmailSent, fail)
	c.RateLimits.SMSSent = envFloat("RATE_LIMIT_SMS_SENT", c.RateLimits.SMSSent, fail)
	c.RateLimits.Verify = envFloat("RATE_LIMIT_VERIFY", c.RateLimits.Verify, fail)
	c.RateLimits.TokenRefresh = envFloat("RATE_LIMIT_TOKEN_REFRESH", c.RateLimits.TokenRefresh, fail)
	c.RateLimits.SSO = envFloat("RATE_LIMIT_SSO", c.RateLimits.SSO, fail)
	c.RateLimits.AnonymousUsers = envFloat("RATE_LIMIT_ANONYMOUS_USERS", c.RateLimits.AnonymousUsers, fail)
	c.RateLimits.OTP = envFloat("RATE_LIMIT_OTP", c.RateLimits.OTP, fail)
	c.RateLimits.Web3 = envFloat("RATE_LIMIT_WEB3", c.RateLimits.Web3, fail)
	c.RateLimits.Passkey = envFloat("RATE_LIMIT_PASSKEY", c.RateLimits.Passkey, fail)

	// External providers.
	for _, p := range ExternalProviders {
		prefix := "EXTERNAL_" + providerEnvName(p) + "_"
		pc := c.External[p]
		pc.Enabled = envBool(prefix+"ENABLED", pc.Enabled, fail)
		pc.ClientID = envStringSlice(prefix+"CLIENT_ID", pc.ClientID)
		pc.Secret = envString(prefix+"SECRET", pc.Secret)
		pc.RedirectURI = envString(prefix+"REDIRECT_URI", pc.RedirectURI)
		pc.URL = envString(prefix+"URL", pc.URL)
		pc.SkipNonceCheck = envBool(prefix+"SKIP_NONCE_CHECK", pc.SkipNonceCheck, fail)
		c.External[p] = pc
	}
	c.FlowStateExpiry = envDuration("EXTERNAL_FLOW_STATE_EXPIRY_DURATION", c.FlowStateExpiry, fail)
	c.AnonymousUsersEnabled = envBool("EXTERNAL_ANONYMOUS_USERS_ENABLED", c.AnonymousUsersEnabled, fail)

	// MFA / passkeys / SAML / OAuth server.
	c.MFA.TOTP.EnrollEnabled = envBool("MFA_TOTP_ENROLL_ENABLED", c.MFA.TOTP.EnrollEnabled, fail)
	c.MFA.TOTP.VerifyEnabled = envBool("MFA_TOTP_VERIFY_ENABLED", c.MFA.TOTP.VerifyEnabled, fail)
	c.MFA.Phone.EnrollEnabled = envBool("MFA_PHONE_ENROLL_ENABLED", c.MFA.Phone.EnrollEnabled, fail)
	c.MFA.Phone.VerifyEnabled = envBool("MFA_PHONE_VERIFY_ENABLED", c.MFA.Phone.VerifyEnabled, fail)
	c.MFA.WebAuthn.EnrollEnabled = envBool("MFA_WEB_AUTHN_ENROLL_ENABLED", c.MFA.WebAuthn.EnrollEnabled, fail)
	c.MFA.WebAuthn.VerifyEnabled = envBool("MFA_WEB_AUTHN_VERIFY_ENABLED", c.MFA.WebAuthn.VerifyEnabled, fail)
	c.MFA.MaxEnrolledFactors = envInt("MFA_MAX_ENROLLED_FACTORS", c.MFA.MaxEnrolledFactors, fail)
	c.MFA.PhoneOTPLength = envInt("MFA_PHONE_OTP_LENGTH", c.MFA.PhoneOTPLength, fail)
	// Hooks (Supabase-compatible external extension points).
	parseHook(&c.Hooks.CustomAccessToken, "HOOK_CUSTOM_ACCESS_TOKEN", fail)
	parseHook(&c.Hooks.SendEmail, "HOOK_SEND_EMAIL", fail)
	parseHook(&c.Hooks.SendSMS, "HOOK_SEND_SMS", fail)
	parseHook(&c.Hooks.BeforeUserCreated, "HOOK_BEFORE_USER_CREATED", fail)
	parseHook(&c.Hooks.AfterUserCreated, "HOOK_AFTER_USER_CREATED", fail)
	parseHook(&c.Hooks.MFAVerificationAttempt, "HOOK_MFA_VERIFICATION_ATTEMPT", fail)
	parseHook(&c.Hooks.PasswordVerificationAttempt, "HOOK_PASSWORD_VERIFICATION_ATTEMPT", fail)
	c.Passkeys.Enabled = envBool("PASSKEY_ENABLED", c.Passkeys.Enabled, fail)
	c.Passkeys.RPID = envString("WEBAUTHN_RP_ID", c.Passkeys.RPID)
	c.Passkeys.RPOrigins = envStringSlice("WEBAUTHN_RP_ORIGINS", c.Passkeys.RPOrigins)
	c.SAML.Enabled = envBool("SAML_ENABLED", c.SAML.Enabled, fail)
	c.SAML.PrivateKey = envString("SAML_PRIVATE_KEY", c.SAML.PrivateKey)
	c.OAuthServer.Enabled = envBool("OAUTH_SERVER_ENABLED", c.OAuthServer.Enabled, fail)

	// Transport.
	c.CORS.AllowedHeaders = envStringSlice("CORS_ALLOWED_HEADERS", c.CORS.AllowedHeaders)
	c.CleanupEnabled = envBool("DB_CLEANUP_ENABLED", c.CleanupEnabled, fail)
	c.CleanupInterval = envDuration("DB_CLEANUP_INTERVAL", c.CleanupInterval, fail)
	c.APIMaxRequestDuration = envDuration("API_MAX_REQUEST_DURATION", c.APIMaxRequestDuration, fail)

	if len(errs) > 0 {
		return nil, fmt.Errorf("auth: invalid configuration: %s", strings.Join(errs, "; "))
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate normalizes and checks the configuration, and compiles the redirect
// allow-list. It is called by LoadConfig and by newAPI, so an embedder-supplied
// Config is always usable.
func (c *Config) Validate() error {
	if strings.TrimSpace(c.SiteURL) == "" {
		c.SiteURL = DefaultSiteURL
	}
	if _, err := url.Parse(c.SiteURL); err != nil {
		return fmt.Errorf("auth: invalid SITE_URL %q: %w", c.SiteURL, err)
	}
	if c.JWT.Exp <= 0 {
		c.JWT.Exp = DefaultJWTExp
	}
	if c.JWT.Aud == "" {
		c.JWT.Aud = AudienceAuthenticated
	}
	if len(c.JWT.AdminRoles) == 0 {
		c.JWT.AdminRoles = []string{RoleServiceRole, "supabase_admin"}
	}
	if c.JWT.Keys.Len() > 0 {
		signing := 0
		for _, kid := range c.JWT.Keys.Order {
			k := c.JWT.Keys.Keys[kid]
			if k.KeyID == "" {
				return fmt.Errorf("auth: JWT_KEYS: every key needs a kid")
			}
			if k.CanSign() {
				signing++
				if k.Algorithm != "" && k.Algorithm != "ES256" {
					return fmt.Errorf("auth: JWT_KEYS: signing key %q uses alg %q; Dilion signs with ES256", k.KeyID, k.Algorithm)
				}
			}
		}
		if signing != 1 {
			return fmt.Errorf("auth: JWT_KEYS: exactly one key must carry key_ops \"sign\", found %d", signing)
		}
	}
	if c.Mailer.OTPExp <= 0 {
		c.Mailer.OTPExp = 3600
	}
	if c.Mailer.OTPLength < 6 || c.Mailer.OTPLength > 10 {
		c.Mailer.OTPLength = DefaultOTPLength
	}
	if c.SMS.OTPExp <= 0 {
		c.SMS.OTPExp = 60
	}
	if c.SMS.OTPLength < 6 || c.SMS.OTPLength > 10 {
		c.SMS.OTPLength = DefaultOTPLength
	}
	if c.Mailer.MaxFrequency <= 0 {
		c.Mailer.MaxFrequency = time.Minute
	}
	for _, p := range []*string{
		&c.Mailer.URLPaths.Invite, &c.Mailer.URLPaths.Confirmation, &c.Mailer.URLPaths.Recovery,
		&c.Mailer.URLPaths.EmailChange, &c.Mailer.URLPaths.MagicLink, &c.Mailer.URLPaths.Reauthentication,
	} {
		if strings.TrimSpace(*p) == "" {
			*p = DefaultMailerURLPath
		}
	}
	if c.SMS.MaxFrequency <= 0 {
		c.SMS.MaxFrequency = time.Minute
	}
	// A broken SMS template must fail at mount time, not on the first OTP.
	if _, err := template.New("sms").Parse(c.SMS.SMSTemplateOrDefault()); err != nil {
		return fmt.Errorf("auth: invalid SMS_TEMPLATE %q: %w", c.SMS.Template, err)
	}
	c.SMS.Twilio.APIBase = strings.TrimRight(strings.TrimSpace(c.SMS.Twilio.APIBase), "/")
	if c.Sessions.Timebox < 0 {
		return fmt.Errorf("auth: SESSIONS_TIMEBOX must not be negative, was %v", c.Sessions.Timebox)
	}
	if c.Sessions.InactivityTimeout < 0 {
		return fmt.Errorf("auth: SESSIONS_INACTIVITY_TIMEOUT must not be negative, was %v", c.Sessions.InactivityTimeout)
	}
	if c.Security.RefreshTokenReuseInterval < 0 {
		return fmt.Errorf("auth: SECURITY_REFRESH_TOKEN_REUSE_INTERVAL must not be negative, was %d", c.Security.RefreshTokenReuseInterval)
	}
	if c.Security.Captcha.Enabled {
		switch c.Security.Captcha.Provider {
		case "hcaptcha", "turnstile":
		default:
			return fmt.Errorf("auth: unsupported captcha provider %q", c.Security.Captcha.Provider)
		}
		if strings.TrimSpace(c.Security.Captcha.Secret) == "" {
			return fmt.Errorf("auth: captcha is enabled but its provider secret is empty")
		}
	}
	if c.Security.Captcha.Timeout <= 0 {
		c.Security.Captcha.Timeout = DefaultCaptchaTimeout
	}
	c.Security.HIBPBaseURL = strings.TrimRight(strings.TrimSpace(c.Security.HIBPBaseURL), "/")
	if c.Password.MinLength < MinPasswordLength {
		c.Password.MinLength = MinPasswordLength
	}
	if c.External == nil {
		c.External = map[string]ProviderConfig{}
	}
	for _, p := range ExternalProviders {
		if _, ok := c.External[p]; !ok {
			c.External[p] = ProviderConfig{}
		}
	}
	if c.FlowStateExpiry <= 0 {
		c.FlowStateExpiry = 5 * time.Minute
	}
	if c.CleanupInterval <= 0 {
		c.CleanupInterval = 5 * time.Minute
	}
	if c.APIMaxRequestDuration < 0 {
		return fmt.Errorf("auth: API_MAX_REQUEST_DURATION must not be negative, was %v", c.APIMaxRequestDuration)
	}
	return c.compile()
}

// compile builds the URIAllowList matchers.
func (c *Config) compile() error {
	c.allowGlobs = c.allowGlobs[:0]
	for _, pattern := range c.URIAllowList {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		g, err := compileGlob(pattern)
		if err != nil {
			return fmt.Errorf("auth: invalid URI_ALLOW_LIST entry %q: %w", pattern, err)
		}
		c.allowGlobs = append(c.allowGlobs, g)
	}
	return nil
}

// ---- redirect allow list ---------------------------------------------------

var (
	decimalIPAddressPattern = regexp.MustCompile(`^[0-9]+$`)
	regularHostname         = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)
)

// IsRedirectAllowed reports whether redirectURL may be used as a redirect
// target. It reproduces upstream utilities.IsRedirectURLValid exactly:
//
//   - the empty string is never allowed;
//   - a URL with the same scheme+host as SiteURL is allowed; the PORT must match
//     too, except for loopback hosts (RFC 8252 §7.3 native apps);
//   - a host in decimal-integer form (http://2130706433/) is never allowed;
//   - any other IP literal is allowed only if it is a loopback address;
//   - an http(s) URL whose hostname contains unusual characters is rejected;
//   - otherwise the URL — WITHOUT its #fragment — must match one URIAllowList
//     glob, where `.` and `/` are separators: `*` does not cross them, `**` does.
func (c *Config) IsRedirectAllowed(redirectURL string) bool {
	if c == nil || redirectURL == "" {
		return false
	}
	base, berr := url.Parse(c.SiteURL)
	ref, rerr := url.Parse(redirectURL)
	if berr != nil || rerr != nil {
		return false
	}

	if base.Hostname() == ref.Hostname() && base.Scheme == ref.Scheme &&
		(base.Port() == ref.Port() || isLoopbackHostname(ref.Hostname())) {
		return true
	}

	scheme := strings.TrimSuffix(strings.ToLower(ref.Scheme), ":")
	isHTTP := scheme == "http" || scheme == "https"

	host := ref.Hostname()
	switch {
	case decimalIPAddressPattern.MatchString(host):
		return false
	case net.ParseIP(host) != nil:
		return net.ParseIP(host).IsLoopback()
	case isHTTP && !regularHostname.MatchString(host):
		return false
	}

	matchAgainst, _, _ := strings.Cut(redirectURL, "#")
	for _, g := range c.allowGlobs {
		if g.Match(matchAgainst) {
			return true
		}
	}
	return false
}

// RedirectURLOrSiteURL is upstream's utilities.GetReferrer decision: the caller
// supplied redirect_to when it is allowed, otherwise the referrer when it is
// allowed, otherwise SiteURL. Feature agents building email links call this.
func (c *Config) RedirectURLOrSiteURL(candidates ...string) string {
	for _, candidate := range candidates {
		if c.IsRedirectAllowed(candidate) {
			return candidate
		}
	}
	return c.SiteURL
}

func isLoopbackHostname(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ---- glob ------------------------------------------------------------------

// globPattern is a compiled URI_ALLOW_LIST pattern. It reproduces the subset of
// github.com/gobwas/glob that upstream compiles with the separators '.' and '/'
// (glob.MustCompile(uri, '.', '/')):
//
//	"*"     any run of characters except '.' and '/'
//	"**"    any run of characters, separators included
//	"?"     exactly one character that is not '.' or '/'
//	"[abc]" character class, [!abc] / [^abc] negated, ranges allowed
//	"{a,b}" alternation
//
// It is implemented over regexp so no third-party dependency is needed.
type globPattern struct {
	src string
	re  *regexp.Regexp
}

// Match reports whether s matches the whole pattern.
func (g *globPattern) Match(s string) bool { return g != nil && g.re.MatchString(s) }

// String returns the original pattern.
func (g *globPattern) String() string { return g.src }

const globSeparators = "./"

func compileGlob(pattern string) (*globPattern, error) {
	var b strings.Builder
	b.WriteString(`\A`)

	notSep := `[^` + regexp.QuoteMeta(globSeparators) + `]`
	runes := []rune(pattern)
	depth := 0
	for i := 0; i < len(runes); i++ {
		switch ch := runes[i]; ch {
		case '*':
			if i+1 < len(runes) && runes[i+1] == '*' {
				for i+1 < len(runes) && runes[i+1] == '*' {
					i++
				}
				b.WriteString(`.*`)
			} else {
				b.WriteString(notSep + `*`)
			}
		case '?':
			b.WriteString(notSep)
		case '[':
			j := i + 1
			if j < len(runes) && (runes[j] == '!' || runes[j] == '^') {
				j++
			}
			if j < len(runes) && runes[j] == ']' {
				j++
			}
			for j < len(runes) && runes[j] != ']' {
				j++
			}
			if j >= len(runes) {
				return nil, fmt.Errorf("unterminated character class")
			}
			class := string(runes[i+1 : j])
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + class + "]")
			i = j
		case '{':
			depth++
			b.WriteString(`(?:`)
		case '}':
			if depth == 0 {
				return nil, fmt.Errorf("unmatched }")
			}
			depth--
			b.WriteString(`)`)
		case ',':
			if depth > 0 {
				b.WriteString(`|`)
			} else {
				b.WriteString(regexp.QuoteMeta(string(ch)))
			}
		case '\\':
			if i+1 < len(runes) {
				i++
				b.WriteString(regexp.QuoteMeta(string(runes[i])))
			} else {
				b.WriteString(regexp.QuoteMeta(`\`))
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(ch)))
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("unmatched {")
	}
	b.WriteString(`\z`)

	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, err
	}
	return &globPattern{src: pattern, re: re}, nil
}

// ---- parsing helpers -------------------------------------------------------

// parseJWKSet decodes GOTRUE_JWT_KEYS: a JSON array of private JWKs.
func parseJWKSet(raw string) (JWKSet, error) {
	var items []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return JWKSet{}, fmt.Errorf("expected a JSON array of JWKs: %w", err)
	}
	set := JWKSet{Keys: make(map[string]JWK, len(items))}
	for i, item := range items {
		var k JWK
		if err := json.Unmarshal(item, &k); err != nil {
			return JWKSet{}, fmt.Errorf("key %d: %w", i, err)
		}
		if k.KeyID == "" {
			return JWKSet{}, fmt.Errorf("key %d: missing kid", i)
		}
		k.Raw = append(json.RawMessage(nil), item...)
		if _, dup := set.Keys[k.KeyID]; dup {
			return JWKSet{}, fmt.Errorf("duplicate kid %q", k.KeyID)
		}
		set.Keys[k.KeyID] = k
		set.Order = append(set.Order, k.KeyID)
	}
	return set, nil
}

// parseRequiredCharacters reproduces upstream conf.PasswordRequiredCharacters'
// decoder: colon separated sets, `\:` escaping a literal colon.
func parseRequiredCharacters(value string) []string {
	parts := strings.Split(value, ":")
	for i := 0; i < len(parts)-1; i++ {
		part := parts[i]
		if part == "" {
			continue
		}
		if part[len(part)-1] == '\\' {
			parts[i] = part[:len(part)-1] + ":" + parts[i+1]
			parts[i+1] = ""
		}
	}
	out := []string{}
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func loadEmailContent(prefix string, dst *EmailContentConfig) {
	dst.Invite = envString(prefix+"INVITE", dst.Invite)
	dst.Confirmation = envString(prefix+"CONFIRMATION", dst.Confirmation)
	dst.Recovery = envString(prefix+"RECOVERY", dst.Recovery)
	dst.EmailChange = envString(prefix+"EMAIL_CHANGE", dst.EmailChange)
	dst.MagicLink = envString(prefix+"MAGIC_LINK", dst.MagicLink)
	dst.Reauthentication = envString(prefix+"REAUTHENTICATION", dst.Reauthentication)
}

// EnvPrefix is the preferred prefix of every Dilion auth environment variable.
const EnvPrefix = "DILION_AUTH_"

// LegacyEnvPrefix is the upstream prefix accepted as a fallback so an existing
// gotrue environment keeps working during a migration.
const LegacyEnvPrefix = "GOTRUE_"

// lookupEnv reads DILION_AUTH_<name>, falling back to GOTRUE_<name>.
func lookupEnv(name string) (string, bool) {
	if v, ok := os.LookupEnv(EnvPrefix + name); ok {
		return v, true
	}
	return os.LookupEnv(LegacyEnvPrefix + name)
}

// parseHook fills a HookEndpointConfig from GOTRUE_<prefix>_{ENABLED,URI,SECRETS}
// (DILION_AUTH_<prefix>_* preferred). Enabling a hook without a URI is fatal.
func parseHook(h *HookEndpointConfig, prefix string, fail func(string, ...any)) {
	h.Enabled = envBool(prefix+"_ENABLED", h.Enabled, fail)
	h.URI = envString(prefix+"_URI", h.URI)
	h.Secrets = envStringSlice(prefix+"_SECRETS", h.Secrets)
	if h.Enabled && strings.TrimSpace(h.URI) == "" {
		fail("hook %s enabled but %s_URI is empty", prefix, prefix)
	}
}

func envString(name, def string) string {
	if v, ok := lookupEnv(name); ok {
		return v
	}
	return def
}

func envStringSlice(name string, def []string) []string {
	v, ok := lookupEnv(name)
	if !ok {
		return def
	}
	out := []string{}
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func envBool(name string, def bool, fail func(string, ...any)) bool {
	v, ok := lookupEnv(name)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		fail("%s: %q is not a boolean", name, v)
		return def
	}
	return b
}

func envInt(name string, def int, fail func(string, ...any)) int {
	v, ok := lookupEnv(name)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		fail("%s: %q is not an integer", name, v)
		return def
	}
	return n
}

func envFloat(name string, def float64, fail func(string, ...any)) float64 {
	v, ok := lookupEnv(name)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		fail("%s: %q is not a number", name, v)
		return def
	}
	if f < 0 {
		fail("%s: must not be negative, was %v", name, f)
		return def
	}
	return f
}

// envDuration accepts a Go duration ("5m", "1h30m") and, like upstream's
// envconfig, a bare number of seconds ("300").
func envDuration(name string, def time.Duration, fail func(string, ...any)) time.Duration {
	v, ok := lookupEnv(name)
	if !ok || strings.TrimSpace(v) == "" {
		return def
	}
	v = strings.TrimSpace(v)
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Duration(n) * time.Second
	}
	fail("%s: %q is not a duration", name, v)
	return def
}

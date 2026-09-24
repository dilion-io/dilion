package auth

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestOpaqueEnvironmentDefaults(t *testing.T) {
	key := opaqueTestConfig().Opaque.MasterKey
	for _, tc := range []struct {
		name      string
		env       map[string]string
		enabled   bool
		wantError bool
	}{
		{name: "no key stays disabled"},
		{name: "key enables by default", env: map[string]string{"DILION_AUTH_OPAQUE_MASTER_KEY": key}, enabled: true},
		{name: "explicit opt out", env: map[string]string{"DILION_AUTH_OPAQUE_MASTER_KEY": key, "DILION_AUTH_OPAQUE_ENABLED": "false"}},
		{name: "explicit opt in", env: map[string]string{"DILION_AUTH_OPAQUE_MASTER_KEY": key, "DILION_AUTH_OPAQUE_ENABLED": "true"}, enabled: true},
		{name: "enabled without key fails", env: map[string]string{"DILION_AUTH_OPAQUE_ENABLED": "true"}, wantError: true},
		{name: "invalid key fails by default", env: map[string]string{"DILION_AUTH_OPAQUE_MASTER_KEY": "invalid"}, wantError: true},
		{name: "empty key stays disabled", env: map[string]string{"DILION_AUTH_OPAQUE_MASTER_KEY": ""}},
		{name: "legacy key enables", env: map[string]string{"GOTRUE_OPAQUE_MASTER_KEY": key}, enabled: true},
		{name: "legacy opt out", env: map[string]string{"GOTRUE_OPAQUE_MASTER_KEY": key, "GOTRUE_OPAQUE_ENABLED": "false"}},
		{name: "preferred opt out wins", env: map[string]string{"GOTRUE_OPAQUE_MASTER_KEY": key, "GOTRUE_OPAQUE_ENABLED": "true", "DILION_AUTH_OPAQUE_ENABLED": "false"}},
		{name: "invalid flag fails", env: map[string]string{"DILION_AUTH_OPAQUE_MASTER_KEY": key, "DILION_AUTH_OPAQUE_ENABLED": "invalid"}, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, name := range []string{"DILION_AUTH_OPAQUE_MASTER_KEY", "DILION_AUTH_OPAQUE_ENABLED", "GOTRUE_OPAQUE_MASTER_KEY", "GOTRUE_OPAQUE_ENABLED"} {
				// Register restoration before unsetting, so absence (not merely an
				// empty value) exercises defaults and legacy fallback correctly.
				t.Setenv(name, "")
				if err := os.Unsetenv(name); err != nil {
					t.Fatal(err)
				}
			}
			for name, value := range tc.env {
				t.Setenv(name, value)
			}
			cfg, err := LoadConfig()
			if (err != nil) != tc.wantError {
				t.Fatalf("configuration error = %v, wantError = %v", err, tc.wantError)
			}
			if err == nil && cfg.Opaque.Enabled != tc.enabled {
				t.Fatalf("enabled = %v, want %v", cfg.Opaque.Enabled, tc.enabled)
			}
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()

	if c.SiteURL != DefaultSiteURL {
		t.Errorf("SiteURL = %q, want %q", c.SiteURL, DefaultSiteURL)
	}
	if c.JWT.Exp != 3600 || c.JWT.Aud != AudienceAuthenticated {
		t.Errorf("JWT = %+v", c.JWT)
	}
	if !c.Mailer.Autoconfirm {
		t.Error("Mailer.Autoconfirm must default to true until the email flows land")
	}
	if c.Mailer.OTPExp != 3600 || c.Mailer.OTPLength != 6 {
		t.Errorf("Mailer OTP = %d/%d, want 3600/6", c.Mailer.OTPExp, c.Mailer.OTPLength)
	}
	// DEVIATION from upstream's "/verify": Dilion mounts this surface under
	// /auth/v1, so the default link path carries that prefix.
	if c.Mailer.URLPaths.Confirmation != DefaultMailerURLPath || c.Mailer.URLPaths.Recovery != DefaultMailerURLPath {
		t.Errorf("URLPaths = %+v, want %s", c.Mailer.URLPaths, DefaultMailerURLPath)
	}
	if c.Mailer.MaxFrequency != time.Minute {
		t.Errorf("Mailer.MaxFrequency = %v, want 1m", c.Mailer.MaxFrequency)
	}
	if !c.Security.RefreshTokenRotationEnabled || c.Security.RefreshTokenReuseInterval != 10 {
		t.Errorf("Security = %+v", c.Security)
	}
	if c.Password.MinLength != 6 {
		t.Errorf("Password.MinLength = %d, want 6", c.Password.MinLength)
	}
	rl := c.RateLimits
	if rl.EmailSent != 30 || rl.SMSSent != 30 || rl.Verify != 30 || rl.TokenRefresh != 150 ||
		rl.SSO != 30 || rl.AnonymousUsers != 30 || rl.OTP != 30 || rl.Web3 != 30 || rl.Passkey != 30 {
		t.Errorf("RateLimits = %+v", rl)
	}
	if !c.CleanupEnabled || c.CleanupInterval != 5*time.Minute {
		t.Errorf("cleanup = %v/%v", c.CleanupEnabled, c.CleanupInterval)
	}
	if c.APIMaxRequestDuration != 10*time.Second {
		t.Errorf("APIMaxRequestDuration = %v", c.APIMaxRequestDuration)
	}
	if c.AnonymousUsersEnabled {
		t.Error("anonymous users must be off by default")
	}
	if !c.External["email"].Enabled {
		t.Error("the email provider must be enabled by default")
	}
	for _, p := range ExternalProviders {
		if _, ok := c.External[p]; !ok {
			t.Errorf("provider %q missing from the External map", p)
		}
	}
	if len(ExternalProviders) != 25 {
		t.Errorf("ExternalProviders has %d entries; /settings reports 26 booleans (25 + anonymous_users)", len(ExternalProviders))
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	t.Setenv("DILION_AUTH_SITE_URL", "https://app.example.com")
	t.Setenv("DILION_AUTH_URI_ALLOW_LIST", "https://app.example.com/**,myapp://callback")
	t.Setenv("DILION_AUTH_JWT_EXP", "900")
	t.Setenv("DILION_AUTH_DISABLE_SIGNUP", "true")
	t.Setenv("DILION_AUTH_SESSIONS_TIMEBOX", "24h")
	t.Setenv("DILION_AUTH_SESSIONS_INACTIVITY_TIMEOUT", "300")
	t.Setenv("DILION_AUTH_SECURITY_REFRESH_TOKEN_REUSE_INTERVAL", "30")
	t.Setenv("DILION_AUTH_RATE_LIMIT_TOKEN_REFRESH", "60")
	t.Setenv("DILION_AUTH_EXTERNAL_GOOGLE_ENABLED", "true")
	t.Setenv("DILION_AUTH_EXTERNAL_GOOGLE_CLIENT_ID", "a.apps.googleusercontent.com, b.apps.googleusercontent.com")
	t.Setenv("DILION_AUTH_EXTERNAL_ANONYMOUS_USERS_ENABLED", "true")
	t.Setenv("DILION_AUTH_PASSWORD_REQUIRED_CHARACTERS", `abc:ABC:012`)
	t.Setenv("DILION_AUTH_CORS_ALLOWED_HEADERS", "X-Tenant-Id")

	c, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if c.SiteURL != "https://app.example.com" {
		t.Errorf("SiteURL = %q", c.SiteURL)
	}
	if c.JWT.Exp != 900 || c.JWT.ExpDuration() != 15*time.Minute {
		t.Errorf("JWT.Exp = %d", c.JWT.Exp)
	}
	if !c.DisableSignup {
		t.Error("DisableSignup not read")
	}
	if c.Sessions.Timebox != 24*time.Hour {
		t.Errorf("Timebox = %v", c.Sessions.Timebox)
	}
	// A bare number is read as seconds, like upstream's envconfig.
	if c.Sessions.InactivityTimeout != 5*time.Minute {
		t.Errorf("InactivityTimeout = %v", c.Sessions.InactivityTimeout)
	}
	if c.Security.RefreshTokenReuseInterval != 30 {
		t.Errorf("reuse interval = %d", c.Security.RefreshTokenReuseInterval)
	}
	if c.RateLimits.TokenRefresh != 60 {
		t.Errorf("TokenRefresh = %v", c.RateLimits.TokenRefresh)
	}
	g := c.External["google"]
	if !g.Enabled || len(g.ClientID) != 2 || g.ClientID[1] != "b.apps.googleusercontent.com" {
		t.Errorf("google = %+v", g)
	}
	if !c.AnonymousUsersEnabled {
		t.Error("AnonymousUsersEnabled not read")
	}
	if len(c.Password.RequiredCharacters) != 3 {
		t.Errorf("RequiredCharacters = %q", c.Password.RequiredCharacters)
	}
	if len(c.CORS.AllowedHeaders) != 1 || c.CORS.AllowedHeaders[0] != "X-Tenant-Id" {
		t.Errorf("CORS.AllowedHeaders = %q", c.CORS.AllowedHeaders)
	}
}

// The upstream GOTRUE_* spelling is accepted as a fallback, and the DILION_AUTH_*
// name wins when both are set.
func TestLoadConfigLegacyEnvFallback(t *testing.T) {
	t.Setenv("GOTRUE_SITE_URL", "https://legacy.example.com")
	t.Setenv("GOTRUE_JWT_EXP", "1200")
	t.Setenv("GOTRUE_MAILER_AUTOCONFIRM", "false")

	c, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if c.SiteURL != "https://legacy.example.com" || c.JWT.Exp != 1200 || c.Mailer.Autoconfirm {
		t.Fatalf("legacy env not honoured: %q %d %v", c.SiteURL, c.JWT.Exp, c.Mailer.Autoconfirm)
	}

	t.Setenv("DILION_AUTH_SITE_URL", "https://new.example.com")
	c, err = LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if c.SiteURL != "https://new.example.com" {
		t.Errorf("SiteURL = %q, want the DILION_AUTH_ value to win", c.SiteURL)
	}
}

func TestLoadConfigInvalidValuesAreFatal(t *testing.T) {
	t.Setenv("DILION_AUTH_JWT_EXP", "not-a-number")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("LoadConfig accepted a non-numeric JWT_EXP")
	}
}

func TestLoadConfigRejectsBadCaptchaAndKeys(t *testing.T) {
	t.Setenv("DILION_AUTH_SECURITY_CAPTCHA_ENABLED", "true")
	t.Setenv("DILION_AUTH_SECURITY_CAPTCHA_PROVIDER", "recaptcha")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("LoadConfig accepted an unsupported captcha provider")
	}
}

func TestJWTKeysParsing(t *testing.T) {
	const keys = `[
	  {"kty":"EC","crv":"P-256","kid":"active","alg":"ES256","use":"sig","key_ops":["sign","verify"],"x":"x","y":"y","d":"d"},
	  {"kty":"EC","crv":"P-256","kid":"retired","alg":"ES256","use":"sig","key_ops":["verify"],"x":"x","y":"y"}
	]`
	t.Setenv("DILION_AUTH_JWT_KEYS", keys)
	t.Setenv("DILION_AUTH_JWT_SECRET", "legacy-hs256-secret")

	c, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if c.JWT.Keys.Len() != 2 {
		t.Fatalf("parsed %d keys, want 2", c.JWT.Keys.Len())
	}
	k, ok := c.JWT.Keys.SigningKey()
	if !ok || k.KeyID != "active" {
		t.Fatalf("signing key = %+v (found=%v), want kid=active", k, ok)
	}
	if len(k.Raw) == 0 {
		t.Error("the raw JWK JSON must be preserved for the signer")
	}
	if c.JWT.Secret != "legacy-hs256-secret" {
		t.Error("the legacy HS256 secret must survive alongside a key set")
	}

	// Two signing keys is a configuration error, exactly as upstream.
	t.Setenv("DILION_AUTH_JWT_KEYS", `[
	  {"kty":"EC","crv":"P-256","kid":"a","alg":"ES256","key_ops":["sign"],"x":"x","y":"y","d":"d"},
	  {"kty":"EC","crv":"P-256","kid":"b","alg":"ES256","key_ops":["sign"],"x":"x","y":"y","d":"d"}
	]`)
	if _, err := LoadConfig(); err == nil {
		t.Fatal("LoadConfig accepted two signing keys")
	}

	// RS256 is deliberately NOT supported for signing.
	t.Setenv("DILION_AUTH_JWT_KEYS", `[{"kty":"RSA","kid":"r","alg":"RS256","key_ops":["sign"],"n":"n","e":"AQAB"}]`)
	if _, err := LoadConfig(); err == nil {
		t.Fatal("LoadConfig accepted an RS256 signing key")
	}
}

func TestPasswordRequiredCharactersParsing(t *testing.T) {
	got := parseRequiredCharacters(`abc:ABC:!@#`)
	want := []string{"abc", "ABC", "!@#"}
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
	// An escaped colon stays inside its set.
	if got := parseRequiredCharacters(`a\:b:cd`); len(got) != 2 || got[0] != "a:b" || got[1] != "cd" {
		t.Errorf("escaped colon: got %q", got)
	}
}

func TestIsRedirectAllowed(t *testing.T) {
	c := DefaultConfig()
	c.SiteURL = "https://app.example.com"
	c.URIAllowList = []string{
		"https://*.example.com/callback",
		"https://deep.example.org/**",
		"myapp://auth/*",
		"http://localhost:3000/**",
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	cases := []struct {
		url  string
		want bool
	}{
		{"", false},
		// SiteURL itself, and any path under it (same scheme+host+port).
		{"https://app.example.com", true},
		{"https://app.example.com/deep/link?x=1", true},
		{"https://app.example.com:8443/", false},
		{"http://app.example.com/", false},
		{"https://evil.example.net/", false},
		// Allow-list globs: '*' does not cross '.' or '/'.
		{"https://www.example.com/callback", true},
		{"https://a.b.example.com/callback", false},
		{"https://www.example.com/callback/extra", false},
		{"https://deep.example.org/a/b/c", true},
		{"myapp://auth/done", true},
		{"myapp://auth/done/extra", false},
		// The fragment is ignored when matching.
		{"https://deep.example.org/a#access_token=x", true},
		// Loopback is allowed on any port; decimal IPs never are.
		{"http://localhost:3000/x/y", true},
		{"http://127.0.0.1:9999/anything", true},
		{"http://2130706433/", false},
		{"http://93.184.216.34/", false},
		{"https://exa_mple.com/callback", false},
	}
	for _, tc := range cases {
		if got := c.IsRedirectAllowed(tc.url); got != tc.want {
			t.Errorf("IsRedirectAllowed(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}

	if got := c.RedirectURLOrSiteURL("https://evil.example.net/", "https://app.example.com/next"); got != "https://app.example.com/next" {
		t.Errorf("RedirectURLOrSiteURL = %q", got)
	}
	if got := c.RedirectURLOrSiteURL("https://evil.example.net/"); got != c.SiteURL {
		t.Errorf("RedirectURLOrSiteURL fallback = %q, want SiteURL", got)
	}
}

func TestGlobPatterns(t *testing.T) {
	cases := []struct {
		pattern, input string
		want           bool
	}{
		{"a/*/c", "a/b/c", true},
		{"a/*/c", "a/b/b/c", false},
		{"a/**/c", "a/b/b/c", true},
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"**.example.com", "a.b.example.com", true},
		{"file?.txt", "file1.txt", true},
		{"file?.txt", "file12.txt", false},
		{"{http,https}://x.com/", "https://x.com/", true},
		{"{http,https}://x.com/", "ftp://x.com/", false},
		{"[abc]bc", "abc", true},
		{"[!abc]bc", "abc", false},
	}
	for _, tc := range cases {
		g, err := compileGlob(tc.pattern)
		if err != nil {
			t.Fatalf("compileGlob(%q): %v", tc.pattern, err)
		}
		if got := g.Match(tc.input); got != tc.want {
			t.Errorf("glob %q match %q = %v, want %v", tc.pattern, tc.input, got, tc.want)
		}
	}
	if _, err := compileGlob("a{b"); err == nil {
		t.Error("compileGlob accepted an unmatched {")
	}
}

// A webhook secret is "v1,whsec_...", so the list of them cannot be
// comma-separated: splitting on "," tore every secret in two and each hook call
// failed with "Error generating hook signatures". Upstream separates them
// with "|".
func TestHookSecretsSplitOnPipe(t *testing.T) {
	const a, b = "v1,whsec_MDEyMzQ1Njc4OWFiY2RlZg==", "v1,whsec_ZmVkY2JhOTg3NjU0MzIxMA=="
	t.Setenv("DILION_AUTH_HOOK_SEND_EMAIL_ENABLED", "true")
	t.Setenv("DILION_AUTH_HOOK_SEND_EMAIL_URI", "https://hooks.example.com/send-email")
	t.Setenv("DILION_AUTH_HOOK_SEND_EMAIL_SECRETS", a+" | "+b)
	t.Setenv("DILION_AUTH_HOOK_SEND_EMAIL_LOCKED", "true")
	c, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if got := c.Hooks.SendEmail.Secrets; len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("secrets = %q, want [%q %q]", got, a, b)
	}
	if !c.Hooks.SendEmail.Locked {
		t.Error("DILION_AUTH_HOOK_SEND_EMAIL_LOCKED was not read")
	}
	if _, err := signHookPayload(c.Hooks.SendEmail.Secrets, "msg", time.Now(), []byte("{}")); err != nil {
		t.Errorf("configured secrets cannot sign: %v", err)
	}
}

// A secret that cannot sign fails at startup, not on the first hook call.
func TestHookSecretsRejectedAtLoad(t *testing.T) {
	t.Setenv("DILION_AUTH_HOOK_SEND_EMAIL_SECRETS", "whsec_MDEyMzQ1Njc4OWFiY2RlZg==")
	if _, err := LoadConfig(); err == nil || !strings.Contains(err.Error(), "HOOK_SEND_EMAIL_SECRETS") {
		t.Fatalf("LoadConfig error = %v, want one naming HOOK_SEND_EMAIL_SECRETS", err)
	}
}

func TestDeletionReauthWindowFromEnv(t *testing.T) {
	if c := DefaultConfig(); c.Security.DeletionReauthWindow != DefaultDeletionReauthWindow {
		t.Errorf("default = %s, want %s", c.Security.DeletionReauthWindow, DefaultDeletionReauthWindow)
	}
	t.Setenv("DILION_AUTH_SECURITY_DELETION_REAUTH_WINDOW", "5m")
	c, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if c.Security.DeletionReauthWindow != 5*time.Minute {
		t.Errorf("window = %s, want 5m", c.Security.DeletionReauthWindow)
	}
	t.Setenv("DILION_AUTH_SECURITY_DELETION_REAUTH_WINDOW", "-1m")
	if _, err := LoadConfig(); err == nil {
		t.Error("a negative window was accepted")
	}
}

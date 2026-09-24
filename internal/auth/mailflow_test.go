package auth

// Unit tests for the pieces of the email lifecycle that need no database:
// token hashing, OTP generation, PKCE challenge validation and verification,
// and email action link construction.

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// timeAt is a terse UTC constructor for the table-driven cases below.
func timeAt(y int, mo time.Month, d, h, mi int) time.Time {
	return time.Date(y, mo, d, h, mi, 0, 0, time.UTC)
}

// The hash is the compatibility contract with upstream: a token minted by
// gotrue must be redeemable by Dilion and vice versa. The vector below is
// sha224("user@example.com" + "123456") — upstream's
// crypto.GenerateTokenHash(email, otp).
func TestGenerateTokenHashMatchesUpstream(t *testing.T) {
	const email, otp = "user@example.com", "123456"

	want := fmt.Sprintf("%x", sha256.Sum224([]byte(email+otp)))
	got := generateTokenHash(email, otp)
	if got != want {
		t.Fatalf("generateTokenHash = %q, want %q", got, want)
	}
	if len(got) != 56 {
		t.Errorf("hash length = %d, want 56 hex characters (224 bits)", len(got))
	}

	// The recipient is part of the pre-image: the same OTP for a different
	// address must not produce the same hash, or a token could be replayed
	// against another account.
	if generateTokenHash("other@example.com", otp) == got {
		t.Error("hash does not depend on the recipient")
	}
}

func TestGenerateOTPShape(t *testing.T) {
	for _, digits := range []int{6, 8, 10} {
		for i := 0; i < 50; i++ {
			otp, err := generateOTP(digits)
			if err != nil {
				t.Fatalf("generateOTP(%d): %v", digits, err)
			}
			if len(otp) != digits {
				t.Fatalf("generateOTP(%d) = %q, want %d digits", digits, otp, digits)
			}
			if strings.Trim(otp, "0123456789") != "" {
				t.Fatalf("generateOTP(%d) = %q, want decimal digits only", digits, otp)
			}
		}
	}
	// Out-of-range lengths fall back to the default rather than failing, the
	// same clamp Config.Validate applies.
	otp, err := generateOTP(3)
	if err != nil {
		t.Fatalf("generateOTP(3): %v", err)
	}
	if len(otp) != DefaultOTPLength {
		t.Errorf("generateOTP(3) = %q, want %d digits", otp, DefaultOTPLength)
	}
}

func TestAddFlowPrefix(t *testing.T) {
	if got := addFlowPrefix("abc", false); got != "abc" {
		t.Errorf("implicit flow token = %q, want unprefixed", got)
	}
	got := addFlowPrefix("abc", true)
	if got != "pkce_abc" {
		t.Errorf("pkce token = %q, want %q", got, "pkce_abc")
	}
	if !isPKCEToken(got) || isPKCEToken("abc") {
		t.Error("isPKCEToken disagrees with addFlowPrefix")
	}
}

// ---- PKCE ------------------------------------------------------------------

func TestValidatePKCEParams(t *testing.T) {
	valid := strings.Repeat("a", 43)

	tests := []struct {
		name           string
		method, chal   string
		wantErr        bool
		wantErrMessage string
	}{
		{name: "both empty is the implicit flow", method: "", chal: ""},
		{name: "s256", method: "s256", chal: valid},
		{name: "S256 is case insensitive", method: "S256", chal: valid},
		{name: "plain", method: "plain", chal: valid},
		{
			name: "challenge without method", method: "", chal: valid,
			wantErr: true, wantErrMessage: invalidPKCEParamsMessage,
		},
		{
			name: "method without challenge", method: "s256", chal: "",
			wantErr: true, wantErrMessage: invalidPKCEParamsMessage,
		},
		{
			name: "too short", method: "s256", chal: strings.Repeat("a", 42),
			wantErr: true, wantErrMessage: "between 43 and 128",
		},
		{
			name: "too long", method: "s256", chal: strings.Repeat("a", 129),
			wantErr: true, wantErrMessage: "between 43 and 128",
		},
		{
			name: "illegal character", method: "s256", chal: strings.Repeat("a", 42) + "/",
			wantErr: true, wantErrMessage: "alphanumeric",
		},
		{
			name: "unknown method", method: "sha512", chal: valid,
			wantErr: true, wantErrMessage: "unsupported code_challenge method",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePKCEParams(tc.method, tc.chal)
			if tc.wantErr == (err == nil) {
				t.Fatalf("validatePKCEParams(%q, %q) error = %v, wantErr = %v", tc.method, tc.chal, err, tc.wantErr)
			}
			if err == nil {
				return
			}
			he, ok := err.(*HTTPError)
			if !ok {
				t.Fatalf("error is %T, want *HTTPError", err)
			}
			if he.HTTPStatus != 400 || he.ErrorCode != ErrorCodeValidationFailed {
				t.Errorf("error = %d/%s, want 400/validation_failed", he.HTTPStatus, he.ErrorCode)
			}
			if !strings.Contains(he.Message, tc.wantErrMessage) {
				t.Errorf("message = %q, want it to contain %q", he.Message, tc.wantErrMessage)
			}
		})
	}
}

func TestVerifyPKCEChallenge(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	if err := verifyPKCEChallenge(challenge, "s256", verifier); err != nil {
		t.Fatalf("matching s256 verifier rejected: %v", err)
	}
	if err := verifyPKCEChallenge(challenge, "S256", verifier); err != nil {
		t.Fatalf("method comparison is not case insensitive: %v", err)
	}
	if err := verifyPKCEChallenge(challenge, "s256", verifier+"x"); err == nil {
		t.Error("wrong verifier accepted")
	} else if err.Error() != pkceInvalidCodeChallengeError {
		t.Errorf("error = %q, want %q", err, pkceInvalidCodeChallengeError)
	}

	if err := verifyPKCEChallenge(verifier, "plain", verifier); err != nil {
		t.Fatalf("matching plain verifier rejected: %v", err)
	}
	if err := verifyPKCEChallenge(verifier, "plain", "nope"); err == nil {
		t.Error("wrong plain verifier accepted")
	}

	if err := verifyPKCEChallenge(challenge, "md5", verifier); err == nil {
		t.Error("unknown method accepted")
	} else if err.Error() != pkceInvalidCodeMethodError {
		t.Errorf("error = %q, want %q", err, pkceInvalidCodeMethodError)
	}
}

func TestAuthMethodForVerifyType(t *testing.T) {
	cases := map[string]string{
		mailSignup:      authMethodEmailSignup,
		mailMagicLink:   authMethodMagicLink,
		mailRecovery:    authMethodRecovery,
		mailEmailChange: authMethodEmailChange,
		mailEmailOTP:    authMethodOTP,
		mailInvite:      authMethodInvite,
	}
	for verifyType, want := range cases {
		got, err := authMethodForVerifyType(verifyType)
		if err != nil {
			t.Fatalf("authMethodForVerifyType(%q): %v", verifyType, err)
		}
		if got != want {
			t.Errorf("authMethodForVerifyType(%q) = %q, want %q", verifyType, got, want)
		}
	}
	if _, err := authMethodForVerifyType("nonsense"); err == nil {
		t.Error("unknown verification type accepted")
	}
}

// ---- link construction -----------------------------------------------------

// The query string of an action link is built by hand upstream, so its
// parameter ORDER is part of the wire contract.
func TestActionLinkPathOrderAndEncoding(t *testing.T) {
	// A redirect without &, = or # is embedded verbatim (upstream's
	// encodeRedirectURL only escapes URLs that would otherwise truncate the
	// query string).
	p, err := actionLinkPath("/verify", "pkce_abc", "signup", "https://app.test/welcome")
	if err != nil {
		t.Fatalf("actionLinkPath: %v", err)
	}
	const want = "token=pkce_abc&type=signup&redirect_to=https://app.test/welcome"
	if p.RawQuery != want {
		t.Errorf("RawQuery = %q, want %q", p.RawQuery, want)
	}
	if p.Path != "/verify" {
		t.Errorf("Path = %q, want /verify", p.Path)
	}

	// One that WOULD truncate it is escaped.
	p, err = actionLinkPath("/verify", "t", "signup", "https://app.test/x?a=1&b=2")
	if err != nil {
		t.Fatalf("actionLinkPath: %v", err)
	}
	if !strings.HasSuffix(p.RawQuery, "redirect_to=https%3A%2F%2Fapp.test%2Fx%3Fa%3D1%26b%3D2") {
		t.Errorf("RawQuery = %q, want an escaped redirect_to", p.RawQuery)
	}
}

func TestEncodeRedirectURL(t *testing.T) {
	// A plain URL is taken as-is; one carrying &, = or # is escaped, so a
	// redirect with its own query does not truncate the link.
	if got := encodeRedirectURL("https://app.test/x"); got != "https://app.test/x" {
		t.Errorf("plain URL was re-encoded: %q", got)
	}
	got := encodeRedirectURL("https://app.test/x?a=1&b=2")
	if !strings.Contains(got, "%3D") || !strings.Contains(got, "%26") {
		t.Errorf("URL with & and = was not escaped: %q", got)
	}
}

// externalHost must never trust an arbitrary Host header: a forged one would
// plant an attacker's domain into a confirmation link.
func TestExternalHostRejectsForeignHost(t *testing.T) {
	cfg := testConfig()
	cfg.SiteURL = "https://app.test"
	cfg.Mailer.ExternalHosts = []string{"auth.app.test"}
	a := &api{cfg: cfg}

	r := httptest.NewRequest("GET", "http://evil.test/verify", nil)
	r.Host = "evil.test"
	if got := a.externalHost(r).String(); got != "https://app.test" {
		t.Errorf("forged Host was trusted: %q", got)
	}

	r.Host = "auth.app.test"
	if got := a.externalHost(r).String(); got != "http://auth.app.test" {
		t.Errorf("allow-listed external host = %q", got)
	}

	r.Host = "app.test"
	if got := a.externalHost(r).String(); got != "http://app.test" {
		t.Errorf("SiteURL host = %q", got)
	}
}

func TestSubjectFallsBackToUpstreamDefaults(t *testing.T) {
	a := &api{cfg: testConfig()}
	if got := a.subjectFor(mailSignup, ""); got != "Confirm your email address" {
		t.Errorf("signup subject = %q", got)
	}
	if got := a.subjectFor(mailReauthentication, "424242"); got != "424242 is your verification code" {
		t.Errorf("reauthentication subject = %q", got)
	}

	a.cfg.Mailer.Subjects.Confirmation = "Bestätigen Sie Ihre E-Mail"
	if got := a.subjectFor(mailSignup, ""); got != "Bestätigen Sie Ihre E-Mail" {
		t.Errorf("configured subject was ignored: %q", got)
	}
}

func TestFlowStateExpiryUsesIssuedAtForMagicLinks(t *testing.T) {
	base := timeAt(2026, 8, 20, 12, 0)
	issued := base.Add(30 * time.Minute)

	magic := &flowState{AuthenticationMethod: authMethodMagicLink, CreatedAt: base, AuthCodeIssuedAt: &issued}
	// 40 minutes after creation but only 10 after issuance: still alive.
	if magic.IsExpired(base.Add(40*time.Minute), 15*time.Minute) {
		t.Error("magic link flow expired from created_at instead of auth_code_issued_at")
	}
	if !magic.IsExpired(issued.Add(16*time.Minute), 15*time.Minute) {
		t.Error("magic link flow did not expire after auth_code_issued_at + expiry")
	}

	other := &flowState{AuthenticationMethod: authMethodEmailSignup, CreatedAt: base, AuthCodeIssuedAt: &issued}
	if !other.IsExpired(base.Add(16*time.Minute), 15*time.Minute) {
		t.Error("non-magic-link flow did not expire from created_at")
	}
}

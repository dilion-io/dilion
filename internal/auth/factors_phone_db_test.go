package auth

// Database-backed tests for the phone (SMS) MFA factor: enroll -> challenge
// (asserting an SMS was sent through an injected stub sender) -> verify (correct
// OTP yields an aal2 JWT with the mfa/phone AMR method; wrong and expired codes
// yield upstream's error codes), the enroll/verify feature gates, the shared
// MaxEnrolledFactors budget across factor types, and phone uniqueness.

import (
	"context"
	"net/http"
	"regexp"
	"testing"
	"time"
)

// recordingSender captures every SMS the phone factor delivers.
type recordingSender struct {
	to   []string
	body []string
}

func (s *recordingSender) Send(_ context.Context, to, body string) error {
	s.to = append(s.to, to)
	s.body = append(s.body, body)
	return nil
}

func (s *recordingSender) last() (string, string) {
	if len(s.body) == 0 {
		return "", ""
	}
	return s.to[len(s.to)-1], s.body[len(s.body)-1]
}

// testPhoneOTPExp mirrors DefaultConfig().MFA.PhoneOTPExp, which phoneConfig
// leaves at its default.
const testPhoneOTPExp = 300 * time.Second

var otpDigits = regexp.MustCompile(`\d{4,10}`)

func extractOTP(t *testing.T, body string) string {
	t.Helper()
	m := otpDigits.FindString(body)
	if m == "" {
		t.Fatalf("no OTP found in SMS body %q", body)
	}
	return m
}

// phoneConfig returns a config with the phone factor enabled and an injected
// recording SMS sender.
func phoneConfig(sender *recordingSender) *Config {
	cfg := DefaultConfig()
	cfg.MFA.Phone.EnrollEnabled = true
	cfg.MFA.Phone.VerifyEnabled = true
	cfg.SMS.Sender = sender
	return cfg
}

func (e *mfaEnv) enrollPhone(t *testing.T, token, phone, name string) EnrollFactorResponse {
	t.Helper()
	rec := e.do(t, http.MethodPost, "/factors",
		map[string]any{"factor_type": "phone", "phone": phone, "friendly_name": name}, token)
	return decodeInto[EnrollFactorResponse](t, rec, http.StatusOK)
}

// TestMFAPhoneEnrollChallengeVerifyProducesAAL2 is the whole phone happy path.
func TestMFAPhoneEnrollChallengeVerifyProducesAAL2(t *testing.T) {
	sender := &recordingSender{}
	env := newMFAEnv(t, phoneConfig(sender))

	session := env.signupUser(t, "mfa-phone@dilion.test")

	enrolled := env.enrollPhone(t, session.Token, "+1 555 010 0001", "My phone")
	if enrolled.Type != FactorTypePhone {
		t.Fatalf("enroll type = %q, want phone", enrolled.Type)
	}
	// The stored/echoed number is normalized to bare E.164 digits.
	if enrolled.Phone != "15550100001" {
		t.Fatalf("enroll phone = %q, want 15550100001", enrolled.Phone)
	}

	ch := env.do(t, http.MethodPost, "/factors/"+enrolled.ID+"/challenge", map[string]any{}, session.Token)
	challenge := decodeInto[ChallengeFactorResponse](t, ch, http.StatusOK)
	if challenge.Type != FactorTypePhone {
		t.Fatalf("challenge type = %q, want phone", challenge.Type)
	}
	if want := env.clock.Now().Add(testPhoneOTPExp).Unix(); challenge.ExpiresAt != want {
		t.Fatalf("expires_at = %d, want %d", challenge.ExpiresAt, want)
	}

	// The SMS went out to the dialable +E.164 form.
	to, body := sender.last()
	if to != "+15550100001" {
		t.Fatalf("sms to = %q, want +15550100001", to)
	}
	code := extractOTP(t, body)

	env.clock.advance(2 * time.Second)

	rec := env.do(t, http.MethodPost, "/factors/"+enrolled.ID+"/verify",
		map[string]any{"challenge_id": challenge.ID, "code": code}, session.Token)
	upgraded := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	if got := env.aal(t, upgraded.Token); got != AAL2 {
		t.Fatalf("post-verify aal = %q, want aal2", got)
	}
	if got := env.amrMethods(t, upgraded.Token); !equalMethods(got, []string{AMRMethodMFAPhone, AMRMethodPassword}) {
		t.Fatalf("post-verify amr = %v, want [mfa/phone password]", got)
	}
	if upgraded.RefreshToken == session.RefreshToken {
		t.Fatal("verify must issue a NEW refresh token")
	}
}

// TestMFAPhoneVerifyRejectsBadAndExpired covers the two OTP failure modes.
func TestMFAPhoneVerifyRejectsBadAndExpired(t *testing.T) {
	sender := &recordingSender{}
	env := newMFAEnv(t, phoneConfig(sender))
	session := env.signupUser(t, "mfa-phone-bad@dilion.test")
	f := env.enrollPhone(t, session.Token, "+15550100002", "Phone")

	challenge := decodeInto[ChallengeFactorResponse](t,
		env.do(t, http.MethodPost, "/factors/"+f.ID+"/challenge", map[string]any{}, session.Token), http.StatusOK)
	_, body := sender.last()
	good := extractOTP(t, body)

	// A wrong code fails.
	rec := env.do(t, http.MethodPost, "/factors/"+f.ID+"/verify",
		map[string]any{"challenge_id": challenge.ID, "code": "000000"}, session.Token)
	if b := decodeInto[errorBody](t, rec, http.StatusUnprocessableEntity); b.ErrorCode != ErrorCodeMFAVerificationFailed {
		t.Fatalf("bad-code error_code = %q, want %q", b.ErrorCode, ErrorCodeMFAVerificationFailed)
	}

	// Past the OTP expiry the challenge is destroyed and reported as expired.
	env.clock.advance(testPhoneOTPExp + time.Second)
	rec = env.do(t, http.MethodPost, "/factors/"+f.ID+"/verify",
		map[string]any{"challenge_id": challenge.ID, "code": good}, session.Token)
	if b := decodeInto[errorBody](t, rec, http.StatusUnprocessableEntity); b.ErrorCode != ErrorCodeMFAChallengeExpired {
		t.Fatalf("expired error_code = %q, want %q", b.ErrorCode, ErrorCodeMFAChallengeExpired)
	}
}

// TestMFAPhoneEnrollDisabled: a default deployment leaves phone MFA off.
func TestMFAPhoneEnrollDisabled(t *testing.T) {
	env := newMFAEnv(t, nil) // DefaultConfig: phone MFA off
	session := env.signupUser(t, "mfa-phone-off@dilion.test")
	rec := env.do(t, http.MethodPost, "/factors",
		map[string]any{"factor_type": "phone", "phone": "+15550100003"}, session.Token)
	if b := decodeInto[errorBody](t, rec, http.StatusUnprocessableEntity); b.ErrorCode != ErrorCodeMFAPhoneEnrollDisabled {
		t.Fatalf("error_code = %q, want %q", b.ErrorCode, ErrorCodeMFAPhoneEnrollDisabled)
	}
}

// TestMFAPhoneVerifyDisabled: enroll allowed, verify blocked -> challenge is
// refused with the phone verify-disabled code.
func TestMFAPhoneVerifyDisabled(t *testing.T) {
	sender := &recordingSender{}
	cfg := phoneConfig(sender)
	cfg.MFA.Phone.VerifyEnabled = false
	env := newMFAEnv(t, cfg)
	session := env.signupUser(t, "mfa-phone-noverify@dilion.test")
	f := env.enrollPhone(t, session.Token, "+15550100004", "Phone")

	rec := env.do(t, http.MethodPost, "/factors/"+f.ID+"/challenge", map[string]any{}, session.Token)
	if b := decodeInto[errorBody](t, rec, http.StatusUnprocessableEntity); b.ErrorCode != ErrorCodeMFAPhoneVerifyDisabled {
		t.Fatalf("error_code = %q, want %q", b.ErrorCode, ErrorCodeMFAPhoneVerifyDisabled)
	}
}

// TestMFAMaxEnrolledFactorsAcrossTypes: the budget counts TOTP and phone
// together (upstream MaxEnrolledFactors is not per-type).
func TestMFAMaxEnrolledFactorsAcrossTypes(t *testing.T) {
	sender := &recordingSender{}
	cfg := phoneConfig(sender)
	cfg.MFA.MaxEnrolledFactors = 1
	env := newMFAEnv(t, cfg)

	session := env.signupUser(t, "mfa-mixed@dilion.test")
	env.enroll(t, session.Token, "Authenticator") // a TOTP factor fills the budget

	rec := env.do(t, http.MethodPost, "/factors",
		map[string]any{"factor_type": "phone", "phone": "+15550100005", "friendly_name": "Phone"}, session.Token)
	if b := decodeInto[errorBody](t, rec, http.StatusUnprocessableEntity); b.ErrorCode != ErrorCodeTooManyEnrolledMFAFactors {
		t.Fatalf("error_code = %q, want %q", b.ErrorCode, ErrorCodeTooManyEnrolledMFAFactors)
	}
}

// TestMFAPhoneUniqueness: once a phone factor on a number is verified, a second
// enrolment of the same number is refused.
func TestMFAPhoneUniqueness(t *testing.T) {
	sender := &recordingSender{}
	env := newMFAEnv(t, phoneConfig(sender))
	session := env.signupUser(t, "mfa-phone-unique@dilion.test")

	f := env.enrollPhone(t, session.Token, "+15550100006", "Phone")
	challenge := decodeInto[ChallengeFactorResponse](t,
		env.do(t, http.MethodPost, "/factors/"+f.ID+"/challenge", map[string]any{}, session.Token), http.StatusOK)
	_, body := sender.last()
	env.clock.advance(2 * time.Second)
	decodeInto[AccessTokenResponse](t, env.do(t, http.MethodPost, "/factors/"+f.ID+"/verify",
		map[string]any{"challenge_id": challenge.ID, "code": extractOTP(t, body)}, session.Token), http.StatusOK)

	// Re-enrolling the same, now-verified number is refused. (Session is aal2, so
	// the "aal2 required to add a factor" rule does not interfere.)
	rec := env.do(t, http.MethodPost, "/factors",
		map[string]any{"factor_type": "phone", "phone": "+15550100006", "friendly_name": "Phone again"}, session.Token)
	if b := decodeInto[errorBody](t, rec, http.StatusUnprocessableEntity); b.ErrorCode != ErrorCodeMFAVerifiedFactorExists {
		t.Fatalf("error_code = %q, want %q", b.ErrorCode, ErrorCodeMFAVerifiedFactorExists)
	}
}

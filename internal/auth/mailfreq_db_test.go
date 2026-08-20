package auth

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Mailer.MaxFrequency suppresses a SECOND mail of the same kind to the same
// user, and lets it through once the window has passed (upstream's
// validateSentWithinFrequencyLimit).
func TestMailFrequencyLimitsRepeatedRecovery(t *testing.T) {
	env := newEmailEnv(t, nil)
	env.confirmedUser(t, "freq-recover@app.test", "correct-horse")

	rec := env.do(t, http.MethodPost, "/recover", map[string]any{"email": "freq-recover@app.test"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("first /recover status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if got := len(env.mails.to("freq-recover@app.test")); got != 1 {
		t.Fatalf("recovery mails after the first request = %d, want 1", got)
	}

	// Immediately again: upstream's 429.
	rec = env.do(t, http.MethodPost, "/recover", map[string]any{"email": "freq-recover@app.test"}, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second /recover status = %d, want 429; body = %s", rec.Code, rec.Body.String())
	}
	var body HTTPError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal %q: %v", rec.Body.String(), err)
	}
	if body.ErrorCode != ErrorCodeOverEmailSendRateLimit {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeOverEmailSendRateLimit)
	}
	if !strings.HasPrefix(body.Message, "For security purposes, you can only request this after ") {
		t.Errorf("msg = %q, want upstream's frequency-limit message", body.Message)
	}
	if got := len(env.mails.to("freq-recover@app.test")); got != 1 {
		t.Errorf("recovery mails after the throttled request = %d, want 1 (nothing new sent)", got)
	}

	// Past the window the next request is served again.
	env.clock.advance(time.Minute + time.Second)
	rec = env.do(t, http.MethodPost, "/recover", map[string]any{"email": "freq-recover@app.test"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("third /recover status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if got := len(env.mails.to("freq-recover@app.test")); got != 2 {
		t.Errorf("recovery mails after the window = %d, want 2", got)
	}
}

// The same throttle guards /resend of a signup confirmation.
func TestMailFrequencyLimitsResendConfirmation(t *testing.T) {
	env := newEmailEnv(t, nil)
	env.unconfirmedSignup(t, "freq-resend@app.test", "correct-horse")

	rec := env.do(t, http.MethodPost, "/resend",
		map[string]any{"type": mailSignup, "email": "freq-resend@app.test"}, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("immediate /resend status = %d, want 429; body = %s", rec.Code, rec.Body.String())
	}

	env.clock.advance(time.Minute + time.Second)
	rec = env.do(t, http.MethodPost, "/resend",
		map[string]any{"type": mailSignup, "email": "freq-resend@app.test"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("/resend after the window status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if got := len(env.mails.to("freq-resend@app.test")); got != 2 {
		t.Errorf("confirmation mails = %d, want 2 (signup + resend)", got)
	}
}

// The throttle is per TOKEN TYPE: a pending signup confirmation does not block
// a password reset, even though both are mails to the same user.
func TestMailFrequencyIsPerTokenType(t *testing.T) {
	env := newEmailEnv(t, nil)
	env.unconfirmedSignup(t, "freq-mixed@app.test", "correct-horse")

	rec := env.do(t, http.MethodPost, "/recover", map[string]any{"email": "freq-mixed@app.test"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("/recover status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if got := len(env.mails.to("freq-mixed@app.test")); got != 2 {
		t.Errorf("mails = %d, want 2 (confirmation + recovery)", got)
	}
}

// A short MaxFrequency is honoured: with the window effectively off, repeated
// sends go through.
func TestMailFrequencyCanBeEffectivelyDisabled(t *testing.T) {
	cfg := emailTestConfig()
	cfg.Mailer.MaxFrequency = time.Nanosecond
	env := newEmailEnv(t, cfg)
	env.confirmedUser(t, "freq-off@app.test", "correct-horse")

	for i := 0; i < 3; i++ {
		rec := env.do(t, http.MethodPost, "/recover", map[string]any{"email": "freq-off@app.test"}, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("/recover #%d status = %d, want 200; body = %s", i+1, rec.Code, rec.Body.String())
		}
	}
	if got := len(env.mails.to("freq-off@app.test")); got != 3 {
		t.Errorf("recovery mails = %d, want 3", got)
	}
}

// An invited address is exempt (upstream's sendInvite has no frequency check):
// an admin re-inviting must not be throttled by the anonymous-abuse guard.
func TestMailFrequencyExemptsInvite(t *testing.T) {
	env := newEmailEnv(t, nil)
	token := env.serviceRoleToken(t)

	for i := 0; i < 2; i++ {
		rec := env.do(t, http.MethodPost, "/invite", map[string]any{"email": "freq-invite@app.test"}, token)
		if rec.Code != http.StatusOK {
			t.Fatalf("/invite #%d status = %d, want 200; body = %s", i+1, rec.Code, rec.Body.String())
		}
	}
	if got := len(env.mails.to("freq-invite@app.test")); got != 2 {
		t.Errorf("invite mails = %d, want 2", got)
	}
}

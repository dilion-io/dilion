package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// Guessing one account's password from many addresses is stopped by the
// per-account count, not only by per-IP limits — and the right password is
// refused too while the account is locked.
func TestPasswordGuessesAreLimitedPerAccount(t *testing.T) {
	env := newTestEnv(t)
	env.signup(t, "guessed@example.com", "correct-horse-battery")
	try := func(password string, n int) int {
		t.Helper()
		req := map[string]any{"email": "guessed@example.com", "password": password}
		// A different client address for every try: the per-IP limiter never
		// sees two.
		rec := env.doFrom(t, http.MethodPost, "/token?grant_type=password", req, "198.51.100."+itoa(n))
		return rec.Code
	}
	for i := 0; i < attemptLimits[attemptPassword]; i++ {
		if code := try("wrong-password", i); code != http.StatusBadRequest {
			t.Fatalf("guess %d = %d, want 400", i, code)
		}
	}
	if code := try("wrong-password", 200); code != http.StatusTooManyRequests {
		t.Fatalf("guess past the limit = %d, want 429", code)
	}
	if code := try("correct-horse-battery", 201); code != http.StatusTooManyRequests {
		t.Fatalf("right password while locked = %d, want 429", code)
	}
	// Another account is unaffected.
	env.signup(t, "other@example.com", "correct-horse-battery")
	if rec := env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"email": "other@example.com", "password": "correct-horse-battery"}, ""); rec.Code != http.StatusOK {
		t.Fatalf("another account = %d, want 200", rec.Code)
	}
}

// A success clears the count.
func TestPasswordSuccessClearsFailures(t *testing.T) {
	env := newTestEnv(t)
	env.signup(t, "clears@example.com", "correct-horse-battery")
	body := func(pw string) map[string]any { return map[string]any{"email": "clears@example.com", "password": pw} }
	for i := 0; i < attemptLimits[attemptPassword]-1; i++ {
		env.doFrom(t, http.MethodPost, "/token?grant_type=password", body("wrong"), "198.51.100."+itoa(i))
	}
	if rec := env.doFrom(t, http.MethodPost, "/token?grant_type=password", body("correct-horse-battery"), "198.51.100.250"); rec.Code != http.StatusOK {
		t.Fatalf("right password under the limit = %d, want 200", rec.Code)
	}
	for i := 0; i < attemptLimits[attemptPassword]-1; i++ {
		if rec := env.doFrom(t, http.MethodPost, "/token?grant_type=password", body("wrong"), "198.51.101."+itoa(i)); rec.Code != http.StatusBadRequest {
			t.Fatalf("failure after a success = %d, want 400 (the count was not cleared)", rec.Code)
		}
	}
}

// doFrom is do from a given client address.
func (e *testEnv) doFrom(t *testing.T, method, path string, body any, ip string) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":41234"
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func itoa(i int) string { return strconv.Itoa(i) }

// A factor code is six digits; the per-factor count stops it being guessed,
// fresh challenge after fresh challenge.
func TestFactorCodeGuessesAreLimited(t *testing.T) {
	env := newMFAEnv(t, nil)
	user := env.signupUser(t, "factor-guess@example.com")
	factor := env.enroll(t, user.Token, "phone app")
	verify := func(code string) int {
		ch := env.challenge(t, user.Token, factor.ID)
		return env.do(t, http.MethodPost, "/factors/"+factor.ID+"/verify",
			map[string]any{"challenge_id": ch.ID, "code": code}, user.Token).Code
	}
	for i := 0; i < attemptLimits[attemptFactor]; i++ {
		if code := verify("000000"); code != http.StatusUnprocessableEntity {
			t.Fatalf("wrong code %d = %d, want 422", i, code)
		}
	}
	if code := verify(env.totpCode(t, factor.TOTP.Secret)); code != http.StatusTooManyRequests {
		t.Fatalf("right code after %d failures = %d, want 429", attemptLimits[attemptFactor], code)
	}
}

// A typed OTP is six digits and lives for an hour: the per-address count
// stops it being guessed.
func TestTypedOTPGuessesAreLimited(t *testing.T) {
	env := newEmailEnv(t, nil)
	env.confirmedUser(t, "otp-guess@example.com", "hunter22")
	if rec := env.do(t, http.MethodPost, "/recover", map[string]any{"email": "otp-guess@example.com"}, ""); rec.Code != http.StatusOK {
		t.Fatalf("/recover = %d", rec.Code)
	}
	otp := env.mails.to("otp-guess@example.com")[0].otp(t)
	verify := func(token string) int {
		return env.do(t, http.MethodPost, "/verify", map[string]any{
			"type": mailRecovery, "email": "otp-guess@example.com", "token": token}, "").Code
	}
	for i := 0; i < attemptLimits[attemptOTP]; i++ {
		if code := verify("000000"); code != http.StatusForbidden {
			t.Fatalf("wrong OTP %d = %d, want 403", i, code)
		}
	}
	if code := verify(otp); code != http.StatusTooManyRequests {
		t.Fatalf("right OTP after %d failures = %d, want 429", attemptLimits[attemptOTP], code)
	}
}

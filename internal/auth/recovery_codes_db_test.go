package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// recoveryCodesConfig enables recovery codes with the smallest valid set, so
// the argon2id hashing (about 20 MiB and two passes per code) stays cheap.
func recoveryCodesConfig() *Config {
	cfg := testConfig()
	cfg.MFA.RecoveryCodes.EnrollEnabled = true
	cfg.MFA.RecoveryCodes.VerifyEnabled = true
	cfg.MFA.RecoveryCodes.Count = 4
	cfg.MFA.RecoveryCodes.CodeLength = 16
	cfg.MFA.RecoveryCodes.MaxVerifyAttempts = 3
	cfg.MFA.RecoveryCodes.LockoutDuration = time.Minute
	return cfg
}

// aal2User signs a user up, enrolls and verifies a TOTP factor and returns the
// aal2 session and the factor.
func (e *mfaEnv) aal2User(t *testing.T, email string) (AccessTokenResponse, EnrollFactorResponse) {
	t.Helper()
	session := e.signupUser(t, email)
	f := e.enroll(t, session.Token, "Authenticator")
	ch := e.challenge(t, session.Token, f.ID)
	e.clock.advance(2 * time.Second)
	rec := e.do(t, http.MethodPost, "/factors/"+f.ID+"/verify",
		map[string]any{"challenge_id": ch.ID, "code": e.totpCode(t, f.TOTP.Secret)}, session.Token)
	upgraded := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if got := e.aal(t, upgraded.Token); got != AAL2 {
		t.Fatalf("setup aal = %q, want aal2", got)
	}
	return upgraded, f
}

// passwordSession is a fresh aal1 sign-in.
func (e *mfaEnv) passwordSession(t *testing.T, email string) AccessTokenResponse {
	t.Helper()
	e.clock.advance(time.Second)
	return decodeInto[AccessTokenResponse](t, e.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"email": email, "password": "correct-horse-battery"}, ""), http.StatusOK)
}

func (e *mfaEnv) generateRecoveryCodes(t *testing.T, token string) RecoveryCodesResponse {
	t.Helper()
	return decodeInto[RecoveryCodesResponse](t,
		e.do(t, http.MethodPost, "/factors/recovery-codes", nil, token), http.StatusOK)
}

func (e *mfaEnv) verifyRecoveryCode(t *testing.T, token, code string) *httptest.ResponseRecorder {
	t.Helper()
	return e.do(t, http.MethodPost, "/factors/recovery-codes/verify", map[string]any{"code": code}, token)
}

func wantErrorCode(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if body := decodeInto[errorBody](t, rec, status); body.ErrorCode != code {
		t.Fatalf("error_code = %q, want %q (msg %q)", body.ErrorCode, code, body.Msg)
	}
}

// dashed is how a client would show a code: upper case, in groups of four.
func dashed(code string) string {
	var b strings.Builder
	for i, r := range strings.ToUpper(code) {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func TestRecoveryCodesLifecycle(t *testing.T) {
	env := newMFAEnv(t, recoveryCodesConfig())
	const email = "recovery-life@dilion.test"

	// aal1 with no factor at all: generating needs aal2 first.
	aal1 := env.signupUser(t, "recovery-aal1@dilion.test")
	wantErrorCode(t, env.do(t, http.MethodPost, "/factors/recovery-codes", nil, aal1.Token),
		http.StatusForbidden, ErrorCodeInsufficientAAL)

	session, _ := env.aal2User(t, email)

	wantErrorCode(t, env.do(t, http.MethodGet, "/factors/recovery-codes", nil, session.Token),
		http.StatusNotFound, ErrorCodeMFAFactorNotFound)

	gen := env.generateRecoveryCodes(t, session.Token)
	if gen.Type != FactorTypeRecoveryCode || gen.FriendlyName != DefaultRecoveryCodeFriendlyName ||
		gen.Total != 4 || len(gen.Codes) != 4 || gen.Remaining != nil {
		t.Fatalf("generate = %+v", gen)
	}
	seen := map[string]bool{}
	for _, c := range gen.Codes {
		if len(c) != 16 || strings.Trim(c, recoveryCodeAlphabet) != "" || seen[c] {
			t.Fatalf("code %q is not a distinct 16-character canonical code", c)
		}
		seen[c] = true
	}

	// The factor shows on the user, verified; the plaintexts are not stored.
	var status, factorType string
	if err := env.pool.QueryRow(context.Background(),
		`select status::text, factor_type::text from auth.mfa_factors where id = $1::uuid`, gen.ID).
		Scan(&status, &factorType); err != nil {
		t.Fatalf("read factor: %v", err)
	}
	if status != FactorStateVerified || factorType != FactorTypeRecoveryCode {
		t.Fatalf("factor = %s/%s, want verified/recovery_code", status, factorType)
	}
	var plain int
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from auth.mfa_recovery_codes where code_hash = any($1)`, gen.Codes).Scan(&plain); err != nil {
		t.Fatal(err)
	}
	if plain != 0 {
		t.Fatal("a recovery code is stored in plaintext")
	}

	wantErrorCode(t, env.do(t, http.MethodPost, "/factors/recovery-codes", nil, session.Token),
		http.StatusUnprocessableEntity, ErrorCodeMFAVerifiedFactorExists)

	st := decodeInto[RecoveryCodesResponse](t, env.do(t, http.MethodGet, "/factors/recovery-codes", nil, session.Token), http.StatusOK)
	if st.ID != gen.ID || st.Total != 4 || st.Remaining == nil || *st.Remaining != 4 || len(st.Codes) != 0 {
		t.Fatalf("status = %+v", st)
	}

	// A new password session redeems a code, typed with separators and in
	// upper case, and comes out aal2 on the SAME session.
	fresh := env.passwordSession(t, email)
	if got := env.aal(t, fresh.Token); got != AAL1 {
		t.Fatalf("password session aal = %q", got)
	}
	upgraded := decodeInto[AccessTokenResponse](t, env.verifyRecoveryCode(t, fresh.Token, " "+dashed(gen.Codes[1])+" "), http.StatusOK)
	if got := env.aal(t, upgraded.Token); got != AAL2 {
		t.Fatalf("post-verify aal = %q, want aal2", got)
	}
	if got := env.amrMethods(t, upgraded.Token); len(got) == 0 || got[0] != AMRMethodMFARecoveryCode {
		t.Fatalf("post-verify amr = %v, want mfa/recovery_code first", got)
	}
	if env.claims(t, upgraded.Token).Extra["session_id"] != env.claims(t, fresh.Token).Extra["session_id"] {
		t.Fatal("verify must upgrade the current session")
	}
	if upgraded.RefreshToken == fresh.RefreshToken {
		t.Fatal("verify must issue a new refresh token")
	}

	// Single use.
	other := env.passwordSession(t, email)
	wantErrorCode(t, env.verifyRecoveryCode(t, other.Token, gen.Codes[1]),
		http.StatusUnprocessableEntity, ErrorCodeMFAVerificationFailed)
	st = decodeInto[RecoveryCodesResponse](t, env.do(t, http.MethodGet, "/factors/recovery-codes", nil, upgraded.Token), http.StatusOK)
	if *st.Remaining != 3 {
		t.Fatalf("remaining = %d, want 3", *st.Remaining)
	}

	// Regenerate needs aal2, replaces every code and keeps the factor.
	wantErrorCode(t, env.do(t, http.MethodPost, "/factors/recovery-codes/regenerate", nil, other.Token),
		http.StatusForbidden, ErrorCodeInsufficientAAL)
	regen := decodeInto[RecoveryCodesResponse](t,
		env.do(t, http.MethodPost, "/factors/recovery-codes/regenerate", nil, upgraded.Token), http.StatusOK)
	if regen.ID != gen.ID || len(regen.Codes) != 4 {
		t.Fatalf("regenerate = %+v", regen)
	}
	wantErrorCode(t, env.verifyRecoveryCode(t, other.Token, gen.Codes[0]),
		http.StatusUnprocessableEntity, ErrorCodeMFAVerificationFailed)

	// Delete needs aal2, removes the factor and downgrades the sessions the
	// codes raised: the session a code upgraded refreshes to aal1.
	wantErrorCode(t, env.do(t, http.MethodDelete, "/factors/recovery-codes", nil, other.Token),
		http.StatusForbidden, ErrorCodeInsufficientAAL)
	del := decodeInto[UnenrollFactorResponse](t, env.do(t, http.MethodDelete, "/factors/recovery-codes", nil, upgraded.Token), http.StatusOK)
	if del.ID != gen.ID {
		t.Fatalf("delete id = %q, want %q", del.ID, gen.ID)
	}
	refreshed := env.refresh(t, upgraded.RefreshToken)
	if got := env.aal(t, refreshed.Token); got != AAL1 {
		t.Fatalf("aal after deleting the codes = %q, want aal1", got)
	}
	wantErrorCode(t, env.do(t, http.MethodGet, "/factors/recovery-codes", nil, session.Token),
		http.StatusNotFound, ErrorCodeMFAFactorNotFound)
	var sets int
	if err := env.pool.QueryRow(context.Background(), `select count(*) from auth.mfa_recovery_code_sets`).Scan(&sets); err != nil {
		t.Fatal(err)
	}
	if sets != 0 {
		t.Fatalf("recovery code sets left = %d, want 0", sets)
	}
}

func TestRecoveryCodesLockout(t *testing.T) {
	env := newMFAEnv(t, recoveryCodesConfig())
	const email = "recovery-lock@dilion.test"
	session, _ := env.aal2User(t, email)
	gen := env.generateRecoveryCodes(t, session.Token)
	fresh := env.passwordSession(t, email)

	// MaxVerifyAttempts = 3 wrong codes in a row lock verification; the
	// third failure is still a 422, everything after it a 429 — the right
	// code included.
	for i := 0; i < 3; i++ {
		wantErrorCode(t, env.verifyRecoveryCode(t, fresh.Token, "wrongwrongwrong0"),
			http.StatusUnprocessableEntity, ErrorCodeMFAVerificationFailed)
	}
	wantErrorCode(t, env.verifyRecoveryCode(t, fresh.Token, gen.Codes[0]),
		http.StatusTooManyRequests, ErrorCodeMFARecoveryCodesLocked)

	// The lock lapses after LockoutDuration, and the count starts afresh.
	env.clock.advance(time.Minute + time.Second)
	wantErrorCode(t, env.verifyRecoveryCode(t, fresh.Token, "wrongwrongwrong0"),
		http.StatusUnprocessableEntity, ErrorCodeMFAVerificationFailed)
	decodeInto[AccessTokenResponse](t, env.verifyRecoveryCode(t, fresh.Token, gen.Codes[0]), http.StatusOK)

	var failures int
	if err := env.pool.QueryRow(context.Background(),
		`select failed_verification_count from auth.mfa_recovery_code_sets`).Scan(&failures); err != nil {
		t.Fatal(err)
	}
	if failures != 0 {
		t.Fatalf("failed_verification_count after a success = %d, want 0", failures)
	}

	// Regenerating from an aal2 session clears an active lock.
	locked := env.passwordSession(t, email)
	for i := 0; i < 3; i++ {
		env.verifyRecoveryCode(t, locked.Token, "wrongwrongwrong0")
	}
	wantErrorCode(t, env.verifyRecoveryCode(t, locked.Token, gen.Codes[1]),
		http.StatusTooManyRequests, ErrorCodeMFARecoveryCodesLocked)
	regen := decodeInto[RecoveryCodesResponse](t,
		env.do(t, http.MethodPost, "/factors/recovery-codes/regenerate", nil, session.Token), http.StatusOK)
	decodeInto[AccessTokenResponse](t, env.verifyRecoveryCode(t, locked.Token, regen.Codes[0]), http.StatusOK)
}

// Recovery codes are never a user's only second factor.
func TestRecoveryCodesSoleFactorGuards(t *testing.T) {
	env := newMFAEnv(t, recoveryCodesConfig())
	session, totpFactor := env.aal2User(t, "recovery-sole@dilion.test")
	gen := env.generateRecoveryCodes(t, session.Token)

	// The codes have their own delete endpoint.
	wantErrorCode(t, env.do(t, http.MethodDelete, "/factors/"+gen.ID, nil, session.Token),
		http.StatusUnprocessableEntity, ErrorCodeValidationFailed)

	// The only TOTP factor cannot go while the codes exist...
	wantErrorCode(t, env.do(t, http.MethodDelete, "/factors/"+totpFactor.ID, nil, session.Token),
		http.StatusUnprocessableEntity, ErrorCodeMFARecoveryCodesSoleFactor)

	// ...but can once another usable factor is verified.
	second := env.enroll(t, session.Token, "Second")
	ch := env.challenge(t, session.Token, second.ID)
	env.clock.advance(2 * time.Second)
	session = decodeInto[AccessTokenResponse](t, env.do(t, http.MethodPost, "/factors/"+second.ID+"/verify",
		map[string]any{"challenge_id": ch.ID, "code": env.totpCode(t, second.TOTP.Secret)}, session.Token), http.StatusOK)
	if rec := env.do(t, http.MethodDelete, "/factors/"+totpFactor.ID, nil, session.Token); rec.Code != http.StatusOK {
		t.Fatalf("unenroll with another factor left: status %d, body %s", rec.Code, rec.Body.String())
	}

	// A factor that is unverified is not protecting anything and may go.
	third := env.enroll(t, session.Token, "Third")
	if rec := env.do(t, http.MethodDelete, "/factors/"+third.ID, nil, session.Token); rec.Code != http.StatusOK {
		t.Fatalf("unenroll unverified factor: status %d, body %s", rec.Code, rec.Body.String())
	}

	// After the codes are deleted the last TOTP factor may go too.
	decodeInto[UnenrollFactorResponse](t, env.do(t, http.MethodDelete, "/factors/recovery-codes", nil, session.Token), http.StatusOK)
	if rec := env.do(t, http.MethodDelete, "/factors/"+second.ID, nil, session.Token); rec.Code != http.StatusOK {
		t.Fatalf("unenroll last factor without codes: status %d, body %s", rec.Code, rec.Body.String())
	}
}

// A user whose only verified factor's type has verification switched off has
// no usable second factor, so codes cannot be generated.
func TestRecoveryCodesNeedAUsableFactor(t *testing.T) {
	cfg := recoveryCodesConfig()
	env := newMFAEnv(t, cfg)
	session, _ := env.aal2User(t, "recovery-usable@dilion.test")
	cfg.MFA.TOTP.VerifyEnabled = false
	wantErrorCode(t, env.do(t, http.MethodPost, "/factors/recovery-codes", nil, session.Token),
		http.StatusUnprocessableEntity, ErrorCodeMFARecoveryCodesSoleFactor)
}

func TestRecoveryCodesDisabled(t *testing.T) {
	cfg := recoveryCodesConfig()
	env := newMFAEnv(t, cfg)
	const email = "recovery-off@dilion.test"
	session, _ := env.aal2User(t, email)
	gen := env.generateRecoveryCodes(t, session.Token)

	cfg.MFA.RecoveryCodes.EnrollEnabled = false
	cfg.MFA.RecoveryCodes.VerifyEnabled = false
	wantErrorCode(t, env.do(t, http.MethodPost, "/factors/recovery-codes/regenerate", nil, session.Token),
		http.StatusUnprocessableEntity, ErrorCodeMFARecoveryCodesEnrollDisabled)
	wantErrorCode(t, env.verifyRecoveryCode(t, env.passwordSession(t, email).Token, gen.Codes[0]),
		http.StatusUnprocessableEntity, ErrorCodeMFARecoveryCodesVerifyDisabled)

	// Status and delete work whatever the flags say.
	decodeInto[RecoveryCodesResponse](t, env.do(t, http.MethodGet, "/factors/recovery-codes", nil, session.Token), http.StatusOK)
	decodeInto[UnenrollFactorResponse](t, env.do(t, http.MethodDelete, "/factors/recovery-codes", nil, session.Token), http.StatusOK)
	wantErrorCode(t, env.do(t, http.MethodPost, "/factors/recovery-codes", nil, session.Token),
		http.StatusUnprocessableEntity, ErrorCodeMFARecoveryCodesEnrollDisabled)
}

package auth

// GOTRUE_SESSIONS_SINGLE_PER_USER, end to end.
//
// The flag's real semantics are refresh-time, not creation-time: see
// grant.go checkSinglePerUser for the upstream reading these tests encode.
// Signing in again is always allowed and always creates a second session; the
// older session is only rejected when it next tries to REFRESH, and nothing is
// deleted or revoked when that happens.

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func singlePerUserConfig(on bool) *Config {
	cfg := testConfig()
	cfg.Sessions.SinglePerUser = on
	return cfg
}

// twoSessions signs a user up (session 1) and then signs the same credentials
// in again a clock-step later (session 2), returning both envelopes.
func twoSessions(t *testing.T, env *mfaEnv, email string) (older, newer AccessTokenResponse) {
	t.Helper()
	older = env.signupUser(t, email)

	env.clock.advance(30 * time.Second)
	rec := env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"email": email, "password": "correct-horse-battery"}, "")
	newer = decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	if older.RefreshToken == newer.RefreshToken {
		t.Fatal("the second sign-in must mint a distinct session")
	}
	return older, newer
}

func sessionCount(t *testing.T, env *mfaEnv, userID string) int {
	t.Helper()
	var n int
	if err := env.pool.QueryRow(t.Context(),
		`select count(*) from auth.sessions where user_id = $1::uuid`, userID).Scan(&n); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	return n
}

// TestSinglePerUserRejectsTheOlderSessionsRefresh is the flag's whole effect:
// with it on, the session that lost the race can no longer refresh, while the
// winner refreshes normally.
func TestSinglePerUserRejectsTheOlderSessionsRefresh(t *testing.T) {
	env := newMFAEnv(t, singlePerUserConfig(true))
	older, newer := twoSessions(t, env, "single-per-user@dilion.test")
	userID := env.claims(t, newer.Token).Subject

	// Creating the second session did NOT touch the first: upstream deletes
	// nothing here, and neither do we.
	if got := sessionCount(t, env, userID); got != 2 {
		t.Fatalf("session count after the second sign-in = %d, want 2 (nothing is terminated at creation)", got)
	}

	env.clock.advance(10 * time.Second)
	rec := env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": older.RefreshToken}, "")
	body := decodeInto[errorBody](t, rec, http.StatusBadRequest)
	if body.ErrorCode != ErrorCodeSessionExpired {
		t.Fatalf("error_code = %q, want %q (body %s)", body.ErrorCode, ErrorCodeSessionExpired, rec.Body.String())
	}
	if body.Msg != "Invalid Refresh Token: Session Expired (Revoked by Newer Login)" {
		t.Errorf("msg = %q, want upstream's \"(Revoked by Newer Login)\" wording", body.Msg)
	}

	// The rejection is a verdict, not a reaping: unlike the timebox/inactivity
	// paths, upstream destroys nothing, so both rows survive.
	if got := sessionCount(t, env, userID); got != 2 {
		t.Errorf("session count after the rejection = %d, want 2 (nothing is destroyed)", got)
	}

	// The winner is unaffected.
	refreshed := env.refresh(t, newer.RefreshToken)
	if refreshed.RefreshToken == newer.RefreshToken {
		t.Error("the newest session must still rotate normally")
	}
}

// TestSinglePerUserOffKeepsEverySessionRefreshable is the default deployment:
// the check must be a complete no-op, which is what keeps every other test in
// this package green.
func TestSinglePerUserOffKeepsEverySessionRefreshable(t *testing.T) {
	env := newMFAEnv(t, singlePerUserConfig(false))
	older, newer := twoSessions(t, env, "multi-session@dilion.test")

	env.clock.advance(10 * time.Second)
	if got := env.refresh(t, older.RefreshToken); got.RefreshToken == older.RefreshToken {
		t.Error("the older session must rotate normally while the flag is off")
	}
	if got := env.refresh(t, newer.RefreshToken); got.RefreshToken == newer.RefreshToken {
		t.Error("the newer session must rotate normally while the flag is off")
	}
}

// TestSinglePerUserAllowsTheNewestSessionToKeepRefreshing: the comparison is on
// LAST REFRESH, not on creation, so a session that has refreshed most recently
// keeps winning even after several rounds — and, once the loser is out, the
// winner never locks itself out by refreshing again.
func TestSinglePerUserAllowsTheNewestSessionToKeepRefreshing(t *testing.T) {
	env := newMFAEnv(t, singlePerUserConfig(true))
	_, newer := twoSessions(t, env, "single-per-user-rounds@dilion.test")

	token := newer.RefreshToken
	for i := 0; i < 3; i++ {
		env.clock.advance(10 * time.Second)
		next := env.refresh(t, token)
		if next.RefreshToken == token {
			t.Fatalf("round %d: refresh did not rotate", i)
		}
		token = next.RefreshToken
	}
}

// TestSinglePerUserIgnoresExpiredCompetitors: upstream skips any session that
// fails CheckValidity before comparing timestamps, so a newer session that has
// already timed out cannot lock an older, still-live one out.
func TestSinglePerUserIgnoresExpiredCompetitors(t *testing.T) {
	cfg := singlePerUserConfig(true)
	cfg.Sessions.Timebox = time.Minute
	env := newMFAEnv(t, cfg)

	older, _ := twoSessions(t, env, "single-per-user-expired@dilion.test")

	// Past the timebox both sessions are invalid; the older one is destroyed by
	// its own validity check (checkSessionValidity), which runs after this one
	// — so what we assert is the ERROR, not the mechanism: it must be the
	// plain expiry, never "(Revoked by Newer Login)".
	env.clock.advance(2 * time.Minute)
	rec := env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": older.RefreshToken}, "")
	body := decodeInto[errorBody](t, rec, http.StatusBadRequest)
	if body.ErrorCode != ErrorCodeSessionExpired {
		t.Fatalf("error_code = %q, want %q", body.ErrorCode, ErrorCodeSessionExpired)
	}
	if body.Msg != "Invalid Refresh Token: Session Expired" {
		t.Errorf("msg = %q, want the plain timebox expiry (an invalid competitor must be skipped)", body.Msg)
	}
}

// ---- AccessTokenResponse.id_token ------------------------------------------

// TestSessionGrantsNeverEmitIDToken is the runtime half of item C3.
//
// Upstream shares ONE AccessTokenResponse between the session envelope and the
// OAuth-server token endpoint, but the field's only assignment in the whole
// tree is internal/api/oauthserver/handlers.go:461 — the authorization_code
// grant with the `openid` scope — and that handler re-projects into a map
// rather than serializing the struct. So no upstream SESSION body has ever
// carried the key, and none of ours may either. (The OAuth-server endpoint's
// own id_token lives on OAuthTokenResponse and is covered by
// oauthserver_db_test.go, which this change does not touch.)
func TestSessionGrantsNeverEmitIDToken(t *testing.T) {
	env := newMFAEnv(t, nil)
	const email = "id-token-absent@dilion.test"

	signup := env.do(t, http.MethodPost, "/signup",
		map[string]any{"email": email, "password": "correct-horse-battery"}, "")
	if signup.Code != http.StatusOK {
		t.Fatalf("signup status = %d: %s", signup.Code, signup.Body.String())
	}
	session := decodeInto[AccessTokenResponse](t, signup, http.StatusOK)

	env.clock.advance(time.Second)
	password := env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"email": email, "password": "correct-horse-battery"}, "")
	if password.Code != http.StatusOK {
		t.Fatalf("password grant status = %d: %s", password.Code, password.Body.String())
	}

	env.clock.advance(time.Second)
	refresh := env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": session.RefreshToken}, "")
	if refresh.Code != http.StatusOK {
		t.Fatalf("refresh grant status = %d: %s", refresh.Code, refresh.Body.String())
	}

	for name, rec := range map[string]string{
		"signup":        signup.Body.String(),
		"password":      password.Body.String(),
		"refresh_token": refresh.Body.String(),
	} {
		var body map[string]any
		if err := json.Unmarshal([]byte(rec), &body); err != nil {
			t.Fatalf("%s: unmarshal %s: %v", name, rec, err)
		}
		if _, ok := body["id_token"]; ok {
			t.Errorf("%s session envelope must not carry id_token: %s", name, rec)
		}
	}
}

package auth

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// A revoked token presented inside Security.RefreshTokenReuseInterval is a
// client that lost the response of its last refresh: it gets the session's
// CURRENT token back, nothing is revoked and the session survives.
func TestRefreshReuseWithinIntervalReturnsActiveToken(t *testing.T) {
	cfg := testConfig()
	cfg.Security.RefreshTokenReuseInterval = 60
	env := newTestEnvWithConfig(t, cfg)

	first := env.signup(t, "reuse-ok@example.com", "hunter22")

	rec := env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": first.RefreshToken}, "")
	second := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	// Re-present the revoked token: tolerated.
	rec = env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": first.RefreshToken}, "")
	again := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	if again.RefreshToken != second.RefreshToken {
		t.Errorf("refresh_token = %q, want the session's active token %q", again.RefreshToken, second.RefreshToken)
	}
	if again.User.ID != first.User.ID {
		t.Errorf("user = %s, want %s", again.User.ID, first.User.ID)
	}

	// No new token was minted and the family is intact.
	var live int64
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from auth.refresh_tokens where user_id = $1 and revoked is not true`,
		first.User.ID).Scan(&live); err != nil {
		t.Fatalf("count live tokens: %v", err)
	}
	if live != 1 {
		t.Errorf("%d live refresh tokens, want exactly 1", live)
	}

	// The active token still works.
	rec = env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": second.RefreshToken}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("the active token stopped working: %d %s", rec.Code, rec.Body.String())
	}
}

// Beyond the window the same reuse is abuse: family revoked, session destroyed.
func TestRefreshReuseBeyondIntervalIsPunished(t *testing.T) {
	cfg := testConfig()
	cfg.Security.RefreshTokenReuseInterval = 1
	env := newTestEnvWithConfig(t, cfg)

	first := env.signup(t, "reuse-bad@example.com", "hunter22")
	rec := env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": first.RefreshToken}, "")
	_ = decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	// Age the revoked token past the 1s window.
	if _, err := env.pool.Exec(context.Background(),
		`update auth.refresh_tokens set updated_at = now() - interval '1 hour' where token = $1`,
		first.RefreshToken); err != nil {
		t.Fatalf("age token: %v", err)
	}

	rec = env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": first.RefreshToken}, "")
	e := decodeInto[HTTPError](t, rec, http.StatusBadRequest)
	if e.ErrorCode != ErrorCodeRefreshTokenAlreadyUsed {
		t.Errorf("error_code = %q, want %q", e.ErrorCode, ErrorCodeRefreshTokenAlreadyUsed)
	}

	var live, sessions int64
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from auth.refresh_tokens where user_id = $1 and revoked is not true`,
		first.User.ID).Scan(&live); err != nil {
		t.Fatalf("count live tokens: %v", err)
	}
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from auth.sessions where user_id = $1::uuid`, first.User.ID).Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if live != 0 || sessions != 0 {
		t.Errorf("after punishment: %d live tokens, %d sessions; want 0/0", live, sessions)
	}
}

func TestAnonymousSignup(t *testing.T) {
	// Disabled by default: upstream's 422.
	env := newTestEnv(t)
	rec := env.do(t, http.MethodPost, "/signup", map[string]any{}, "")
	e := decodeInto[HTTPError](t, rec, http.StatusUnprocessableEntity)
	if e.ErrorCode != ErrorCodeAnonymousProviderDisabled || e.Message != "Anonymous sign-ins are disabled" {
		t.Errorf("body = %+v", e)
	}

	cfg := testConfig()
	cfg.AnonymousUsersEnabled = true
	env = newTestEnvWithConfig(t, cfg)

	rec = env.do(t, http.MethodPost, "/signup", map[string]any{"data": map[string]any{"guest": true}}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	if !session.User.IsAnonymous {
		t.Error("is_anonymous = false, want true")
	}
	if session.User.Email != "" || session.RefreshToken == "" || session.Token == "" {
		t.Errorf("session = %+v", session)
	}
	if session.User.AppMetaData["provider"] != ProviderAnonymous {
		t.Errorf("app_metadata = %+v", session.User.AppMetaData)
	}
	if session.User.UserMetaData["guest"] != true {
		t.Errorf("user_metadata = %+v", session.User.UserMetaData)
	}

	// The access token carries the is_anonymous claim.
	claims, err := env.tokens.Verify(context.Background(), session.Token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Extra["is_anonymous"] != true {
		t.Errorf("is_anonymous claim = %v", claims.Extra["is_anonymous"])
	}

	// The session is usable.
	rec = env.do(t, http.MethodGet, "/user", nil, session.Token)
	user := decodeInto[User](t, rec, http.StatusOK)
	if user.ID != session.User.ID || !user.IsAnonymous {
		t.Errorf("user = %+v", user)
	}

	// Signups disabled wins over the anonymous path.
	cfg = testConfig()
	cfg.AnonymousUsersEnabled = true
	cfg.DisableSignup = true
	env = newTestEnvWithConfig(t, cfg)
	rec = env.do(t, http.MethodPost, "/signup", map[string]any{}, "")
	e = decodeInto[HTTPError](t, rec, http.StatusUnprocessableEntity)
	if e.ErrorCode != ErrorCodeSignupDisabled {
		t.Errorf("error_code = %q, want signup_disabled", e.ErrorCode)
	}
}

func TestDisableSignup(t *testing.T) {
	cfg := testConfig()
	cfg.DisableSignup = true
	env := newTestEnvWithConfig(t, cfg)

	rec := env.do(t, http.MethodPost, "/signup",
		map[string]any{"email": "nope@example.com", "password": "hunter22"}, "")
	e := decodeInto[HTTPError](t, rec, http.StatusUnprocessableEntity)
	if e.ErrorCode != ErrorCodeSignupDisabled || e.Message != "Signups not allowed for this instance" {
		t.Errorf("body = %+v", e)
	}
}

func TestSessionTimeboxOnRefresh(t *testing.T) {
	cfg := testConfig()
	cfg.Sessions.Timebox = time.Hour
	env := newTestEnvWithConfig(t, cfg)

	session := env.signup(t, "timebox@example.com", "hunter22")

	// Refreshing right away is fine.
	rec := env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": session.RefreshToken}, "")
	next := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	// Age the session past its timebox.
	if _, err := env.pool.Exec(context.Background(),
		`update auth.sessions set created_at = now() - interval '2 hours' where user_id = $1::uuid`,
		session.User.ID); err != nil {
		t.Fatalf("age session: %v", err)
	}

	rec = env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": next.RefreshToken}, "")
	e := decodeInto[HTTPError](t, rec, http.StatusBadRequest)
	if e.ErrorCode != ErrorCodeSessionExpired || e.Message != "Invalid Refresh Token: Session Expired" {
		t.Errorf("body = %+v", e)
	}

	var sessions int64
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from auth.sessions where user_id = $1::uuid`, session.User.ID).Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 0 {
		t.Errorf("%d sessions survived the timebox, want 0", sessions)
	}
}

func TestSessionInactivityTimeoutOnRefresh(t *testing.T) {
	cfg := testConfig()
	cfg.Sessions.InactivityTimeout = 10 * time.Minute
	env := newTestEnvWithConfig(t, cfg)

	session := env.signup(t, "inactive@example.com", "hunter22")

	// A refresh bumps sessions.refreshed_at.
	rec := env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": session.RefreshToken}, "")
	next := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	var refreshedAt, createdAt time.Time
	if err := env.pool.QueryRow(context.Background(),
		`select refreshed_at, created_at from auth.sessions where user_id = $1::uuid`,
		session.User.ID).Scan(&refreshedAt, &createdAt); err != nil {
		t.Fatalf("read session: %v", err)
	}
	if !refreshedAt.After(createdAt) {
		t.Errorf("refreshed_at (%v) was not bumped past created_at (%v)", refreshedAt, createdAt)
	}

	// Idle for longer than the timeout: both the session row and the presented
	// token must look stale, since the later of the two decides.
	if _, err := env.pool.Exec(context.Background(),
		`update auth.sessions set refreshed_at = now() - interval '1 hour',
		                          created_at = now() - interval '1 hour'
		 where user_id = $1::uuid`, session.User.ID); err != nil {
		t.Fatalf("age session: %v", err)
	}
	if _, err := env.pool.Exec(context.Background(),
		`update auth.refresh_tokens set updated_at = now() - interval '1 hour' where user_id = $1`,
		session.User.ID); err != nil {
		t.Fatalf("age tokens: %v", err)
	}

	rec = env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": next.RefreshToken}, "")
	e := decodeInto[HTTPError](t, rec, http.StatusBadRequest)
	if e.ErrorCode != ErrorCodeSessionExpired || e.Message != "Invalid Refresh Token: Session Expired (Inactivity)" {
		t.Errorf("body = %+v", e)
	}

	var sessions int64
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from auth.sessions where user_id = $1::uuid`, session.User.ID).Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 0 {
		t.Errorf("%d sessions survived the inactivity timeout, want 0", sessions)
	}
}

func TestCleanupDeletesExpiredRows(t *testing.T) {
	cfg := testConfig()
	env := newTestEnvWithConfig(t, cfg)
	a := newAPI(Deps{Pool: env.pool, Tokens: env.tokens, Config: cfg})

	keep := env.signup(t, "keep@example.com", "hunter22")
	stale := env.signup(t, "stale@example.com", "hunter22")

	ctx := context.Background()
	// A refresh token revoked longer ago than the retention window.
	if _, err := env.pool.Exec(ctx,
		`update auth.refresh_tokens set revoked = true, updated_at = now() - interval '60 days'
		 where token = $1`, stale.RefreshToken); err != nil {
		t.Fatalf("age token: %v", err)
	}
	// A session past its absolute expiry.
	if _, err := env.pool.Exec(ctx,
		`update auth.sessions set not_after = now() - interval '1 minute' where user_id = $1::uuid`,
		stale.User.ID); err != nil {
		t.Fatalf("expire session: %v", err)
	}

	n, err := a.cleanupOnce(ctx)
	if err != nil {
		t.Fatalf("cleanupOnce: %v", err)
	}
	if n < 2 {
		t.Errorf("cleanup removed %d rows, want at least 2", n)
	}

	var staleTokens, staleSessions int64
	if err := env.pool.QueryRow(ctx,
		`select count(*) from auth.refresh_tokens where token = $1`, stale.RefreshToken).Scan(&staleTokens); err != nil {
		t.Fatalf("count: %v", err)
	}
	if err := env.pool.QueryRow(ctx,
		`select count(*) from auth.sessions where user_id = $1::uuid`, stale.User.ID).Scan(&staleSessions); err != nil {
		t.Fatalf("count: %v", err)
	}
	if staleTokens != 0 || staleSessions != 0 {
		t.Errorf("expired rows survived: %d tokens, %d sessions", staleTokens, staleSessions)
	}

	// The healthy session is untouched.
	rec := env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": keep.RefreshToken}, "")
	if rec.Code != http.StatusOK {
		t.Errorf("cleanup broke a live session: %d %s", rec.Code, rec.Body.String())
	}

	// RunCleanup honours CleanupEnabled=false by returning immediately.
	off := testConfig()
	off.CleanupEnabled = false
	done := make(chan struct{})
	go func() {
		newAPI(Deps{Pool: env.pool, Tokens: env.tokens, Config: off}).RunCleanup(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("RunCleanup did not return with cleanup disabled")
	}
}

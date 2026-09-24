package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/internal/hooks"
	"github.com/dilion-io/dilion/ports"
)

// These tests need a real Postgres and only run when DILION_TEST_DB is set:
//
//	docker exec dilion-pg createdb -U dilion dilion_test_b
//	DILION_TEST_DB=postgres://dilion:dilion@localhost:55432/dilion_test_b \
//	  go test ./internal/auth/...
const defaultTestDSN = "postgres://dilion:dilion@localhost:55432/dilion_test_b"

type testEnv struct {
	pool   *pgxpool.Pool
	router chi.Router
	tokens *TokenService
	hooks  *hooks.Registry
	mailer *captureMailer
}

type captureMailer struct {
	sent []string
}

func (m *captureMailer) Send(_ context.Context, to, subject, _, _ string) error {
	m.sent = append(m.sent, to+"|"+subject)
	return nil
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	return newTestEnvWithConfig(t, nil)
}

// testConfig is DefaultConfig with sign-ups confirmed at once, which is what
// most tests want: a session straight from /signup. Tests of confirmation
// mail turn it back off.
func testConfig() *Config {
	cfg := DefaultConfig()
	cfg.Mailer.Autoconfirm = true
	return cfg
}

// newTestEnvWithConfig is newTestEnv with an explicit /auth/v1 configuration.
// nil means testConfig().
func newTestEnvWithConfig(t *testing.T, cfg *Config) *testEnv {
	t.Helper()

	if cfg == nil {
		cfg = testConfig()
	}
	dsn := os.Getenv("DILION_TEST_DB")
	if dsn == "" {
		t.Skip("DILION_TEST_DB not set; skipping database-backed tests")
	}
	if !strings.HasPrefix(dsn, "postgres") {
		dsn = defaultTestDSN
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect %s: %v", dsn, err)
	}
	t.Cleanup(pool.Close)

	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping %s: %v", dsn, err)
	}

	applySchema(t, pool)
	truncateAll(t, pool)

	env := &testEnv{
		pool:   pool,
		tokens: NewTokenServiceHS(testSecret()),
		hooks:  hooks.NewRegistry(),
		mailer: &captureMailer{},
	}
	env.router = chi.NewRouter()
	Register(env.router, Deps{
		Pool:   pool,
		Tokens: env.tokens,
		Mailer: env.mailer,
		Hooks:  env.hooks,
		Config: cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return env
}

// applySchema installs the WHOLE auth migration chain (0100 + 0110..0116) plus
// the prerequisites owned by other packages (0001_core's extensions/schemas and
// 0200's outbox table). Those prerequisites are created HERE ONLY — never in
// migrations/0100_auth.sql.
//
// The full chain matters: grantSession writes auth.mfa_amr_claims (0112) on
// every sign-in, so a harness that stops at 0100 only passes when some earlier
// test in the same run happened to create that table — a hidden ordering
// dependency that fails on a genuinely fresh database (as CI proved).
func applySchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if !firstApply("applySchema") {
		return
	}
	ctx := context.Background()

	const prereqs = `
		create extension if not exists pgcrypto;
		create schema if not exists auth;
		create schema if not exists dilion_privacy;
		create table if not exists dilion_privacy.outbox (
			id uuid primary key default gen_random_uuid(),
			event_type text not null,
			aggregate_id text not null,
			payload jsonb not null,
			created_at timestamptz not null default now(),
			published_at timestamptz
		);`
	if _, err := pool.Exec(ctx, prereqs); err != nil {
		t.Fatalf("create test prerequisites: %v", err)
	}

	// Every auth migration, in lexicographic order — the same order the real
	// runner (internal/store.Migrate) uses. All are idempotent.
	files, err := filepath.Glob(filepath.Join("..", "..", "migrations", "01*.sql"))
	if err != nil {
		t.Fatalf("glob auth migrations: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no auth migrations found")
	}
	sort.Strings(files)
	for _, path := range files {
		sql, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatalf("read %s: %v", path, rerr)
		}
		if _, eerr := pool.Exec(ctx, string(sql)); eerr != nil {
			t.Fatalf("apply %s: %v", filepath.Base(path), eerr)
		}
	}
}

func truncateAll(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	clearTables(t, pool, "auth.users", "auth.sessions", "auth.refresh_tokens", "auth.identities",
		"dilion_privacy.outbox", "dilion_auth.hooks", "dilion_auth.auth_attempts")
}

// appliedSchemas records the schema helpers that already ran in this test
// process. Every one of them is idempotent and every test uses the same
// database, so running each once is enough; running them per test cost more
// than most tests themselves.
var appliedSchemas sync.Map

// firstApply reports whether the schema helper name has not run yet in this
// process, and marks it as run.
func firstApply(name string) bool {
	_, done := appliedSchemas.LoadOrStore(name, true)
	return !done
}

// clearTables empties tables and every table that references them, directly
// or not — what TRUNCATE ... CASCADE empties — with DELETE. A test leaves a
// handful of rows behind, and TRUNCATE's fixed cost of swapping and syncing
// the files of some thirty tables was most of each database test's run time;
// deleting the rows takes milliseconds. Foreign keys are not checked while it
// runs (session_replication_role = replica, which needs a superuser, as the
// test database's owner is), so the order does not matter and no rows are
// left behind by a restricting key.
func clearTables(t *testing.T, pool *pgxpool.Pool, tables ...string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("clear tables: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `
		with recursive closure(oid) as (
			select unnest($1::text[])::regclass::oid
			union
			select c.conrelid from pg_constraint c join closure on c.confrelid = closure.oid
			where c.contype = 'f'
		)
		select oid::regclass::text from closure`, tables)
	if err != nil {
		t.Fatalf("clear tables: %v", err)
	}
	var all []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("clear tables: %v", err)
		}
		all = append(all, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("clear tables: %v", err)
	}
	if _, err := tx.Exec(ctx, `set local session_replication_role = replica`); err != nil {
		t.Fatalf("clear tables: %v", err)
	}
	for _, name := range all {
		if _, err := tx.Exec(ctx, `delete from `+name); err != nil {
			t.Fatalf("clear %s: %v", name, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("clear tables: %v", err)
	}
}

// ---- request helpers ------------------------------------------------------

func (e *testEnv) do(t *testing.T, method, path string, body any, bearer string) *httptest.ResponseRecorder {
	t.Helper()

	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.7:41234"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func decodeInto[T any](t *testing.T, rec *httptest.ResponseRecorder, want int) T {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, want, rec.Body.String())
	}
	var out T
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal %q: %v", rec.Body.String(), err)
	}
	return out
}

func (e *testEnv) serviceRoleToken(t *testing.T) string {
	t.Helper()
	token, err := e.tokens.Sign(context.Background(), ports.Claims{
		Subject: "00000000-0000-4000-8000-000000000001",
		Role:    RoleServiceRole,
		Email:   "admin@dilion.test",
	})
	if err != nil {
		t.Fatalf("sign service_role token: %v", err)
	}
	return token
}

func (e *testEnv) signup(t *testing.T, email, password string) AccessTokenResponse {
	t.Helper()
	rec := e.do(t, http.MethodPost, "/signup",
		map[string]any{"email": email, "password": password}, "")
	return decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
}

// ---- tests ----------------------------------------------------------------

func TestSignupReturnsGotrueSession(t *testing.T) {
	env := newTestEnv(t)

	rec := env.do(t, http.MethodPost, "/signup",
		map[string]any{"email": "Alice@Example.com", "password": "hunter22", "data": map[string]any{"name": "Alice"}}, "")

	// Assert on the raw body: the field names are the compatibility contract.
	var raw map[string]any
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"access_token", "token_type", "expires_in", "expires_at", "refresh_token", "user"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("session body is missing %q; got keys %v", k, keysOf(raw))
		}
	}
	if raw["token_type"] != "bearer" {
		t.Errorf("token_type = %v, want bearer", raw["token_type"])
	}
	if raw["expires_in"].(float64) != DefaultAccessTokenTTL.Seconds() {
		t.Errorf("expires_in = %v, want %v", raw["expires_in"], DefaultAccessTokenTTL.Seconds())
	}

	user := raw["user"].(map[string]any)
	for _, k := range []string{"id", "aud", "role", "email", "email_confirmed_at", "phone",
		"confirmed_at", "last_sign_in_at", "app_metadata", "user_metadata", "identities",
		"created_at", "updated_at", "is_anonymous"} {
		if _, ok := user[k]; !ok {
			t.Errorf("user object is missing %q; got keys %v", k, keysOf(user))
		}
	}
	if user["email"] != "alice@example.com" {
		t.Errorf("email = %v, want the lowercased address", user["email"])
	}
	if user["aud"] != AudienceAuthenticated || user["role"] != RoleAuthenticated {
		t.Errorf("aud/role = %v/%v", user["aud"], user["role"])
	}
	if user["is_anonymous"] != false {
		t.Errorf("is_anonymous = %v, want false", user["is_anonymous"])
	}

	// Wave 1: the account is confirmed and usable immediately.
	if user["email_confirmed_at"] == nil || user["confirmed_at"] == nil {
		t.Error("wave 1 signups must be auto-confirmed")
	}

	// Timestamps must be RFC 3339 UTC regardless of the server's time zone.
	for _, k := range []string{"created_at", "updated_at", "email_confirmed_at", "last_sign_in_at"} {
		v, _ := user[k].(string)
		if !strings.HasSuffix(v, "Z") {
			t.Errorf("%s = %q, want a UTC (…Z) timestamp", k, v)
		}
		if _, err := time.Parse(time.RFC3339, v); err != nil {
			t.Errorf("%s = %q is not RFC 3339: %v", k, v, err)
		}
	}

	ids := user["identities"].([]any)
	if len(ids) != 1 {
		t.Fatalf("identities = %v, want exactly one email identity", ids)
	}
	identity := ids[0].(map[string]any)
	if identity["provider"] != ProviderEmail {
		t.Errorf("identity provider = %v, want email", identity["provider"])
	}
	// gotrue-js expects the crossed id/identity_id tags.
	if identity["identity_id"] == nil || identity["id"] == nil {
		t.Errorf("identity is missing identity_id/id: %v", identity)
	}

	// The access token must carry the gotrue claim set.
	claims := decodeClaims(t, raw["access_token"].(string))
	for _, k := range []string{"sub", "aud", "exp", "iat", "role", "email", "session_id",
		"app_metadata", "user_metadata", "is_anonymous"} {
		if _, ok := claims[k]; !ok {
			t.Errorf("access token is missing claim %q; got %v", k, keysOf(claims))
		}
	}
	if claims["sub"] != user["id"] {
		t.Errorf("sub = %v, want the user id %v", claims["sub"], user["id"])
	}
}

func TestSignupRejectsDuplicateAndBadInput(t *testing.T) {
	env := newTestEnv(t)
	env.signup(t, "dup@example.com", "hunter22")

	rec := env.do(t, http.MethodPost, "/signup",
		map[string]any{"email": "dup@example.com", "password": "hunter22"}, "")
	body := decodeInto[HTTPError](t, rec, http.StatusUnprocessableEntity)
	if body.ErrorCode != ErrorCodeUserAlreadyExists {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeUserAlreadyExists)
	}

	rec = env.do(t, http.MethodPost, "/signup", map[string]any{"email": "x@example.com", "password": "abc"}, "")
	body = decodeInto[HTTPError](t, rec, http.StatusUnprocessableEntity)
	if body.ErrorCode != ErrorCodeWeakPassword {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeWeakPassword)
	}

	rec = env.do(t, http.MethodPost, "/signup", map[string]any{"email": "not-an-email", "password": "hunter22"}, "")
	body = decodeInto[HTTPError](t, rec, http.StatusBadRequest)
	if body.ErrorCode != ErrorCodeValidationFailed {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeValidationFailed)
	}
}

// BeforeSignup is a validating hook: rejecting it must abort the signup with no
// user row left behind. AfterSignup only observes.
func TestSignupHooks(t *testing.T) {
	env := newTestEnv(t)

	var observed []string
	env.hooks.Register(ports.AfterSignup, func(_ context.Context, p map[string]any) (map[string]any, error) {
		observed = append(observed, p["email"].(string))
		return nil, nil
	})
	env.hooks.Register(ports.BeforeSignup, func(_ context.Context, p map[string]any) (map[string]any, error) {
		if strings.HasSuffix(p["email"].(string), "@blocked.test") {
			return nil, context.Canceled
		}
		return nil, nil
	})

	rec := env.do(t, http.MethodPost, "/signup",
		map[string]any{"email": "nope@blocked.test", "password": "hunter22"}, "")
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body = %s", rec.Code, rec.Body.String())
	}

	var n int64
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from auth.users where email = 'nope@blocked.test'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Errorf("a rejected signup left %d user rows behind", n)
	}

	env.signup(t, "ok@example.com", "hunter22")
	if len(observed) != 1 || observed[0] != "ok@example.com" {
		t.Errorf("AfterSignup observed %v, want [ok@example.com]", observed)
	}
}

// A TokenClaims hook must be able to add custom claims to the access token. It
// receives the same envelope the external custom_access_token hook does:
// {user_id, claims, authentication_method}, with claims the FULL view of the
// token about to be signed.
func TestTokenClaimsHookInjectsCustomClaims(t *testing.T) {
	env := newTestEnv(t)
	var gotUserID, gotMethod string
	var sawReserved bool
	env.hooks.Register(ports.TokenClaims, func(_ context.Context, p map[string]any) (map[string]any, error) {
		gotUserID, _ = p["user_id"].(string)
		gotMethod, _ = p["authentication_method"].(string)
		claims, ok := p["claims"].(map[string]any)
		if !ok {
			t.Errorf("payload claims = %#v, want a map", p["claims"])
			return p, nil
		}
		_, hasSub := claims["sub"]
		_, hasEmail := claims["email"]
		sawReserved = hasSub && hasEmail
		claims["tenant_id"] = "acme"
		return p, nil
	})

	session := env.signup(t, "claims@example.com", "hunter22")
	claims := decodeClaims(t, session.Token)
	if claims["tenant_id"] != "acme" {
		t.Errorf("tenant_id claim = %v, want acme", claims["tenant_id"])
	}
	if session.User == nil || gotUserID != session.User.ID {
		t.Errorf("hook user_id = %q, want the signed-up user", gotUserID)
	}
	if gotMethod != "password" {
		t.Errorf("hook authentication_method = %q, want password", gotMethod)
	}
	if !sawReserved {
		t.Error("hook did not receive the reserved claims in its claim view")
	}
}

// A refresh reports how the SESSION was established, since no new
// authentication happened, and the hook envelope survives rotation.
func TestTokenClaimsHookAuthMethodOnRefresh(t *testing.T) {
	env := newTestEnv(t)
	var methods []string
	env.hooks.Register(ports.TokenClaims, func(_ context.Context, p map[string]any) (map[string]any, error) {
		m, _ := p["authentication_method"].(string)
		methods = append(methods, m)
		return p, nil
	})

	session := env.signup(t, "refresh-claims@example.com", "hunter22")
	rec := env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": session.RefreshToken}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh status = %d: %s", rec.Code, rec.Body.String())
	}
	if len(methods) != 2 || methods[0] != "password" || methods[1] != "password" {
		t.Errorf("authentication_method per issuance = %v, want [password password]", methods)
	}
}

// A hook that returns the old flat payload has no `claims` object, and that
// must fail loudly rather than mint a token with no custom claims at all.
func TestTokenClaimsHookWithoutClaimsFieldFails(t *testing.T) {
	env := newTestEnv(t)
	env.hooks.Register(ports.TokenClaims, func(_ context.Context, _ map[string]any) (map[string]any, error) {
		return map[string]any{"tenant_id": "acme"}, nil
	})

	rec := env.do(t, http.MethodPost, "/signup",
		map[string]any{"email": "flat-hook@example.com", "password": "hunter22"}, "")
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("signup status = %d, want 500: %s", rec.Code, rec.Body.String())
	}
}

func TestPasswordGrant(t *testing.T) {
	env := newTestEnv(t)
	env.signup(t, "login@example.com", "hunter22")

	rec := env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"email": "login@example.com", "password": "hunter22"}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if session.Token == "" || session.RefreshToken == "" || session.User == nil {
		t.Fatalf("incomplete session: %+v", session)
	}
	if session.User.LastSignInAt == nil {
		t.Error("last_sign_in_at was not stamped on sign-in")
	}

	// Wrong password and unknown user must be indistinguishable.
	for _, body := range []map[string]any{
		{"email": "login@example.com", "password": "wrong-password"},
		{"email": "ghost@example.com", "password": "hunter22"},
	} {
		rec := env.do(t, http.MethodPost, "/token?grant_type=password", body, "")
		e := decodeInto[HTTPError](t, rec, http.StatusBadRequest)
		if e.ErrorCode != ErrorCodeInvalidCredentials || e.Message != InvalidLoginMessage {
			t.Errorf("body = %+v, want invalid_credentials/%q", e, InvalidLoginMessage)
		}
	}

	rec = env.do(t, http.MethodPost, "/token?grant_type=carrier_pigeon",
		map[string]any{"email": "login@example.com", "password": "hunter22"}, "")
	e := decodeInto[HTTPError](t, rec, http.StatusBadRequest)
	if e.Message != "unsupported_grant_type" {
		t.Errorf("msg = %q, want unsupported_grant_type", e.Message)
	}
}

// A password that still AUTHENTICATES but no longer satisfies the strength
// policy must sign in anyway, carrying upstream's advisory
// (tokens.AccessTokenResponse.WeakPassword, assigned by
// api.ResourceOwnerPasswordGrant). Raising the policy must never lock an
// existing user out of their own account — the client is told to prompt for a
// change instead of being handed a 4xx.
func TestPasswordGrantReturnsWeakPasswordAdvisory(t *testing.T) {
	cfg := testConfig()
	cfg.Password.MinLength = 12
	env := newTestEnvWithConfig(t, cfg)

	// Sign up under the strict policy, then rewrite the stored hash to a
	// password that predates it. This is what a real deployment looks like the
	// day after GOTRUE_PASSWORD_MIN_LENGTH is raised.
	env.signup(t, "grandfathered@example.com", "long-enough-password")
	legacy, err := HashPassword("hunter")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if _, err := env.pool.Exec(context.Background(),
		`update auth.users set encrypted_password = $2 where email = $1`,
		"grandfathered@example.com", legacy); err != nil {
		t.Fatalf("backdate password: %v", err)
	}

	rec := env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"email": "grandfathered@example.com", "password": "hunter"}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if session.Token == "" {
		t.Fatal("the login must succeed: a tightened policy is not a credential failure")
	}
	if session.WeakPassword == nil {
		t.Fatalf("weak_password advisory missing from %s", rec.Body.String())
	}
	if got := session.WeakPassword.Reasons; len(got) != 1 || got[0] != "length" {
		t.Errorf("weak_password.reasons = %v, want [length]", got)
	}
	if session.WeakPassword.Message == "" {
		t.Error("weak_password.message must carry upstream's human-readable text")
	}

	// A compliant password leaves the key out of the body entirely. (Upstream
	// renders a literal `"weak_password": null` here — deviation
	// token-weak-password-field in test/parity/deviations.yaml.)
	env.signup(t, "compliant@example.com", "long-enough-password")
	rec = env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"email": "compliant@example.com", "password": "long-enough-password"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "weak_password") {
		t.Errorf("weak_password must be absent for a compliant password: %s", rec.Body.String())
	}
}

// Rotation: the presented token is revoked and a child is issued on the same
// session. Re-presenting a revoked token is reuse: the whole family dies.
//
// The reuse interval is disabled here on purpose — this test covers the
// PUNITIVE branch. The tolerated branch (a reuse inside
// Security.RefreshTokenReuseInterval, which is 10s by default) is covered by
// TestRefreshReuseWithinIntervalReturnsActiveToken in conf_db_test.go.
func TestRefreshRotationAndReuseDetection(t *testing.T) {
	cfg := testConfig()
	cfg.Security.RefreshTokenReuseInterval = 0
	env := newTestEnvWithConfig(t, cfg)
	first := env.signup(t, "rotate@example.com", "hunter22")

	rec := env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": first.RefreshToken}, "")
	second := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	if second.RefreshToken == first.RefreshToken {
		t.Fatal("refresh token was not rotated")
	}
	if second.User.ID != first.User.ID {
		t.Errorf("rotation returned a different user: %s vs %s", second.User.ID, first.User.ID)
	}

	// The old token is now revoked and its child records the parent link.
	var revoked bool
	var parent string
	if err := env.pool.QueryRow(context.Background(),
		`select revoked from auth.refresh_tokens where token = $1`, first.RefreshToken).Scan(&revoked); err != nil {
		t.Fatalf("query old token: %v", err)
	}
	if !revoked {
		t.Error("the presented refresh token was not revoked")
	}
	if err := env.pool.QueryRow(context.Background(),
		`select coalesce(parent, '') from auth.refresh_tokens where token = $1`, second.RefreshToken).Scan(&parent); err != nil {
		t.Fatalf("query new token: %v", err)
	}
	if parent != first.RefreshToken {
		t.Errorf("parent = %q, want %q", parent, first.RefreshToken)
	}

	// Reuse of the revoked token.
	rec = env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": first.RefreshToken}, "")
	e := decodeInto[HTTPError](t, rec, http.StatusBadRequest)
	if e.ErrorCode != ErrorCodeRefreshTokenAlreadyUsed {
		t.Errorf("error_code = %q, want %q", e.ErrorCode, ErrorCodeRefreshTokenAlreadyUsed)
	}

	// ...and the still-valid child is now dead too (whole family revoked).
	rec = env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": second.RefreshToken}, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}

	var live int64
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from auth.refresh_tokens where user_id = $1 and revoked is not true`,
		first.User.ID).Scan(&live); err != nil {
		t.Fatalf("count live tokens: %v", err)
	}
	if live != 0 {
		t.Errorf("%d refresh tokens survived reuse detection, want 0", live)
	}
}

func TestRefreshUnknownToken(t *testing.T) {
	env := newTestEnv(t)
	rec := env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": "zzzzzzzzzzzz"}, "")
	e := decodeInto[HTTPError](t, rec, http.StatusBadRequest)
	if e.ErrorCode != ErrorCodeRefreshTokenNotFound {
		t.Errorf("error_code = %q, want %q", e.ErrorCode, ErrorCodeRefreshTokenNotFound)
	}
}

func TestGetUser(t *testing.T) {
	env := newTestEnv(t)
	session := env.signup(t, "me@example.com", "hunter22")

	rec := env.do(t, http.MethodGet, "/user", nil, session.Token)
	user := decodeInto[User](t, rec, http.StatusOK)
	if user.Email != "me@example.com" || user.ID != session.User.ID {
		t.Errorf("user = %+v", user)
	}

	rec = env.do(t, http.MethodGet, "/user", nil, "not-a-token")
	e := decodeInto[HTTPError](t, rec, http.StatusForbidden)
	if e.ErrorCode != ErrorCodeBadJWT {
		t.Errorf("error_code = %q, want %q", e.ErrorCode, ErrorCodeBadJWT)
	}
}

func TestUpdateUserMetadataAndEmail(t *testing.T) {
	env := newTestEnv(t)
	session := env.signup(t, "old@example.com", "hunter22")

	rec := env.do(t, http.MethodPut, "/user",
		map[string]any{"data": map[string]any{"nickname": "sky"}}, session.Token)
	user := decodeInto[User](t, rec, http.StatusOK)
	if user.UserMetaData["nickname"] != "sky" {
		t.Errorf("user_metadata = %v", user.UserMetaData)
	}

	rec = env.do(t, http.MethodPut, "/user", map[string]any{"email": "new@example.com"}, session.Token)
	user = decodeInto[User](t, rec, http.StatusOK)
	if user.Email != "new@example.com" {
		t.Errorf("email = %q, want new@example.com", user.Email)
	}
	// The email identity must follow the address.
	if len(user.Identities) != 1 || user.Identities[0].IdentityData["email"] != "new@example.com" {
		t.Errorf("identity was not updated: %+v", user.Identities)
	}
	// The previous address is notified (best effort).
	if len(env.mailer.sent) == 0 || !strings.HasPrefix(env.mailer.sent[0], "old@example.com|") {
		t.Errorf("mailer.sent = %v, want a notice to the old address", env.mailer.sent)
	}

	// Taking someone else's address is a 422 email_exists.
	env.signup(t, "taken@example.com", "hunter22")
	rec = env.do(t, http.MethodPut, "/user", map[string]any{"email": "taken@example.com"}, session.Token)
	e := decodeInto[HTTPError](t, rec, http.StatusUnprocessableEntity)
	if e.ErrorCode != ErrorCodeEmailExists {
		t.Errorf("error_code = %q, want %q", e.ErrorCode, ErrorCodeEmailExists)
	}
}

// A password change must keep the calling session alive and kill every other one.
func TestUpdateUserPasswordRevokesOtherSessions(t *testing.T) {
	env := newTestEnv(t)
	first := env.signup(t, "pw@example.com", "hunter22")

	rec := env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"email": "pw@example.com", "password": "hunter22"}, "")
	second := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	rec = env.do(t, http.MethodPut, "/user", map[string]any{"password": "new-hunter22"}, second.Token)
	decodeInto[User](t, rec, http.StatusOK)

	// The other session's refresh token is gone.
	rec = env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": first.RefreshToken}, "")
	if rec.Code == http.StatusOK {
		t.Error("the other session survived a password change")
	}
	// The caller's own session still refreshes.
	rec = env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": second.RefreshToken}, "")
	if rec.Code != http.StatusOK {
		t.Errorf("the calling session was revoked by its own password change: %s", rec.Body.String())
	}

	// The new password works, the old one does not.
	rec = env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"email": "pw@example.com", "password": "new-hunter22"}, "")
	decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	rec = env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"email": "pw@example.com", "password": "hunter22"}, "")
	if rec.Code != http.StatusBadRequest {
		t.Error("the old password still works")
	}

	// Reusing the same password is rejected as same_password.
	rec = env.do(t, http.MethodPut, "/user", map[string]any{"password": "new-hunter22"}, second.Token)
	e := decodeInto[HTTPError](t, rec, http.StatusUnprocessableEntity)
	if e.ErrorCode != ErrorCodeSamePassword {
		t.Errorf("error_code = %q, want %q", e.ErrorCode, ErrorCodeSamePassword)
	}
}

func TestLogout(t *testing.T) {
	env := newTestEnv(t)
	session := env.signup(t, "bye@example.com", "hunter22")

	rec := env.do(t, http.MethodPost, "/logout", nil, session.Token)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body = %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Errorf("204 response has a body: %s", rec.Body.String())
	}

	rec = env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": session.RefreshToken}, "")
	if rec.Code == http.StatusOK {
		t.Error("the refresh token still works after logout")
	}

	var sessions, live int64
	ctx := context.Background()
	if err := env.pool.QueryRow(ctx, `select count(*) from auth.sessions where user_id = $1::uuid`,
		session.User.ID).Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if err := env.pool.QueryRow(ctx,
		`select count(*) from auth.refresh_tokens where user_id = $1 and revoked is not true`,
		session.User.ID).Scan(&live); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if sessions != 0 || live != 0 {
		t.Errorf("after logout: %d sessions, %d live refresh tokens; want 0/0", sessions, live)
	}
}

func TestAdminUserCRUD(t *testing.T) {
	env := newTestEnv(t)
	admin := env.serviceRoleToken(t)

	rec := env.do(t, http.MethodPost, "/admin/users", map[string]any{
		"email":         "created@example.com",
		"password":      "hunter22",
		"email_confirm": true,
		"user_metadata": map[string]any{"plan": "pro"},
	}, admin)
	created := decodeInto[User](t, rec, http.StatusOK)
	if created.ID == "" || created.Email != "created@example.com" {
		t.Fatalf("created = %+v", created)
	}
	if created.EmailConfirmedAt == nil {
		t.Error("email_confirm was ignored")
	}

	// The created user can sign in.
	rec = env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"email": "created@example.com", "password": "hunter22"}, "")
	decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	rec = env.do(t, http.MethodGet, "/admin/users/"+created.ID, nil, admin)
	fetched := decodeInto[User](t, rec, http.StatusOK)
	if fetched.ID != created.ID {
		t.Errorf("fetched %s, want %s", fetched.ID, created.ID)
	}

	rec = env.do(t, http.MethodPut, "/admin/users/"+created.ID, map[string]any{
		"app_metadata": map[string]any{"tier": "gold"},
		"ban_duration": "24h",
	}, admin)
	updated := decodeInto[User](t, rec, http.StatusOK)
	if updated.AppMetaData["tier"] != "gold" {
		t.Errorf("app_metadata = %v", updated.AppMetaData)
	}
	if updated.BannedUntil == nil || !updated.BannedUntil.After(time.Now()) {
		t.Errorf("banned_until = %v", updated.BannedUntil)
	}

	// A banned user cannot sign in.
	rec = env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"email": "created@example.com", "password": "hunter22"}, "")
	e := decodeInto[HTTPError](t, rec, http.StatusForbidden)
	if e.ErrorCode != ErrorCodeUserBanned {
		t.Errorf("error_code = %q, want %q", e.ErrorCode, ErrorCodeUserBanned)
	}

	// Unknown / malformed ids are 404, per upstream.
	rec = env.do(t, http.MethodGet, "/admin/users/11111111-2222-4333-8444-555555555555", nil, admin)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	rec = env.do(t, http.MethodGet, "/admin/users/not-a-uuid", nil, admin)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
}

func TestAdminListUsersPagination(t *testing.T) {
	env := newTestEnv(t)
	admin := env.serviceRoleToken(t)

	for _, e := range []string{"a@example.com", "b@example.com", "c@example.com"} {
		env.signup(t, e, "hunter22")
	}

	rec := env.do(t, http.MethodGet, "/admin/users?page=1&per_page=2", nil, admin)
	page := decodeInto[AdminListUsersResponse](t, rec, http.StatusOK)
	if len(page.Users) != 2 {
		t.Errorf("got %d users, want 2", len(page.Users))
	}
	if page.Aud != AudienceAuthenticated {
		t.Errorf("aud = %q", page.Aud)
	}
	if got := rec.Header().Get("X-Total-Count"); got != "3" {
		t.Errorf("X-Total-Count = %q, want 3", got)
	}
	link := rec.Header().Get("Link")
	if !strings.Contains(link, `rel="next"`) || !strings.Contains(link, `rel="last"`) {
		t.Errorf("Link = %q, want next+last relations", link)
	}

	rec = env.do(t, http.MethodGet, "/admin/users?page=2&per_page=2", nil, admin)
	page = decodeInto[AdminListUsersResponse](t, rec, http.StatusOK)
	if len(page.Users) != 1 {
		t.Errorf("page 2 has %d users, want 1", len(page.Users))
	}
	if strings.Contains(rec.Header().Get("Link"), `rel="next"`) {
		t.Error("the last page must not advertise a next relation")
	}
}

// project.md §2.5: the account deletion and the compliance outbox row commit
// together, in one transaction.
func TestAdminDeleteUserHardWritesOutbox(t *testing.T) {
	env := newTestEnv(t)
	admin := env.serviceRoleToken(t)
	session := env.signup(t, "gone@example.com", "hunter22")

	var deleted []string
	env.hooks.Register(ports.AfterUserDelete, func(_ context.Context, p map[string]any) (map[string]any, error) {
		deleted = append(deleted, p["user_id"].(string))
		return nil, nil
	})

	rec := env.do(t, http.MethodDelete, "/admin/users/"+session.User.ID, nil, admin)
	body := decodeInto[map[string]any](t, rec, http.StatusOK)
	if len(body) != 0 {
		t.Errorf("delete body = %v, want {} (upstream sends an empty object)", body)
	}

	ctx := context.Background()

	// Default is a hard delete.
	var users int64
	if err := env.pool.QueryRow(ctx, `select count(*) from auth.users where id = $1::uuid`,
		session.User.ID).Scan(&users); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if users != 0 {
		t.Error("default delete must be a hard delete")
	}

	// Sessions/refresh tokens are gone with it.
	var sessions int64
	if err := env.pool.QueryRow(ctx, `select count(*) from auth.sessions where user_id = $1::uuid`,
		session.User.ID).Scan(&sessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if sessions != 0 {
		t.Errorf("%d sessions survived the delete", sessions)
	}

	// And the outbox row is there for the privacy engine.
	var eventType, aggregateID string
	var payload map[string]any
	var published *time.Time
	if err := env.pool.QueryRow(ctx,
		`select event_type, aggregate_id, payload, published_at from dilion_privacy.outbox`).
		Scan(&eventType, &aggregateID, &payload, &published); err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	if eventType != "user.deleted" {
		t.Errorf("event_type = %q, want user.deleted", eventType)
	}
	if aggregateID != session.User.ID {
		t.Errorf("aggregate_id = %q, want %q", aggregateID, session.User.ID)
	}
	if payload["user_id"] != session.User.ID ||
		payload["requested_by"] != "admin" {
		t.Errorf("payload = %v", payload)
	}
	if published != nil {
		t.Error("published_at must start NULL so the dispatcher picks the row up")
	}

	if len(deleted) != 1 || deleted[0] != session.User.ID {
		t.Errorf("AfterUserDelete observed %v", deleted)
	}
}

// ?should_soft_delete keeps the row but frees the unique email/phone slots.
func TestAdminDeleteUserSoft(t *testing.T) {
	env := newTestEnv(t)
	admin := env.serviceRoleToken(t)
	session := env.signup(t, "soft@example.com", "hunter22")

	rec := env.do(t, http.MethodDelete, "/admin/users/"+session.User.ID,
		map[string]any{"should_soft_delete": true}, admin)
	decodeInto[map[string]any](t, rec, http.StatusOK)

	ctx := context.Background()
	var email string
	var deletedAt *time.Time
	var encrypted *string
	var meta map[string]any
	if err := env.pool.QueryRow(ctx,
		`select coalesce(email, ''), deleted_at, encrypted_password, raw_user_meta_data
		 from auth.users where id = $1::uuid`, session.User.ID).
		Scan(&email, &deletedAt, &encrypted, &meta); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if deletedAt == nil {
		t.Error("deleted_at was not set")
	}
	if email == "soft@example.com" || strings.Contains(email, "@") {
		t.Errorf("email = %q, want an obfuscated value", email)
	}
	if encrypted != nil {
		t.Error("encrypted_password must be cleared on soft delete")
	}
	if len(meta) != 0 {
		t.Errorf("raw_user_meta_data = %v, want {}", meta)
	}

	// The freed address can be registered again.
	env.signup(t, "soft@example.com", "hunter22")

	// The outbox row is written for soft deletes too.
	var n int64
	if err := env.pool.QueryRow(ctx,
		`select count(*) from dilion_privacy.outbox where event_type = 'user.deleted' and aggregate_id = $1`,
		session.User.ID).Scan(&n); err != nil {
		t.Fatalf("count outbox: %v", err)
	}
	if n != 1 {
		t.Errorf("outbox rows = %d, want 1", n)
	}
}

// A validating BeforeUserDelete hook must be able to veto, leaving no outbox row.
func TestAdminDeleteUserHookVeto(t *testing.T) {
	env := newTestEnv(t)
	admin := env.serviceRoleToken(t)
	session := env.signup(t, "keep@example.com", "hunter22")

	env.hooks.Register(ports.BeforeUserDelete, func(_ context.Context, _ map[string]any) (map[string]any, error) {
		return nil, context.Canceled
	})

	rec := env.do(t, http.MethodDelete, "/admin/users/"+session.User.ID, nil, admin)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body = %s", rec.Code, rec.Body.String())
	}

	ctx := context.Background()
	var users, outbox int64
	if err := env.pool.QueryRow(ctx, `select count(*) from auth.users where id = $1::uuid`,
		session.User.ID).Scan(&users); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if err := env.pool.QueryRow(ctx, `select count(*) from dilion_privacy.outbox`).Scan(&outbox); err != nil {
		t.Fatalf("count outbox: %v", err)
	}
	if users != 1 || outbox != 0 {
		t.Errorf("after a vetoed delete: %d users, %d outbox rows; want 1/0", users, outbox)
	}
}

func keysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

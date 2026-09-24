package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/ports"
)

// applyHookMigrations installs the feature migrations the signup path touches
// beyond the shared harness's 0100: one_time_tokens / flow_state (0110/0111) and
// the MFA AMR table (0112) that grantSession writes into. Sibling _db_test files
// do the same for their own features.
func applyHookMigrations(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if !firstApply("applyHookMigrations") {
		return
	}
	for _, name := range []string{
		"0110_auth_one_time_tokens.sql",
		"0111_auth_flow_state.sql",
		"0112_auth_mfa.sql",
	} {
		path := filepath.Join("..", "..", "migrations", name)
		sql, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if _, err := pool.Exec(context.Background(), string(sql)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
}

// jsonHookServer starts an httptest server that responds to a webhook with the
// given JSON body and records that it was called.
func jsonHookServer(t *testing.T, status int, body string, hits *int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// a valid, parseable webhook secret (key = "0123456789abcdef").
const testHookSecret = "v1,whsec_MDEyMzQ1Njc4OWFiY2RlZg=="

// ---- pg-functions driver ---------------------------------------------------

func TestHookPGDriverInvokesFunction(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	if _, err := env.pool.Exec(ctx, `
		create schema if not exists hooktest;
		create or replace function hooktest.custom_access_token(input jsonb)
		returns jsonb language sql as $$
			select jsonb_build_object(
				'claims',
				coalesce(input->'claims', '{}'::jsonb) || '{"pg_added":"yes"}'::jsonb)
		$$;`); err != nil {
		t.Fatalf("create hook function: %v", err)
	}

	a := newAPI(Deps{Pool: env.pool, Tokens: env.tokens, Config: DefaultConfig()})
	cfg := HookEndpointConfig{Enabled: true, URI: "pg-functions://dilion/hooktest/custom_access_token"}

	in := &CustomAccessTokenInput{
		Metadata: newHookMetadata(context.Background(), nil, HookNameCustomAccessToken),
		UserID:   uuid.NewString(),
		Claims:   map[string]any{"role": "authenticated"},
	}
	out := &CustomAccessTokenOutput{}
	// tx == nil: the driver opens its own transaction.
	if err := a.runExtHook(ctx, cfg, nil, in, out); err != nil {
		t.Fatalf("runExtHook (pg): %v", err)
	}
	if out.Claims["pg_added"] != "yes" {
		t.Fatalf("out.Claims = %v, want pg_added=yes", out.Claims)
	}
	if out.Claims["role"] != "authenticated" {
		t.Fatalf("input claim not preserved: %v", out.Claims)
	}
}

func TestHookPGDriverErrorEnvelopeRejects(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	if _, err := env.pool.Exec(ctx, `
		create schema if not exists hooktest;
		create or replace function hooktest.rejecter(input jsonb)
		returns jsonb language sql as $$
			select '{"error":{"http_code":403,"message":"pg blocked"}}'::jsonb
		$$;`); err != nil {
		t.Fatalf("create reject function: %v", err)
	}

	a := newAPI(Deps{Pool: env.pool, Tokens: env.tokens, Config: DefaultConfig()})
	cfg := HookEndpointConfig{Enabled: true, URI: "pg-functions://dilion/hooktest/rejecter"}
	err := a.runExtHook(ctx, cfg, nil, map[string]any{}, &BeforeUserCreatedOutput{})
	if err == nil {
		t.Fatal("expected a rejection error")
	}
	he, ok := err.(*HTTPError)
	if !ok {
		t.Fatalf("error type = %T, want *HTTPError", err)
	}
	if he.HTTPStatus != 403 || he.Message != "pg blocked" {
		t.Fatalf("error = %d %q, want 403 pg blocked", he.HTTPStatus, he.Message)
	}
}

// ---- custom_access_token merges into a real token --------------------------

func TestCustomAccessTokenHookMergesClaims(t *testing.T) {
	// The hook echoes the input claims back with an extra custom claim; Dilion
	// replaces the token's claims with the returned set (reserved claims are then
	// re-asserted by Sign).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in CustomAccessTokenInput
		_ = json.NewDecoder(r.Body).Decode(&in)
		claims := in.Claims
		if claims == nil {
			claims = map[string]any{}
		}
		claims["hook_added"] = "yes"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"claims": claims})
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.Hooks.CustomAccessToken = HookEndpointConfig{Enabled: true, URI: srv.URL, Secrets: []string{testHookSecret}}
	env := newTestEnvWithConfig(t, cfg)
	applyHookMigrations(t, env.pool)

	rec := env.do(t, http.MethodPost, "/signup", map[string]any{
		"email":    "cat@example.com",
		"password": "correct-horse-battery",
	}, "")
	resp := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if resp.Token == "" {
		t.Fatalf("no access token in response: %s", rec.Body.String())
	}

	claims, err := env.tokens.Verify(context.Background(), resp.Token)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if got := claims.Extra["hook_added"]; got != "yes" {
		t.Fatalf("hook_added claim = %v, want yes; extra=%v", got, claims.Extra)
	}
	// Reserved claims are still asserted by Sign, not the hook.
	if claims.Subject == "" {
		t.Fatal("token missing sub")
	}
}

// ---- before_user_created blocks signup -------------------------------------

func TestBeforeUserCreatedRejectsSignup(t *testing.T) {
	var hits int32
	srv := jsonHookServer(t, http.StatusOK,
		`{"error":{"http_code":403,"message":"signup blocked by hook"}}`, &hits)

	cfg := DefaultConfig()
	cfg.Hooks.BeforeUserCreated = HookEndpointConfig{Enabled: true, URI: srv.URL, Secrets: []string{testHookSecret}}
	env := newTestEnvWithConfig(t, cfg)
	applyHookMigrations(t, env.pool)

	rec := env.do(t, http.MethodPost, "/signup", map[string]any{
		"email":    "blocked@example.com",
		"password": "correct-horse-battery",
	}, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
	if atomic.LoadInt32(&hits) == 0 {
		t.Fatal("before_user_created hook was not called")
	}
	// The rejection must have prevented the row from being written.
	var n int64
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from auth.users where email = 'blocked@example.com'`).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if n != 0 {
		t.Fatalf("user row was written despite rejection (%d rows)", n)
	}
}

// ---- send_email / send_sms suppress the built-in delivery ------------------

func TestSendEmailHookSuppressesMailer(t *testing.T) {
	var hits int32
	srv := jsonHookServer(t, http.StatusOK, `{}`, &hits)

	cfg := DefaultConfig()
	cfg.Mailer.Autoconfirm = false // force a confirmation email
	cfg.Hooks.SendEmail = HookEndpointConfig{Enabled: true, URI: srv.URL, Secrets: []string{testHookSecret}}
	env := newTestEnvWithConfig(t, cfg)
	applyHookMigrations(t, env.pool)

	rec := env.do(t, http.MethodPost, "/signup", map[string]any{
		"email":    "mail@example.com",
		"password": "correct-horse-battery",
	}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if atomic.LoadInt32(&hits) == 0 {
		t.Fatal("send_email hook was not called")
	}
	if len(env.mailer.sent) != 0 {
		t.Fatalf("built-in mailer was called despite send_email hook: %v", env.mailer.sent)
	}
}

func TestSendSMSHookSuppressesProvider(t *testing.T) {
	var hits int32
	srv := jsonHookServer(t, http.StatusOK, `{}`, &hits)

	cfg := DefaultConfig()
	cfg.External["phone"] = ProviderConfig{Enabled: true}
	cfg.SMS.Autoconfirm = false // force an OTP send
	// No SMS provider is configured: if the hook did NOT take over delivery,
	// deliverSMS would 500 with "Unable to get SMS provider".
	cfg.Hooks.SendSMS = HookEndpointConfig{Enabled: true, URI: srv.URL, Secrets: []string{testHookSecret}}
	env := newTestEnvWithConfig(t, cfg)
	applyHookMigrations(t, env.pool)

	rec := env.do(t, http.MethodPost, "/signup", map[string]any{
		"phone":    "+15551234567",
		"password": "correct-horse-battery",
	}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if atomic.LoadInt32(&hits) == 0 {
		t.Fatal("send_sms hook was not called")
	}
}

// Hook endpoints are configured once per process, so every instance calls the
// same URL. The payload's metadata names the instance the event happened in —
// the one selected on the request — and always does, "default" included, so a
// shared receiver can route without special cases.
func TestHookMetadataCarriesInstance(t *testing.T) {
	var (
		mu     sync.Mutex
		bodies []map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		bodies = append(bodies, body)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)

	cfg := DefaultConfig()
	cfg.Mailer.Autoconfirm = false // force a confirmation email through the hook
	cfg.Hooks.SendEmail = HookEndpointConfig{Enabled: true, URI: srv.URL, Secrets: []string{testHookSecret}}
	env := newTestEnvWithConfig(t, cfg)
	applyHookMigrations(t, env.pool)

	signup := func(email, instance string) {
		t.Helper()
		b, _ := json.Marshal(map[string]any{"email": email, "password": "correct-horse-battery"})
		req := httptest.NewRequest(http.MethodPost, "/signup", bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		if instance != "" {
			req = req.WithContext(ports.ContextWithInstance(req.Context(), instance))
		}
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("signup %s: status = %d; body = %s", email, rec.Code, rec.Body.String())
		}
	}
	signup("single@example.com", "")
	signup("tenant@example.com", "tenant-a")

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("hook calls = %d, want 2", len(bodies))
	}
	for i, want := range []string{ports.DefaultInstanceID, "tenant-a"} {
		meta, _ := bodies[i]["metadata"].(map[string]any)
		if got := meta["dilion_instance_id"]; got != want {
			t.Errorf("call %d: metadata.dilion_instance_id = %v, want %q (metadata %v)", i, got, want, meta)
		}
		if meta["name"] != HookNameSendEmail {
			t.Errorf("call %d: metadata.name = %v, upstream members must be unchanged", i, meta["name"])
		}
	}
}

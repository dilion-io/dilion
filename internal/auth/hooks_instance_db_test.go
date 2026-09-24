package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/dilion-io/dilion/ports"
)

// putHook sets the instance's setting for name and returns the response.
func (e *testEnv) putHook(t *testing.T, name string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	return e.do(t, http.MethodPut, "/admin/hooks/"+name, body, e.serviceRoleToken(t))
}

// storeInstanceHook writes a setting straight into dilion_auth.hooks, as a
// setting saved before a policy change would be.
func storeInstanceHook(t *testing.T, e *testEnv, name string, enabled bool, uri string) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), `
		insert into dilion_auth.hooks (name, enabled, uri) values ($1, $2, $3)`, name, enabled, uri); err != nil {
		t.Fatalf("store hook setting: %v", err)
	}
}

func (e *testEnv) trySignup(t *testing.T, email string) int {
	t.Helper()
	return e.do(t, http.MethodPost, "/signup",
		map[string]any{"email": email, "password": "correct-horse-battery"}, "").Code
}

func createRejectingPGHook(t *testing.T, e *testEnv) string {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), `
		create schema if not exists hooktest;
		create or replace function hooktest.instance_reject(input jsonb)
		returns jsonb language sql as $$
			select '{"error":{"http_code":403,"message":"instance says no"}}'::jsonb
		$$;`); err != nil {
		t.Fatalf("create hook function: %v", err)
	}
	return "pg-functions://dilion/hooktest/instance_reject"
}

// An instance turns on a hook the server leaves off, with a pg-functions URI in
// its own database, and removing the setting returns it to the server's.
func TestInstanceHookEnablesAndReverts(t *testing.T) {
	env := newTestEnv(t)
	uri := createRejectingPGHook(t, env)

	view := decodeInto[hookSettingView](t, env.putHook(t, hookBeforeUserCreated,
		map[string]any{"enabled": true, "uri": uri}), http.StatusOK)
	if view.Source != "instance" || !view.Enabled || view.URI != uri {
		t.Fatalf("PUT view = %+v", view)
	}
	if code := env.trySignup(t, "first@example.com"); code != http.StatusForbidden {
		t.Fatalf("signup with the instance's hook = %d, want 403", code)
	}

	view = decodeInto[hookSettingView](t, env.do(t, http.MethodDelete, "/admin/hooks/"+hookBeforeUserCreated,
		nil, env.serviceRoleToken(t)), http.StatusOK)
	if view.Source != "server" || view.Enabled {
		t.Fatalf("DELETE view = %+v, want the server's disabled setting", view)
	}
	if code := env.trySignup(t, "second@example.com"); code != http.StatusOK {
		t.Fatalf("signup after removing the setting = %d, want 200", code)
	}
}

// enabled=false in an instance switches a server-wide hook off there.
func TestInstanceHookDisablesServerHook(t *testing.T) {
	var hits int32
	srv := jsonHookServer(t, http.StatusOK, `{"error":{"http_code":403,"message":"server says no"}}`, &hits)
	cfg := DefaultConfig()
	cfg.Hooks.BeforeUserCreated = HookEndpointConfig{Enabled: true, URI: srv.URL}
	env := newTestEnvWithConfig(t, cfg)

	decodeInto[hookSettingView](t, env.putHook(t, hookBeforeUserCreated, map[string]any{"enabled": false}), http.StatusOK)
	if code := env.trySignup(t, "free@example.com"); code != http.StatusOK {
		t.Fatalf("signup = %d, want 200 with the hook off in this instance", code)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("server hook was called %d times after the instance switched it off", n)
	}
}

// A locked server hook cannot be replaced, and a setting stored anyway is
// ignored.
func TestInstanceHookLocked(t *testing.T) {
	var hits int32
	srv := jsonHookServer(t, http.StatusOK, `{"error":{"http_code":403,"message":"server says no"}}`, &hits)
	cfg := DefaultConfig()
	cfg.Hooks.BeforeUserCreated = HookEndpointConfig{Enabled: true, URI: srv.URL, Locked: true}
	env := newTestEnvWithConfig(t, cfg)

	for _, rec := range []*httptest.ResponseRecorder{
		env.putHook(t, hookBeforeUserCreated, map[string]any{"enabled": false}),
		env.do(t, http.MethodDelete, "/admin/hooks/"+hookBeforeUserCreated, nil, env.serviceRoleToken(t)),
	} {
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), ErrorCodeHookLocked) {
			t.Fatalf("write to a locked hook = %d %s, want 403 %s", rec.Code, rec.Body.String(), ErrorCodeHookLocked)
		}
	}

	storeInstanceHook(t, env, hookBeforeUserCreated, false, "")
	if code := env.trySignup(t, "pinned@example.com"); code != http.StatusForbidden {
		t.Fatalf("signup = %d, want the locked server hook's 403", code)
	}
	if atomic.LoadInt32(&hits) == 0 {
		t.Fatal("locked server hook was not called")
	}
	view := decodeInto[hookSettingView](t, env.do(t, http.MethodGet, "/admin/hooks/"+hookBeforeUserCreated,
		nil, env.serviceRoleToken(t)), http.StatusOK)
	if view.Source != "server" || !view.Locked {
		t.Fatalf("GET view = %+v, want the locked server setting", view)
	}
}

// With no policy, an instance's webhook may only reach public addresses: saving
// a loopback URL fails, and one stored anyway is never dialled.
func TestInstanceHookSSRFGuardByDefault(t *testing.T) {
	withoutOutboundAllowance(t)
	var hits int32
	srv := jsonHookServer(t, http.StatusOK, `{}`, &hits)
	env := newTestEnv(t)

	rec := env.putHook(t, hookBeforeUserCreated, map[string]any{"enabled": true, "uri": srv.URL})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not public") {
		t.Fatalf("PUT loopback webhook = %d %s, want 400 naming the address", rec.Code, rec.Body.String())
	}

	storeInstanceHook(t, env, hookBeforeUserCreated, true, srv.URL)
	if code := env.trySignup(t, "rebound@example.com"); code != http.StatusInternalServerError {
		t.Fatalf("signup = %d, want 500 from the refused hook call", code)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("guarded hook reached a loopback receiver %d times", n)
	}
}

// The operator's AuthHookSetting policy sees every URI, can exempt one from the
// SSRF guard or reject it, and runs again on each call.
func TestInstanceHookPolicy(t *testing.T) {
	var (
		hits      int32
		signature atomic.Value
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		signature.Store(r.Header.Get("webhook-signature"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	env := newTestEnv(t)

	var (
		mu      sync.Mutex
		seen    []map[string]any
		closing bool
	)
	env.hooks.Register(ports.AuthHookSetting, func(_ context.Context, p map[string]any) (map[string]any, error) {
		mu.Lock()
		defer mu.Unlock()
		in := map[string]any{}
		for k, v := range p {
			in[k] = v
		}
		seen = append(seen, in)
		uri, _ := p["uri"].(string)
		switch {
		case closing || strings.Contains(uri, "blocked"):
			return nil, errors.New("receivers must be on the allow list")
		case strings.HasPrefix(uri, srv.URL):
			p["ssrf_protection"] = false
		}
		return p, nil
	})

	rec := env.putHook(t, hookBeforeUserCreated, map[string]any{"enabled": true, "uri": "https://blocked.example.com/hook"})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "receivers must be on the allow list") {
		t.Fatalf("PUT rejected URI = %d %s, want 400 with the policy's reason", rec.Code, rec.Body.String())
	}

	decodeInto[hookSettingView](t, env.putHook(t, hookBeforeUserCreated, map[string]any{
		"enabled": true, "uri": srv.URL, "secrets": []string{testHookSecret},
	}), http.StatusOK)
	mu.Lock()
	last := seen[len(seen)-1]
	mu.Unlock()
	if last["hook"] != hookBeforeUserCreated || last["uri"] != srv.URL || last["ssrf_protection"] != true {
		t.Fatalf("policy payload = %v", last)
	}
	if code := env.trySignup(t, "exempt@example.com"); code != http.StatusOK {
		t.Fatalf("signup through an exempted internal hook = %d, want 200", code)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("exempted hook called %d times, want 1", hits)
	}
	if sig, _ := signature.Load().(string); !strings.HasPrefix(sig, "v1,") {
		t.Fatalf("webhook-signature = %q, want one made with the stored secret", sig)
	}

	mu.Lock()
	closing = true
	mu.Unlock()
	if code := env.trySignup(t, "closed@example.com"); code != http.StatusInternalServerError {
		t.Fatalf("signup after the policy closed = %d, want 500", code)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatal("hook was called although the policy now rejects it")
	}
}

// Secrets are write-only and kept when a PUT leaves them out.
func TestInstanceHookSecretsWriteOnly(t *testing.T) {
	env := newTestEnv(t)
	const uri = "https://hooks.example.com/send-email"

	view := decodeInto[hookSettingView](t, env.putHook(t, hookSendEmail, map[string]any{
		"enabled": false, "uri": uri, "secrets": []string{testHookSecret},
	}), http.StatusOK)
	if view.SecretsCount != 1 {
		t.Fatalf("secrets_count = %d, want 1", view.SecretsCount)
	}
	list := env.do(t, http.MethodGet, "/admin/hooks", nil, env.serviceRoleToken(t))
	if list.Code != http.StatusOK || strings.Contains(list.Body.String(), "whsec_") {
		t.Fatalf("GET /admin/hooks = %d, leaks a secret: %s", list.Code, list.Body.String())
	}
	if all := decodeInto[struct{ Hooks []hookSettingView }](t, list, http.StatusOK); len(all.Hooks) != len(hookKeys) {
		t.Fatalf("listed %d hooks, want %d", len(all.Hooks), len(hookKeys))
	}

	view = decodeInto[hookSettingView](t, env.putHook(t, hookSendEmail, map[string]any{"enabled": false, "uri": uri}), http.StatusOK)
	if view.SecretsCount != 1 {
		t.Fatalf("secrets_count after a PUT without secrets = %d, want the stored 1", view.SecretsCount)
	}
	view = decodeInto[hookSettingView](t, env.putHook(t, hookSendEmail, map[string]any{"enabled": false, "uri": uri, "secrets": []string{}}), http.StatusOK)
	if view.SecretsCount != 0 {
		t.Fatalf("secrets_count after clearing = %d, want 0", view.SecretsCount)
	}

	for name, body := range map[string]map[string]any{
		"bad secret":      {"enabled": false, "uri": uri, "secrets": []string{"whsec_MDEy"}},
		"bad scheme":      {"enabled": false, "uri": "ftp://hooks.example.com"},
		"bad pg uri":      {"enabled": false, "uri": "pg-functions://only-db"},
		"enabled, no uri": {"enabled": true},
		"no enabled":      {"uri": uri},
	} {
		if rec := env.putHook(t, hookSendEmail, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: PUT = %d %s, want 400", name, rec.Code, rec.Body.String())
		}
	}
}

func TestInstanceHookAdminSurface(t *testing.T) {
	env := newTestEnv(t)
	if rec := env.do(t, http.MethodGet, "/admin/hooks/nope", nil, env.serviceRoleToken(t)); rec.Code != http.StatusNotFound {
		t.Errorf("unknown hook = %d, want 404", rec.Code)
	}
	user := env.signup(t, "plain@example.com", "hunter22")
	if rec := env.do(t, http.MethodPut, "/admin/hooks/"+hookSendEmail,
		map[string]any{"enabled": false}, user.Token); rec.Code != http.StatusForbidden {
		t.Errorf("PUT by a user without users.admin = %d, want 403", rec.Code)
	}
}

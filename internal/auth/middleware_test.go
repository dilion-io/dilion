package auth

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/dilion-io/dilion/internal/netguard"

	"github.com/dilion-io/dilion/ports"
)

// newRouterEnv mounts /auth/v1 without a database. Every endpoint that does not
// touch Postgres (CORS, /settings, rate limiting, grant dispatch) is testable
// through it.
func newRouterEnv(t *testing.T, cfg *Config) chi.Router {
	t.Helper()
	r := chi.NewRouter()
	Register(r, Deps{
		Tokens: NewTokenServiceHS(testSecret()),
		Config: cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return r
}

func TestCORSPreflight(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CORS.AllowedHeaders = []string{"X-Tenant-Id"}
	r := newRouterEnv(t, cfg)

	req := httptest.NewRequest(http.MethodOptions, "/token?grant_type=password", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "authorization, content-type")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", rec.Code)
	}
	h := rec.Header()
	if h.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("Allow-Origin = %q", h.Get("Access-Control-Allow-Origin"))
	}
	if h.Get("Access-Control-Allow-Credentials") != "" {
		t.Error("credentials must not be allowed with a wildcard origin")
	}
	for _, m := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		if !strings.Contains(h.Get("Access-Control-Allow-Methods"), m) {
			t.Errorf("Allow-Methods %q is missing %s", h.Get("Access-Control-Allow-Methods"), m)
		}
	}
	allowed := h.Get("Access-Control-Allow-Headers")
	for _, want := range []string{"Accept", "Authorization", "Content-Type", "X-Client-Info",
		"X-Client-IP", "X-JWT-AUD", "x-use-cookie", "X-Supabase-Api-Version", "X-Tenant-Id"} {
		if !strings.Contains(allowed, want) {
			t.Errorf("Allow-Headers %q is missing %s", allowed, want)
		}
	}
	if h.Get("Access-Control-Max-Age") == "" {
		t.Error("preflight must be cacheable")
	}
}

func TestCORSSimpleRequest(t *testing.T) {
	r := newRouterEnv(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Allow-Origin = %q", got)
	}
	exposed := rec.Header().Get("Access-Control-Expose-Headers")
	for _, want := range []string{"X-Total-Count", "Link", "X-Supabase-Api-Version"} {
		if !strings.Contains(exposed, want) {
			t.Errorf("Expose-Headers %q is missing %s", exposed, want)
		}
	}
}

// X-Forwarded-For counts only as far as a trusted proxy vouches for it.
func TestClientIPTrustsOnlyConfiguredProxies(t *testing.T) {
	resolve := func(trusted string, xff string) string {
		a := &api{trustedProxies: netguard.MustParseNetworks(trusted)}
		var got string
		h := a.clientIPMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = clientIP(r) }))
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		h.ServeHTTP(httptest.NewRecorder(), req)
		return got
	}
	if got := resolve("", "203.0.113.9"); got != "10.0.0.1" {
		t.Errorf("no trusted proxy: clientIP = %q, want the peer", got)
	}
	if got := resolve("10.0.0.0/8", "203.0.113.9, 70.41.3.18"); got != "70.41.3.18" {
		t.Errorf("trusted proxy: clientIP = %q, want the hop it vouches for", got)
	}
	if got := resolve("*", "203.0.113.9, 70.41.3.18"); got != "203.0.113.9" {
		t.Errorf("trust everything: clientIP = %q, want the first hop", got)
	}
}

func TestRateLimiterBurstRefillAndIsolation(t *testing.T) {
	now := time.Now()
	// 30 requests per 5 minutes, burst 3.
	l := newRateLimiter(30, 5*time.Minute, 3)
	l.now = func() time.Time { return now }

	for i := range 3 {
		if !l.allow("1.1.1.1") {
			t.Fatalf("request %d of the burst was rejected", i+1)
		}
	}
	if l.allow("1.1.1.1") {
		t.Fatal("the burst was not enforced")
	}
	// Another IP has its own bucket.
	if !l.allow("2.2.2.2") {
		t.Fatal("per-IP isolation broken: a second IP was rate limited")
	}
	// 30/5min = one token every 10s.
	now = now.Add(9 * time.Second)
	if l.allow("1.1.1.1") {
		t.Fatal("a token was refilled too early")
	}
	now = now.Add(2 * time.Second)
	if !l.allow("1.1.1.1") {
		t.Fatal("no token was refilled after the window elapsed")
	}
	// Refill never exceeds the burst.
	now = now.Add(time.Hour)
	for i := range 3 {
		if !l.allow("1.1.1.1") {
			t.Fatalf("refilled request %d rejected", i+1)
		}
	}
	if l.allow("1.1.1.1") {
		t.Fatal("the bucket refilled beyond its burst")
	}

	// Idle buckets are dropped by the janitor sweep.
	l.sweep(now.Add(2 * time.Hour))
	l.mu.Lock()
	n := len(l.buckets)
	l.mu.Unlock()
	if n != 0 {
		t.Errorf("%d buckets survived the sweep, want 0", n)
	}
}

func TestRateLimitedEndpointReturnsUpstreamShape(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RateLimits.TokenRefresh = 0 // burst only, then 429
	r := newRouterEnv(t, cfg)

	var last *httptest.ResponseRecorder
	for range rateBurst + 1 {
		req := httptest.NewRequest(http.MethodPost, "/token?grant_type=refresh_token",
			strings.NewReader(`{"refresh_token":"aaaaaaaaaaaa"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "198.51.100.7:5000"
		last = httptest.NewRecorder()
		r.ServeHTTP(last, req)
	}

	if last.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429; body = %s", last.Code, last.Body.String())
	}
	var e HTTPError
	if err := json.Unmarshal(last.Body.Bytes(), &e); err != nil {
		t.Fatalf("decode 429 body: %v", err)
	}
	if e.HTTPStatus != http.StatusTooManyRequests || e.ErrorCode != ErrorCodeOverRequestRateLimit || e.Message == "" {
		t.Errorf("429 body = %+v", e)
	}

	// A different client IP is unaffected.
	req := httptest.NewRequest(http.MethodPost, "/token?grant_type=refresh_token",
		strings.NewReader(`{"refresh_token":"aaaaaaaaaaaa"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.8:1234"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Error("a different client IP shares the bucket")
	}

	// The same address on another instance has a budget of its own.
	req = httptest.NewRequest(http.MethodPost, "/token?grant_type=refresh_token",
		strings.NewReader(`{"refresh_token":"aaaaaaaaaaaa"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.7:5000"
	req = req.WithContext(ports.ContextWithInstance(req.Context(), "another-instance"))
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code == http.StatusTooManyRequests {
		t.Error("another instance shares the bucket")
	}
}

func TestGrantTypeFromQueryAndForm(t *testing.T) {
	// Query wins over the body.
	req := httptest.NewRequest(http.MethodPost, "/token?grant_type=refresh_token",
		strings.NewReader("grant_type=password"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if got := grantTypeOf(req); got != "refresh_token" {
		t.Errorf("grantTypeOf = %q, want the query value", got)
	}

	// Form body is read when the query has none...
	req = httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader("grant_type=password&password=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if got := grantTypeOf(req); got != "password" {
		t.Errorf("grantTypeOf = %q, want password", got)
	}
	// ...and the body is still readable afterwards.
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "grant_type=password") {
		t.Errorf("body was consumed: %q", body)
	}

	// A JSON body is untouched.
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"refresh_token":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	if got := grantTypeOf(req); got != "" {
		t.Errorf("grantTypeOf = %q, want empty", got)
	}
	body, _ = io.ReadAll(req.Body)
	if string(body) != `{"refresh_token":"abc"}` {
		t.Errorf("JSON body was consumed: %q", body)
	}
}

func TestGrantDispatch(t *testing.T) {
	// A feature file registers its grant from init(); do the same here.
	registerGrant("unit_test_grant", LimiterToken, func(a *api, w http.ResponseWriter, r *http.Request) error {
		return sendJSON(w, http.StatusOK, map[string]string{"grant": "ok"})
	})
	t.Cleanup(func() {
		delete(grantHandlers, "unit_test_grant")
		delete(grantLimiters, "unit_test_grant")
	})

	r := newRouterEnv(t, nil)

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader("grant_type=unit_test_grant"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"grant":"ok"`) {
		t.Fatalf("dispatch through the form body failed: %d %s", rec.Code, rec.Body.String())
	}

	// Unknown and missing grant types get upstream's answer.
	for _, path := range []string{"/token", "/token?grant_type=nope"} {
		req = httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", path, rec.Code)
		}
		var e HTTPError
		_ = json.Unmarshal(rec.Body.Bytes(), &e)
		if e.ErrorCode != ErrorCodeInvalidCredentials || e.Message != "unsupported_grant_type" {
			t.Errorf("%s: body = %+v", path, e)
		}
	}
}

func TestFeatureRegistryIsSorted(t *testing.T) {
	mounts := sortedFeatureMounts()
	for i := 1; i < len(mounts); i++ {
		if mounts[i-1].name >= mounts[i].name {
			t.Fatalf("feature mounts are not sorted: %q then %q", mounts[i-1].name, mounts[i].name)
		}
	}
	found := false
	for _, m := range mounts {
		if m.name == "settings" {
			found = true
		}
	}
	if !found {
		t.Error("the settings feature did not register itself")
	}
}

func TestSettingsResponseShape(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DisableSignup = true
	cfg.AnonymousUsersEnabled = true
	cfg.SMS.Provider = "twilio"
	cfg.SMS.Autoconfirm = true
	cfg.SAML.Enabled = true
	cfg.Passkeys.Enabled = true
	ext := cfg.External["google"]
	ext.Enabled = true
	cfg.External["google"] = ext

	r := newRouterEnv(t, cfg)
	req := httptest.NewRequest(http.MethodGet, "/settings", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, key := range []string{"external", "disable_signup", "mailer_autoconfirm",
		"phone_autoconfirm", "sms_provider", "saml_enabled", "passkeys_enabled"} {
		if _, ok := body[key]; !ok {
			t.Errorf("missing key %q", key)
		}
	}
	external, _ := body["external"].(map[string]any)
	if len(external) != 26 {
		t.Errorf("external has %d providers, want 26", len(external))
	}
	if external["google"] != true || external["email"] != true || external["apple"] != false {
		t.Errorf("external = %+v", external)
	}
	if external["anonymous_users"] != true {
		t.Error("anonymous_users must reflect AnonymousUsersEnabled")
	}
	if body["disable_signup"] != true || body["sms_provider"] != "twilio" ||
		body["phone_autoconfirm"] != true || body["saml_enabled"] != true || body["passkeys_enabled"] != true {
		t.Errorf("settings = %+v", body)
	}
}

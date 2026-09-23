package auth

// Database-backed tests for the custom OAuth provider admin surface and the
// runtime resolution of a custom provider through /authorize + /callback. Only
// run when DILION_TEST_DB is set:
//
//	docker exec dilion-db createdb -U dilion dilion_test_prov
//	DILION_TEST_DB=postgres://dilion:dilion@localhost:55432/dilion_test_prov \
//	  go test -run 'Custom' -race ./internal/auth/...

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/internal/hooks"
)

// newFakeOIDCProviderTLS is newFakeOIDCProvider over HTTPS: the custom-provider
// DB constraints require https:// endpoints, so the fake must serve TLS. The
// caller must point providerTransport at srv.Client().Transport so the fake's
// self-signed certificate is trusted.
func newFakeOIDCProviderTLS(t *testing.T) *fakeOIDCProvider {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p := &fakeOIDCProvider{
		key: key, kid: "tls-key-1", sub: "fake-sub",
		email: "fake@example.com", emailVerified: true, name: "Fake User",
		picture:     "https://cdn.example.com/fake.png",
		accessToken: "fake-access-token", refreshToken: "fake-refresh-token",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, map[string]any{
			"issuer":                 p.srv.URL,
			"authorization_endpoint": p.srv.URL + "/o/oauth2/auth",
			"token_endpoint":         p.srv.URL + "/token",
			"userinfo_endpoint":      p.srv.URL + "/userinfo",
			"jwks_uri":               p.srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, map[string]any{"keys": []any{p.publicJWK()}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.tokenRedirectURI = r.FormValue("redirect_uri")
		if r.FormValue("grant_type") != "authorization_code" || r.FormValue("code") == "" {
			http.Error(w, "bad token request", http.StatusBadRequest)
			return
		}
		writeTestJSON(w, map[string]any{
			"access_token": p.accessToken, "refresh_token": p.refreshToken,
			"token_type": "bearer", "expires_in": 3600, "id_token": p.signIDToken(nil),
		})
	})
	p.srv = httptest.NewTLSServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

type customEnv struct {
	*testEnv
	cfg   *Config
	oidc  *fakeOIDCProvider
	admin string
}

func newCustomEnv(t *testing.T) *customEnv {
	t.Helper()

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
	applyEmailSchema(t, pool)         // 0110 one-time tokens, 0111 auth.flow_state
	applyExternalExtraSchema(t, pool) // 0112: mfa_amr_claims (sessions record their sign-in method)
	applyOAuthServerSchema(t, pool)   // 0116: auth.custom_oauth_providers
	truncateAll(t, pool)
	if _, err := pool.Exec(ctx, `truncate auth.flow_state, auth.custom_oauth_providers restart identity cascade`); err != nil {
		t.Fatalf("truncate custom tables: %v", err)
	}

	cfg := DefaultConfig()
	cfg.SiteURL = "https://app.test"
	cfg.URIAllowList = []string{"https://app.test/**"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}

	env := &customEnv{
		testEnv: &testEnv{
			pool:   pool,
			tokens: NewTokenServiceHS(testSecret()),
			hooks:  hooks.NewRegistry(),
			mailer: &captureMailer{},
		},
		cfg:  cfg,
		oidc: newFakeOIDCProviderTLS(t),
	}
	// Trust the fake's self-signed certificate for the duration of the test.
	prev := providerTransport
	providerTransport = env.oidc.srv.Client().Transport
	t.Cleanup(func() { providerTransport = prev })
	resetOIDCCache()
	t.Cleanup(resetOIDCCache)

	env.router = chi.NewRouter()
	Register(env.router, Deps{
		Pool:   pool,
		Tokens: env.tokens,
		Mailer: env.mailer,
		Hooks:  env.hooks,
		Config: cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	env.admin = env.serviceRoleToken(t)
	return env
}

// ---- admin CRUD ------------------------------------------------------------

func TestCustomProviderAdminCRUD(t *testing.T) {
	env := newCustomEnv(t)

	create := map[string]any{
		"provider_type":     "oidc",
		"identifier":        "custom:acme",
		"name":              "Acme SSO",
		"client_id":         "acme-client",
		"client_secret":     "top-secret",
		"issuer":            "https://idp.acme.test",
		"scopes":            []string{"openid", "email"},
		"attribute_mapping": map[string]any{"email": "mail"},
	}
	rec := env.do(t, http.MethodPost, "/admin/custom-providers", create, env.admin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d; body = %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "top-secret") || strings.Contains(rec.Body.String(), "client_secret") {
		t.Fatalf("client_secret leaked in create response: %s", rec.Body.String())
	}
	created := decodeInto[customOAuthProvider](t, rec, http.StatusCreated)
	if created.ID == "" || created.Identifier != "custom:acme" || !created.Enabled {
		t.Fatalf("created = %+v", created)
	}

	// List.
	listRec := env.do(t, http.MethodGet, "/admin/custom-providers", nil, env.admin)
	list := decodeInto[struct {
		Providers []customOAuthProvider `json:"providers"`
	}](t, listRec, http.StatusOK)
	if len(list.Providers) != 1 {
		t.Fatalf("list = %d providers", len(list.Providers))
	}

	// Get by id.
	getRec := env.do(t, http.MethodGet, "/admin/custom-providers/"+created.ID, nil, env.admin)
	got := decodeInto[customOAuthProvider](t, getRec, http.StatusOK)
	if got.Name != "Acme SSO" {
		t.Fatalf("get = %+v", got)
	}

	// Update (omitting client_secret keeps the stored one; toggle enabled).
	update := map[string]any{
		"provider_type": "oidc",
		"name":          "Acme Renamed",
		"client_id":     "acme-client",
		"issuer":        "https://idp.acme.test",
		"enabled":       false,
	}
	updRec := env.do(t, http.MethodPut, "/admin/custom-providers/"+created.ID, update, env.admin)
	upd := decodeInto[customOAuthProvider](t, updRec, http.StatusOK)
	if upd.Name != "Acme Renamed" || upd.Enabled {
		t.Fatalf("update = %+v", upd)
	}
	// The stored secret must have survived the update.
	var storedSecret string
	if err := env.pool.QueryRow(context.Background(),
		`select client_secret from auth.custom_oauth_providers where id = $1::uuid`, created.ID).Scan(&storedSecret); err != nil {
		t.Fatalf("read secret: %v", err)
	}
	if storedSecret != "top-secret" {
		t.Fatalf("secret after update = %q, want it preserved", storedSecret)
	}

	// Delete echoes the deleted provider.
	delRec := env.do(t, http.MethodDelete, "/admin/custom-providers/"+created.ID, nil, env.admin)
	if delRec.Code != http.StatusOK {
		t.Fatalf("delete status = %d", delRec.Code)
	}
	if again := env.do(t, http.MethodGet, "/admin/custom-providers/"+created.ID, nil, env.admin); again.Code != http.StatusNotFound {
		t.Fatalf("get after delete = %d", again.Code)
	}
}

func TestCustomProviderAdminValidationAndAuthz(t *testing.T) {
	env := newCustomEnv(t)

	// requireAdmin: no token -> 401.
	if rec := env.do(t, http.MethodGet, "/admin/custom-providers", nil, ""); rec.Code == http.StatusOK {
		t.Fatalf("unauthenticated list must not be 200, got %d", rec.Code)
	}

	// Bad provider_type -> 400.
	bad := map[string]any{"provider_type": "saml", "identifier": "custom:x", "name": "X", "client_id": "c", "client_secret": "s"}
	if rec := env.do(t, http.MethodPost, "/admin/custom-providers", bad, env.admin); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad type status = %d; body = %s", rec.Code, rec.Body.String())
	}

	// Duplicate identifier -> conflict.
	ok := map[string]any{"provider_type": "oidc", "identifier": "custom:dup", "name": "D", "client_id": "c", "client_secret": "s", "issuer": "https://idp.test"}
	if rec := env.do(t, http.MethodPost, "/admin/custom-providers", ok, env.admin); rec.Code != http.StatusCreated {
		t.Fatalf("first create status = %d; body = %s", rec.Code, rec.Body.String())
	}
	if rec := env.do(t, http.MethodPost, "/admin/custom-providers", ok, env.admin); rec.Code < 400 {
		t.Fatalf("duplicate identifier must fail, got %d", rec.Code)
	}
}

// ---- runtime resolution: /authorize + /callback ----------------------------

func TestCustomProviderAuthorizeAndCallback(t *testing.T) {
	env := newCustomEnv(t)

	// A custom OIDC provider pointing at the fake issuer. The fake's id_token
	// audience is "google-client-id", so that is the client_id.
	create := map[string]any{
		"provider_type": "oidc",
		"identifier":    "custom:fake",
		"name":          "Fake IdP",
		"client_id":     "google-client-id",
		"client_secret": "fake-secret",
		"issuer":        env.oidc.srv.URL,
		"scopes":        []string{"openid", "email"},
	}
	if rec := env.do(t, http.MethodPost, "/admin/custom-providers", create, env.admin); rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d; body = %s", rec.Code, rec.Body.String())
	}

	// /authorize -> 302 to the provider, carrying our flow state as `state`.
	authRec := env.do(t, http.MethodGet,
		"/authorize?provider=custom:fake&redirect_to="+url.QueryEscape("https://app.test/welcome"), nil, "")
	if authRec.Code != http.StatusFound {
		t.Fatalf("authorize status = %d; body = %s", authRec.Code, authRec.Body.String())
	}
	loc, err := url.Parse(authRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if !strings.HasPrefix(authRec.Header().Get("Location"), env.oidc.srv.URL) {
		t.Fatalf("authorize did not redirect to the provider: %s", authRec.Header().Get("Location"))
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatalf("no state in %s", loc)
	}

	// /callback -> the code is exchanged, the id_token verified, an account is
	// created and the implicit flow redirects back with tokens in the fragment.
	cbRec := env.do(t, http.MethodGet,
		"/callback?state="+url.QueryEscape(state)+"&code=the-code", nil, "")
	cb := redirectLocation(t, cbRec, http.StatusFound)
	if !strings.HasPrefix(cb.String(), "https://app.test/welcome") {
		t.Fatalf("callback redirect = %s", cb)
	}
	frag, _ := url.ParseQuery(cb.Fragment)
	if frag.Get("access_token") == "" {
		t.Fatalf("no access_token in fragment: %s", cb.Fragment)
	}

	// The account carries the fake provider's claims.
	var email, provider string
	if err := env.pool.QueryRow(context.Background(),
		`select u.email, i.provider from auth.users u
		   join auth.identities i on i.user_id = u.id
		  where i.provider = 'custom:fake'`).Scan(&email, &provider); err != nil {
		t.Fatalf("load created user: %v", err)
	}
	if email != env.oidc.email {
		t.Fatalf("created email = %q, want %q", email, env.oidc.email)
	}
}

package auth

// Database-backed tests for the external (social) login surface: /authorize,
// /callback, grant_type=id_token and the identity-linking endpoints.
//
// The providers are httptest servers shaped like the real ones — a Google-shaped
// OIDC issuer (discovery + JWKS + id_token) and a GitHub-shaped REST provider.
// NOTHING here talks to the internet.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/internal/hooks"
)

// ---- fake OIDC (Google-shaped) provider -------------------------------------

type fakeOIDCProvider struct {
	srv *httptest.Server
	key *ecdsa.PrivateKey
	kid string

	// Profile handed out by the token and user-info endpoints.
	sub           string
	email         string
	emailVerified bool
	name          string
	picture       string

	// Token endpoint behaviour.
	accessToken  string
	refreshToken string
	nonce        string // hashed nonce claim to embed, "" for none
	omitIDToken  bool

	tokenRequests int
	// tokenRedirectURI is the redirect_uri the last token request presented;
	// OAuth requires it to equal the one the authorization request carried.
	tokenRedirectURI string
	// tokenCodeVerifier is the PKCE code_verifier the last token request
	// carried, and tokenBasic whether its credentials came by HTTP Basic.
	tokenCodeVerifier string
	tokenBasic        bool
	// rejectBasic makes the token endpoint refuse HTTP Basic credentials,
	// like a server whose client is registered for client_secret_post.
	rejectBasic bool
}

func newFakeOIDCProvider(t *testing.T) *fakeOIDCProvider {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	p := &fakeOIDCProvider{
		key:           key,
		kid:           "test-key-1",
		sub:           "google-sub-1",
		email:         "gina@example.com",
		emailVerified: true,
		name:          "Gina Green",
		picture:       "https://cdn.example.com/gina.png",
		accessToken:   "provider-access-token",
		refreshToken:  "provider-refresh-token",
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
		p.tokenRequests++
		_ = r.ParseForm()
		p.recordTokenRequest(r)
		if p.rejectBasic && p.tokenBasic {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		if r.FormValue("grant_type") != "authorization_code" || r.FormValue("code") == "" {
			http.Error(w, "bad token request", http.StatusBadRequest)
			return
		}
		body := map[string]any{
			"access_token":  p.accessToken,
			"refresh_token": p.refreshToken,
			"token_type":    "bearer",
			"expires_in":    3600,
		}
		if !p.omitIDToken {
			body["id_token"] = p.signIDToken(nil)
		}
		writeTestJSON(w, body)
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, map[string]any{
			"id":             p.sub,
			"email":          p.email,
			"verified_email": p.emailVerified,
			"name":           p.name,
			"picture":        p.picture,
		})
	})

	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// recordTokenRequest notes what a token request presented, for the tests to
// check against what the authorization request sent.
func (p *fakeOIDCProvider) recordTokenRequest(r *http.Request) {
	p.tokenRedirectURI = r.FormValue("redirect_uri")
	p.tokenCodeVerifier = r.FormValue("code_verifier")
	_, _, p.tokenBasic = r.BasicAuth()
}

func (p *fakeOIDCProvider) publicJWK() map[string]any {
	return map[string]any{
		"kty": "EC",
		"kid": p.kid,
		"crv": "P-256",
		"alg": "ES256",
		"use": "sig",
		"x":   base64.RawURLEncoding.EncodeToString(p.key.X.FillBytes(make([]byte, 32))),
		"y":   base64.RawURLEncoding.EncodeToString(p.key.Y.FillBytes(make([]byte, 32))),
	}
}

// signIDToken mints an id_token for the profile, letting a test override any
// claim (nil for the defaults).
func (p *fakeOIDCProvider) signIDToken(override map[string]any) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":            p.srv.URL,
		"sub":            p.sub,
		"aud":            "google-client-id",
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
		"email":          p.email,
		"email_verified": p.emailVerified,
		"name":           p.name,
		"picture":        p.picture,
		"at_hash":        accessTokenHash(p.accessToken),
	}
	if p.nonce != "" {
		claims["nonce"] = p.nonce
	}
	for k, v := range override {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = p.kid
	signed, err := tok.SignedString(p.key)
	if err != nil {
		panic(err)
	}
	return signed
}

func accessTokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// ---- fake GitHub-shaped provider --------------------------------------------

type fakeGitHubProvider struct {
	srv *httptest.Server

	id     int64
	login  string
	name   string
	avatar string
	emails []map[string]any
}

func newFakeGitHubProvider(t *testing.T) *fakeGitHubProvider {
	t.Helper()
	p := &fakeGitHubProvider{
		id:     4242,
		login:  "octo",
		name:   "Octo Cat",
		avatar: "https://cdn.github.test/octo.png",
		emails: []map[string]any{
			{"email": "secondary@example.com", "primary": false, "verified": true},
			{"email": "octo@example.com", "primary": true, "verified": true},
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("code") == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}
		// GitHub answers form-encoded unless Accept: application/json is set;
		// the client always sets it, so answer JSON — but exercise the
		// form-encoded branch when the test asks for it via the code value.
		if r.FormValue("code") == "form-encoded" {
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			_, _ = io.WriteString(w, "access_token=gho_test&token_type=bearer")
			return
		}
		writeTestJSON(w, map[string]any{"access_token": "gho_test", "token_type": "bearer"})
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gho_test" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeTestJSON(w, map[string]any{
			"id": p.id, "login": p.login, "name": p.name, "avatar_url": p.avatar,
		})
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, p.emails)
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func writeTestJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ---- environment -------------------------------------------------------------

type externalEnv struct {
	*testEnv
	cfg    *Config
	google *fakeOIDCProvider
	github *fakeGitHubProvider
}

// externalTestConfig is the configuration the OAuth flows are exercised under.
func externalTestConfig() *Config {
	cfg := testConfig()
	cfg.SiteURL = "https://app.test"
	cfg.URIAllowList = []string{"https://app.test/**"}
	cfg.External["google"] = ProviderConfig{
		Enabled:     true,
		ClientID:    []string{"google-client-id"},
		Secret:      "google-secret",
		RedirectURI: "https://api.test/auth/v1/callback",
	}
	cfg.External["github"] = ProviderConfig{
		Enabled:     true,
		ClientID:    []string{"github-client-id"},
		Secret:      "github-secret",
		RedirectURI: "https://api.test/auth/v1/callback",
	}
	return cfg
}

func newExternalEnv(t *testing.T, cfg *Config) *externalEnv {
	t.Helper()

	dsn := os.Getenv("DILION_TEST_DB")
	if dsn == "" {
		t.Skip("DILION_TEST_DB not set; skipping database-backed tests")
	}
	if !strings.HasPrefix(dsn, "postgres") {
		dsn = defaultTestDSN
	}
	if cfg == nil {
		cfg = externalTestConfig()
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}

	ctx := t.Context()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect %s: %v", dsn, err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping %s: %v", dsn, err)
	}

	applySchema(t, pool)
	applyEmailSchema(t, pool)
	applyExternalExtraSchema(t, pool)
	truncateAll(t, pool)
	truncateEmailTables(t, pool)

	env := &externalEnv{
		testEnv: &testEnv{
			pool:   pool,
			tokens: NewTokenServiceHS(testSecret()),
			hooks:  hooks.NewRegistry(),
			mailer: &captureMailer{},
		},
		cfg:    cfg,
		google: newFakeOIDCProvider(t),
		github: newFakeGitHubProvider(t),
	}

	// Point the built-in providers at the fake servers.
	overrideProviderEndpoints("google", providerEndpoints{Issuer: env.google.srv.URL})
	overrideProviderEndpoints("github", providerEndpoints{
		AuthURL:  env.github.srv.URL + "/login/oauth/authorize",
		TokenURL: env.github.srv.URL + "/login/oauth/access_token",
		APIHost:  env.github.srv.URL,
	})
	resetOIDCCache()
	t.Cleanup(func() {
		resetProviderEndpoints("google")
		resetProviderEndpoints("github")
		resetOIDCCache()
	})

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

// applyExternalExtraSchema installs the migrations the SESSION path depends on
// beyond the shared harness: every session now records its authentication
// method in auth.mfa_amr_claims (migration 0112), which the OAuth flows create
// sessions through.
func applyExternalExtraSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if !firstApply("applyExternalExtraSchema") {
		return
	}
	for _, name := range []string{"0112_auth_mfa.sql"} {
		path := filepath.Join("..", "..", "migrations", name)
		sql, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if _, err := pool.Exec(t.Context(), string(sql)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
}

// authorize starts a flow and returns the provider authorization URL.
func (e *externalEnv) authorize(t *testing.T, query string, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	return e.do(t, http.MethodGet, "/authorize?"+query, nil, bearer)
}

// stateFromRedirect extracts the `state` parameter of a 302 to the provider.
func stateFromRedirect(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body = %s", rec.Code, rec.Body.String())
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatalf("no state in %s", u)
	}
	return state
}

// callback runs GET /callback and returns the recorder.
func (e *externalEnv) callback(t *testing.T, state, code string) *httptest.ResponseRecorder {
	t.Helper()
	return e.do(t, http.MethodGet,
		fmt.Sprintf("/callback?state=%s&code=%s", url.QueryEscape(state), url.QueryEscape(code)), nil, "")
}

// redirectLocation asserts a redirect and returns its parsed Location.
func redirectLocation(t *testing.T, rec *httptest.ResponseRecorder, want int) *url.URL {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, want, rec.Body.String())
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location %q: %v", rec.Header().Get("Location"), err)
	}
	return u
}

func fragmentValues(t *testing.T, u *url.URL) url.Values {
	t.Helper()
	v, err := url.ParseQuery(u.Fragment)
	if err != nil {
		t.Fatalf("parse fragment %q: %v", u.Fragment, err)
	}
	return v
}

// signInWithGoogle runs a complete implicit flow and returns the redirect.
func (e *externalEnv) signInWithGoogle(t *testing.T) *url.URL {
	t.Helper()
	rec := e.authorize(t, "provider=google&redirect_to=https%3A%2F%2Fapp.test%2Fwelcome", "")
	state := stateFromRedirect(t, rec)
	return redirectLocation(t, e.callback(t, state, "auth-code"), http.StatusFound)
}

func (e *externalEnv) countUsers(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.pool.QueryRow(t.Context(), `select count(*) from auth.users`).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	return n
}

func (e *externalEnv) identityRows(t *testing.T, userID string) []Identity {
	t.Helper()
	ids, err := findIdentitiesByUserID(t.Context(), e.pool, userID)
	if err != nil {
		t.Fatalf("load identities: %v", err)
	}
	return ids
}

func (e *externalEnv) userByEmail(t *testing.T, email string) *User {
	t.Helper()
	u, err := findUserByEmail(t.Context(), e.pool, email, AudienceAuthenticated)
	if err != nil {
		t.Fatalf("find user %s: %v", email, err)
	}
	return u
}

// ---- GET /authorize ----------------------------------------------------------

func TestExternalAuthorizeRedirectsToProvider(t *testing.T) {
	env := newExternalEnv(t, nil)

	rec := env.authorize(t, "provider=github&redirect_to=https%3A%2F%2Fapp.test%2Fwelcome&scopes=read%3Aorg", "")
	loc := redirectLocation(t, rec, http.StatusFound)

	if !strings.HasPrefix(loc.String(), env.github.srv.URL+"/login/oauth/authorize") {
		t.Fatalf("Location = %s, want the provider authorization endpoint", loc)
	}
	q := loc.Query()
	if q.Get("client_id") != "github-client-id" {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q", q.Get("response_type"))
	}
	if q.Get("redirect_uri") != "https://api.test/auth/v1/callback" {
		t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	if got := q.Get("scope"); got != "user:email read:org" {
		t.Errorf("scope = %q, want the defaults plus the requested scope", got)
	}

	state := q.Get("state")
	fs, err := findOAuthFlowStateByID(t.Context(), env.pool, state)
	if err != nil {
		t.Fatalf("flow state %q: %v", state, err)
	}
	if fs.ProviderType != "github" {
		t.Errorf("provider_type = %q", fs.ProviderType)
	}
	if fs.AuthenticationMethod != authMethodOAuth {
		t.Errorf("authentication_method = %q", fs.AuthenticationMethod)
	}
	if fs.Referrer != "https://app.test/welcome" {
		t.Errorf("referrer = %q", fs.Referrer)
	}
	if fs.IsPKCE() {
		t.Error("flow state should not be a PKCE flow")
	}
	if fs.UserID != nil {
		t.Error("flow state must not name a user before the callback")
	}
}

func TestExternalAuthorizeSkipHTTPRedirect(t *testing.T) {
	env := newExternalEnv(t, nil)

	rec := env.authorize(t, "provider=github&skip_http_redirect=true", "")
	body := decodeInto[map[string]any](t, rec, http.StatusOK)
	rurl, _ := body["url"].(string)
	if !strings.HasPrefix(rurl, env.github.srv.URL) {
		t.Fatalf("url = %q, want the provider authorization endpoint", rurl)
	}
}

func TestExternalAuthorizeRejectsUnknownAndDisabledProviders(t *testing.T) {
	env := newExternalEnv(t, nil)

	for _, provider := range []string{"nosuchprovider", "kakao" /* configured but not enabled */} {
		rec := env.authorize(t, "provider="+provider, "")
		body := decodeInto[HTTPError](t, rec, http.StatusBadRequest)
		if body.ErrorCode != ErrorCodeValidationFailed {
			t.Errorf("provider %q: error_code = %q, want %q", provider, body.ErrorCode, ErrorCodeValidationFailed)
		}
	}
}

func TestExternalAuthorizeEnforcesRedirectAllowList(t *testing.T) {
	env := newExternalEnv(t, nil)

	rec := env.authorize(t, "provider=github&redirect_to=https%3A%2F%2Fevil.test%2Fsteal", "")
	state := stateFromRedirect(t, rec)

	fs, err := findOAuthFlowStateByID(t.Context(), env.pool, state)
	if err != nil {
		t.Fatalf("flow state: %v", err)
	}
	if fs.Referrer != env.cfg.SiteURL {
		t.Fatalf("referrer = %q, want the site URL — a redirect off the allow-list must be dropped", fs.Referrer)
	}
}

func TestExternalAuthorizeRejectsHalfPKCEParams(t *testing.T) {
	env := newExternalEnv(t, nil)

	rec := env.authorize(t, "provider=github&code_challenge_method=s256", "")
	body := decodeInto[HTTPError](t, rec, http.StatusBadRequest)
	if body.ErrorCode != ErrorCodeValidationFailed {
		t.Fatalf("error_code = %q, want %q", body.ErrorCode, ErrorCodeValidationFailed)
	}
}

// ---- GET /callback -----------------------------------------------------------

func TestOAuthCallbackCreatesUserAndSession(t *testing.T) {
	env := newExternalEnv(t, nil)

	loc := env.signInWithGoogle(t)
	if loc.Scheme+"://"+loc.Host+loc.Path != "https://app.test/welcome" {
		t.Fatalf("redirect = %s, want the requested redirect_to", loc)
	}

	frag := fragmentValues(t, loc)
	for _, k := range []string{"access_token", "refresh_token", "expires_in", "expires_at", "token_type"} {
		if frag.Get(k) == "" {
			t.Errorf("fragment is missing %q; got %v", k, frag.Encode())
		}
	}
	if frag.Get("provider_token") != env.google.accessToken {
		t.Errorf("provider_token = %q", frag.Get("provider_token"))
	}
	if frag.Get("provider_refresh_token") != env.google.refreshToken {
		t.Errorf("provider_refresh_token = %q", frag.Get("provider_refresh_token"))
	}

	user := env.userByEmail(t, "gina@example.com")
	if user.EmailConfirmedAt == nil {
		t.Error("a provider-verified email must land confirmed")
	}
	if user.LastSignInAt == nil {
		t.Error("last_sign_in_at was not stamped")
	}
	if got := user.AppMetaData["provider"]; got != "google" {
		t.Errorf("app_metadata.provider = %v", got)
	}

	ids := env.identityRows(t, user.ID)
	if len(ids) != 1 {
		t.Fatalf("identities = %d, want 1", len(ids))
	}
	id := ids[0]
	if id.Provider != "google" || id.ProviderID != env.google.sub {
		t.Errorf("identity = (%s, %s)", id.Provider, id.ProviderID)
	}
	if id.IdentityData["sub"] != env.google.sub ||
		id.IdentityData["email"] != env.google.email ||
		id.IdentityData["name"] != env.google.name ||
		id.IdentityData["avatar_url"] != env.google.picture ||
		id.IdentityData["email_verified"] != true {
		t.Errorf("identity_data = %v", id.IdentityData)
	}
	if id.Email != env.google.email {
		t.Errorf("identity email column = %q", id.Email)
	}
	// The access token in the fragment must be a usable session.
	rec := env.do(t, http.MethodGet, "/user", nil, frag.Get("access_token"))
	got := decodeInto[User](t, rec, http.StatusOK)
	if got.ID != user.ID {
		t.Errorf("GET /user returned %s, want %s", got.ID, user.ID)
	}
	if len(got.Identities) != 1 {
		t.Errorf("GET /user identities = %d, want 1", len(got.Identities))
	}
}

func TestOAuthCallbackExistingIdentitySignsIn(t *testing.T) {
	env := newExternalEnv(t, nil)

	env.signInWithGoogle(t)
	first := env.userByEmail(t, "gina@example.com")

	// A second flow for the same provider subject must NOT create a user.
	env.google.name = "Gina Greene"
	env.signInWithGoogle(t)

	if n := env.countUsers(t); n != 1 {
		t.Fatalf("users = %d, want 1 — an existing identity must sign in, not sign up", n)
	}
	again := env.userByEmail(t, "gina@example.com")
	if again.ID != first.ID {
		t.Fatalf("user id changed: %s -> %s", first.ID, again.ID)
	}
	ids := env.identityRows(t, again.ID)
	if len(ids) != 1 {
		t.Fatalf("identities = %d, want 1", len(ids))
	}
	if ids[0].IdentityData["name"] != "Gina Greene" {
		t.Errorf("identity_data was not refreshed on sign-in: %v", ids[0].IdentityData)
	}
	if ids[0].LastSignInAt == nil {
		t.Error("identity last_sign_in_at was not stamped")
	}
}

func TestOAuthCallbackLinksVerifiedEmailToExistingUser(t *testing.T) {
	env := newExternalEnv(t, nil)

	// An email+password account that owns the address the provider asserts.
	session := env.signup(t, "gina@example.com", "hunter22-strong")
	env.signInWithGoogle(t)

	if n := env.countUsers(t); n != 1 {
		t.Fatalf("users = %d, want 1 — a verified provider email must link, not fork the account", n)
	}
	ids := env.identityRows(t, session.User.ID)
	if len(ids) != 2 {
		t.Fatalf("identities = %d, want 2 (email + google)", len(ids))
	}
	user := env.userByEmail(t, "gina@example.com")
	providers, _ := user.AppMetaData["providers"].([]any)
	if len(providers) != 2 {
		t.Fatalf("app_metadata.providers = %v, want both providers", user.AppMetaData["providers"])
	}
	if user.AppMetaData["provider"] != "email" {
		t.Errorf("app_metadata.provider = %v, want the original provider", user.AppMetaData["provider"])
	}
}

func TestOAuthCallbackUnverifiedEmailDoesNotClaimAnotherAccount(t *testing.T) {
	cfg := externalTestConfig()
	// With autoconfirm off, an unverified provider email stays unverified.
	cfg.Mailer.Autoconfirm = false
	env := newExternalEnv(t, cfg)
	env.google.emailVerified = false

	// Somebody already registered the address (confirmation still pending).
	env.do(t, http.MethodPost, "/signup",
		map[string]any{"email": "gina@example.com", "password": "hunter22-strong"}, "")
	before := env.countUsers(t)

	loc := env.signInWithGoogle(t)
	q := loc.Query()
	if q.Get("error_code") != ErrorCodeProviderEmailNeedsVerification {
		t.Fatalf("error_code = %q, want %q (redirect: %s)",
			q.Get("error_code"), ErrorCodeProviderEmailNeedsVerification, loc)
	}
	if q.Get("error") != "access_denied" {
		t.Errorf("error = %q, want access_denied", q.Get("error"))
	}

	// A brand-new, email-less account was created for the provider identity —
	// the existing account must NOT have been touched.
	if n := env.countUsers(t); n != before+1 {
		t.Fatalf("users = %d, want %d", n, before+1)
	}
	owner := env.userByEmail(t, "gina@example.com")
	if len(env.identityRows(t, owner.ID)) != 1 {
		t.Fatalf("the pre-existing account must keep exactly its own identity")
	}
}

func TestOAuthCallbackRespectsDisableSignup(t *testing.T) {
	cfg := externalTestConfig()
	cfg.DisableSignup = true
	env := newExternalEnv(t, cfg)

	loc := env.signInWithGoogle(t)
	q := loc.Query()
	if q.Get("error_code") != ErrorCodeSignupDisabled {
		t.Fatalf("error_code = %q, want %q (redirect %s)", q.Get("error_code"), ErrorCodeSignupDisabled, loc)
	}
	if q.Get("error") != "access_denied" {
		t.Errorf("error = %q, want access_denied", q.Get("error"))
	}
	if n := env.countUsers(t); n != 0 {
		t.Fatalf("users = %d, want 0", n)
	}
	// The error is repeated in the fragment (upstream compatibility).
	if fragmentValues(t, loc).Get("error_code") != ErrorCodeSignupDisabled {
		t.Errorf("fragment = %q", loc.Fragment)
	}
}

func TestOAuthCallbackGitHubUsesPrimaryEmail(t *testing.T) {
	env := newExternalEnv(t, nil)

	rec := env.authorize(t, "provider=github&redirect_to=https%3A%2F%2Fapp.test%2Fwelcome", "")
	state := stateFromRedirect(t, rec)
	loc := redirectLocation(t, env.callback(t, state, "auth-code"), http.StatusFound)
	if frag := fragmentValues(t, loc); frag.Get("access_token") == "" {
		t.Fatalf("no session in %s", loc)
	}

	user := env.userByEmail(t, "octo@example.com")
	if user == nil {
		t.Fatal("the primary address must become the account email")
	}
	ids := env.identityRows(t, user.ID)
	if len(ids) != 1 || ids[0].Provider != "github" || ids[0].ProviderID != "4242" {
		t.Fatalf("identities = %+v", ids)
	}
	if ids[0].IdentityData["user_name"] != "octo" || ids[0].IdentityData["preferred_username"] != "octo" {
		t.Errorf("identity_data = %v", ids[0].IdentityData)
	}
}

func TestOAuthCallbackPKCEReturnsCodeAndExchanges(t *testing.T) {
	env := newExternalEnv(t, nil)

	verifier := "dilion-test-verifier-0123456789012345678901234567890123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	rec := env.authorize(t, "provider=google&redirect_to=https%3A%2F%2Fapp.test%2Fwelcome"+
		"&code_challenge_method=s256&code_challenge="+challenge, "")
	state := stateFromRedirect(t, rec)

	loc := redirectLocation(t, env.callback(t, state, "auth-code"), http.StatusFound)
	if loc.Fragment != "" {
		t.Errorf("a PKCE flow must not leak tokens in the fragment: %q", loc.Fragment)
	}
	authCode := loc.Query().Get("code")
	if authCode == "" {
		t.Fatalf("no ?code= in %s", loc)
	}

	// The provider tokens are parked on the flow state for the exchange.
	fs, err := findOAuthFlowStateByID(t.Context(), env.pool, state)
	if err != nil {
		t.Fatalf("flow state: %v", err)
	}
	if fs.UserID == nil {
		t.Error("the callback must claim the flow state for the user")
	}
	if fs.ProviderAccessToken != env.google.accessToken {
		t.Errorf("provider_access_token = %q", fs.ProviderAccessToken)
	}
	if fs.ProviderRefreshToken != env.google.refreshToken {
		t.Errorf("provider_refresh_token = %q", fs.ProviderRefreshToken)
	}

	// Redeeming the code yields the session.
	exchange := env.do(t, http.MethodPost, "/token?grant_type=pkce",
		map[string]any{"auth_code": authCode, "code_verifier": verifier}, "")
	session := decodeInto[AccessTokenResponse](t, exchange, http.StatusOK)
	if session.Token == "" || session.User == nil || session.User.Email != "gina@example.com" {
		t.Fatalf("unexpected session: %+v", session)
	}

	// The code is single use.
	again := env.do(t, http.MethodPost, "/token?grant_type=pkce",
		map[string]any{"auth_code": authCode, "code_verifier": verifier}, "")
	if again.Code != http.StatusNotFound {
		t.Errorf("replayed auth code: status = %d, want 404", again.Code)
	}
}

func TestOAuthCallbackPKCEStateCannotBeReused(t *testing.T) {
	env := newExternalEnv(t, nil)

	verifier := "dilion-test-verifier-0123456789012345678901234567890123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	rec := env.authorize(t, "provider=google&redirect_to=https%3A%2F%2Fapp.test%2Fwelcome"+
		"&code_challenge_method=s256&code_challenge="+challenge, "")
	state := stateFromRedirect(t, rec)
	redirectLocation(t, env.callback(t, state, "auth-code"), http.StatusFound)

	loc := redirectLocation(t, env.callback(t, state, "auth-code"), http.StatusSeeOther)
	if got := loc.Query().Get("error_code"); got != ErrorCodeFlowStateAlreadyUsed {
		t.Fatalf("error_code = %q, want %q", got, ErrorCodeFlowStateAlreadyUsed)
	}
}

func TestOAuthCallbackRejectsTamperedState(t *testing.T) {
	env := newExternalEnv(t, nil)

	rec := env.authorize(t, "provider=google&redirect_to=https%3A%2F%2Fapp.test%2Fwelcome", "")
	state := stateFromRedirect(t, rec)

	// A state that is not a UUID, an unknown UUID, and a single flipped
	// character of a real one all have to be refused, and the bounce goes to
	// SiteURL because a bad state names no redirect target.
	tampered := strings.Replace(state, string(state[0]), map[bool]string{true: "a", false: "b"}[state[0] != 'a'], 1)
	for name, bad := range map[string]string{
		"not a uuid":    "definitely-not-a-uuid",
		"unknown uuid":  "8f14e45f-ce0a-4f2b-9d0b-2f2a2f0e1111",
		"flipped state": tampered,
	} {
		loc := redirectLocation(t, env.callback(t, bad, "auth-code"), http.StatusSeeOther)
		if !strings.HasPrefix(loc.String(), env.cfg.SiteURL) {
			t.Errorf("%s: redirect = %s, want the site URL", name, loc)
		}
		if got := loc.Query().Get("error_code"); got != ErrorCodeBadOAuthState {
			t.Errorf("%s: error_code = %q, want %q", name, got, ErrorCodeBadOAuthState)
		}
	}
	if n := env.countUsers(t); n != 0 {
		t.Fatalf("users = %d, want 0", n)
	}
}

func TestOAuthCallbackRejectsExpiredFlowState(t *testing.T) {
	env := newExternalEnv(t, nil)

	rec := env.authorize(t, "provider=google&redirect_to=https%3A%2F%2Fapp.test%2Fwelcome", "")
	state := stateFromRedirect(t, rec)

	// Age the row past Config.FlowStateExpiry.
	if _, err := env.pool.Exec(t.Context(),
		`update auth.flow_state set created_at = created_at - interval '1 hour' where id = $1::uuid`, state); err != nil {
		t.Fatalf("age flow state: %v", err)
	}

	loc := redirectLocation(t, env.callback(t, state, "auth-code"), http.StatusSeeOther)
	if got := loc.Query().Get("error_code"); got != ErrorCodeBadOAuthState {
		t.Fatalf("error_code = %q, want %q", got, ErrorCodeBadOAuthState)
	}
	if desc := loc.Query().Get("error_description"); !strings.Contains(desc, "expired") {
		t.Errorf("error_description = %q", desc)
	}
}

func TestOAuthCallbackRejectsMissingCodeAndProviderError(t *testing.T) {
	env := newExternalEnv(t, nil)

	rec := env.authorize(t, "provider=google&redirect_to=https%3A%2F%2Fapp.test%2Fwelcome", "")
	state := stateFromRedirect(t, rec)

	loc := redirectLocation(t, env.do(t, http.MethodGet, "/callback?state="+state, nil, ""), http.StatusFound)
	if got := loc.Query().Get("error_code"); got != ErrorCodeBadOAuthCallback {
		t.Errorf("missing code: error_code = %q, want %q", got, ErrorCodeBadOAuthCallback)
	}
	if !strings.HasPrefix(loc.String(), "https://app.test/welcome") {
		t.Errorf("error redirect = %s, want the flow's referrer", loc)
	}

	rec = env.authorize(t, "provider=google&redirect_to=https%3A%2F%2Fapp.test%2Fwelcome", "")
	state = stateFromRedirect(t, rec)
	loc = redirectLocation(t, env.do(t, http.MethodGet,
		"/callback?state="+state+"&error=access_denied&error_description=User+said+no", nil, ""), http.StatusFound)
	if got := loc.Query().Get("error"); got != "access_denied" {
		t.Errorf("provider error passthrough: error = %q", got)
	}
}

// ---- grant_type=id_token -----------------------------------------------------

func (e *externalEnv) idTokenGrantRequest(t *testing.T, body map[string]any, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	return e.do(t, http.MethodPost, "/token?grant_type=id_token", body, bearer)
}

func TestIDTokenGrantSignsUserIn(t *testing.T) {
	env := newExternalEnv(t, nil)

	nonce := "client-nonce-value"
	env.google.nonce = fmt.Sprintf("%x", sha256.Sum256([]byte(nonce)))

	rec := env.idTokenGrantRequest(t, map[string]any{
		"provider":     "google",
		"id_token":     env.google.signIDToken(nil),
		"access_token": env.google.accessToken,
		"nonce":        nonce,
	}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if session.Token == "" || session.User == nil {
		t.Fatalf("no session: %s", rec.Body.String())
	}
	if session.User.Email != "gina@example.com" {
		t.Errorf("email = %q", session.User.Email)
	}
	ids := env.identityRows(t, session.User.ID)
	if len(ids) != 1 || ids[0].Provider != "google" {
		t.Fatalf("identities = %+v", ids)
	}
	if env.google.tokenRequests != 0 {
		t.Errorf("the id_token grant must not call the provider's token endpoint")
	}
}

func TestIDTokenGrantRejectsBadTokens(t *testing.T) {
	env := newExternalEnv(t, nil)

	badAlg := func() string {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"iss": env.google.srv.URL,
			"sub": env.google.sub,
			"aud": "google-client-id",
			"exp": time.Now().Add(time.Hour).Unix(),
		})
		s, err := tok.SignedString([]byte("not-a-real-key"))
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return s
	}()

	cases := []struct {
		name  string
		body  map[string]any
		error string
	}{
		{
			name:  "wrong audience",
			body:  map[string]any{"provider": "google", "id_token": env.google.signIDToken(map[string]any{"aud": "some-other-app"})},
			error: "invalid request",
		},
		{
			name:  "expired",
			body:  map[string]any{"provider": "google", "id_token": env.google.signIDToken(map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})},
			error: "invalid request",
		},
		{
			name:  "symmetric algorithm",
			body:  map[string]any{"provider": "google", "id_token": badAlg},
			error: "invalid request",
		},
		{
			name: "nonce mismatch",
			body: map[string]any{
				"provider": "google",
				"id_token": env.google.signIDToken(map[string]any{"nonce": fmt.Sprintf("%x", sha256.Sum256([]byte("other")))}),
				"nonce":    "client-nonce-value",
			},
			error: "invalid nonce",
		},
		{
			name: "nonce missing from the request",
			body: map[string]any{
				"provider": "google",
				"id_token": env.google.signIDToken(map[string]any{"nonce": fmt.Sprintf("%x", sha256.Sum256([]byte("x")))}),
			},
			error: "invalid request",
		},
		{
			name:  "missing id_token",
			body:  map[string]any{"provider": "google"},
			error: "invalid request",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := env.idTokenGrantRequest(t, tc.body, "")
			body := decodeInto[oauthErrorBody](t, rec, http.StatusBadRequest)
			if body.Err != tc.error {
				t.Fatalf("error = %q, want %q (body %s)", body.Err, tc.error, rec.Body.String())
			}
		})
	}
	if n := env.countUsers(t); n != 0 {
		t.Fatalf("users = %d, want 0 — no rejected token may create an account", n)
	}
}

func TestIDTokenGrantRejectsDisabledAndUnknownProviders(t *testing.T) {
	env := newExternalEnv(t, nil)

	rec := env.idTokenGrantRequest(t, map[string]any{
		"provider": "kakao", "id_token": env.google.signIDToken(nil),
	}, "")
	body := decodeInto[HTTPError](t, rec, http.StatusBadRequest)
	if body.ErrorCode != ErrorCodeProviderDisabled {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeProviderDisabled)
	}

	rec = env.idTokenGrantRequest(t, map[string]any{
		"issuer": "https://issuer.evil.test", "client_id": "x", "id_token": env.google.signIDToken(nil),
	}, "")
	body = decodeInto[HTTPError](t, rec, http.StatusBadRequest)
	if body.ErrorCode != ErrorCodeValidationFailed {
		t.Errorf("unknown issuer: error_code = %q, want %q", body.ErrorCode, ErrorCodeValidationFailed)
	}
}

// ---- identity linking --------------------------------------------------------

func TestLinkIdentityRequiresManualLinking(t *testing.T) {
	env := newExternalEnv(t, nil)
	session := env.signup(t, "owner@example.com", "hunter22-strong")

	rec := env.do(t, http.MethodGet, "/user/identities/authorize?provider=google", nil, session.Token)
	body := decodeInto[HTTPError](t, rec, http.StatusUnprocessableEntity)
	if body.ErrorCode != ErrorCodeManualLinkingDisabled {
		t.Fatalf("error_code = %q, want %q", body.ErrorCode, ErrorCodeManualLinkingDisabled)
	}

	// And it needs a token at all.
	rec = env.do(t, http.MethodGet, "/user/identities/authorize?provider=google", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestLinkIdentityAttachesProviderToCaller(t *testing.T) {
	cfg := externalTestConfig()
	cfg.Security.ManualLinkingEnabled = true
	env := newExternalEnv(t, cfg)

	session := env.signup(t, "owner@example.com", "hunter22-strong")

	rec := env.do(t, http.MethodGet,
		"/user/identities/authorize?provider=google&redirect_to=https%3A%2F%2Fapp.test%2Fwelcome", nil, session.Token)
	state := stateFromRedirect(t, rec)

	fs, err := findOAuthFlowStateByID(t.Context(), env.pool, state)
	if err != nil {
		t.Fatalf("flow state: %v", err)
	}
	if fs.LinkingTargetID == nil || *fs.LinkingTargetID != session.User.ID {
		t.Fatalf("linking_target_id = %v, want %s", fs.LinkingTargetID, session.User.ID)
	}

	redirectLocation(t, env.callback(t, state, "auth-code"), http.StatusFound)

	if n := env.countUsers(t); n != 1 {
		t.Fatalf("users = %d, want 1 — linking must not create an account", n)
	}
	ids := env.identityRows(t, session.User.ID)
	if len(ids) != 2 {
		t.Fatalf("identities = %d, want 2", len(ids))
	}
	user := decodeInto[User](t, env.do(t, http.MethodGet, "/user", nil, session.Token), http.StatusOK)
	if len(user.Identities) != 2 {
		t.Fatalf("GET /user identities = %d, want 2", len(user.Identities))
	}

	// Linking the same provider identity again is refused.
	rec = env.do(t, http.MethodGet, "/user/identities/authorize?provider=google", nil, session.Token)
	state = stateFromRedirect(t, rec)
	loc := redirectLocation(t, env.callback(t, state, "auth-code"), http.StatusFound)
	if got := loc.Query().Get("error_code"); got != ErrorCodeIdentityAlreadyExists {
		t.Fatalf("error_code = %q, want %q", got, ErrorCodeIdentityAlreadyExists)
	}
}

func TestUnlinkIdentity(t *testing.T) {
	cfg := externalTestConfig()
	cfg.Security.ManualLinkingEnabled = true
	env := newExternalEnv(t, cfg)

	session := env.signup(t, "owner@example.com", "hunter22-strong")
	rec := env.do(t, http.MethodGet, "/user/identities/authorize?provider=google", nil, session.Token)
	redirectLocation(t, env.callback(t, stateFromRedirect(t, rec), "auth-code"), http.StatusFound)

	ids := env.identityRows(t, session.User.ID)
	if len(ids) != 2 {
		t.Fatalf("identities = %d, want 2", len(ids))
	}
	var googleIdentity, emailIdentity Identity
	for _, i := range ids {
		if i.Provider == "google" {
			googleIdentity = i
		} else {
			emailIdentity = i
		}
	}

	// An identity that is not the caller's.
	other := env.do(t, http.MethodDelete,
		"/user/identities/8f14e45f-ce0a-4f2b-9d0b-2f2a2f0e1111", nil, session.Token)
	body := decodeInto[HTTPError](t, other, http.StatusUnprocessableEntity)
	if body.ErrorCode != ErrorCodeIdentityNotFound {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeIdentityNotFound)
	}

	// A malformed id.
	bad := env.do(t, http.MethodDelete, "/user/identities/not-a-uuid", nil, session.Token)
	if bad.Code != http.StatusNotFound {
		t.Errorf("malformed identity id: status = %d, want 404", bad.Code)
	}

	// The real unlink.
	ok := env.do(t, http.MethodDelete, "/user/identities/"+googleIdentity.ID, nil, session.Token)
	if ok.Code != http.StatusOK {
		t.Fatalf("unlink: status = %d, body = %s", ok.Code, ok.Body.String())
	}
	if ids := env.identityRows(t, session.User.ID); len(ids) != 1 {
		t.Fatalf("identities after unlink = %d, want 1", len(ids))
	}
	user := env.userByEmail(t, "owner@example.com")
	providers, _ := user.AppMetaData["providers"].([]any)
	if len(providers) != 1 || providers[0] != "email" {
		t.Errorf("app_metadata.providers = %v", user.AppMetaData["providers"])
	}

	// The last identity may never be removed.
	last := env.do(t, http.MethodDelete, "/user/identities/"+emailIdentity.ID, nil, session.Token)
	body = decodeInto[HTTPError](t, last, http.StatusUnprocessableEntity)
	if body.ErrorCode != ErrorCodeSingleIdentityNotDeletable {
		t.Fatalf("error_code = %q, want %q", body.ErrorCode, ErrorCodeSingleIdentityNotDeletable)
	}
}

// TestOAuthCallbackAcceptsFormPost covers the Apple shape: the provider POSTs
// the callback as an HTML form rather than redirecting with a query string.
func TestOAuthCallbackAcceptsFormPost(t *testing.T) {
	env := newExternalEnv(t, nil)

	rec := env.authorize(t, "provider=google&redirect_to=https%3A%2F%2Fapp.test%2Fwelcome", "")
	state := stateFromRedirect(t, rec)

	form := url.Values{"state": {state}, "code": {"auth-code"}}
	req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.7:41234"
	post := httptest.NewRecorder()
	env.router.ServeHTTP(post, req)

	loc := redirectLocation(t, post, http.StatusFound)
	if fragmentValues(t, loc).Get("access_token") == "" {
		t.Fatalf("no session in %s", loc)
	}
	if env.userByEmail(t, "gina@example.com") == nil {
		t.Fatal("the form-post callback must create the account")
	}
}

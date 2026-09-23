package auth

// Database-backed tests for the OAuth 2.1 authorization-server surface. Like
// every other *_db_test.go in this package they only run when DILION_TEST_DB is
// set:
//
//	docker exec dilion-db createdb -U dilion dilion_test_oas
//	DILION_TEST_DB=postgres://dilion:dilion@localhost:55432/dilion_test_oas \
//	  go test -run 'OAuthServer|DCR|Consent|UserInfo' -race ./internal/auth/...
//
// The mount under test signs ES256 (an OIDC id_token cannot be signed HS256),
// runs on a stubbed clock so authorization expiry is testable without sleeping,
// and has the OAuth server enabled unless a test says otherwise.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

// ---- harness ---------------------------------------------------------------

type oauthEnv struct {
	*testEnv
	clock *stepClock
	cfg   *Config
}

// newOAuthEnv builds a /auth/v1 mount with the OAuth server enabled and an
// ES256 key set.
func newOAuthEnv(t *testing.T, mutate func(*Config)) *oauthEnv {
	t.Helper()
	return newOAuthEnvWithDeps(t, mutate, nil)
}

// newOAuthEnvWithDeps is newOAuthEnv with a hook to adjust the mount's Deps
// (a code-defined client resolver, say) before it is registered.
func newOAuthEnvWithDeps(t *testing.T, mutate func(*Config), mutateDeps func(*Deps)) *oauthEnv {
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
	// auth.mfa_amr_claims lives in 0112 and every session records its sign-in
	// method there, so the OAuth flow needs it too.
	applyMFASchema(t, pool)
	applyOAuthServerSchema(t, pool)
	truncateOAuthAll(t, pool)

	signing, _ := newTestJWK(t, "oauth-test-key", "sign")
	cfg := configWithKeys(t, string(testSecret()), signing)
	cfg.OAuthServer.Enabled = true
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	clock := &stepClock{t: time.Now().UTC().Truncate(time.Second)}
	tokens := mustTokenService(t, cfg).WithClock(clock)

	env := &oauthEnv{
		testEnv: &testEnv{
			pool:   pool,
			tokens: tokens,
			hooks:  hooks.NewRegistry(),
			mailer: &captureMailer{},
		},
		clock: clock,
		cfg:   cfg,
	}
	env.router = chi.NewRouter()
	deps := Deps{
		Pool:   pool,
		Tokens: tokens,
		Mailer: env.mailer,
		Hooks:  env.hooks,
		Config: cfg,
		Clock:  clock,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	if mutateDeps != nil {
		mutateDeps(&deps)
	}
	Register(env.router, deps)
	return env
}

// applyOAuthServerSchema installs migration 0116, which the shared harness
// (0100 only) does not apply.
func applyOAuthServerSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	path := filepath.Join("..", "..", "migrations", "0116_auth_oauth_server.sql")
	sql, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read 0116_auth_oauth_server.sql: %v", err)
	}
	if _, err := pool.Exec(context.Background(), string(sql)); err != nil {
		t.Fatalf("apply 0116_auth_oauth_server.sql: %v", err)
	}
}

func truncateOAuthAll(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`truncate auth.users, auth.sessions, auth.refresh_tokens, auth.identities,
		          auth.mfa_amr_claims, auth.oauth_clients, auth.oauth_authorizations, auth.oauth_consents,
		          dilion_privacy.outbox restart identity cascade`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
}

// ---- request helpers -------------------------------------------------------

// doForm issues an application/x-www-form-urlencoded request, optionally with
// HTTP Basic client credentials.
func (e *oauthEnv) doForm(t *testing.T, method, path string, form url.Values, basicID, basicSecret string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.7:41234"
	if basicID != "" {
		req.SetBasicAuth(basicID, basicSecret)
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

// registerClient creates a client through the admin surface and returns the
// response (client_secret included, exactly once).
func (e *oauthEnv) registerClient(t *testing.T, body map[string]any) OAuthClientResponse {
	t.Helper()
	rec := e.do(t, http.MethodPost, "/admin/oauth/clients", body, e.serviceRoleToken(t))
	return decodeInto[OAuthClientResponse](t, rec, http.StatusCreated)
}

// codeChallengeS256 is the client side of PKCE.
func codeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

const testCodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

const testRedirectURI = "https://app.example.com/callback"

// authorize starts an authorization request and returns the authorization_id
// the browser would be redirected to the consent page with.
func (e *oauthEnv) authorize(t *testing.T, clientID, scope, state string, extra url.Values) string {
	t.Helper()
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"scope":                 {scope},
		"state":                 {state},
		"code_challenge":        {codeChallengeS256(testCodeVerifier)},
		"code_challenge_method": {"S256"},
	}
	for k, vs := range extra {
		q[k] = vs
	}
	rec := e.do(t, http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, "")
	if rec.Code != http.StatusFound {
		t.Fatalf("GET /oauth/authorize status = %d, want 302; body = %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	id := loc.Query().Get("authorization_id")
	if id == "" {
		t.Fatalf("Location %q carries no authorization_id", loc.String())
	}
	if !strings.HasPrefix(loc.String(), e.cfg.SiteURL+OAuthServerAuthorizationPath) {
		t.Errorf("consent redirect = %q, want it under %q", loc.String(), e.cfg.SiteURL+OAuthServerAuthorizationPath)
	}
	return id
}

// consent approves or denies an authorization and returns the redirect_url.
func (e *oauthEnv) consent(t *testing.T, authorizationID, userToken, action string) string {
	t.Helper()
	rec := e.do(t, http.MethodPost, "/oauth/authorizations/"+authorizationID+"/consent",
		map[string]any{"action": action}, userToken)
	resp := decodeInto[ConsentResponse](t, rec, http.StatusOK)
	if resp.RedirectURL == "" {
		t.Fatalf("consent returned no redirect_url; body = %s", rec.Body.String())
	}
	return resp.RedirectURL
}

// claimAndApprove runs the consent-page half of the flow: claim the pending
// authorization for the signed-in user and approve it. A user who has already
// consented to these scopes is auto-approved by the GET itself, in which case
// there is no decision left to POST.
func (e *oauthEnv) claimAndApprove(t *testing.T, authorizationID, userToken, wantState string) string {
	t.Helper()
	claimed := decodeInto[map[string]any](t,
		e.do(t, http.MethodGet, "/oauth/authorizations/"+authorizationID, nil, userToken), http.StatusOK)
	if redirectURL, ok := claimed["redirect_url"].(string); ok && redirectURL != "" {
		return codeFrom(t, redirectURL, wantState)
	}
	return codeFrom(t, e.consent(t, authorizationID, userToken, "approve"), wantState)
}

// codeFrom pulls ?code= (and asserts ?state=) out of a success redirect URL.
func codeFrom(t *testing.T, redirectURL, wantState string) string {
	t.Helper()
	u, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parse redirect_url: %v", err)
	}
	if got := u.Query().Get("state"); got != wantState {
		t.Errorf("state = %q, want %q", got, wantState)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("redirect_url %q carries no code", redirectURL)
	}
	return code
}

// ---- dynamic client registration -------------------------------------------

func TestOAuthServerDCRRegistersPublicAndConfidentialClients(t *testing.T) {
	env := newOAuthEnv(t, nil)

	t.Run("confidential by default", func(t *testing.T) {
		rec := env.do(t, http.MethodPost, "/oauth/clients/register", map[string]any{
			"redirect_uris": []string{testRedirectURI},
			"client_name":   "Dynamic Confidential",
		}, "")
		resp := decodeInto[OAuthClientResponse](t, rec, http.StatusCreated)

		if resp.ClientType != OAuthClientTypeConfidential {
			t.Errorf("client_type = %q, want confidential", resp.ClientType)
		}
		// RFC 7591: an omitted method defaults to client_secret_basic.
		if resp.TokenEndpointAuthMethod != TokenEndpointAuthMethodClientSecretBasic {
			t.Errorf("token_endpoint_auth_method = %q", resp.TokenEndpointAuthMethod)
		}
		if resp.ClientSecret == "" {
			t.Error("a confidential client must receive its secret exactly once, at registration")
		}
		if resp.RegistrationType != OAuthRegistrationDynamic {
			t.Errorf("registration_type = %q, want dynamic", resp.RegistrationType)
		}
		if len(resp.GrantTypes) != 2 {
			t.Errorf("grant_types = %v, want both authorization_code and refresh_token", resp.GrantTypes)
		}

		// The secret is returned ONCE: reading the client back never shows it.
		read := decodeInto[OAuthClientResponse](t,
			env.do(t, http.MethodGet, "/admin/oauth/clients/"+resp.ClientID, nil, env.serviceRoleToken(t)),
			http.StatusOK)
		if read.ClientSecret != "" {
			t.Error("GET must never return the client secret")
		}
	})

	t.Run("public with token_endpoint_auth_method none", func(t *testing.T) {
		rec := env.do(t, http.MethodPost, "/oauth/clients/register", map[string]any{
			"redirect_uris":              []string{"myapp://cb"},
			"token_endpoint_auth_method": TokenEndpointAuthMethodNone,
		}, "")
		resp := decodeInto[OAuthClientResponse](t, rec, http.StatusCreated)

		if resp.ClientType != OAuthClientTypePublic {
			t.Errorf("client_type = %q, want public", resp.ClientType)
		}
		if resp.ClientSecret != "" {
			t.Error("a public client must never be issued a secret")
		}
	})

	t.Run("inconsistent client_type and auth method", func(t *testing.T) {
		rec := env.do(t, http.MethodPost, "/oauth/clients/register", map[string]any{
			"redirect_uris":              []string{testRedirectURI},
			"client_type":                OAuthClientTypePublic,
			"token_endpoint_auth_method": TokenEndpointAuthMethodClientSecretBasic,
		}, "")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("rejects a non-loopback http redirect_uri", func(t *testing.T) {
		rec := env.do(t, http.MethodPost, "/oauth/clients/register", map[string]any{
			"redirect_uris": []string{"http://app.example.com/cb"},
		}, "")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
		}
	})
}

// ---- admin CRUD ------------------------------------------------------------

func TestOAuthServerAdminClientCRUDAndRegenerateSecret(t *testing.T) {
	env := newOAuthEnv(t, nil)
	admin := env.serviceRoleToken(t)

	created := env.registerClient(t, map[string]any{
		"redirect_uris": []string{testRedirectURI},
		"client_name":   "Admin Registered",
		"client_uri":    "https://app.example.com",
	})
	if created.RegistrationType != OAuthRegistrationManual {
		t.Errorf("registration_type = %q, want manual", created.RegistrationType)
	}
	firstSecret := created.ClientSecret
	if firstSecret == "" {
		t.Fatal("no client_secret returned")
	}

	list := decodeInto[OAuthClientListResponse](t,
		env.do(t, http.MethodGet, "/admin/oauth/clients", nil, admin), http.StatusOK)
	if len(list.Clients) != 1 || list.Clients[0].ClientID != created.ClientID {
		t.Fatalf("list = %+v", list.Clients)
	}

	updated := decodeInto[OAuthClientResponse](t,
		env.do(t, http.MethodPut, "/admin/oauth/clients/"+created.ClientID, map[string]any{
			"client_name":                "Renamed",
			"token_endpoint_auth_method": TokenEndpointAuthMethodClientSecretPost,
		}, admin), http.StatusOK)
	if updated.ClientName != "Renamed" {
		t.Errorf("client_name = %q", updated.ClientName)
	}
	if updated.TokenEndpointAuthMethod != TokenEndpointAuthMethodClientSecretPost {
		t.Errorf("token_endpoint_auth_method = %q", updated.TokenEndpointAuthMethod)
	}
	if len(updated.RedirectURIs) != 1 || updated.RedirectURIs[0] != testRedirectURI {
		t.Errorf("redirect_uris changed on a partial update: %v", updated.RedirectURIs)
	}

	if rec := env.do(t, http.MethodPut, "/admin/oauth/clients/"+created.ClientID, map[string]any{}, admin); rec.Code != http.StatusBadRequest {
		t.Errorf("empty update status = %d, want 400", rec.Code)
	}
	// client_type is immutable, so `none` is not a legal method for it.
	if rec := env.do(t, http.MethodPut, "/admin/oauth/clients/"+created.ClientID,
		map[string]any{"token_endpoint_auth_method": TokenEndpointAuthMethodNone}, admin); rec.Code != http.StatusBadRequest {
		t.Errorf("confidential client accepting 'none' status = %d, want 400", rec.Code)
	}

	regenerated := decodeInto[OAuthClientResponse](t,
		env.do(t, http.MethodPost, "/admin/oauth/clients/"+created.ClientID+"/regenerate_secret", nil, admin),
		http.StatusOK)
	if regenerated.ClientSecret == "" || regenerated.ClientSecret == firstSecret {
		t.Error("regenerate_secret must return a NEW secret")
	}

	// A non-admin caller is refused.
	user := env.signup(t, "notadmin@example.com", "hunter22")
	if rec := env.do(t, http.MethodGet, "/admin/oauth/clients", nil, user.Token); rec.Code != http.StatusForbidden {
		t.Errorf("non-admin list status = %d, want 403", rec.Code)
	}

	if rec := env.do(t, http.MethodDelete, "/admin/oauth/clients/"+created.ClientID, nil, admin); rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204; body = %s", rec.Code, rec.Body.String())
	}
	rec := env.do(t, http.MethodGet, "/admin/oauth/clients/"+created.ClientID, nil, admin)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET after delete status = %d, want 404", rec.Code)
	}
	if body := decodeInto[HTTPError](t, rec, http.StatusNotFound); body.ErrorCode != ErrorCodeOAuthClientNotFound {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeOAuthClientNotFound)
	}
}

// ---- the full authorization-code flow --------------------------------------

func TestOAuthServerAuthorizationCodeFlowIssuesVerifiableTokens(t *testing.T) {
	env := newOAuthEnv(t, nil)

	client := env.registerClient(t, map[string]any{
		"redirect_uris": []string{testRedirectURI},
		"client_name":   "Flow App",
	})
	user := env.signup(t, "flow@example.com", "hunter22")

	authorizationID := env.authorize(t, client.ClientID, "openid email profile", "state-123",
		url.Values{"nonce": {"nonce-abc"}})

	// The consent screen payload.
	details := decodeInto[AuthorizationDetailsResponse](t,
		env.do(t, http.MethodGet, "/oauth/authorizations/"+authorizationID, nil, user.Token), http.StatusOK)
	if details.AuthorizationID != authorizationID {
		t.Errorf("authorization_id = %q", details.AuthorizationID)
	}
	if details.Client.ID != client.ClientID || details.Client.Name != "Flow App" {
		t.Errorf("client details = %+v", details.Client)
	}
	if details.User.Email != "flow@example.com" {
		t.Errorf("user details = %+v", details.User)
	}
	if details.Scope != "openid email profile" {
		t.Errorf("scope = %q", details.Scope)
	}

	code := codeFrom(t, env.consent(t, authorizationID, user.Token, "approve"), "state-123")

	// Redeem it: HTTP Basic client authentication + PKCE verifier.
	rec := env.doForm(t, http.MethodPost, "/oauth/token", url.Values{
		"grant_type":    {GrantTypeAuthorizationCode},
		"code":          {code},
		"redirect_uri":  {testRedirectURI},
		"code_verifier": {testCodeVerifier},
	}, client.ClientID, client.ClientSecret)
	tokens := decodeInto[OAuthTokenResponse](t, rec, http.StatusOK)

	if tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.IDToken == "" {
		t.Fatalf("token response = %+v", tokens)
	}
	if tokens.TokenType != "bearer" {
		t.Errorf("token_type = %q, want bearer", tokens.TokenType)
	}

	// The OAuth token body must NOT carry the gotrue session envelope's user.
	var raw map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := raw["user"]; ok {
		t.Error("the OAuth token response must not embed the user object")
	}

	// The access token verifies, is ES256, and carries client_id + scope.
	claims, err := env.tokens.Verify(context.Background(), tokens.AccessToken)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if alg, kid := peekHeader(tokens.AccessToken); alg != AlgES256 || kid != "oauth-test-key" {
		t.Errorf("access token header alg/kid = %q/%q", alg, kid)
	}
	if claims.Subject != user.User.ID {
		t.Errorf("sub = %q, want %q", claims.Subject, user.User.ID)
	}
	if got, _ := claims.Extra["client_id"].(string); got != client.ClientID {
		t.Errorf("client_id claim = %q, want %q", got, client.ClientID)
	}
	if got, _ := claims.Extra["scope"].(string); got != "openid email profile" {
		t.Errorf("scope claim = %q", got)
	}

	// The ID token is audienced at the CLIENT and replays the nonce.
	idClaims := parseIDToken(t, env, tokens.IDToken)
	if aud := audienceString(idClaims["aud"]); aud != client.ClientID {
		t.Errorf("id_token aud = %v, want the client id", idClaims["aud"])
	}
	if idClaims["sub"] != user.User.ID {
		t.Errorf("id_token sub = %v", idClaims["sub"])
	}
	if idClaims["nonce"] != "nonce-abc" {
		t.Errorf("id_token nonce = %v, want nonce-abc", idClaims["nonce"])
	}
	if idClaims["email"] != "flow@example.com" {
		t.Errorf("id_token email = %v", idClaims["email"])
	}
	if idClaims["iss"] != issuerURL(env.cfg, nil) {
		t.Errorf("id_token iss = %v, want %q", idClaims["iss"], issuerURL(env.cfg, nil))
	}
	if _, ok := idClaims["auth_time"]; !ok {
		t.Error("id_token is missing auth_time")
	}

	// The code is single use.
	if rec := env.doForm(t, http.MethodPost, "/oauth/token", url.Values{
		"grant_type":    {GrantTypeAuthorizationCode},
		"code":          {code},
		"code_verifier": {testCodeVerifier},
	}, client.ClientID, client.ClientSecret); rec.Code != http.StatusBadRequest {
		t.Errorf("replaying the code status = %d, want 400", rec.Code)
	} else if body := decodeInto[OAuthError](t, rec, http.StatusBadRequest); body.Err != oAuth2ErrorInvalidGrant {
		t.Errorf("replay error = %q, want invalid_grant", body.Err)
	}

	// The refresh token rotates, and the new access token keeps the OAuth claims.
	refreshed := decodeInto[OAuthTokenResponse](t, env.doForm(t, http.MethodPost, "/oauth/token", url.Values{
		"grant_type":    {GrantTypeRefreshToken},
		"refresh_token": {tokens.RefreshToken},
	}, client.ClientID, client.ClientSecret), http.StatusOK)
	if refreshed.RefreshToken == "" || refreshed.RefreshToken == tokens.RefreshToken {
		t.Error("the refresh token must rotate")
	}
	refreshedClaims, err := env.tokens.Verify(context.Background(), refreshed.AccessToken)
	if err != nil {
		t.Fatalf("verify refreshed access token: %v", err)
	}
	if got, _ := refreshedClaims.Extra["client_id"].(string); got != client.ClientID {
		t.Errorf("refreshed client_id claim = %q", got)
	}

	// /oauth/userinfo, filtered by the granted scopes.
	info := decodeInto[map[string]any](t,
		env.do(t, http.MethodGet, "/oauth/userinfo", nil, refreshed.AccessToken), http.StatusOK)
	if info["sub"] != user.User.ID {
		t.Errorf("userinfo sub = %v", info["sub"])
	}
	if info["email"] != "flow@example.com" {
		t.Errorf("userinfo email = %v", info["email"])
	}
	if _, ok := info["phone"]; ok {
		t.Error("userinfo leaked a phone claim without the phone scope")
	}
	if _, ok := info["name"]; !ok {
		t.Error("userinfo is missing name despite the profile scope")
	}

	// The user can see and revoke the grant.
	grants := decodeInto[[]UserOAuthGrantResponse](t,
		env.do(t, http.MethodGet, "/user/oauth/grants", nil, user.Token), http.StatusOK)
	if len(grants) != 1 || grants[0].Client.ID != client.ClientID {
		t.Fatalf("grants = %+v", grants)
	}
	if !hasAllScopes(grants[0].Scopes, []string{ScopeOpenID, ScopeEmail, ScopeProfile}) {
		t.Errorf("granted scopes = %v", grants[0].Scopes)
	}

	if rec := env.do(t, http.MethodDelete, "/user/oauth/grants?client_id="+client.ClientID, nil, user.Token); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want 204; body = %s", rec.Code, rec.Body.String())
	}
	// Revoking destroys the client's sessions, so its refresh token dies with them.
	if rec := env.doForm(t, http.MethodPost, "/oauth/token", url.Values{
		"grant_type":    {GrantTypeRefreshToken},
		"refresh_token": {refreshed.RefreshToken},
	}, client.ClientID, client.ClientSecret); rec.Code != http.StatusBadRequest {
		t.Errorf("refresh after revocation status = %d, want 400", rec.Code)
	}
	if rec := env.do(t, http.MethodDelete, "/user/oauth/grants?client_id="+client.ClientID, nil, user.Token); rec.Code != http.StatusNotFound {
		t.Errorf("second revoke status = %d, want 404", rec.Code)
	}
}

// parseIDToken parses an ID token against the mount's ES256 public key.
func parseIDToken(t *testing.T, env *oauthEnv, idToken string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{AlgES256}), jwt.WithTimeFunc(env.clock.Now))
	if _, err := parser.ParseWithClaims(idToken, claims, func(*jwt.Token) (any, error) {
		return env.tokens.sign.pub, nil
	}); err != nil {
		t.Fatalf("parse id_token: %v", err)
	}
	return claims
}

// ---- consent: skip, deny ---------------------------------------------------

func TestOAuthServerConsentIsSkippedOnReAuthorization(t *testing.T) {
	env := newOAuthEnv(t, nil)
	client := env.registerClient(t, map[string]any{"redirect_uris": []string{testRedirectURI}})
	user := env.signup(t, "repeat@example.com", "hunter22")

	first := env.authorize(t, client.ClientID, "openid email", "s1", nil)
	env.claimAndApprove(t, first, user.Token, "s1")

	// Same scopes again: the GET auto-approves and answers with the redirect
	// URL instead of a consent payload.
	second := env.authorize(t, client.ClientID, "openid email", "s2", nil)
	auto := decodeInto[ConsentResponse](t,
		env.do(t, http.MethodGet, "/oauth/authorizations/"+second, nil, user.Token), http.StatusOK)
	if auto.RedirectURL == "" {
		t.Fatal("a previously consented client must skip the consent screen")
	}
	codeFrom(t, auto.RedirectURL, "s2")

	// A WIDER scope is not covered by the stored consent, so it asks again.
	third := env.authorize(t, client.ClientID, "openid email profile", "s3", nil)
	details := decodeInto[AuthorizationDetailsResponse](t,
		env.do(t, http.MethodGet, "/oauth/authorizations/"+third, nil, user.Token), http.StatusOK)
	if details.AuthorizationID != third {
		t.Errorf("a newly requested scope must be consented to again; got %+v", details)
	}
}

func TestOAuthServerConsentDenyRedirectsWithAccessDenied(t *testing.T) {
	env := newOAuthEnv(t, nil)
	client := env.registerClient(t, map[string]any{"redirect_uris": []string{testRedirectURI}})
	user := env.signup(t, "deny@example.com", "hunter22")

	authorizationID := env.authorize(t, client.ClientID, "openid", "deny-state", nil)
	if rec := env.do(t, http.MethodGet, "/oauth/authorizations/"+authorizationID, nil, user.Token); rec.Code != http.StatusOK {
		t.Fatalf("claim status = %d; body = %s", rec.Code, rec.Body.String())
	}

	redirect := env.consent(t, authorizationID, user.Token, "deny")
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("parse redirect_url: %v", err)
	}
	if got := u.Query().Get("error"); got != oAuth2ErrorAccessDenied {
		t.Errorf("error = %q, want access_denied", got)
	}
	if got := u.Query().Get("state"); got != "deny-state" {
		t.Errorf("state = %q", got)
	}
	if u.Query().Get("code") != "" {
		t.Error("a denied authorization must not carry a code")
	}

	// The row is no longer pending.
	if rec := env.do(t, http.MethodPost, "/oauth/authorizations/"+authorizationID+"/consent",
		map[string]any{"action": "approve"}, user.Token); rec.Code != http.StatusBadRequest {
		t.Errorf("second decision status = %d, want 400", rec.Code)
	}

	// Nothing was stored, so a fresh request asks again.
	if _, err := findActiveOAuthConsent(context.Background(), env.pool, user.User.ID, client.ClientID); err != nil {
		t.Fatalf("findActiveOAuthConsent: %v", err)
	}
}

// ---- authorization endpoint validation -------------------------------------

func TestOAuthServerAuthorizeValidatesClientAndRedirectURI(t *testing.T) {
	env := newOAuthEnv(t, nil)
	client := env.registerClient(t, map[string]any{"redirect_uris": []string{testRedirectURI}})

	base := url.Values{
		"client_id":             {client.ClientID},
		"redirect_uri":          {testRedirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"code_challenge":        {codeChallengeS256(testCodeVerifier)},
		"code_challenge_method": {"S256"},
	}
	with := func(mutate func(url.Values)) string {
		q := url.Values{}
		for k, v := range base {
			q[k] = append([]string(nil), v...)
		}
		mutate(q)
		return "/oauth/authorize?" + q.Encode()
	}

	t.Run("unregistered redirect_uri is a JSON 400, never a redirect", func(t *testing.T) {
		rec := env.do(t, http.MethodGet, with(func(q url.Values) {
			q.Set("redirect_uri", "https://evil.example.com/cb")
		}), nil, "")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
		}
		if body := decodeInto[HTTPError](t, rec, http.StatusBadRequest); body.ErrorCode != ErrorCodeValidationFailed {
			t.Errorf("error_code = %q", body.ErrorCode)
		}
	})

	t.Run("unknown client_id is a JSON 400", func(t *testing.T) {
		rec := env.do(t, http.MethodGet, with(func(q url.Values) {
			q.Set("client_id", "11111111-1111-4111-8111-111111111111")
		}), nil, "")
		if body := decodeInto[HTTPError](t, rec, http.StatusBadRequest); body.ErrorCode != ErrorCodeOAuthClientNotFound {
			t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeOAuthClientNotFound)
		}
	})

	t.Run("missing redirect_uri is a JSON 400", func(t *testing.T) {
		rec := env.do(t, http.MethodGet, with(func(q url.Values) { q.Del("redirect_uri") }), nil, "")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})

	// Once the redirect target is trusted, errors travel on it.
	for name, mutate := range map[string]func(url.Values){
		"unsupported scope":     func(q url.Values) { q.Set("scope", "openid admin") },
		"missing PKCE":          func(q url.Values) { q.Del("code_challenge"); q.Del("code_challenge_method") },
		"short code_challenge":  func(q url.Values) { q.Set("code_challenge", "too-short") },
		"bad response_type":     func(q url.Values) { q.Set("response_type", "token") },
		"resource with a query": func(q url.Values) { q.Set("resource", "https://api.example.com/?x=1") },
	} {
		t.Run(name+" redirects with invalid_request", func(t *testing.T) {
			rec := env.do(t, http.MethodGet, with(mutate), nil, "")
			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302; body = %s", rec.Code, rec.Body.String())
			}
			loc, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse Location: %v", err)
			}
			if !strings.HasPrefix(loc.String(), testRedirectURI) {
				t.Fatalf("error went to %q, want the client's redirect_uri", loc.String())
			}
			if got := loc.Query().Get("error"); got != oAuth2ErrorInvalidRequest {
				t.Errorf("error = %q, want invalid_request", got)
			}
			if loc.Query().Get("error_description") == "" {
				t.Error("error_description is empty")
			}
		})
	}
}

func TestOAuthServerAuthorizationExpires(t *testing.T) {
	env := newOAuthEnv(t, nil)
	client := env.registerClient(t, map[string]any{"redirect_uris": []string{testRedirectURI}})
	user := env.signup(t, "expired@example.com", "hunter22")

	authorizationID := env.authorize(t, client.ClientID, "openid", "s", nil)
	env.clock.advance(OAuthServerAuthorizationTTL + time.Second)

	rec := env.do(t, http.MethodGet, "/oauth/authorizations/"+authorizationID, nil, user.Token)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}
	if body := decodeInto[HTTPError](t, rec, http.StatusNotFound); body.ErrorCode != ErrorCodeOAuthAuthorizationNotFound {
		t.Errorf("error_code = %q", body.ErrorCode)
	}

	// The expiry was COMMITTED even though the request failed.
	var status string
	if err := env.pool.QueryRow(context.Background(),
		`select status::text from auth.oauth_authorizations where authorization_id = $1`, authorizationID).
		Scan(&status); err != nil {
		t.Fatalf("read status: %v", err)
	}
	if status != OAuthAuthorizationExpired {
		t.Errorf("status = %q, want expired", status)
	}
}

func TestOAuthServerAuthorizationIsPrivateToItsUser(t *testing.T) {
	env := newOAuthEnv(t, nil)
	client := env.registerClient(t, map[string]any{"redirect_uris": []string{testRedirectURI}})
	owner := env.signup(t, "owner@example.com", "hunter22")
	stranger := env.signup(t, "stranger@example.com", "hunter22")

	authorizationID := env.authorize(t, client.ClientID, "openid", "s", nil)
	if rec := env.do(t, http.MethodGet, "/oauth/authorizations/"+authorizationID, nil, owner.Token); rec.Code != http.StatusOK {
		t.Fatalf("owner claim status = %d", rec.Code)
	}
	if rec := env.do(t, http.MethodGet, "/oauth/authorizations/"+authorizationID, nil, stranger.Token); rec.Code != http.StatusNotFound {
		t.Errorf("stranger status = %d, want 404", rec.Code)
	}
	if rec := env.do(t, http.MethodPost, "/oauth/authorizations/"+authorizationID+"/consent",
		map[string]any{"action": "approve"}, stranger.Token); rec.Code != http.StatusNotFound {
		t.Errorf("stranger consent status = %d, want 404", rec.Code)
	}
	// The consent endpoints require an end-user token at all.
	if rec := env.do(t, http.MethodGet, "/oauth/authorizations/"+authorizationID, nil, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous status = %d, want 401", rec.Code)
	}
}

// ---- the token endpoint ----------------------------------------------------

func TestOAuthServerTokenRejectsBadGrants(t *testing.T) {
	env := newOAuthEnv(t, nil)
	client := env.registerClient(t, map[string]any{"redirect_uris": []string{testRedirectURI}})
	user := env.signup(t, "grant@example.com", "hunter22")

	newCode := func(t *testing.T) string {
		t.Helper()
		return env.claimAndApprove(t, env.authorize(t, client.ClientID, "openid email", "st", nil), user.Token, "st")
	}

	oauthErrorOf := func(t *testing.T, rec *httptest.ResponseRecorder) OAuthError {
		t.Helper()
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
		}
		// The body must be RFC 6749, not the gotrue {code,error_code,msg}.
		var raw map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatalf("unmarshal %q: %v", rec.Body.String(), err)
		}
		if _, ok := raw["msg"]; ok {
			t.Errorf("the OAuth token endpoint must not answer in the gotrue envelope: %s", rec.Body.String())
		}
		return decodeInto[OAuthError](t, rec, http.StatusBadRequest)
	}

	t.Run("wrong code_verifier", func(t *testing.T) {
		code := newCode(t)
		body := oauthErrorOf(t, env.doForm(t, http.MethodPost, "/oauth/token", url.Values{
			"grant_type":    {GrantTypeAuthorizationCode},
			"code":          {code},
			"code_verifier": {"CvGmvL0Nq1nOSbYCEwkQeNGaGoAcMLDkfLqYzP3Wd5Y"},
		}, client.ClientID, client.ClientSecret))
		if body.Err != oAuth2ErrorInvalidGrant {
			t.Errorf("error = %q, want invalid_grant", body.Err)
		}
		if !strings.Contains(body.Description, "PKCE") {
			t.Errorf("error_description = %q", body.Description)
		}
	})

	t.Run("missing code_verifier", func(t *testing.T) {
		code := newCode(t)
		if body := oauthErrorOf(t, env.doForm(t, http.MethodPost, "/oauth/token", url.Values{
			"grant_type": {GrantTypeAuthorizationCode},
			"code":       {code},
		}, client.ClientID, client.ClientSecret)); body.Err != oAuth2ErrorInvalidGrant {
			t.Errorf("error = %q, want invalid_grant", body.Err)
		}
	})

	t.Run("redirect_uri mismatch", func(t *testing.T) {
		code := newCode(t)
		if body := oauthErrorOf(t, env.doForm(t, http.MethodPost, "/oauth/token", url.Values{
			"grant_type":    {GrantTypeAuthorizationCode},
			"code":          {code},
			"redirect_uri":  {"https://app.example.com/other"},
			"code_verifier": {testCodeVerifier},
		}, client.ClientID, client.ClientSecret)); body.Err != oAuth2ErrorInvalidGrant {
			t.Errorf("error = %q, want invalid_grant", body.Err)
		}
	})

	t.Run("code issued to another client", func(t *testing.T) {
		other := env.registerClient(t, map[string]any{"redirect_uris": []string{testRedirectURI}})
		code := newCode(t)
		if body := oauthErrorOf(t, env.doForm(t, http.MethodPost, "/oauth/token", url.Values{
			"grant_type":    {GrantTypeAuthorizationCode},
			"code":          {code},
			"code_verifier": {testCodeVerifier},
		}, other.ClientID, other.ClientSecret)); body.Err != oAuth2ErrorInvalidGrant {
			t.Errorf("error = %q, want invalid_grant", body.Err)
		}
	})

	t.Run("unknown code", func(t *testing.T) {
		if body := oauthErrorOf(t, env.doForm(t, http.MethodPost, "/oauth/token", url.Values{
			"grant_type":    {GrantTypeAuthorizationCode},
			"code":          {"11111111-1111-4111-8111-111111111111"},
			"code_verifier": {testCodeVerifier},
		}, client.ClientID, client.ClientSecret)); body.Err != oAuth2ErrorInvalidGrant {
			t.Errorf("error = %q, want invalid_grant", body.Err)
		}
	})

	t.Run("a pending authorization has no code yet", func(t *testing.T) {
		id := env.authorize(t, client.ClientID, "openid", "st", nil)
		var code *string
		if err := env.pool.QueryRow(context.Background(),
			`select authorization_code from auth.oauth_authorizations where authorization_id = $1`, id).
			Scan(&code); err != nil {
			t.Fatalf("read code: %v", err)
		}
		if code != nil {
			t.Errorf("a pending authorization must not carry an authorization_code, got %q", *code)
		}
	})

	t.Run("missing grant_type", func(t *testing.T) {
		if body := oauthErrorOf(t, env.doForm(t, http.MethodPost, "/oauth/token", url.Values{},
			client.ClientID, client.ClientSecret)); body.Err != oAuth2ErrorInvalidRequest {
			t.Errorf("error = %q, want invalid_request", body.Err)
		}
	})

	t.Run("a grant the client did not register for", func(t *testing.T) {
		limited := env.registerClient(t, map[string]any{
			"redirect_uris": []string{testRedirectURI},
			"grant_types":   []string{GrantTypeAuthorizationCode},
		})
		if body := oauthErrorOf(t, env.doForm(t, http.MethodPost, "/oauth/token", url.Values{
			"grant_type":    {GrantTypeRefreshToken},
			"refresh_token": {"abcdefghijkl"},
		}, limited.ClientID, limited.ClientSecret)); body.Err != oAuth2ErrorUnsupportedGrantType {
			t.Errorf("error = %q, want unsupported_grant_type", body.Err)
		}
	})

	t.Run("a non-OAuth session cannot be refreshed here", func(t *testing.T) {
		// user.RefreshToken belongs to a plain password sign-in.
		if body := oauthErrorOf(t, env.doForm(t, http.MethodPost, "/oauth/token", url.Values{
			"grant_type":    {GrantTypeRefreshToken},
			"refresh_token": {user.RefreshToken},
		}, client.ClientID, client.ClientSecret)); body.Err != oAuth2ErrorInvalidClient {
			t.Errorf("error = %q, want invalid_client", body.Err)
		}
	})
}

// ---- client authentication matrix ------------------------------------------

func TestOAuthServerClientAuthenticationMatrix(t *testing.T) {
	env := newOAuthEnv(t, nil)

	basicClient := env.registerClient(t, map[string]any{
		"redirect_uris":              []string{testRedirectURI},
		"token_endpoint_auth_method": TokenEndpointAuthMethodClientSecretBasic,
	})
	postClient := env.registerClient(t, map[string]any{
		"redirect_uris":              []string{testRedirectURI},
		"token_endpoint_auth_method": TokenEndpointAuthMethodClientSecretPost,
	})
	publicClient := env.registerClient(t, map[string]any{
		"redirect_uris":              []string{testRedirectURI},
		"token_endpoint_auth_method": TokenEndpointAuthMethodNone,
	})

	// A bogus authorization code is the probe: reaching the GRANT (and its RFC
	// 6749 invalid_grant body) proves client authentication succeeded, while a
	// gotrue 400 invalid_credentials proves it did not.
	probe := url.Values{
		"grant_type":    {GrantTypeAuthorizationCode},
		"code":          {"11111111-1111-4111-8111-111111111111"},
		"code_verifier": {testCodeVerifier},
	}
	withClient := func(id, secret string) url.Values {
		v := url.Values{}
		for k, vs := range probe {
			v[k] = append([]string(nil), vs...)
		}
		if id != "" {
			v.Set("client_id", id)
		}
		if secret != "" {
			v.Set("client_secret", secret)
		}
		return v
	}
	assertAuthenticated := func(t *testing.T, rec *httptest.ResponseRecorder) {
		t.Helper()
		body := decodeInto[OAuthError](t, rec, http.StatusBadRequest)
		if body.Err != oAuth2ErrorInvalidGrant {
			t.Errorf("error = %q, want invalid_grant (i.e. the client authenticated)", body.Err)
		}
	}
	assertRejected := func(t *testing.T, rec *httptest.ResponseRecorder) {
		t.Helper()
		body := decodeInto[HTTPError](t, rec, http.StatusBadRequest)
		if body.ErrorCode != ErrorCodeInvalidCredentials {
			t.Errorf("error_code = %q, want invalid_credentials", body.ErrorCode)
		}
	}

	t.Run("client_secret_basic accepts Basic", func(t *testing.T) {
		assertAuthenticated(t, env.doForm(t, http.MethodPost, "/oauth/token", probe,
			basicClient.ClientID, basicClient.ClientSecret))
	})
	t.Run("client_secret_basic rejects a wrong secret", func(t *testing.T) {
		assertRejected(t, env.doForm(t, http.MethodPost, "/oauth/token", probe,
			basicClient.ClientID, "not-the-secret"))
	})
	t.Run("client_secret_basic rejects the body form", func(t *testing.T) {
		assertRejected(t, env.doForm(t, http.MethodPost, "/oauth/token",
			withClient(basicClient.ClientID, basicClient.ClientSecret), "", ""))
	})
	t.Run("client_secret_post accepts body credentials", func(t *testing.T) {
		assertAuthenticated(t, env.doForm(t, http.MethodPost, "/oauth/token",
			withClient(postClient.ClientID, postClient.ClientSecret), "", ""))
	})
	t.Run("client_secret_post rejects Basic", func(t *testing.T) {
		assertRejected(t, env.doForm(t, http.MethodPost, "/oauth/token", probe,
			postClient.ClientID, postClient.ClientSecret))
	})
	t.Run("client_secret_post rejects a wrong secret", func(t *testing.T) {
		assertRejected(t, env.doForm(t, http.MethodPost, "/oauth/token",
			withClient(postClient.ClientID, "wrong"), "", ""))
	})
	t.Run("none accepts a bare client_id", func(t *testing.T) {
		assertAuthenticated(t, env.doForm(t, http.MethodPost, "/oauth/token",
			withClient(publicClient.ClientID, ""), "", ""))
	})
	t.Run("none rejects a presented secret", func(t *testing.T) {
		assertRejected(t, env.doForm(t, http.MethodPost, "/oauth/token",
			withClient(publicClient.ClientID, "anything"), "", ""))
	})
	t.Run("an unknown client is rejected", func(t *testing.T) {
		assertRejected(t, env.doForm(t, http.MethodPost, "/oauth/token",
			withClient("11111111-1111-4111-8111-111111111111", ""), "", ""))
	})
	t.Run("a missing client_id is rejected", func(t *testing.T) {
		assertRejected(t, env.doForm(t, http.MethodPost, "/oauth/token", probe, "", ""))
	})

	// A public client completes the whole flow on PKCE alone.
	t.Run("public client completes the flow with PKCE only", func(t *testing.T) {
		user := env.signup(t, "publicflow@example.com", "hunter22")
		code := env.claimAndApprove(t, env.authorize(t, publicClient.ClientID, "openid email", "pub", nil), user.Token, "pub")

		tokens := decodeInto[OAuthTokenResponse](t, env.doForm(t, http.MethodPost, "/oauth/token", url.Values{
			"grant_type":    {GrantTypeAuthorizationCode},
			"code":          {code},
			"client_id":     {publicClient.ClientID},
			"code_verifier": {testCodeVerifier},
		}, "", ""), http.StatusOK)
		if tokens.AccessToken == "" || tokens.IDToken == "" {
			t.Fatalf("token response = %+v", tokens)
		}
	})
}

// ---- userinfo scopes -------------------------------------------------------

func TestOAuthServerUserInfoFollowsGrantedScopes(t *testing.T) {
	env := newOAuthEnv(t, nil)
	client := env.registerClient(t, map[string]any{"redirect_uris": []string{testRedirectURI}})
	user := env.signup(t, "scopes@example.com", "hunter22")

	// openid only: nothing but `sub`.
	code := env.claimAndApprove(t, env.authorize(t, client.ClientID, "openid", "s", nil), user.Token, "s")
	tokens := decodeInto[OAuthTokenResponse](t, env.doForm(t, http.MethodPost, "/oauth/token", url.Values{
		"grant_type":    {GrantTypeAuthorizationCode},
		"code":          {code},
		"code_verifier": {testCodeVerifier},
	}, client.ClientID, client.ClientSecret), http.StatusOK)

	info := decodeInto[map[string]any](t,
		env.do(t, http.MethodGet, "/oauth/userinfo", nil, tokens.AccessToken), http.StatusOK)
	if info["sub"] != user.User.ID {
		t.Errorf("sub = %v", info["sub"])
	}
	for _, leaked := range []string{"email", "email_verified", "name", "phone", "user_metadata"} {
		if _, ok := info[leaked]; ok {
			t.Errorf("userinfo leaked %q with only the openid scope", leaked)
		}
	}

	// A plain (non-OAuth) Supabase token gets the bare `sub` too.
	plain := decodeInto[map[string]any](t,
		env.do(t, http.MethodGet, "/oauth/userinfo", nil, user.Token), http.StatusOK)
	if len(plain) != 1 || plain["sub"] != user.User.ID {
		t.Errorf("userinfo for a non-OAuth token = %v, want only sub", plain)
	}
}

// ---- the feature gate ------------------------------------------------------

func TestOAuthServerDisabledReturns404(t *testing.T) {
	env := newOAuthEnv(t, func(c *Config) { c.OAuthServer.Enabled = false })
	admin := env.serviceRoleToken(t)

	cases := []struct {
		method, path, bearer string
	}{
		{http.MethodGet, "/oauth/authorize?client_id=x", ""},
		{http.MethodPost, "/oauth/token", ""},
		{http.MethodPost, "/oauth/clients/register", ""},
		{http.MethodGet, "/oauth/userinfo", ""},
		{http.MethodGet, "/oauth/authorizations/abc", ""},
		{http.MethodGet, "/user/oauth/grants", ""},
		{http.MethodGet, "/admin/oauth/clients", admin},
		{http.MethodPost, "/admin/oauth/clients", admin},
		{http.MethodGet, "/.well-known/oauth-authorization-server", ""},
	}
	for _, tc := range cases {
		rec := env.do(t, tc.method, tc.path, nil, tc.bearer)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s status = %d, want 404; body = %s", tc.method, tc.path, rec.Code, rec.Body.String())
			continue
		}
		if body := decodeInto[HTTPError](t, rec, http.StatusNotFound); body.ErrorCode != ErrorCodeFeatureDisabled {
			t.Errorf("%s %s error_code = %q, want %q", tc.method, tc.path, body.ErrorCode, ErrorCodeFeatureDisabled)
		}
	}

	// OIDC discovery keeps working, but stops advertising the registration
	// endpoint (upstream's condition).
	doc := decodeInto[OpenIDConfigurationResponse](t,
		env.do(t, http.MethodGet, "/.well-known/openid-configuration", nil, ""), http.StatusOK)
	if doc.RegistrationEndpoint != "" {
		t.Errorf("registration_endpoint = %q, want empty while the OAuth server is off", doc.RegistrationEndpoint)
	}
}

func TestOAuthServerWellKnownMetadata(t *testing.T) {
	env := newOAuthEnv(t, nil)
	issuer := issuerURL(env.cfg, nil)

	for _, path := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		doc := decodeInto[OpenIDConfigurationResponse](t,
			env.do(t, http.MethodGet, path, nil, ""), http.StatusOK)

		if doc.Issuer != issuer {
			t.Errorf("%s issuer = %q, want %q", path, doc.Issuer, issuer)
		}
		if doc.AuthorizationEndpoint != issuer+"/oauth/authorize" {
			t.Errorf("%s authorization_endpoint = %q", path, doc.AuthorizationEndpoint)
		}
		if doc.TokenEndpoint != issuer+"/oauth/token" {
			t.Errorf("%s token_endpoint = %q", path, doc.TokenEndpoint)
		}
		if doc.UserInfoEndpoint != issuer+"/oauth/userinfo" {
			t.Errorf("%s userinfo_endpoint = %q", path, doc.UserInfoEndpoint)
		}
		if doc.RegistrationEndpoint != issuer+"/oauth/clients/register" {
			t.Errorf("%s registration_endpoint = %q", path, doc.RegistrationEndpoint)
		}
		if !hasScope(doc.ScopesSupported, ScopeOpenID) {
			t.Errorf("%s scopes_supported = %v", path, doc.ScopesSupported)
		}
		if !hasScope(doc.IDTokenSigningAlgValuesSupported, AlgES256) {
			t.Errorf("%s id_token_signing_alg_values_supported = %v", path, doc.IDTokenSigningAlgValuesSupported)
		}
	}
}

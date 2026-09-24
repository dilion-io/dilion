package auth

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// Like upstream, a token whose session has ended is refused: signing out ends
// it now, not when the access token expires.
func TestEndedSessionTokenIsRefused(t *testing.T) {
	env := newTestEnv(t)
	user := env.signup(t, "ended@example.com", "correct-horse-battery")
	if rec := env.do(t, http.MethodPost, "/logout", nil, user.Token); rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d", rec.Code)
	}
	for _, rec := range []*struct {
		method, path string
		body         any
	}{{http.MethodGet, "/user", nil}, {http.MethodPut, "/user", map[string]any{"email": "stolen@example.com"}}} {
		r := env.do(t, rec.method, rec.path, rec.body, user.Token)
		if r.Code != http.StatusForbidden || !strings.Contains(r.Body.String(), ErrorCodeSessionNotFound) {
			t.Errorf("%s %s after logout = %d %s, want 403 %s", rec.method, rec.path, r.Code, r.Body.String(), ErrorCodeSessionNotFound)
		}
	}
}

// oauthAppTokens runs the authorization-code flow for a fresh client and
// user, returning the OAuth application's tokens.
func oauthAppTokens(t *testing.T, env *oauthEnv, email string) (OAuthTokenResponse, AccessTokenResponse) {
	t.Helper()
	client := env.registerClient(t, map[string]any{"redirect_uris": []string{testRedirectURI}})
	user := env.signup(t, email, "hunter22")
	id := env.authorize(t, client.ClientID, "openid email", "s", nil)
	code := env.claimAndApprove(t, id, user.Token, "s")
	tokens := decodeInto[OAuthTokenResponse](t, env.doForm(t, http.MethodPost, "/oauth/token", url.Values{
		"grant_type":    {GrantTypeAuthorizationCode},
		"code":          {code},
		"redirect_uri":  {testRedirectURI},
		"code_verifier": {testCodeVerifier},
	}, client.ClientID, client.ClientSecret), http.StatusOK)
	return tokens, user
}

// An application the user authorized for some scopes holds those scopes, not
// the account: its token may read the user and sign out, nothing more, and its
// refresh token cannot be turned into the user's own session at /token.
func TestOAuthAppTokenStaysAnApplicationToken(t *testing.T) {
	env := newOAuthEnv(t, nil)
	app, _ := oauthAppTokens(t, env, "app-boundary@example.com")

	if rec := env.do(t, http.MethodGet, "/user", nil, app.AccessToken); rec.Code != http.StatusOK {
		t.Errorf("GET /user with the app's token = %d, want 200", rec.Code)
	}
	for _, req := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPut, "/user", map[string]any{"data": map[string]any{"x": 1}}},
		{http.MethodGet, "/factors", nil},
		{http.MethodGet, "/user/oauth/grants", nil},
	} {
		rec := env.do(t, req.method, req.path, req.body, app.AccessToken)
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), ErrorCodeOAuthClientToken) {
			t.Errorf("%s %s with the app's token = %d %s, want 403 %s", req.method, req.path, rec.Code, rec.Body.String(), ErrorCodeOAuthClientToken)
		}
	}

	rec := env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": app.RefreshToken}, "")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), oAuth2ErrorInvalidClient) {
		t.Errorf("app refresh token at /token = %d %s, want 400 %s", rec.Code, rec.Body.String(), oAuth2ErrorInvalidClient)
	}
}

// The admin surface admits a users.admin user token only from an active
// account's own, open, aal2 session.
func TestAdminGateNeedsAssuredSession(t *testing.T) {
	env := newOAuthEnv(t, nil)
	authz := &stubAuthorizer{allow: map[string]bool{PermUsersAdmin: true}}
	r := env.routerWith(authz)

	admin := env.signup(t, "gate-admin@example.com", "hunter22")
	if code := getAdminUsers(t, env.testEnv, r, admin.Token); code != http.StatusForbidden {
		t.Errorf("aal1 admin = %d, want 403", code)
	}
	env.stepUp(t, admin.Token)
	if code := getAdminUsers(t, env.testEnv, r, admin.Token); code != http.StatusOK {
		t.Fatalf("aal2 admin = %d, want 200", code)
	}

	if _, err := env.pool.Exec(context.Background(),
		`update auth.users set banned_until = now() + interval '1 day' where id = $1::uuid`, admin.User.ID); err != nil {
		t.Fatalf("ban: %v", err)
	}
	if code := getAdminUsers(t, env.testEnv, r, admin.Token); code != http.StatusForbidden {
		t.Errorf("banned admin = %d, want 403", code)
	}

	app, _ := oauthAppTokens(t, env, "gate-app@example.com")
	if code := getAdminUsers(t, env.testEnv, r, app.AccessToken); code != http.StatusForbidden {
		t.Errorf("an OAuth application's token = %d, want 403", code)
	}
}

// WithoutAdminMFA (development) drops the aal2 requirement, and only that.
func TestAdminGateWithoutAdminMFA(t *testing.T) {
	oenv := newOAuthEnv(t, nil)
	env := oenv.testEnv
	r := chi.NewRouter()
	Register(r, Deps{
		Pool: env.pool, Tokens: env.tokens, Mailer: env.mailer, Hooks: env.hooks,
		Authz:            &stubAuthorizer{allow: map[string]bool{PermUsersAdmin: true}},
		AdminMFADisabled: true,
		Logger:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	admin := env.signup(t, "dev-admin@example.com", "hunter22")
	if code := getAdminUsers(t, env, r, admin.Token); code != http.StatusOK {
		t.Errorf("aal1 admin with WithoutAdminMFA = %d, want 200", code)
	}
	app, _ := oauthAppTokens(t, oenv, "dev-app@example.com")
	if code := getAdminUsers(t, env, r, app.AccessToken); code != http.StatusForbidden {
		t.Errorf("an OAuth application's token with WithoutAdminMFA = %d, want 403", code)
	}
}

// Every body is capped, including ones a handler decodes itself: the OAuth
// token endpoint's JSON form used to buffer whatever it was sent.
func TestRequestBodiesAreCapped(t *testing.T) {
	env := newOAuthEnv(t, nil)
	client := env.registerClient(t, map[string]any{"redirect_uris": []string{testRedirectURI}})
	big := `{"grant_type":"authorization_code","code":"` + strings.Repeat("a", 2<<20) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(big))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(client.ClientID, client.ClientSecret)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	// Cut off at the cap, the body no longer parses: invalid_request, not the
	// invalid_grant a fully read (and buffered) bogus code would get.
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid_request") {
		t.Fatalf("2 MiB token request = %d %s, want 400 invalid_request", rec.Code, rec.Body.String())
	}
}

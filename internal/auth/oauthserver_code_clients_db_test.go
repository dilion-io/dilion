package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/dilion-io/dilion/ports"
)

// codeClientEnv is an OAuth server whose clients come from a resolver the test
// can change between requests.
type codeClientEnv struct {
	*oauthEnv
	clients map[string]*ports.OAuthClient
	err     error
}

func newCodeClientEnv(t *testing.T) *codeClientEnv {
	t.Helper()
	env := &codeClientEnv{clients: map[string]*ports.OAuthClient{}}
	env.oauthEnv = newOAuthEnvWithDeps(t, nil, func(d *Deps) {
		d.OAuthClients = func(_ context.Context, _, clientID string) (*ports.OAuthClient, error) {
			if env.err != nil {
				return nil, env.err
			}
			return env.clients[clientID], nil
		}
	})
	return env
}

const codeClientSecret = "workspace-client-secret"

// workspaceClient is a confidential client whose redirect targets are one per
// tenant, decided by a function — the case a fixed list cannot express.
func (e *codeClientEnv) workspaceClient(firstParty bool) *ports.OAuthClient {
	c := &ports.OAuthClient{
		ID:   uuid.NewString(),
		Name: "Workspace",
		VerifySecret: func(s string) bool {
			return subtle.ConstantTimeCompare([]byte(s), []byte(codeClientSecret)) == 1
		},
		AllowRedirectURI: func(uri string) bool {
			// Exactly https://{tenant}.api.example.com/callback for a known tenant.
			for _, tenant := range []string{"acme", "globex"} {
				if uri == "https://"+tenant+".api.example.com/callback" {
					return true
				}
			}
			return false
		},
		FirstParty: firstParty,
	}
	e.clients[c.ID] = c
	return c
}

// authorizeTo runs GET /oauth/authorize for clientID with redirectURI and
// returns the response, un-asserted.
func (e *codeClientEnv) authorizeTo(t *testing.T, clientID, redirectURI, state string) (*http.Response, string) {
	t.Helper()
	q := url.Values{
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid email"},
		"state":                 {state},
		"code_challenge":        {codeChallengeS256(testCodeVerifier)},
		"code_challenge_method": {"S256"},
	}
	rec := e.do(t, http.MethodGet, "/oauth/authorize?"+q.Encode(), nil, "")
	loc, _ := url.Parse(rec.Header().Get("Location"))
	id := ""
	if loc != nil {
		id = loc.Query().Get("authorization_id")
	}
	return rec.Result(), id
}

// exchange redeems code for client, authenticating with secret by HTTP Basic
// (or in the body when post is set).
func (e *codeClientEnv) exchange(t *testing.T, clientID, secret, code, redirectURI string, post bool) (int, OAuthTokenResponse) {
	t.Helper()
	form := url.Values{
		"grant_type":    {GrantTypeAuthorizationCode},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {testCodeVerifier},
	}
	basicID, basicSecret := clientID, secret
	if post {
		form.Set("client_id", clientID)
		if secret != "" {
			form.Set("client_secret", secret)
		}
		basicID, basicSecret = "", ""
	}
	rec := e.doForm(t, http.MethodPost, "/oauth/token", form, basicID, basicSecret)
	var out OAuthTokenResponse
	if rec.Code == http.StatusOK {
		out = decodeInto[OAuthTokenResponse](t, rec, http.StatusOK)
	}
	return rec.Code, out
}

// A code-defined client runs the whole authorization-code flow with its
// redirect targets and secret decided by the resolver, and nothing in
// auth.oauth_clients but an inert shadow of it.
func TestCodeClientAuthorizationCodeFlow(t *testing.T) {
	env := newCodeClientEnv(t)
	client := env.workspaceClient(false)
	user := env.signup(t, "member@example.com", "hunter22")
	const redirect = "https://acme.api.example.com/callback"

	res, authorizationID := env.authorizeTo(t, client.ID, redirect, "st-1")
	if res.StatusCode != http.StatusFound || authorizationID == "" {
		t.Fatalf("authorize = %d, Location %q; want a redirect to consent", res.StatusCode, res.Header.Get("Location"))
	}

	// Not first-party: the consent page gets the details, including the name
	// the resolver gave.
	details := decodeInto[AuthorizationDetailsResponse](t,
		env.do(t, http.MethodGet, "/oauth/authorizations/"+authorizationID, nil, user.Token), http.StatusOK)
	if details.Client.ID != client.ID || details.Client.Name != "Workspace" {
		t.Errorf("consent client = %+v", details.Client)
	}
	code := codeFrom(t, env.consent(t, authorizationID, user.Token, "approve"), "st-1")

	if status, _ := env.exchange(t, client.ID, "wrong-secret", code, redirect, false); status == http.StatusOK {
		t.Fatal("a wrong secret redeemed the code")
	}
	status, tokens := env.exchange(t, client.ID, codeClientSecret, code, redirect, false)
	if status != http.StatusOK || tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatalf("exchange = %d %+v", status, tokens)
	}
	claims, err := env.tokens.Verify(context.Background(), tokens.AccessToken)
	if err != nil || claims.Subject != user.User.ID {
		t.Fatalf("access token = %+v, %v; want it issued to the user", claims, err)
	}
	if claims.Extra["client_id"] != client.ID {
		t.Errorf("client_id claim = %v, want %s", claims.Extra["client_id"], client.ID)
	}

	// Refresh works too: the session references the shadow row.
	rec := env.doForm(t, http.MethodPost, "/oauth/token", url.Values{
		"grant_type": {GrantTypeRefreshToken}, "refresh_token": {tokens.RefreshToken},
	}, client.ID, codeClientSecret)
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh = %d; body = %s", rec.Code, rec.Body.String())
	}

	// The shadow row exists, is soft-deleted, and has nothing to validate
	// against — and the admin API does not list it.
	var deleted bool
	var secret *string
	var uris string
	if err := env.pool.QueryRow(context.Background(),
		`select deleted_at is not null, client_secret_hash, redirect_uris from auth.oauth_clients where id = $1::uuid`,
		client.ID).Scan(&deleted, &secret, &uris); err != nil {
		t.Fatalf("shadow row: %v", err)
	}
	if !deleted || secret != nil || uris != "" {
		t.Errorf("shadow row = deleted %v, secret %v, redirect_uris %q; want an inert row", deleted, secret, uris)
	}
	list := decodeInto[map[string]any](t,
		env.do(t, http.MethodGet, "/admin/oauth/clients", nil, env.serviceRoleToken(t)), http.StatusOK)
	if strings.Contains(stringOf(list), client.ID) {
		t.Error("the admin client list shows a code-defined client")
	}
}

// Redirect targets are exactly what the resolver's AllowRedirectURI accepts:
// another tenant's callback works, anything else is refused before an
// authorization exists.
func TestCodeClientRedirectURIIsTheResolversCall(t *testing.T) {
	env := newCodeClientEnv(t)
	client := env.workspaceClient(false)

	for _, uri := range []string{
		"https://acme.api.example.com/callback",
		"https://globex.api.example.com/callback",
	} {
		if res, id := env.authorizeTo(t, client.ID, uri, "s"); res.StatusCode != http.StatusFound || id == "" {
			t.Errorf("%s: authorize = %d, want accepted", uri, res.StatusCode)
		}
	}
	for _, uri := range []string{
		"https://evil.example.com/callback",
		"https://acme.api.example.com/callback/extra",
		"https://acme.api.example.com.evil.test/callback",
		"https://unknown.api.example.com/callback",
	} {
		if res, _ := env.authorizeTo(t, client.ID, uri, "s"); res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: authorize = %d, want 400 (no redirect to an unowned target)", uri, res.StatusCode)
		}
	}
}

// A first-party client skips the consent screen: the page learns the user and
// is handed the redirect at once, and no consent is recorded — there was none.
func TestCodeClientFirstPartySkipsConsent(t *testing.T) {
	env := newCodeClientEnv(t)
	client := env.workspaceClient(true)
	user := env.signup(t, "sso@example.com", "hunter22")
	const redirect = "https://acme.api.example.com/callback"

	_, authorizationID := env.authorizeTo(t, client.ID, redirect, "sso-1")
	auto := decodeInto[ConsentResponse](t,
		env.do(t, http.MethodGet, "/oauth/authorizations/"+authorizationID, nil, user.Token), http.StatusOK)
	if auto.RedirectURL == "" {
		t.Fatal("a first-party client was shown the consent screen")
	}
	code := codeFrom(t, auto.RedirectURL, "sso-1")
	if !strings.HasPrefix(auto.RedirectURL, redirect) {
		t.Errorf("redirect_url = %q, want it on %s", auto.RedirectURL, redirect)
	}
	if status, _ := env.exchange(t, client.ID, codeClientSecret, code, redirect, true); status != http.StatusOK {
		t.Errorf("exchange (secret in the body) = %d, want 200", status)
	}

	var consents int
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from auth.oauth_consents where client_id = $1::uuid`, client.ID).Scan(&consents); err != nil {
		t.Fatalf("count consents: %v", err)
	}
	if consents != 0 {
		t.Errorf("consents recorded = %d, want 0 for a first-party client", consents)
	}

	// It still takes a signed-in user: first-party skips the question, not the
	// authentication.
	_, again := env.authorizeTo(t, client.ID, redirect, "sso-2")
	if rec := env.do(t, http.MethodGet, "/oauth/authorizations/"+again, nil, ""); rec.Code == http.StatusOK {
		t.Error("an anonymous request was granted a first-party authorization")
	}
}

// A public client authenticates the exchange with PKCE alone, and may not
// present a secret at all.
func TestCodeClientPublicUsesPKCE(t *testing.T) {
	env := newCodeClientEnv(t)
	client := &ports.OAuthClient{
		ID: uuid.NewString(), Name: "CLI", Public: true, FirstParty: true,
		RedirectURIs: []string{"http://127.0.0.1:8976/callback"},
	}
	env.clients[client.ID] = client
	user := env.signup(t, "cli@example.com", "hunter22")

	_, id := env.authorizeTo(t, client.ID, "http://127.0.0.1:8976/callback", "p1")
	auto := decodeInto[ConsentResponse](t,
		env.do(t, http.MethodGet, "/oauth/authorizations/"+id, nil, user.Token), http.StatusOK)
	code := codeFrom(t, auto.RedirectURL, "p1")

	if status, _ := env.exchange(t, client.ID, "any-secret", code, "http://127.0.0.1:8976/callback", true); status == http.StatusOK {
		t.Error("a public client was accepted with a secret")
	}
	if status, _ := env.exchange(t, client.ID, "", code, "http://127.0.0.1:8976/callback", true); status != http.StatusOK {
		t.Errorf("public PKCE exchange = %d, want 200", status)
	}
}

// When the resolver stops claiming a client, the shadow row it left behind
// does not turn into a stored client: that id is simply unknown.
func TestCodeClientShadowIsInertOnceUnclaimed(t *testing.T) {
	env := newCodeClientEnv(t)
	client := env.workspaceClient(false)
	const redirect = "https://acme.api.example.com/callback"
	if res, _ := env.authorizeTo(t, client.ID, redirect, "s"); res.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d", res.StatusCode)
	}

	delete(env.clients, client.ID)
	if res, _ := env.authorizeTo(t, client.ID, redirect, "s"); res.StatusCode != http.StatusBadRequest {
		t.Errorf("authorize after unclaim = %d, want 400 unknown client", res.StatusCode)
	}
	if status, _ := env.exchange(t, client.ID, codeClientSecret, "whatever", redirect, false); status == http.StatusOK {
		t.Error("the token endpoint authenticated an unclaimed client")
	}
}

// Resolver failures fail the request; they are never read as "not mine" and
// never fall through to the database.
func TestCodeClientResolverErrorsFailClosed(t *testing.T) {
	env := newCodeClientEnv(t)
	client := env.workspaceClient(false)
	env.err = errors.New("tenant registry unavailable")

	if res, _ := env.authorizeTo(t, client.ID, "https://acme.api.example.com/callback", "s"); res.StatusCode == http.StatusFound {
		t.Error("authorize succeeded while the resolver was failing")
	}
	if status, _ := env.exchange(t, client.ID, codeClientSecret, "whatever", "https://acme.api.example.com/callback", false); status == http.StatusOK {
		t.Error("token succeeded while the resolver was failing")
	}
}

// A stored client keeps working next to the resolver, unaffected by it.
func TestStoredClientUnaffectedByResolver(t *testing.T) {
	env := newCodeClientEnv(t)
	stored := env.registerClient(t, map[string]any{"redirect_uris": []string{testRedirectURI}, "client_name": "Stored"})
	user := env.signup(t, "stored@example.com", "hunter22")

	id := env.authorize(t, stored.ClientID, "openid", "st", nil)
	code := env.claimAndApprove(t, id, user.Token, "st")
	if status, _ := env.exchange(t, stored.ClientID, stored.ClientSecret, code, testRedirectURI, false); status != http.StatusOK {
		t.Errorf("stored client exchange = %d, want 200", status)
	}
}

func stringOf(v any) string {
	var b strings.Builder
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				b.WriteString(k)
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case string:
			b.WriteString(x)
		}
	}
	walk(v)
	return b.String()
}

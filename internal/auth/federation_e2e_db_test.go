package auth

// Dilion signing users in through Dilion: one mount as the OAuth 2.1 identity
// provider, served over real HTTP, and another as the relying party whose
// provider is defined in code and points at it. Every other external-provider
// test runs against a fake IdP; this is the one that checks the two halves of
// Dilion actually agree on the wire — PKCE, client authentication, redirect
// URIs, discovery, id_token signing — which is exactly what the fakes cannot
// tell us. It was missing, and two interoperability bugs got through: the
// relying party sent no PKCE challenge to an IdP that requires one, and sent
// its credentials only in the body to an IdP whose clients default to Basic.
//
// Both mounts share the test database. The IdP's user therefore already exists
// on the relying-party side too, so LinkBySubject takes its link branch here;
// creating a user under the subject is covered by
// TestLinkBySubjectCreatesUserUnderSubject.

import (
	"context"
	"crypto/subtle"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/dilion-io/dilion/ports"
)

const (
	federationRPHost     = "acme.workspace.test"
	federationRPCallback = "https://" + federationRPHost + "/callback"
)

// federation is the two mounts and the IdP's HTTP server.
type federation struct {
	idp    *oauthEnv
	idpURL string
	rp     *codeProviderEnv
	// client is the IdP client the relying party authenticates as.
	clientID, clientSecret string
}

// newFederation builds an IdP whose clients come from resolve (which may be
// nil, for stored clients only) and a relying party that signs in through it.
// The relying party reads f.clientID and f.clientSecret at request time, so a
// test sets them once it knows the client it registered.
func newFederation(t *testing.T, resolve ports.OAuthClientResolver) *federation {
	t.Helper()
	f := &federation{}

	// The relying party reaches the IdP by HTTP, like any provider, so the IdP
	// needs a real listener — and its issuer must be that listener's URL,
	// which is only known once the server exists.
	var idpHandler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idpHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	f.idpURL = srv.URL

	f.idp = newOAuthEnvWithDeps(t, func(c *Config) {
		c.JWT.Issuer = srv.URL
		c.SiteURL = "https://platform.test"
	}, func(d *Deps) {
		d.OAuthClients = resolve
	})
	idpHandler = f.idp.router

	f.rp = newCodeProviderEnv(t, func(_ *codeProviderEnv, _, name string) (*ports.OIDCProvider, error) {
		if name != "platform" {
			return nil, nil
		}
		return &ports.OIDCProvider{
			Issuer:        f.idpURL,
			ClientID:      f.clientID,
			ClientSecret:  f.clientSecret,
			LinkBySubject: true,
		}, nil
	})
	return f
}

// startSignIn runs the relying party's /authorize and follows its redirect to
// the IdP's /oauth/authorize, returning the IdP's authorization id. An IdP
// that refuses the request answers by redirecting back to the relying party
// with ?error=, which is reported with the IdP's own words.
func (f *federation) startSignIn(t *testing.T) string {
	t.Helper()
	toIdP := f.rp.authorize(t, "platform", federationRPHost)
	if !strings.HasPrefix(toIdP.String(), f.idpURL+"/oauth/authorize") {
		t.Fatalf("relying party sent the browser to %s, want the IdP's authorize endpoint", toIdP)
	}

	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := noFollow.Get(toIdP.String())
	if err != nil {
		t.Fatalf("GET IdP authorize: %v", err)
	}
	_ = res.Body.Close()
	next, err := url.Parse(res.Header.Get("Location"))
	if err != nil || res.StatusCode != http.StatusFound {
		t.Fatalf("IdP authorize = %d, Location %q", res.StatusCode, res.Header.Get("Location"))
	}
	if e := next.Query().Get("error"); e != "" {
		t.Fatalf("IdP refused the relying party's authorization request: %s: %s",
			e, next.Query().Get("error_description"))
	}
	id := next.Query().Get("authorization_id")
	if id == "" {
		t.Fatalf("IdP redirect %s carries no authorization_id", next)
	}
	return id
}

// finishSignIn delivers the IdP's redirect to the relying party's callback
// and returns the user id the relying party's session names.
func (f *federation) finishSignIn(t *testing.T, redirectURL string) string {
	t.Helper()
	back, err := url.Parse(redirectURL)
	if err != nil {
		t.Fatalf("parse IdP redirect: %v", err)
	}
	if got := back.Scheme + "://" + back.Host + back.Path; got != federationRPCallback {
		t.Fatalf("IdP redirected to %s, want the relying party's callback %s", got, federationRPCallback)
	}
	req := httptest.NewRequest(http.MethodGet, "/callback?"+back.RawQuery, nil)
	req.Host = federationRPHost
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	f.rp.router.ServeHTTP(rec, req)

	done := redirectLocation(t, rec, http.StatusFound)
	token := fragmentValues(t, done).Get("access_token")
	if token == "" {
		t.Fatalf("relying party issued no session: %s", done)
	}
	claims, err := f.rp.tokens.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("verify relying-party session: %v", err)
	}
	return claims.Subject
}

// The platform setup: a first-party client decided in code on the IdP, a
// provider defined in code on the relying party, and the IdP's user id
// becoming the relying party's.
func TestFederationCodeClientFirstParty(t *testing.T) {
	// A provider defined in code is the embedder's, and may sit on its own
	// network: the outbound guard does not apply to it.
	withoutOutboundAllowance(t)
	clientID := uuid.NewString()
	const secret = "workspace-client-secret"
	f := newFederation(t, func(_ context.Context, _, id string) (*ports.OAuthClient, error) {
		if id != clientID {
			return nil, nil
		}
		return &ports.OAuthClient{
			ID:           clientID,
			Name:         "Workspace",
			RedirectURIs: []string{federationRPCallback},
			VerifySecret: func(s string) bool { return subtle.ConstantTimeCompare([]byte(s), []byte(secret)) == 1 },
			FirstParty:   true,
		}, nil
	})
	f.clientID, f.clientSecret = clientID, secret
	member := f.idp.signup(t, "member@example.com", "hunter22")

	authorizationID := f.startSignIn(t)
	auto := decodeInto[ConsentResponse](t,
		f.idp.do(t, http.MethodGet, "/oauth/authorizations/"+authorizationID, nil, member.Token), http.StatusOK)
	if auto.RedirectURL == "" {
		t.Fatal("first-party client was shown the consent screen")
	}
	if got := f.finishSignIn(t, auto.RedirectURL); got != member.User.ID {
		t.Errorf("relying party signed in %s, want the IdP's user %s", got, member.User.ID)
	}
}

// A client registered at the IdP the ordinary way keeps the default
// token_endpoint_auth_method, client_secret_basic, which the IdP matches
// exactly. A relying party that only ever sent credentials in the body could
// not use it.
func TestFederationStoredClientWithDefaultBasicAuth(t *testing.T) {
	f := newFederation(t, nil)
	client := f.idp.registerClient(t, map[string]any{
		"redirect_uris": []string{federationRPCallback},
		"client_name":   "Workspace",
	})
	if client.TokenEndpointAuthMethod != TokenEndpointAuthMethodClientSecretBasic {
		t.Fatalf("registered auth method = %q; this test is about the client_secret_basic default",
			client.TokenEndpointAuthMethod)
	}
	f.clientID, f.clientSecret = client.ClientID, client.ClientSecret
	member := f.idp.signup(t, "stored@example.com", "hunter22")

	authorizationID := f.startSignIn(t)
	// Not first-party: opening the consent page claims the request for the
	// member and shows the screen; approving it yields the redirect.
	details := decodeInto[AuthorizationDetailsResponse](t,
		f.idp.do(t, http.MethodGet, "/oauth/authorizations/"+authorizationID, nil, member.Token), http.StatusOK)
	if details.Client.Name != "Workspace" {
		t.Errorf("consent screen client = %+v", details.Client)
	}
	approved := f.idp.consent(t, authorizationID, member.Token, "approve")
	if got := f.finishSignIn(t, approved); got != member.User.ID {
		t.Errorf("relying party signed in %s, want the IdP's user %s", got, member.User.ID)
	}
}

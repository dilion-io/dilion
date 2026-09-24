package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// A provider an instance admin registers is fetched through the outbound
// guard: pointed at the server's own network, its sign-in fails instead of
// the server reading internal endpoints for it.
func TestStoredCustomProviderCannotReachPrivateNetwork(t *testing.T) {
	withoutOutboundAllowance(t)
	env := newCustomEnv(t)
	create := map[string]any{
		"provider_type": "oidc",
		"identifier":    "custom:internal",
		"name":          "Internal",
		"client_id":     "google-client-id",
		"client_secret": "fake-secret",
		"issuer":        env.oidc.srv.URL, // https://127.0.0.1:…
		"scopes":        []string{"openid", "email"},
	}
	if rec := env.do(t, http.MethodPost, "/admin/custom-providers", create, env.admin); rec.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	rec := env.do(t, http.MethodGet,
		"/authorize?provider=custom:internal&redirect_to="+url.QueryEscape("https://app.test/welcome"), nil, "")
	if strings.HasPrefix(rec.Header().Get("Location"), env.oidc.srv.URL) {
		t.Fatalf("authorize reached the loopback provider: %d %s", rec.Code, rec.Header().Get("Location"))
	}
}

// SAML metadata a provider is registered with is fetched through the guard
// too.
func TestSAMLMetadataURLCannotReachPrivateNetwork(t *testing.T) {
	withoutOutboundAllowance(t)
	env := newSSOEnv(t)
	var hits int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
	}))
	t.Cleanup(srv.Close)
	prev := providerTransport
	providerTransport = srv.Client().Transport
	t.Cleanup(func() { providerTransport = prev })

	rec := env.do(t, http.MethodPost, "/admin/sso/providers",
		map[string]any{"type": "saml", "metadata_url": srv.URL + "/metadata"}, env.serviceRoleToken(t))
	if rec.Code < 400 {
		t.Fatalf("registering a loopback metadata_url = %d %s, want a refusal", rec.Code, rec.Body.String())
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("the metadata fetch reached the loopback server %d times", n)
	}
}

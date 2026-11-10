package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/crewjam/saml"
)

// A provider created with dedicated_scope has an SP entity ID and ACS URL of
// its own, /sso/{id}/saml/..., and is accepted only there; every other
// provider only on the shared /sso/saml/acs. Upstream PR supabase/auth#2893.

// respondIdPInitiated is an IdP-initiated POST (crewjam's ServeIDPInitiated)
// to the HTTP-POST ACS that spMD advertises, landing on relayState.
func (ti *samlTestIdP) respondIdPInitiated(t *testing.T, spMD *saml.EntityDescriptor, session *saml.Session) url.Values {
	t.Helper()
	req := &saml.IdpAuthnRequest{
		IDP:                     ti.idp,
		HTTPRequest:             httptest.NewRequest(http.MethodGet, "/", nil),
		RelayState:              "https://app.test/welcome",
		Now:                     saml.TimeNow(),
		ServiceProviderMetadata: spMD,
	}
	for i := range spMD.SPSSODescriptors {
		for j := range spMD.SPSSODescriptors[i].AssertionConsumerServices {
			if acs := spMD.SPSSODescriptors[i].AssertionConsumerServices[j]; acs.Binding == saml.HTTPPostBinding {
				req.SPSSODescriptor = &spMD.SPSSODescriptors[i]
				req.ACSEndpoint = &acs
			}
		}
	}
	if req.ACSEndpoint == nil {
		t.Fatal("SP metadata has no HTTP-POST ACS")
	}
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
		t.Fatalf("IdP could not make the assertion: %v", err)
	}
	if err := req.MakeAssertionEl(); err != nil {
		t.Fatalf("IdP could not sign the assertion: %v", err)
	}
	if err := req.MakeResponse(); err != nil {
		t.Fatalf("IdP could not make the response: %v", err)
	}
	form, err := req.PostBinding()
	if err != nil {
		t.Fatalf("IdP could not build the POST binding: %v", err)
	}
	return url.Values{"SAMLResponse": {form.SAMLResponse}, "RelayState": {form.RelayState}}
}

func TestSAMLDedicatedScope(t *testing.T) {
	env := newSSOEnv(t)

	dedicated := env.createProvider(t, map[string]any{
		"domains":         []string{"dedicated.example"},
		"dedicated_scope": true,
	})
	if !dedicated.SAMLProvider.HasDedicatedScope() {
		t.Fatalf("created provider: saml.dedicated_scope = %v, want true", dedicated.SAMLProvider.DedicatedScope)
	}
	other := newSAMLTestIdP(t)
	shared := env.createProvider(t, map[string]any{
		"domains":      []string{"shared.example"},
		"metadata_xml": other.metadataXML(t),
	})
	if shared.SAMLProvider.DedicatedScope != nil {
		t.Fatalf("shared provider: saml.dedicated_scope = %v, want absent", *shared.SAMLProvider.DedicatedScope)
	}

	scoped := "/sso/" + dedicated.ID + "/saml"
	base := ssoTestSiteURL + "/auth/v1"

	// The dedicated metadata names the provider's own entity ID and ACS.
	md := env.spMetadataAt(t, scoped+"/metadata")
	if want := base + scoped + "/metadata"; md.EntityID != want {
		t.Errorf("dedicated EntityID = %q, want %q", md.EntityID, want)
	}
	if acs := md.SPSSODescriptors[0].AssertionConsumerServices; len(acs) == 0 || acs[0].Location != base+scoped+"/acs" {
		t.Errorf("dedicated ACS = %+v, want %s", acs, base+scoped+"/acs")
	}
	if got := env.spMetadata(t).EntityID; got != base+"/sso/saml/metadata" {
		t.Errorf("shared EntityID = %q, want it unchanged", got)
	}

	// Only a provider with a dedicated scope has an endpoint of its own.
	for _, id := range []string{shared.ID, "8c1b9f5e-1d7a-4c3b-9a35-2f0d6c8e4b71", "not-a-uuid"} {
		rec := env.do(t, http.MethodGet, "/sso/"+id+"/saml/metadata", nil, "")
		if body := decodeInto[errorBody](t, rec, http.StatusNotFound); body.ErrorCode != ErrorCodeSSOProviderNotFound {
			t.Errorf("metadata for %s: error_code = %q, want %q", id, body.ErrorCode, ErrorCodeSSOProviderNotFound)
		}
	}

	session := func(subject, email string) *saml.Session { return testSession(subject, email, "Test User") }
	startSSO := func(domain string) string {
		rec := env.do(t, http.MethodPost, "/sso", map[string]any{"domain": domain,
			"redirect_to": "https://app.test/welcome", "skip_http_redirect": true}, "")
		return decodeInto[SingleSignOnResponse](t, rec, http.StatusOK).URL
	}
	countUsers := func() int {
		var n int
		if err := env.pool.QueryRow(context.Background(), `select count(*) from auth.users`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// SP-initiated: the AuthnRequest names the dedicated entity ID and the
	// answer is accepted at the dedicated ACS...
	env.idp.spMetadataPath = scoped + "/metadata"
	form := env.idp.respond(t, env, startSSO("dedicated.example"), session("d-1", "d1@dedicated.example"))
	if rec := env.form(t, scoped+"/acs", form); rec.Code != http.StatusFound {
		t.Fatalf("dedicated ACS: status = %d, want 302; Location %q", rec.Code, rec.Header().Get("Location"))
	}
	// ...and not at the shared one.
	form = env.idp.respond(t, env, startSSO("dedicated.example"), session("d-2", "d2@dedicated.example"))
	assertACSRedirectError(t, env.form(t, "/sso/saml/acs", form), ErrorCodeValidationFailed)

	before := countUsers()

	// IdP-initiated, each IdP signing for the ACS it posts to, so the
	// assertion itself validates: the provider must still own that scope.
	// The shared provider's IdP posting to the dedicated ACS...
	form = other.respondIdPInitiated(t, md, session("s-1", "s1@shared.example"))
	assertACSRedirectError(t, env.form(t, scoped+"/acs", form), ErrorCodeSAMLIdPNotFound)
	// ...and the dedicated provider's IdP posting to the shared one.
	form = env.idp.respondIdPInitiated(t, env.spMetadata(t), session("d-3", "d3@dedicated.example"))
	assertACSRedirectError(t, env.form(t, "/sso/saml/acs", form), ErrorCodeSAMLIdPNotFound)

	// A Response whose Destination names another ACS is refused up front.
	form = other.respondIdPInitiated(t, env.spMetadata(t), session("s-2", "s2@shared.example"))
	assertACSRedirectError(t, env.form(t, scoped+"/acs", form), ErrorCodeValidationFailed)

	if after := countUsers(); after != before {
		t.Fatalf("users = %d after the refused assertions, want %d", after, before)
	}

	// The controls: each IdP-initiated flow on its own endpoint signs in.
	env.clock.advance(time.Second)
	form = env.idp.respondIdPInitiated(t, md, session("d-4", "d4@dedicated.example"))
	if rec := env.form(t, scoped+"/acs", form); rec.Code != http.StatusFound {
		t.Fatalf("dedicated IdP-initiated: status = %d; Location %q", rec.Code, rec.Header().Get("Location"))
	}
	form = other.respondIdPInitiated(t, env.spMetadata(t), session("s-3", "s3@shared.example"))
	if rec := env.form(t, "/sso/saml/acs", form); rec.Code != http.StatusFound {
		t.Fatalf("shared IdP-initiated: status = %d; Location %q", rec.Code, rec.Header().Get("Location"))
	}
}

// dedicated_scope is set on create and never changed: it changes the entity
// ID the IdP was configured with.
func TestAdminSSOProviderDedicatedScopeIsImmutable(t *testing.T) {
	env := newSSOEnv(t)
	p := env.createProvider(t, map[string]any{"domains": []string{"immutable.example"}})
	for _, v := range []bool{true, false} {
		rec := env.do(t, http.MethodPut, "/admin/sso/providers/"+p.ID,
			map[string]any{"dedicated_scope": v}, env.serviceRoleToken(t))
		if body := decodeInto[errorBody](t, rec, http.StatusBadRequest); body.ErrorCode != ErrorCodeValidationFailed {
			t.Errorf("update dedicated_scope=%v: error_code = %q, want %q", v, body.ErrorCode, ErrorCodeValidationFailed)
		}
	}
	got := decodeInto[SSOProvider](t, env.do(t, http.MethodGet, "/admin/sso/providers/"+p.ID, nil, env.serviceRoleToken(t)), http.StatusOK)
	if got.SAMLProvider.DedicatedScope != nil {
		t.Fatalf("dedicated_scope after refused updates = %v, want absent", *got.SAMLProvider.DedicatedScope)
	}
}

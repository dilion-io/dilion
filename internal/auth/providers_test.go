package auth

// Unit tests for the wave-IV built-in providers and the custom-provider runtime.
// None of these need a database; the REST providers are exercised against
// httptest servers and the OIDC parsers against synthetic idToken values.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---- registry --------------------------------------------------------------

func TestWaveIVProvidersRegistered(t *testing.T) {
	names := registeredProviders()
	for _, want := range []string{
		"azure", "bitbucket", "discord", "facebook", "figma", "fly", "gitlab",
		"keycloak", "linkedin_oidc", "notion", "slack_oidc", "spotify", "twitch",
		"workos", "zoom",
	} {
		if !containsString(names, want) {
			t.Errorf("provider %q is not registered (have %v)", want, names)
		}
	}
	// OAuth1-only Twitter is deliberately NOT implemented.
	if containsString(names, "twitter") {
		t.Error("twitter (OAuth1) must not be registered")
	}
}

// eachProviderConfigurable builds every wave-IV provider from a minimal config
// to prove the factories validate and construct.
func TestWaveIVProvidersConstruct(t *testing.T) {
	base := ProviderConfig{
		Enabled: true, ClientID: []string{"cid"}, Secret: "sec",
		RedirectURI: "https://api.test/callback",
	}
	keycloak := base
	keycloak.URL = "https://kc.test/realms/dilion"

	cases := map[string]ProviderConfig{
		"bitbucket": base, "discord": base, "facebook": base, "figma": base,
		"fly": base, "gitlab": base, "notion": base, "slack_oidc": base,
		"spotify": base, "twitch": base, "workos": base, "zoom": base,
		"azure": base, "linkedin_oidc": base, "keycloak": keycloak,
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			c := testConfig()
			c.External[name] = cfg
			a := testAPI(t, c)
			if _, _, err := a.provider(context.Background(), name, "extra"); err != nil {
				t.Fatalf("provider %q: %v", name, err)
			}
		})
	}

	// Keycloak requires its realm URL.
	c := testConfig()
	c.External["keycloak"] = base // no URL
	a := testAPI(t, c)
	if _, _, err := a.provider(context.Background(), "keycloak", ""); err == nil {
		t.Error("keycloak without a realm URL must fail")
	}
}

// ---- REST userinfo claim mapping -------------------------------------------

func TestGitlabUserData(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, map[string]any{
			"id": 77, "name": "Ada", "email": "ada@example.com",
			"avatar_url": "https://cdn/ada.png", "confirmed_at": "2020-01-01T00:00:00Z",
		})
	})
	mux.HandleFunc("/api/v4/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, []map[string]any{{"email": "second@example.com"}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := &gitlabProvider{apiHost: srv.URL}
	data, err := p.userData(context.Background(), srv.Client(), &oauthToken{AccessToken: "at"})
	if err != nil {
		t.Fatalf("userData: %v", err)
	}
	if data.Metadata.Subject != "77" || data.Metadata.Name != "Ada" {
		t.Fatalf("metadata = %+v", data.Metadata)
	}
	if len(data.Emails) != 2 || !data.Emails[0].Verified || !data.Emails[0].Primary {
		t.Fatalf("emails = %+v", data.Emails)
	}
	if data.Emails[1].Verified {
		t.Error("a secondary /emails address must be unverified")
	}
}

func TestDiscordUserDataAndAvatar(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, map[string]any{
			"id": "42", "username": "neo", "discriminator": "0007",
			"email": "neo@example.com", "verified": true, "global_name": "Neo",
			"avatar": "abc",
		})
	}))
	defer srv.Close()

	p := &discordProvider{apiHost: srv.URL}
	data, err := p.userData(context.Background(), srv.Client(), &oauthToken{AccessToken: "at"})
	if err != nil {
		t.Fatalf("userData: %v", err)
	}
	if data.Metadata.Name != "neo#0007" || data.Metadata.Subject != "42" {
		t.Fatalf("metadata = %+v", data.Metadata)
	}
	if !strings.Contains(data.Metadata.Picture, "avatars/42/abc.png") {
		t.Errorf("avatar = %q", data.Metadata.Picture)
	}
	if data.Metadata.CustomClaims["global_name"] != "Neo" {
		t.Errorf("custom_claims = %v", data.Metadata.CustomClaims)
	}
	if len(data.Emails) != 1 || !data.Emails[0].Verified {
		t.Fatalf("emails = %+v", data.Emails)
	}
}

func TestSpotifyUserDataPicksLargestImage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, map[string]any{
			"id": "spot", "display_name": "DJ", "email": "dj@example.com",
			"images": []map[string]any{
				{"url": "small", "height": 10, "width": 10},
				{"url": "big", "height": 100, "width": 100},
			},
		})
	}))
	defer srv.Close()

	p := &spotifyProvider{apiHost: srv.URL}
	data, err := p.userData(context.Background(), srv.Client(), &oauthToken{AccessToken: "at"})
	if err != nil {
		t.Fatalf("userData: %v", err)
	}
	if data.Metadata.Picture != "big" {
		t.Errorf("picture = %q, want the largest image", data.Metadata.Picture)
	}
	// Spotify never reports verification.
	if data.Emails[0].Verified {
		t.Error("spotify email must be unverified")
	}
}

func TestTwitchUserDataUsesClientIDHeader(t *testing.T) {
	var gotClientID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClientID = r.Header.Get("Client-Id")
		writeTestJSON(w, map[string]any{"data": []map[string]any{{
			"id": "t1", "login": "streamer", "display_name": "Streamer",
			"email": "s@example.com", "profile_image_url": "https://cdn/s.png",
		}}})
	}))
	defer srv.Close()

	p := &twitchProvider{apiHost: srv.URL, clientID: "twitch-cid"}
	data, err := p.userData(context.Background(), srv.Client(), &oauthToken{AccessToken: "at"})
	if err != nil {
		t.Fatalf("userData: %v", err)
	}
	if gotClientID != "twitch-cid" {
		t.Errorf("Client-Id header = %q", gotClientID)
	}
	if data.Metadata.Subject != "t1" || data.Metadata.Name != "streamer" {
		t.Fatalf("metadata = %+v", data.Metadata)
	}
}

func TestNotionUserDataNestedAndVersionHeader(t *testing.T) {
	var gotVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotVersion = r.Header.Get("Notion-Version")
		writeTestJSON(w, map[string]any{"bot": map[string]any{"owner": map[string]any{
			"user": map[string]any{"id": "n1", "name": "Nora", "avatar_url": "a",
				"person": map[string]any{"email": "nora@example.com"}},
		}}})
	}))
	defer srv.Close()

	p := &notionProvider{apiHost: srv.URL}
	data, err := p.userData(context.Background(), srv.Client(), &oauthToken{AccessToken: "at"})
	if err != nil {
		t.Fatalf("userData: %v", err)
	}
	if gotVersion != notionAPIVersion {
		t.Errorf("Notion-Version = %q", gotVersion)
	}
	if data.Metadata.Subject != "n1" || data.Emails[0].Email != "nora@example.com" {
		t.Fatalf("data = %+v / %+v", data.Metadata, data.Emails)
	}
}

func TestWorkOSReadsProfileFromTokenBody(t *testing.T) {
	p := &workosProvider{apiHost: "https://api.workos.com"}
	raw := []byte(`{"access_token":"at","profile":{"id":"w1","email":"w@example.com","first_name":"Wo","last_name":"Kos","connection_id":"c1","organization_id":"o1"}}`)
	data, err := p.userData(context.Background(), nil, &oauthToken{AccessToken: "at", raw: raw})
	if err != nil {
		t.Fatalf("userData: %v", err)
	}
	if data.Metadata.Subject != "w1" || data.Metadata.Name != "Wo Kos" {
		t.Fatalf("metadata = %+v", data.Metadata)
	}
	if data.Metadata.CustomClaims["connection_id"] != "c1" {
		t.Errorf("custom_claims = %v", data.Metadata.CustomClaims)
	}
}

// ---- OIDC parsers ----------------------------------------------------------

func TestParseAzureIDToken(t *testing.T) {
	// xms_edov present and truthy -> verified.
	data := parseAzureIDToken(&idToken{
		Issuer: "https://login.microsoftonline.com/tid/v2.0", Subject: "az-sub",
		Claims: map[string]any{
			"email": "user@corp.test", "name": "Az User",
			"preferred_username": "user@corp.test", "xms_edov": true,
			"tid": "tid",
		},
	})
	if len(data.Emails) != 1 || !data.Emails[0].Verified {
		t.Fatalf("emails = %+v", data.Emails)
	}
	if data.Metadata.PreferredUsername != "user@corp.test" || data.Metadata.FullName != "Az User" {
		t.Fatalf("metadata = %+v", data.Metadata)
	}
	// `name` and `preferred_username` are stripped from custom claims; `tid` stays.
	if _, ok := data.Metadata.CustomClaims["name"]; ok {
		t.Error("name must not be in custom claims")
	}
	if data.Metadata.CustomClaims["tid"] != "tid" {
		t.Errorf("custom claims = %v", data.Metadata.CustomClaims)
	}

	// No xms_edov but an email present -> trusted (upstream behaviour).
	d2 := parseAzureIDToken(&idToken{Subject: "s", Claims: map[string]any{"email": "a@b.test"}})
	if !d2.Emails[0].Verified {
		t.Error("an azure email without xms_edov must be trusted")
	}
	// xms_edov false -> unverified.
	d3 := parseAzureIDToken(&idToken{Subject: "s", Claims: map[string]any{"email": "a@b.test", "xms_edov": "0"}})
	if d3.Emails[0].Verified {
		t.Error("xms_edov=0 must be unverified")
	}
}

func TestIsAzureIssuer(t *testing.T) {
	if !isAzureIssuer("https://login.microsoftonline.com/9188040d-abc/v2.0") {
		t.Error("a canonical azure issuer must be accepted")
	}
	if isAzureIssuer("https://evil.test/tid/v2.0") {
		t.Error("a foreign host must be rejected")
	}
	if isAzureIssuer("https://login.microsoftonline.com/tid") {
		t.Error("a non-v2 issuer must be rejected")
	}
}

func TestParseLinkedinIDToken(t *testing.T) {
	data := parseLinkedinIDToken(&idToken{
		Issuer: IssuerLinkedin, Subject: "li-sub",
		Claims: map[string]any{
			"given_name": "Grace", "family_name": "Hopper",
			"email": "grace@example.com", "email_verified": "true",
			"picture": "https://cdn/g.png", "locale": "en_US",
		},
	})
	if data.Metadata.Name != "Grace Hopper" || data.Metadata.GivenName != "Grace" {
		t.Fatalf("metadata = %+v", data.Metadata)
	}
	if len(data.Emails) != 1 || !data.Emails[0].Verified {
		t.Fatalf("emails = %+v (linkedin sends email_verified as a string)", data.Emails)
	}
}

// ---- custom provider runtime ----------------------------------------------

func TestCustomProviderClaimsMapping(t *testing.T) {
	p := &customRuntimeProvider{
		issuer: "https://idp.test",
		attributeMapping: JSONMap{
			"email": "mail",        // source-claim rename
			"name":  "Static Name", // literal (no such source claim)
		},
		claimsAllowlist: []string{"department"},
	}
	data := p.claimsToUserData(map[string]any{
		"sub": "u-1", "mail": "u@idp.test", "email_verified": true,
		"picture": "https://cdn/u.png", "department": "eng", "secret": "hidden",
	})
	if data.Metadata.Subject != "u-1" {
		t.Fatalf("subject = %q", data.Metadata.Subject)
	}
	if data.Metadata.Email != "u@idp.test" {
		t.Errorf("email mapping failed: %q", data.Metadata.Email)
	}
	if data.Metadata.Name != "Static Name" {
		t.Errorf("literal name mapping failed: %q", data.Metadata.Name)
	}
	if len(data.Emails) != 1 || !data.Emails[0].Verified {
		t.Fatalf("emails = %+v", data.Emails)
	}
	// Only allow-listed keys are captured; everything else is dropped.
	if data.Metadata.CustomClaims["department"] != "eng" {
		t.Errorf("allowlisted claim missing: %v", data.Metadata.CustomClaims)
	}
	if _, ok := data.Metadata.CustomClaims["secret"]; ok {
		t.Error("a non-allowlisted claim must not be captured")
	}
}

func TestExternalCallbackURLDerivation(t *testing.T) {
	a := testAPI(t, nil)
	req := httptest.NewRequest(http.MethodGet, "https://api.test/auth/v1/authorize?provider=x", nil)
	if got := a.externalCallbackURL(req); got != "https://api.test/auth/v1/callback" {
		t.Errorf("callback URL = %q", got)
	}
	req2 := httptest.NewRequest(http.MethodGet, "https://api.test/auth/v1/callback?code=c", nil)
	if got := a.externalCallbackURL(req2); got != "https://api.test/auth/v1/callback" {
		t.Errorf("callback URL (from callback) = %q", got)
	}
}

// ---- custom provider admin validation --------------------------------------

func TestCustomProviderParamsValidate(t *testing.T) {
	ok := CustomOAuthProviderParams{
		ProviderType: "oidc", Identifier: "custom:acme", Name: "Acme",
		ClientID: "cid", ClientSecret: "sec", Issuer: "https://idp.test",
	}
	if err := ok.validate(false); err != nil {
		t.Fatalf("valid oidc params rejected: %v", err)
	}

	cases := []struct {
		name string
		mut  func(p *CustomOAuthProviderParams)
	}{
		{"bad type", func(p *CustomOAuthProviderParams) { p.ProviderType = "saml" }},
		{"bad identifier", func(p *CustomOAuthProviderParams) { p.Identifier = "Bad_Ident!" }},
		{"no client_id", func(p *CustomOAuthProviderParams) { p.ClientID = "" }},
		{"no secret on create", func(p *CustomOAuthProviderParams) { p.ClientSecret = "" }},
		{"oidc without issuer", func(p *CustomOAuthProviderParams) { p.Issuer = "" }},
		{"oidc non-https issuer", func(p *CustomOAuthProviderParams) { p.Issuer = "http://idp.test" }},
		{"reserved auth param", func(p *CustomOAuthProviderParams) {
			p.AuthorizationParams = map[string]any{"client_id": "x"}
		}},
		{"protected attribute target", func(p *CustomOAuthProviderParams) {
			p.AttributeMapping = map[string]any{"role": "x"}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := ok
			tc.mut(&p)
			if err := p.validate(false); err == nil {
				t.Errorf("%s: expected a validation error", tc.name)
			}
		})
	}

	// oauth2 needs all three explicit endpoints.
	o := CustomOAuthProviderParams{
		ProviderType: "oauth2", Identifier: "custom:o2", Name: "O2",
		ClientID: "c", ClientSecret: "s",
		AuthorizationURL: "https://idp.test/auth", TokenURL: "https://idp.test/token",
		UserinfoURL: "https://idp.test/me",
	}
	if err := o.validate(false); err != nil {
		t.Fatalf("valid oauth2 params rejected: %v", err)
	}
	o.UserinfoURL = ""
	if err := o.validate(false); err == nil {
		t.Error("oauth2 without userinfo_url must fail")
	}

	// Update tolerates an omitted secret.
	u := ok
	u.ClientSecret = ""
	if err := u.validate(true); err != nil {
		t.Errorf("update without a secret must be allowed: %v", err)
	}
}

func TestCustomProviderNeverSerializesSecret(t *testing.T) {
	cp := &customOAuthProvider{
		ID: "id", Identifier: "custom:acme", Name: "Acme",
		ClientID: "cid", ClientSecret: "super-secret-value",
	}
	b, err := json.Marshal(cp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "super-secret-value") || strings.Contains(string(b), "client_secret") {
		t.Fatalf("client_secret leaked into JSON: %s", b)
	}
}

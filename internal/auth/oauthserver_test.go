package auth

// Pure unit tests for the OAuth-server helpers: no database, no HTTP mount.

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestOAuthServerClientTypeRules(t *testing.T) {
	cases := []struct {
		authMethod string
		want       string
	}{
		{TokenEndpointAuthMethodNone, OAuthClientTypePublic},
		{TokenEndpointAuthMethodClientSecretBasic, OAuthClientTypeConfidential},
		{TokenEndpointAuthMethodClientSecretPost, OAuthClientTypeConfidential},
		{"", OAuthClientTypeConfidential},
	}
	for _, tc := range cases {
		if got := inferClientTypeFromAuthMethod(tc.authMethod); got != tc.want {
			t.Errorf("inferClientTypeFromAuthMethod(%q) = %q, want %q", tc.authMethod, got, tc.want)
		}
	}

	// A public client may only use `none`; a confidential one may not.
	if isValidAuthMethodForClientType(OAuthClientTypePublic, TokenEndpointAuthMethodClientSecretBasic) {
		t.Error("a public client must not be allowed client_secret_basic")
	}
	if isValidAuthMethodForClientType(OAuthClientTypeConfidential, TokenEndpointAuthMethodNone) {
		t.Error("a confidential client must not be allowed 'none'")
	}
	if !isValidAuthMethodForClientType(OAuthClientTypeConfidential, TokenEndpointAuthMethodClientSecretPost) {
		t.Error("client_secret_post must be valid for a confidential client")
	}

	if err := validateClientTypeConsistency(OAuthClientTypePublic, TokenEndpointAuthMethodClientSecretBasic); err == nil {
		t.Error("public + client_secret_basic must be rejected")
	}
	if err := validateClientTypeConsistency("", TokenEndpointAuthMethodClientSecretBasic); err != nil {
		t.Errorf("an unset client_type must skip the consistency check: %v", err)
	}

	// Explicit type wins, then the type implied by the method, then confidential.
	if got := determineClientType(OAuthClientTypePublic, ""); got != OAuthClientTypePublic {
		t.Errorf("determineClientType explicit = %q", got)
	}
	if got := determineClientType("", TokenEndpointAuthMethodNone); got != OAuthClientTypePublic {
		t.Errorf("determineClientType inferred = %q", got)
	}
	if got := determineClientType("", ""); got != OAuthClientTypeConfidential {
		t.Errorf("determineClientType default = %q", got)
	}
}

func TestOAuthServerClientSecretHashing(t *testing.T) {
	secret, err := generateClientSecret()
	if err != nil {
		t.Fatalf("generateClientSecret: %v", err)
	}
	if raw, derr := base64.RawURLEncoding.DecodeString(secret); derr != nil || len(raw) != 32 {
		t.Fatalf("client secret is not 32 random base64url bytes: %q (%v)", secret, derr)
	}

	hash := hashClientSecret(secret)
	if strings.Contains(hash, secret) {
		t.Fatal("the stored hash must not contain the secret")
	}
	if !validateClientSecret(secret, hash) {
		t.Error("the generated secret must validate against its own hash")
	}
	if validateClientSecret(secret+"x", hash) {
		t.Error("a different secret must not validate")
	}
	if validateClientSecret(secret, "not base64!!") {
		t.Error("an undecodable stored hash must never validate")
	}

	other, _ := generateClientSecret()
	if other == secret {
		t.Error("two generated secrets must differ")
	}
}

func TestOAuthServerClientAuthenticationRules(t *testing.T) {
	secret, _ := generateClientSecret()
	confidential := &oauthClient{
		ClientType:              OAuthClientTypeConfidential,
		TokenEndpointAuthMethod: TokenEndpointAuthMethodClientSecretBasic,
		ClientSecretHash:        hashClientSecret(secret),
	}
	public := &oauthClient{
		ClientType:              OAuthClientTypePublic,
		TokenEndpointAuthMethod: TokenEndpointAuthMethodNone,
	}

	if err := validateClientAuthentication(confidential, secret); err != nil {
		t.Errorf("the registered secret must authenticate: %v", err)
	}
	if err := validateClientAuthentication(confidential, "wrong"); err == nil {
		t.Error("a wrong secret must not authenticate")
	}
	if err := validateClientAuthentication(confidential, ""); err == nil {
		t.Error("a confidential client must present a secret")
	}
	if err := validateClientAuthentication(public, ""); err != nil {
		t.Errorf("a public client authenticates without a secret: %v", err)
	}
	if err := validateClientAuthentication(public, "anything"); err == nil {
		t.Error("a public client must not present a secret")
	}

	if err := validateClientAuthMethod(confidential, TokenEndpointAuthMethodClientSecretPost); err == nil {
		t.Error("a credential presented by an unregistered method must be rejected")
	}
	if err := validateClientAuthMethod(confidential, TokenEndpointAuthMethodClientSecretBasic); err != nil {
		t.Errorf("the registered method must be accepted: %v", err)
	}
}

func TestOAuthServerExtractClientCredentials(t *testing.T) {
	t.Run("basic", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type=refresh_token"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("client-1", "s3cret")

		creds, err := extractClientCredentials(req)
		if err != nil {
			t.Fatalf("extractClientCredentials: %v", err)
		}
		if creds.ClientID != "client-1" || creds.ClientSecret != "s3cret" {
			t.Errorf("creds = %+v", creds)
		}
		if creds.AuthMethod != TokenEndpointAuthMethodClientSecretBasic {
			t.Errorf("auth method = %q", creds.AuthMethod)
		}
		// The body was not consumed.
		body, _ := readAllString(req)
		if body != "grant_type=refresh_token" {
			t.Errorf("body = %q, want it untouched", body)
		}
	})

	t.Run("form with a secret is client_secret_post", func(t *testing.T) {
		form := url.Values{"client_id": {"client-2"}, "client_secret": {"pw"}, "grant_type": {"refresh_token"}}
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		creds, err := extractClientCredentials(req)
		if err != nil {
			t.Fatalf("extractClientCredentials: %v", err)
		}
		if creds.AuthMethod != TokenEndpointAuthMethodClientSecretPost {
			t.Errorf("auth method = %q", creds.AuthMethod)
		}
		// The body is still readable by the handler.
		body, _ := readAllString(req)
		if !strings.Contains(body, "grant_type=refresh_token") {
			t.Errorf("body = %q, want it restored", body)
		}
	})

	t.Run("form without a secret is none", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("client_id=client-3"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		creds, err := extractClientCredentials(req)
		if err != nil {
			t.Fatalf("extractClientCredentials: %v", err)
		}
		if creds.AuthMethod != TokenEndpointAuthMethodNone {
			t.Errorf("auth method = %q", creds.AuthMethod)
		}
	})

	t.Run("json body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/oauth/token",
			strings.NewReader(`{"client_id":"client-4","client_secret":"pw"}`))
		req.Header.Set("Content-Type", "application/json")

		creds, err := extractClientCredentials(req)
		if err != nil {
			t.Fatalf("extractClientCredentials: %v", err)
		}
		if creds.ClientID != "client-4" || creds.AuthMethod != TokenEndpointAuthMethodClientSecretPost {
			t.Errorf("creds = %+v", creds)
		}
	})

	t.Run("no client_id at all", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type=refresh_token"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if _, err := extractClientCredentials(req); err == nil {
			t.Error("a request without client_id must be rejected")
		}
	})
}

func readAllString(r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}
	b, err := io.ReadAll(r.Body)
	return string(b), err
}

func TestOAuthServerRedirectURIValidation(t *testing.T) {
	valid := []string{
		"https://app.example.com/cb",
		"https://app.example.com/cb?x=1",
		"http://localhost:3000/cb",
		"http://127.0.0.1:3000/cb",
		"myapp://callback",
	}
	for _, uri := range valid {
		if err := validateOAuthRedirectURI(uri); err != nil {
			t.Errorf("validateOAuthRedirectURI(%q) = %v, want nil", uri, err)
		}
	}

	invalid := []string{
		"",
		"/relative/cb",
		"https://app.example.com/cb#frag",
		"http://app.example.com/cb",
		"javascript://x/%0aalert(1)",
		"data://text/html",
	}
	for _, uri := range invalid {
		if err := validateOAuthRedirectURI(uri); err == nil {
			t.Errorf("validateOAuthRedirectURI(%q) = nil, want an error", uri)
		}
	}

	if err := validateRedirectURIList(nil, true); err == nil {
		t.Error("redirect_uris is required at registration")
	}
	tooMany := make([]string, maxRedirectURIs+1)
	for i := range tooMany {
		tooMany[i] = "https://app.example.com/cb"
	}
	if err := validateRedirectURIList(tooMany, true); err == nil {
		t.Errorf("more than %d redirect URIs must be rejected", maxRedirectURIs)
	}
	// The column is comma separated, so a comma inside a URI is refused.
	if err := validateRedirectURIList([]string{"https://app.example.com/a,b"}, true); err == nil {
		t.Error("a redirect URI containing a comma must be rejected")
	}
}

func TestOAuthServerScopeHelpers(t *testing.T) {
	if got := parseScopeString("  openid   email "); len(got) != 2 || got[0] != ScopeOpenID || got[1] != ScopeEmail {
		t.Errorf("parseScopeString = %v", got)
	}
	if got := parseScopeString(""); got == nil || len(got) != 0 {
		t.Errorf("parseScopeString(\"\") = %v, want an empty non-nil slice", got)
	}
	if !hasAllScopes([]string{ScopeOpenID, ScopeEmail}, []string{ScopeEmail}) {
		t.Error("a superset must cover a subset")
	}
	if hasAllScopes([]string{ScopeOpenID}, []string{ScopeOpenID, ScopeProfile}) {
		t.Error("a narrower grant must not cover a wider request")
	}
	for _, scope := range supportedOAuthScopes {
		if !isSupportedScope(scope) {
			t.Errorf("%q must be supported", scope)
		}
	}
	if isSupportedScope("admin") {
		t.Error("an unknown scope must not be supported")
	}
	if err := validateOAuthScopes("openid admin"); err == nil {
		t.Error("an unsupported scope must be rejected")
	}
	if err := validateOAuthScopes(""); err == nil {
		t.Error("an empty scope must be rejected")
	}
}

func TestOAuthServerAuthorizePKCEValidation(t *testing.T) {
	challenge := strings.Repeat("a", 43)

	if err := validateAuthorizePKCEParams("S256", challenge); err != nil {
		t.Errorf("S256 + a valid challenge = %v", err)
	}
	if err := validateAuthorizePKCEParams("s256", challenge); err != nil {
		t.Errorf("the method is case-insensitive: %v", err)
	}
	if err := validateAuthorizePKCEParams("plain", challenge); err != nil {
		t.Errorf("plain must be accepted: %v", err)
	}
	// PKCE is mandatory in OAuth 2.1, for confidential clients too.
	if err := validateAuthorizePKCEParams("", ""); err == nil {
		t.Error("a missing challenge must be rejected")
	}
	if err := validateAuthorizePKCEParams("S256", ""); err == nil {
		t.Error("a method without a challenge must be rejected")
	}
	if err := validateAuthorizePKCEParams("md5", challenge); err == nil {
		t.Error("an unknown challenge method must be rejected")
	}
	if err := validateAuthorizePKCEParams("S256", strings.Repeat("a", 42)); err == nil {
		t.Error("a too-short challenge must be rejected")
	}
	if err := validateAuthorizePKCEParams("S256", strings.Repeat("a", 129)); err == nil {
		t.Error("a too-long challenge must be rejected")
	}
}

func TestOAuthServerResourceParamValidation(t *testing.T) {
	if err := validateResourceParam(""); err != nil {
		t.Errorf("the resource parameter is optional: %v", err)
	}
	if err := validateResourceParam("https://api.example.com/v1"); err != nil {
		t.Errorf("an absolute URI must be accepted: %v", err)
	}
	for _, bad := range []string{"/v1", "https://api.example.com/#x", "https://api.example.com/?x=1"} {
		if err := validateResourceParam(bad); err == nil {
			t.Errorf("validateResourceParam(%q) = nil, want an error", bad)
		}
	}
}

func TestOAuthServerRedirectURLBuilders(t *testing.T) {
	code := "the-code"
	state := "the-state"
	o := &oauthAuthorization{
		RedirectURI:       "https://app.example.com/cb?keep=1",
		AuthorizationCode: &code,
		State:             &state,
	}
	u, err := url.Parse(buildSuccessRedirectURL(o))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Query().Get("code") != code || u.Query().Get("state") != state {
		t.Errorf("success redirect = %q", u.String())
	}
	if u.Query().Get("keep") != "1" {
		t.Error("an existing query parameter of the registered redirect_uri must survive")
	}

	e, err := url.Parse(buildErrorRedirectURL("https://app.example.com/cb", oAuth2ErrorAccessDenied, "denied", ""))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if e.Query().Get("error") != oAuth2ErrorAccessDenied || e.Query().Get("error_description") != "denied" {
		t.Errorf("error redirect = %q", e.String())
	}
	if _, ok := e.Query()["state"]; ok {
		t.Error("an empty state must not be echoed")
	}

	if got := joinURLPath("https://site.example.com/", "oauth/consent"); got != "https://site.example.com/oauth/consent" {
		t.Errorf("joinURLPath = %q", got)
	}
	if got := joinURLPath("https://site.example.com", "/oauth/consent"); got != "https://site.example.com/oauth/consent" {
		t.Errorf("joinURLPath = %q", got)
	}
}

func TestOAuthServerAuthorizationPKCEVerification(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := codeChallengeS256(verifier)
	method := challengeMethodS256

	o := &oauthAuthorization{CodeChallenge: &challenge, CodeChallengeMethod: &method}
	if err := o.VerifyPKCE(verifier); err != nil {
		t.Errorf("the matching verifier must pass: %v", err)
	}
	if err := o.VerifyPKCE("some-other-verifier"); err == nil {
		t.Error("a wrong verifier must fail")
	}
	if err := o.VerifyPKCE(""); err == nil {
		t.Error("a missing verifier must fail when a challenge is stored")
	}

	// No challenge stored: nothing to verify (defence in depth — the
	// authorization endpoint makes PKCE mandatory, so this cannot normally
	// happen).
	empty := &oauthAuthorization{}
	if err := empty.VerifyPKCE(""); err != nil {
		t.Errorf("an authorization without a challenge verifies trivially: %v", err)
	}
}

func TestOAuthServerClientColumnHelpers(t *testing.T) {
	c := &oauthClient{
		RedirectURIs: "https://a.example.com/cb,https://b.example.com/cb",
		GrantTypes:   "authorization_code,refresh_token",
		ClientType:   OAuthClientTypeConfidential,
	}
	if got := c.GetRedirectURIs(); len(got) != 2 || got[1] != "https://b.example.com/cb" {
		t.Errorf("GetRedirectURIs = %v", got)
	}
	if !c.IsGrantTypeAllowed(GrantTypeRefreshToken) || c.IsGrantTypeAllowed("password") {
		t.Errorf("IsGrantTypeAllowed is wrong for %v", c.GetGrantTypes())
	}
	if !isRegisteredRedirectURI(c, "https://a.example.com/cb") {
		t.Error("an exactly registered URI must match")
	}
	// Exact match only: no prefix, no wildcard.
	if isRegisteredRedirectURI(c, "https://a.example.com/cb/extra") {
		t.Error("redirect URI matching must be exact")
	}

	empty := &oauthClient{}
	if len(empty.GetRedirectURIs()) != 0 || len(empty.GetGrantTypes()) != 0 {
		t.Error("empty columns must produce empty slices")
	}
}

func TestOAuthServerSecureAlphanumeric(t *testing.T) {
	a := secureAlphanumeric(32)
	if len(a) != 32 {
		t.Fatalf("len = %d, want 32", len(a))
	}
	if a == secureAlphanumeric(32) {
		t.Error("two identifiers must differ")
	}
	for _, r := range a {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz234567", r) {
			t.Fatalf("unexpected character %q in %q", r, a)
		}
	}
	if len(secureAlphanumeric(4)) != 8 {
		t.Error("a length below 8 is raised to 8")
	}
}

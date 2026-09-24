package auth

// Unit tests for the external-provider plumbing: the claim mapping, the minimal
// OAuth 2.0 client, ID-token verification against a fake issuer, the Apple
// client-secret signing and the OAuth error mapping. None of them need a
// database and none of them touch the network.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testAPI(t *testing.T, cfg *Config) *api {
	t.Helper()
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	return &api{cfg: cfg, log: slog.New(slog.NewTextHandler(io.Discard, nil)), outbound: defaultOutboundNetworks}
}

func TestProviderClaimsToMapMatchesUpstreamKeys(t *testing.T) {
	c := &providerClaims{
		Issuer:     "https://accounts.google.com",
		Subject:    "sub-1",
		Name:       "Gina",
		Picture:    "https://cdn/x.png",
		Email:      "gina@example.com",
		AvatarURL:  "https://cdn/x.png",
		FullName:   "Gina",
		ProviderID: "sub-1",
		CustomClaims: map[string]any{
			"hd": "example.com",
		},
	}
	m := c.toMap()

	for k, want := range map[string]any{
		"iss":         "https://accounts.google.com",
		"sub":         "sub-1",
		"name":        "Gina",
		"picture":     "https://cdn/x.png",
		"email":       "gina@example.com",
		"avatar_url":  "https://cdn/x.png",
		"full_name":   "Gina",
		"provider_id": "sub-1",
	} {
		if m[k] != want {
			t.Errorf("%s = %v, want %v", k, m[k], want)
		}
	}
	// Upstream leaves `omitempty` off exactly these two, so they are always
	// present even when false — clients rely on reading them directly.
	for _, k := range []string{"email_verified", "phone_verified"} {
		v, ok := m[k]
		if !ok {
			t.Errorf("%s must always be present", k)
		}
		if v != false {
			t.Errorf("%s = %v, want false", k, v)
		}
	}
	// Zero-valued optional claims must be absent.
	for _, k := range []string{"family_name", "nickname", "phone", "slug", "user_name", "iat", "exp", "aud"} {
		if _, ok := m[k]; ok {
			t.Errorf("%s must be omitted when empty", k)
		}
	}
	if custom, ok := m["custom_claims"].(map[string]any); !ok || custom["hd"] != "example.com" {
		t.Errorf("custom_claims = %v", m["custom_claims"])
	}
}

func TestApplyPrimaryEmailPrefersThePrimaryAddress(t *testing.T) {
	d := &userProvidedData{
		Emails: []providerEmail{
			{Email: "secondary@example.com", Verified: false},
			{Email: "primary@example.com", Verified: true, Primary: true},
			{Email: "third@example.com", Verified: false},
		},
		Metadata: &providerClaims{},
	}
	d.applyPrimaryEmail()
	if d.Metadata.Email != "primary@example.com" || !d.Metadata.EmailVerified {
		t.Fatalf("email = %q verified = %v", d.Metadata.Email, d.Metadata.EmailVerified)
	}

	// Without a primary flag the LAST address wins, as upstream's loop does.
	d = &userProvidedData{Emails: []providerEmail{
		{Email: "a@example.com", Verified: true},
		{Email: "b@example.com", Verified: false},
	}}
	d.applyPrimaryEmail()
	if d.Metadata.Email != "b@example.com" || d.Metadata.EmailVerified {
		t.Fatalf("email = %q verified = %v", d.Metadata.Email, d.Metadata.EmailVerified)
	}
}

func TestOAuthConfigAuthCodeURL(t *testing.T) {
	c := &oauthConfig{
		ClientID:    "client",
		AuthURL:     "https://provider.test/authorize?foo=bar",
		RedirectURL: "https://api.test/callback",
		Scopes:      []string{"email", "profile"},
	}
	raw := c.authCodeURL("state-123", url.Values{"prompt": {"consent"}})
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()
	for k, want := range map[string]string{
		"foo":           "bar",
		"response_type": "code",
		"client_id":     "client",
		"redirect_uri":  "https://api.test/callback",
		"scope":         "email profile",
		"state":         "state-123",
		"prompt":        "consent",
	} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
}

func TestOAuthConfigExchangeCode(t *testing.T) {
	var got url.Values
	mode := "json"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = r.Form
		switch mode {
		case "json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"at","refresh_token":"rt","id_token":"idt","token_type":"bearer"}`)
		case "form":
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			_, _ = io.WriteString(w, "access_token=at&token_type=bearer")
		case "error":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"error":"bad_verification_code"}`)
		case "status":
			http.Error(w, "nope", http.StatusUnauthorized)
		}
	}))
	defer srv.Close()

	c := &oauthConfig{ClientID: "client", ClientSecret: "secret", TokenURL: srv.URL, RedirectURL: "https://api.test/callback"}
	hc := srv.Client()

	tok, err := c.exchangeCode(context.Background(), hc, "the-code", nil)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if tok.AccessToken != "at" || tok.RefreshToken != "rt" || tok.IDToken != "idt" {
		t.Fatalf("token = %+v", tok)
	}
	for k, want := range map[string]string{
		"grant_type":    "authorization_code",
		"code":          "the-code",
		"client_id":     "client",
		"client_secret": "secret",
		"redirect_uri":  "https://api.test/callback",
	} {
		if got.Get(k) != want {
			t.Errorf("form %s = %q, want %q", k, got.Get(k), want)
		}
	}

	// GitHub's legacy form-encoded answer.
	mode = "form"
	tok, err = c.exchangeCode(context.Background(), hc, "the-code", nil)
	if err != nil || tok.AccessToken != "at" {
		t.Fatalf("form-encoded exchange: tok = %+v err = %v", tok, err)
	}

	// A 200 body carrying an OAuth error is still an error.
	mode = "error"
	if _, err := c.exchangeCode(context.Background(), hc, "the-code", nil); err == nil {
		t.Error("an error body must fail the exchange")
	}
	mode = "status"
	if _, err := c.exchangeCode(context.Background(), hc, "the-code", nil); err == nil {
		t.Error("a non-2xx token response must fail the exchange")
	}
}

func TestProviderRegistry(t *testing.T) {
	names := registeredProviders()
	for _, want := range []string{"apple", "github", "google", "kakao"} {
		if !containsString(names, want) {
			t.Errorf("provider %q is not registered (have %v)", want, names)
		}
	}

	a := testAPI(t, nil)
	if _, _, err := a.provider(context.Background(), "nosuchprovider", ""); err == nil {
		t.Error("an unknown provider must fail")
	}
	// Registered but not configured: upstream's ValidateOAuth messages.
	_, _, err := a.provider(context.Background(), "github", "")
	if err == nil || !strings.Contains(err.Error(), "provider is not enabled") {
		t.Errorf("disabled provider error = %v", err)
	}

	cfg := DefaultConfig()
	cfg.External["github"] = ProviderConfig{Enabled: true, ClientID: []string{"id"}}
	a = testAPI(t, cfg)
	if _, _, err := a.provider(context.Background(), "github", ""); err == nil ||
		!strings.Contains(err.Error(), "missing OAuth secret") {
		t.Errorf("incomplete provider error = %v", err)
	}
}

func TestGitHubProviderHonoursEnterpriseURL(t *testing.T) {
	cfg := DefaultConfig()
	cfg.External["github"] = ProviderConfig{
		Enabled: true, ClientID: []string{"id"}, Secret: "s",
		RedirectURI: "https://api.test/callback", URL: "https://ghe.corp.test/",
	}
	a := testAPI(t, cfg)
	p, _, err := a.provider(context.Background(), "github", "")
	if err != nil {
		t.Fatalf("provider: %v", err)
	}
	gh := p.(*githubProvider)
	if gh.apiHost != "https://ghe.corp.test/api/v3" {
		t.Errorf("apiHost = %q", gh.apiHost)
	}
	if !strings.HasPrefix(gh.oauth.AuthURL, "https://ghe.corp.test/login/oauth/authorize") {
		t.Errorf("authURL = %q", gh.oauth.AuthURL)
	}
}

// ---- Apple -------------------------------------------------------------------

func TestAppleSecretAcceptsAPrebuiltJWT(t *testing.T) {
	s, err := parseAppleSecret("header.payload.signature")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got, err := s.clientSecret("client", time.Now())
	if err != nil || got != "header.payload.signature" {
		t.Fatalf("clientSecret = %q, %v — an upstream-format secret must pass through", got, err)
	}
}

func TestAppleSecretSignsES256ClientSecret(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	doc, _ := json.Marshal(map[string]string{
		"team_id": "TEAM123", "key_id": "KEY456", "private_key": keyPEM,
	})
	s, err := parseAppleSecret(string(doc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	now := time.Now()
	secret, err := s.clientSecret("com.example.app", now)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	claims := jwt.MapClaims{}
	tok, err := jwt.NewParser(jwt.WithValidMethods([]string{"ES256"})).
		ParseWithClaims(secret, claims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil })
	if err != nil {
		t.Fatalf("verify client secret: %v", err)
	}
	if tok.Header["kid"] != "KEY456" {
		t.Errorf("kid = %v", tok.Header["kid"])
	}
	if claims["iss"] != "TEAM123" || claims["sub"] != "com.example.app" || claims["aud"] != DefaultAppleIssuer {
		t.Errorf("claims = %v", claims)
	}
	if exp, _ := claims["exp"].(float64); int64(exp) != now.Add(appleClientSecretTTL).Unix() {
		t.Errorf("exp = %v", claims["exp"])
	}

	if _, err := parseAppleSecret(`{"team_id":"T"}`); err == nil {
		t.Error("an incomplete signing-key document must be rejected")
	}
}

func TestAppleAuthCodeURLUsesFormPost(t *testing.T) {
	p := &appleProvider{oauth: oauthConfig{
		ClientID: "com.example.app", AuthURL: "https://appleid.apple.com/auth/authorize",
		RedirectURL: "https://api.test/callback", Scopes: []string{"email", "name"},
	}}
	u, err := url.Parse(p.authCodeURL("state", nil))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.Query().Get("response_mode") != "form_post" {
		t.Fatalf("response_mode = %q, want form_post", u.Query().Get("response_mode"))
	}
}

func TestAppleParseCallbackUser(t *testing.T) {
	p := &appleProvider{}
	data := &userProvidedData{Metadata: &providerClaims{}}
	if err := p.parseCallbackUser(`{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"a@b.test"}`, data); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if data.Metadata.Name != "Ada Lovelace" || data.Metadata.FullName != "Ada Lovelace" {
		t.Fatalf("metadata = %+v", data.Metadata)
	}
}

func TestParseAppleIDTokenCustomClaims(t *testing.T) {
	data := parseAppleIDToken(&idToken{
		Issuer:  DefaultAppleIssuer,
		Subject: "apple-sub",
		Claims: map[string]any{
			"email":            "private@privaterelay.appleid.com",
			"is_private_email": "true", // Apple sends a stringified bool here
		},
	})
	if len(data.Emails) != 1 || !data.Emails[0].Verified || !data.Emails[0].Primary {
		t.Fatalf("emails = %+v", data.Emails)
	}
	if data.Metadata.CustomClaims["is_private_email"] != true {
		t.Errorf("custom_claims = %v", data.Metadata.CustomClaims)
	}
}

// ---- ID token verification ---------------------------------------------------

func TestVerifyIDToken(t *testing.T) {
	p := newFakeOIDCProvider(t)
	a := testAPI(t, nil)
	resetOIDCCache()
	t.Cleanup(resetOIDCCache)

	tok, err := a.verifyIDToken(context.Background(), a.httpClient(), p.srv.URL, p.signIDToken(nil), idTokenOptions{
		AccessToken: p.accessToken,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if tok.Subject != p.sub || tok.Issuer != p.srv.URL {
		t.Fatalf("token = %+v", tok)
	}
	if !containsString(tok.Audience, "google-client-id") {
		t.Errorf("aud = %v", tok.Audience)
	}

	// at_hash must bind the ID token to the access token it came with.
	if _, err := a.verifyIDToken(context.Background(), a.httpClient(), p.srv.URL, p.signIDToken(nil), idTokenOptions{
		AccessToken: "some-other-access-token",
	}); err == nil {
		t.Error("a mismatched access token must fail the at_hash check")
	}

	// A token from a different issuer is refused even though it is signed by
	// the same key set.
	if _, err := a.verifyIDToken(context.Background(), a.httpClient(), p.srv.URL,
		p.signIDToken(map[string]any{"iss": "https://evil.test"}), idTokenOptions{
			SkipAccessTokenCheck: true,
		}); err == nil {
		t.Error("a foreign issuer must be refused")
	}

	// Expired.
	if _, err := a.verifyIDToken(context.Background(), a.httpClient(), p.srv.URL,
		p.signIDToken(map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}), idTokenOptions{
			SkipAccessTokenCheck: true,
		}); err == nil {
		t.Error("an expired token must be refused")
	}

	// No expiry at all.
	if _, err := a.verifyIDToken(context.Background(), a.httpClient(), p.srv.URL,
		p.signIDToken(map[string]any{"exp": nil}), idTokenOptions{SkipAccessTokenCheck: true}); err == nil {
		t.Error("a token without exp must be refused")
	}

	// `alg: none` and HMAC must never verify against a published public key.
	none := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
		"eyJpc3MiOiJodHRwOi8vZXhhbXBsZS5jb20iLCJzdWIiOiJ4In0."
	if _, err := a.verifyIDToken(context.Background(), a.httpClient(), p.srv.URL, none, idTokenOptions{SkipAccessTokenCheck: true}); err == nil {
		t.Error("alg=none must be refused")
	}
	hs := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": p.srv.URL, "sub": "x", "aud": "google-client-id",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	hsToken, err := hs.SignedString([]byte("secret"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := a.verifyIDToken(context.Background(), a.httpClient(), p.srv.URL, hsToken, idTokenOptions{SkipAccessTokenCheck: true}); err == nil {
		t.Error("an HMAC-signed token must be refused")
	}
}

func TestVerifyIDTokenRefreshesRotatedKeys(t *testing.T) {
	p := newFakeOIDCProvider(t)
	a := testAPI(t, nil)
	resetOIDCCache()
	t.Cleanup(resetOIDCCache)

	if _, err := a.verifyIDToken(context.Background(), a.httpClient(), p.srv.URL, p.signIDToken(nil), idTokenOptions{
		SkipAccessTokenCheck: true,
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// The provider rotates its key; the cached set no longer has the kid, so a
	// refresh must happen transparently.
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	p.key = newKey
	p.kid = "test-key-2"

	if _, err := a.verifyIDToken(context.Background(), a.httpClient(), p.srv.URL, p.signIDToken(nil), idTokenOptions{
		SkipAccessTokenCheck: true,
	}); err != nil {
		t.Fatalf("verify after rotation: %v", err)
	}
}

func TestUnverifiedIDTokenIssuer(t *testing.T) {
	p := newFakeOIDCProvider(t)
	iss, err := unverifiedIDTokenIssuer(p.signIDToken(nil))
	if err != nil || iss != p.srv.URL {
		t.Fatalf("issuer = %q, %v", iss, err)
	}
	if _, err := unverifiedIDTokenIssuer("not-a-token"); err == nil {
		t.Error("a malformed token must fail")
	}
}

func TestJSONWebKeyParsing(t *testing.T) {
	// An EC point that is not on the curve must be rejected outright.
	bad := jsonWebKey{KeyType: "EC", Curve: "P-256", X: "AQAB", Y: "AQAB"}
	if _, err := bad.publicKey(); err == nil {
		t.Error("an off-curve point must be rejected")
	}
	// Encryption keys are ignored, not fatal.
	enc := jsonWebKey{KeyType: "RSA", Use: "enc", N: "AQAB", E: "AQAB"}
	if k, err := enc.publicKey(); err != nil || k != nil {
		t.Errorf("use=enc key: %v %v", k, err)
	}
	rsa := jsonWebKey{KeyType: "RSA", N: "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bO", E: "AQAB"}
	if k, err := rsa.publicKey(); err != nil || k == nil {
		t.Errorf("rsa key: %v %v", k, err)
	}
}

// ---- error mapping -----------------------------------------------------------

func TestOAuthErrorQuery(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
		code string
	}{
		{"signup disabled", unprocessableEntityError(ErrorCodeSignupDisabled, "Signups not allowed for this instance"), "access_denied", ErrorCodeSignupDisabled},
		{"banned", forbiddenError(ErrorCodeUserBanned, "User is banned"), "access_denied", ErrorCodeUserBanned},
		{"needs verification", unprocessableEntityError(ErrorCodeProviderEmailNeedsVerification, "x"), "access_denied", ErrorCodeProviderEmailNeedsVerification},
		{"bad state", badRequestError(ErrorCodeBadOAuthState, "OAuth state parameter is invalid"), "invalid_request", ErrorCodeBadOAuthState},
		{"internal", internalServerError("boom"), "server_error", ErrorCodeUnexpectedFailure},
		{"provider error", &providerOAuthError{Err: "access_denied", Description: "user said no"}, "access_denied", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _, code := oauthErrorQuery(tc.err)
			if got != tc.want || code != tc.code {
				t.Fatalf("= (%q, %q), want (%q, %q)", got, code, tc.want, tc.code)
			}
		})
	}
}

func TestSessionRedirectURLPutsTokensInTheFragment(t *testing.T) {
	s := &AccessTokenResponse{Token: "at", TokenType: "bearer", ExpiresIn: 3600, ExpiresAt: 123, RefreshToken: "rt"}
	raw := s.asRedirectURL("https://app.test/welcome", url.Values{"provider_token": {"pt"}})
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if u.RawQuery != "" {
		t.Errorf("tokens must not appear in the query string: %q", u.RawQuery)
	}
	frag, _ := url.ParseQuery(u.Fragment)
	if frag.Get("access_token") != "at" || frag.Get("refresh_token") != "rt" || frag.Get("provider_token") != "pt" {
		t.Fatalf("fragment = %v", frag)
	}
}

func TestRedactURLDropsQueryStrings(t *testing.T) {
	if got := redactURL("https://api.github.com/user?access_token=secret"); got != "https://api.github.com/user" {
		t.Fatalf("redactURL = %q", got)
	}
}

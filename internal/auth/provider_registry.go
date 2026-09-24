package auth

// External identity providers: the data model, the minimal OAuth 2.0 client and
// the provider registry the /authorize + /callback surface is built on.
//
// # Upstream parity
//
// This file reproduces github.com/supabase/auth/internal/api/provider/provider.go
// (Claims, Email, UserProvidedData, the Provider/OAuthProvider interfaces and
// makeRequest) and the parts of golang.org/x/oauth2 upstream leans on.
//
// Dilion has NO golang.org/x/oauth2 dependency (project.md: stdlib + already
// vendored modules only), so the ~80 lines of RFC 6749 §4.1 this package needs —
// building the authorization URL and POSTing the code to the token endpoint —
// are implemented here. The wire behaviour is the same:
//
//   - the authorization request carries response_type=code, client_id,
//     redirect_uri, scope (space separated), state and any extra parameters the
//     caller passed through;
//   - the token request is an application/x-www-form-urlencoded POST with
//     grant_type=authorization_code, code, redirect_uri, client_id and
//     client_secret. Credentials go in the BODY, which x/oauth2 calls
//     AuthStyleInParams: all four wave-III providers accept it (GitHub and Kakao
//     require it), so there is no auth-style probing to reproduce.
//
// # Adding a provider (wave IV)
//
// Write providers_<name>.go, build an externalProvider in a factory and call
// registerProvider("<name>", factory) from that file's init(). NOTHING else in
// the package changes — the registry drives /authorize, /callback and
// GET /settings alike.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dilion-io/dilion/internal/netguard"
)

// ---- provider data model ---------------------------------------------------

// providerEmail is upstream's provider.Email.
type providerEmail struct {
	Email    string
	Verified bool
	Primary  bool
}

// providerClaims is upstream's provider.Claims: the normalized OIDC-shaped view
// of whatever a provider hands back. It is what ends up in
// auth.identities.identity_data (see toMap), so the KEYS are a compatibility
// contract with gotrue-js and with existing Supabase projects.
type providerClaims struct {
	// Reserved claims.
	Issuer   string
	Subject  string
	Audience []string
	IssuedAt float64
	Expires  float64

	// Default profile claims.
	Name              string
	FamilyName        string
	GivenName         string
	MiddleName        string
	NickName          string
	PreferredUsername string
	Profile           string
	Picture           string
	Website           string
	Gender            string
	Birthdate         string
	ZoneInfo          string
	Locale            string
	UpdatedAt         string
	Email             string
	EmailVerified     bool
	Phone             string
	PhoneVerified     bool

	// CustomClaims carries provider-specific claims (Google's `hd`, Apple's
	// `is_private_email`, ...).
	CustomClaims map[string]any

	// Deprecated upstream, still emitted for backwards compatibility.
	FullName   string
	AvatarURL  string
	Slug       string
	ProviderID string
	UserName   string
}

// toMap reproduces upstream's structs.Map(userData.Metadata): every non-zero
// field under its `structs` tag, with email_verified and phone_verified ALWAYS
// present (upstream omits `omitempty` on exactly those two).
func (c *providerClaims) toMap() JSONMap {
	if c == nil {
		return JSONMap{}
	}
	out := JSONMap{
		"email_verified": c.EmailVerified,
		"phone_verified": c.PhoneVerified,
	}
	str := map[string]string{
		"iss":                c.Issuer,
		"sub":                c.Subject,
		"name":               c.Name,
		"family_name":        c.FamilyName,
		"given_name":         c.GivenName,
		"middle_name":        c.MiddleName,
		"nickname":           c.NickName,
		"preferred_username": c.PreferredUsername,
		"profile":            c.Profile,
		"picture":            c.Picture,
		"website":            c.Website,
		"gender":             c.Gender,
		"birthdate":          c.Birthdate,
		"zoneinfo":           c.ZoneInfo,
		"locale":             c.Locale,
		"updated_at":         c.UpdatedAt,
		"email":              c.Email,
		"phone":              c.Phone,
		"full_name":          c.FullName,
		"avatar_url":         c.AvatarURL,
		"slug":               c.Slug,
		"provider_id":        c.ProviderID,
		"user_name":          c.UserName,
	}
	for k, v := range str {
		if v != "" {
			out[k] = v
		}
	}
	if len(c.Audience) > 0 {
		aud := make([]any, 0, len(c.Audience))
		for _, a := range c.Audience {
			aud = append(aud, a)
		}
		out["aud"] = aud
	}
	if c.IssuedAt != 0 {
		out["iat"] = c.IssuedAt
	}
	if c.Expires != 0 {
		out["exp"] = c.Expires
	}
	if len(c.CustomClaims) > 0 {
		out["custom_claims"] = c.CustomClaims
	}
	return out
}

// userProvidedData is upstream's provider.UserProvidedData.
type userProvidedData struct {
	Emails   []providerEmail
	Metadata *providerClaims
}

// applyPrimaryEmail is the loop both the callback and the id_token grant run
// before touching the database (upstream internalExternalProviderCallback /
// IdTokenGrant): the PRIMARY address wins, otherwise the last one seen.
func (d *userProvidedData) applyPrimaryEmail() {
	if d.Metadata == nil {
		d.Metadata = &providerClaims{}
	}
	d.Metadata.EmailVerified = false
	for _, e := range d.Emails {
		d.Metadata.Email = e.Email
		d.Metadata.EmailVerified = e.Verified
		if e.Primary {
			break
		}
	}
}

// ---- provider interface + registry -----------------------------------------

// externalProvider is one configured OAuth 2.0 / OIDC identity provider. It is
// upstream's provider.OAuthProvider, minus the OAuth 1.0a (Twitter) and
// provider-side-PKCE branches, which no wave-III provider needs.
type externalProvider interface {
	// authCodeURL builds the provider's authorization URL. `extra` holds the
	// pass-through query parameters of GET /authorize.
	authCodeURL(state string, extra url.Values) string
	// exchange redeems an authorization code at the provider's token endpoint.
	exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error)
	// userData maps the provider's user info onto the shared claim model.
	userData(ctx context.Context, hc *http.Client, tok *oauthToken) (*userProvidedData, error)
}

// callbackUserParser is implemented by providers that receive part of the
// profile in the CALLBACK request rather than from an API (Apple posts a `user`
// field, once, on first authorization).
type callbackUserParser interface {
	parseCallbackUser(raw string, data *userProvidedData) error
}

// providerFactory builds a provider from its configuration. `scopes` is the
// comma-separated `scopes` query parameter of GET /authorize.
type providerFactory func(ctx context.Context, a *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error)

var providerFactories = map[string]providerFactory{}

// registerProvider adds an external provider to the registry. Call it from the
// provider file's init(). Registering the same name twice is a programming
// error and panics.
func registerProvider(name string, f providerFactory) {
	if name == "" || f == nil {
		panic("auth: registerProvider requires a name and a factory")
	}
	if _, dup := providerFactories[name]; dup {
		panic("auth: duplicate provider registration: " + name)
	}
	providerFactories[name] = f
}

// registeredProviders returns the provider names that have a factory, sorted.
// GET /settings still reports the full ExternalProviders list (upstream does the
// same); this is for diagnostics and tests.
func registeredProviders() []string {
	out := make([]string, 0, len(providerFactories))
	for name := range providerFactories {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// provider resolves a provider by name, exactly as upstream's api.Provider:
// unknown name or failed configuration validation is the caller's 400.
//
// Lookup order: the code-defined source (ports.ProviderSource), then the
// built-in factories, then auth.custom_oauth_providers.
func (a *api) provider(ctx context.Context, name, scopes string) (externalProvider, ProviderConfig, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	cfg := a.cfg.External[name]

	if p, ok, err := a.codeProvider(ctx, name, scopes); err != nil {
		return nil, cfg, err
	} else if ok {
		return p, cfg, nil
	}

	f, ok := providerFactories[name]
	if !ok {
		// Not a built-in: try a runtime custom OAuth provider (admin-registered,
		// auth.custom_oauth_providers), resolved by its identifier. It plugs into
		// the same externalProvider interface, so /authorize and /callback treat
		// it exactly like a built-in.
		cp, cerr := a.resolveCustomProvider(ctx, name, scopes)
		if cerr != nil {
			return nil, cfg, fmt.Errorf("Provider %s could not be found", name)
		}
		return cp, cfg, nil
	}
	p, err := f(ctx, a, name, cfg, scopes)
	if err != nil {
		return nil, cfg, err
	}
	return p, cfg, nil
}

// validateOAuth is upstream's conf.OAuthProviderConfiguration.ValidateOAuth,
// message for message.
func validateOAuth(cfg ProviderConfig) error {
	switch {
	case !cfg.Enabled:
		return errors.New("provider is not enabled")
	case len(cfg.ClientID) == 0:
		return errors.New("missing OAuth client ID")
	case cfg.Secret == "":
		return errors.New("missing OAuth secret")
	case cfg.RedirectURI == "":
		return errors.New("missing redirect URI")
	}
	return nil
}

// chooseHost is upstream's provider.chooseHost: a configured base URL wins over
// the provider's default host, and a trailing slash is trimmed.
func chooseHost(base, defaultHost string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		return "https://" + defaultHost
	}
	return strings.TrimSuffix(base, "/")
}

// scopesWithDefaults appends the caller's comma-separated `scopes` parameter to
// the provider's defaults (upstream does exactly this, comma separated).
func scopesWithDefaults(defaults []string, scopes string) []string {
	out := append([]string(nil), defaults...)
	if scopes = strings.TrimSpace(scopes); scopes != "" {
		out = append(out, strings.Split(scopes, ",")...)
	}
	return out
}

// ---- endpoint overrides (tests only) ---------------------------------------

// providerEndpoints are the network locations of a provider. Tests point a
// built-in provider at an httptest server through overrideProviderEndpoints;
// production code never writes to the override table.
type providerEndpoints struct {
	AuthURL     string
	TokenURL    string
	UserInfoURL string
	Issuer      string
	APIHost     string
}

var (
	endpointOverrideMu sync.RWMutex
	endpointOverrides  = map[string]providerEndpoints{}
)

// overrideProviderEndpoints redirects one provider at the given endpoints. It is
// the equivalent of upstream's provider.OverrideGoogleProvider and MUST only be
// used from tests.
func overrideProviderEndpoints(name string, e providerEndpoints) {
	endpointOverrideMu.Lock()
	defer endpointOverrideMu.Unlock()
	endpointOverrides[name] = e
}

// resetProviderEndpoints drops an override (tests only).
func resetProviderEndpoints(name string) {
	endpointOverrideMu.Lock()
	defer endpointOverrideMu.Unlock()
	delete(endpointOverrides, name)
}

// endpointsFor merges the override for `name` over the provider's defaults;
// every non-empty override field wins.
func endpointsFor(name string, def providerEndpoints) providerEndpoints {
	endpointOverrideMu.RLock()
	o, ok := endpointOverrides[name]
	endpointOverrideMu.RUnlock()
	if !ok {
		return def
	}
	if o.AuthURL != "" {
		def.AuthURL = o.AuthURL
	}
	if o.TokenURL != "" {
		def.TokenURL = o.TokenURL
	}
	if o.UserInfoURL != "" {
		def.UserInfoURL = o.UserInfoURL
	}
	if o.Issuer != "" {
		def.Issuer = o.Issuer
	}
	if o.APIHost != "" {
		def.APIHost = o.APIHost
	}
	return def
}

// ---- minimal OAuth 2.0 client ----------------------------------------------

// oauthConfig is the subset of oauth2.Config this package uses.
type oauthConfig struct {
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	RedirectURL  string
	Scopes       []string

	// AutoDetectAuth sends the client credentials by HTTP Basic first and, if
	// the token endpoint rejects that, once more in the body: x/oauth2's
	// AuthStyleAutoDetect, which is what upstream's custom providers get by
	// leaving the style unset. RFC 6749 §2.3.1 obliges every server to accept
	// Basic and calls credentials in the body NOT RECOMMENDED, so a server that
	// registered this client for Basic — the default of Dilion's own OAuth
	// server, which matches the method exactly — refuses the body.
	//
	// The zero value keeps credentials in the body only, which the built-in
	// providers rely on (GitHub and Kakao require it).
	AutoDetectAuth bool
}

// oauthToken is the token endpoint's response (RFC 6749 §5.1). `IDToken` is the
// OIDC extension member, which x/oauth2 exposes as tok.Extra("id_token").
type oauthToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`

	// Error members, so a 200-with-error body (GitHub) is still detected.
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`

	// raw is the verbatim token-endpoint response body; some providers (workos)
	// return the user profile inline there instead of at a userinfo endpoint.
	raw []byte `json:"-"`
}

// authCodeURL builds the RFC 6749 §4.1.1 authorization request.
func (c *oauthConfig) authCodeURL(state string, extra url.Values) string {
	u, err := url.Parse(c.AuthURL)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.ClientID)
	if c.RedirectURL != "" {
		q.Set("redirect_uri", c.RedirectURL)
	}
	if len(c.Scopes) > 0 {
		q.Set("scope", strings.Join(c.Scopes, " "))
	}
	q.Set("state", state)
	for k, vs := range extra {
		if len(vs) > 0 {
			q.Set(k, vs[0])
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// exchangeCode redeems an authorization code. `extra` lets a provider add form
// fields (Apple sends its client-secret JWT this way; PKCE sends code_verifier).
//
// With AutoDetectAuth the credentials go by HTTP Basic first, and only a
// response the endpoint REJECTED — not a transport failure — is retried with
// them in the body. Retrying is safe because a server authenticates the client
// before it looks at the code: a rejected attempt has not consumed it.
func (c *oauthConfig) exchangeCode(ctx context.Context, hc *http.Client, code string, extra url.Values) (*oauthToken, error) {
	if !c.AutoDetectAuth {
		return c.exchangeCodeAuth(ctx, hc, code, extra, false)
	}
	tok, err := c.exchangeCodeAuth(ctx, hc, code, extra, true)
	var rejected *tokenEndpointStatusError
	if err == nil || !errors.As(err, &rejected) {
		return tok, err
	}
	tok, berr := c.exchangeCodeAuth(ctx, hc, code, extra, false)
	if berr != nil {
		return nil, fmt.Errorf("with HTTP Basic: %w; with credentials in the body: %w", err, berr)
	}
	return tok, nil
}

// tokenEndpointStatusError is a non-2xx answer from a token endpoint: the
// request arrived and was refused, which is what makes a retry meaningful.
type tokenEndpointStatusError struct{ status int }

func (e *tokenEndpointStatusError) Error() string {
	return fmt.Sprintf("token endpoint returned %d", e.status)
}

// exchangeCodeAuth performs one token request, with the client credentials in
// an HTTP Basic header or in the form body.
func (c *oauthConfig) exchangeCodeAuth(ctx context.Context, hc *http.Client, code string, extra url.Values, basic bool) (*oauthToken, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	if c.RedirectURL != "" {
		form.Set("redirect_uri", c.RedirectURL)
	}
	if !basic {
		form.Set("client_id", c.ClientID)
		form.Set("client_secret", c.ClientSecret)
	}
	for k, vs := range extra {
		for _, v := range vs {
			form.Set(k, v)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	if basic {
		// RFC 6749 §2.3.1: both halves are form-urlencoded before the Basic
		// encoding, exactly as x/oauth2 does. For the base64url secrets Dilion
		// and upstream issue that encoding changes nothing.
		req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.ClientSecret))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// GitHub answers form-encoded unless JSON is requested explicitly.
	req.Header.Set("Accept", "application/json")

	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(res.Body, maxProviderResponse))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, &tokenEndpointStatusError{status: res.StatusCode}
	}

	tok := &oauthToken{raw: body}
	mediaType, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if strings.Contains(mediaType, "json") || strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
		if err := json.Unmarshal(body, tok); err != nil {
			return nil, fmt.Errorf("token endpoint returned a malformed body: %w", err)
		}
	} else {
		vals, perr := url.ParseQuery(string(body))
		if perr != nil {
			return nil, fmt.Errorf("token endpoint returned a malformed body: %w", perr)
		}
		tok.AccessToken = vals.Get("access_token")
		tok.TokenType = vals.Get("token_type")
		tok.RefreshToken = vals.Get("refresh_token")
		tok.IDToken = vals.Get("id_token")
		tok.Error = vals.Get("error")
		tok.ErrorDescription = vals.Get("error_description")
	}
	if tok.Error != "" {
		return nil, fmt.Errorf("token endpoint returned error %q", tok.Error)
	}
	if tok.AccessToken == "" && tok.IDToken == "" {
		return nil, errors.New("token endpoint returned no access token")
	}
	return tok, nil
}

// maxProviderResponse caps everything read from a provider. A hostile or broken
// provider must not be able to exhaust memory.
const maxProviderResponse = 1 << 20 // 1 MiB

// getJSON is upstream's provider.makeRequest: a Bearer GET whose JSON body is
// decoded into dst.
// getJSONWithHeaders is getJSON with extra request headers (Twitch Client-Id,
// Notion-Version, etc.).
func getJSONWithHeaders(ctx context.Context, hc *http.Client, endpoint, accessToken string, headers map[string]string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxProviderResponse))
	if err != nil {
		return err
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("GET %s returned %d", redactURL(endpoint), res.StatusCode)
	}
	return json.Unmarshal(body, dst)
}

func getJSON(ctx context.Context, hc *http.Client, endpoint, accessToken string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	req.Header.Set("Accept", "application/json")

	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(res.Body, maxProviderResponse))
	if err != nil {
		return err
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("GET %s returned %d", redactURL(endpoint), res.StatusCode)
	}
	return json.Unmarshal(body, dst)
}

// redactURL keeps a provider URL loggable: scheme, host and path only.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "provider endpoint"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// providerTransport is shared by every outbound provider call so connections are
// pooled across requests. Tests may swap it for an httptest transport.
var providerTransport http.RoundTripper = http.DefaultTransport

// httpClient returns the client used for every provider call. The timeout is
// GOTRUE_API_MAX_REQUEST_DURATION: an external provider must never be able to
// hold a Dilion request open longer than the request's own budget.
//
// Its dials are guarded (internal/netguard): the URLs it fetches — a custom
// provider's endpoints and the ones its discovery document names, SAML
// metadata — are set by instance admins, and must not reach the server's own
// network unless the operator allowed that network (Deps.OutboundNetworks).
func (a *api) httpClient() *http.Client {
	return &http.Client{Transport: netguard.Transport(providerTransport, a.outbound), Timeout: a.outboundTimeout()}
}

// trustedHTTPClient is httpClient without the guard, for providers the
// embedder defines in code (ports.ProviderSource), which may well be on its
// own network — a platform's IdP, say.
func (a *api) trustedHTTPClient() *http.Client {
	return &http.Client{Transport: providerTransport, Timeout: a.outboundTimeout()}
}

func (a *api) outboundTimeout() time.Duration {
	if t := a.cfg.APIMaxRequestDuration; t > 0 {
		return t
	}
	return 10 * time.Second
}

// providerClient is the client for calls to p: unguarded for a code-defined
// provider, guarded otherwise.
func (a *api) providerClient(p externalProvider) *http.Client {
	if t, ok := p.(interface{ trustedOutbound() bool }); ok && t.trustedOutbound() {
		return a.trustedHTTPClient()
	}
	return a.httpClient()
}

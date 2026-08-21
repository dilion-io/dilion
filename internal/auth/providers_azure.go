package auth

// Microsoft Azure / Entra ID (OIDC, id_token only) — upstream
// internal/api/provider/azure.go and the parseAzureIDToken branch of
// provider/oidc.go.
//
// Azure deliberately exposes NO userinfo endpoint here: upstream notes the
// UserInfo endpoint "has a history of being less secure" and reads the profile
// exclusively from the verified id_token.
//
// GOTRUE_EXTERNAL_AZURE_URL selects the authority. The default is the
// multi-tenant "common" endpoint, which accepts any Azure tenant; a
// tenant-specific URL pins the issuer to that tenant.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func init() { registerProvider("azure", newAzureProvider) }

const defaultAzureAuthHost = "https://login.microsoftonline.com/common"

// azureIssuerHost is the host every Azure v2 issuer lives on
// (https://login.microsoftonline.com/{tenant}/v2.0).
const azureIssuerHost = "login.microsoftonline.com"

type azureProvider struct {
	a *api

	oauth oauthConfig
	// authHost is the (trimmed) authority, e.g.
	// https://login.microsoftonline.com/common.
	authHost string
	// expectedIssuer, when non-empty, is the exact `iss` a tenant-pinned
	// deployment requires; empty means "any Azure tenant".
	expectedIssuer string
}

func newAzureProvider(_ context.Context, a *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}
	authHost := chooseHost(cfg.URL, "")
	if authHost == "https://" || authHost == "" {
		authHost = defaultAzureAuthHost
	}

	ep := endpointsFor(name, providerEndpoints{
		AuthURL:  authHost + "/oauth2/v2.0/authorize",
		TokenURL: authHost + "/oauth2/v2.0/token",
	})
	return &azureProvider{
		a:              a,
		authHost:       authHost,
		expectedIssuer: azureExpectedIssuer(authHost),
		oauth: oauthConfig{
			ClientID:     cfg.ClientID[0],
			ClientSecret: cfg.Secret,
			AuthURL:      ep.AuthURL,
			TokenURL:     ep.TokenURL,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       scopesWithDefaults([]string{"openid"}, scopes),
		},
	}, nil
}

// azureExpectedIssuer derives the pinned issuer for a tenant-specific authority.
// The multi-tenant endpoints (common/organizations/consumers) accept any tenant,
// so they pin nothing.
func azureExpectedIssuer(authHost string) string {
	u, err := url.Parse(authHost)
	if err != nil {
		return ""
	}
	tenant := strings.Trim(u.Path, "/")
	switch tenant {
	case "", "common", "organizations", "consumers":
		return ""
	default:
		return strings.TrimSuffix(authHost, "/") + "/v2.0"
	}
}

func (p *azureProvider) authCodeURL(state string, extra url.Values) string {
	return p.oauth.authCodeURL(state, extra)
}

func (p *azureProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return p.oauth.exchangeCode(ctx, hc, code, nil)
}

func (p *azureProvider) userData(ctx context.Context, _ *http.Client, tok *oauthToken) (*userProvidedData, error) {
	if tok.IDToken == "" {
		return nil, fmt.Errorf("azure: token response has no id_token")
	}
	// The token's own issuer names which tenant signed it; it must be an Azure
	// issuer (and the pinned one, if configured) before its keys are trusted.
	detected, err := unverifiedIDTokenIssuer(tok.IDToken)
	if err != nil {
		return nil, err
	}
	if perr := p.validateIssuer(detected); perr != nil {
		return nil, perr
	}

	idt, err := p.a.verifyIDToken(ctx, detected, tok.IDToken, idTokenOptions{
		AcceptableIssuers:    []string{detected},
		AccessToken:          tok.AccessToken,
		SkipAccessTokenCheck: tok.AccessToken == "",
	})
	if err != nil {
		return nil, err
	}
	if !containsString(idt.Audience, p.oauth.ClientID) {
		return nil, fmt.Errorf("azure: id token audience %v does not contain the configured client id", idt.Audience)
	}
	return parseAzureIDToken(idt), nil
}

func (p *azureProvider) validateIssuer(detected string) error {
	if p.expectedIssuer != "" {
		if detected != p.expectedIssuer {
			return fmt.Errorf("azure: id token issuer %q does not match the configured tenant %q", detected, p.expectedIssuer)
		}
		return nil
	}
	if !isAzureIssuer(detected) {
		return fmt.Errorf("azure: id token issuer %q is not a Microsoft issuer", detected)
	}
	return nil
}

// isAzureIssuer is upstream's provider.IsAzureIssuer: an issuer served by the
// canonical Microsoft host, in the v2 form .../{tenant}/v2.0.
func isAzureIssuer(issuer string) bool {
	u, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	return u.Host == azureIssuerHost && strings.HasSuffix(strings.TrimSuffix(u.Path, "/"), "/v2.0")
}

// removeAzureClaimsFromCustomClaims is upstream's exclusion list: the standard
// registered/handled claims that must not be copied into custom_claims.
var removeAzureClaimsFromCustomClaims = []string{
	"aud", "iss", "iat", "nbf", "exp", "c_hash", "at_hash",
	"aio", "nonce", "rh", "uti", "jti", "ver", "sub", "name",
	"preferred_username",
}

// parseAzureIDToken is upstream's provider.parseAzureIDToken.
func parseAzureIDToken(t *idToken) *userProvidedData {
	claims := t.Claims
	email := claimString(claims, "email")
	verified := azureEmailVerified(email, claims["xms_edov"])

	var data userProvidedData
	if email != "" {
		data.Emails = append(data.Emails, providerEmail{Email: email, Verified: verified, Primary: true})
	}

	custom := map[string]any{}
	for k, v := range claims {
		if !containsString(removeAzureClaimsFromCustomClaims, k) {
			custom[k] = v
		}
	}

	data.Metadata = &providerClaims{
		Issuer:            t.Issuer,
		Subject:           t.Subject,
		PreferredUsername: claimString(claims, "preferred_username"),
		Email:             email,
		EmailVerified:     verified,

		// To be deprecated upstream, still emitted.
		FullName:     claimString(claims, "name"),
		ProviderID:   t.Subject,
		CustomClaims: custom,
	}
	return &data
}

// azureEmailVerified is upstream's AzureIDTokenClaims.IsEmailVerified: with no
// xms_edov claim a present email is trusted; with the claim, it must be truthy.
func azureEmailVerified(email string, xmsEdov any) bool {
	if email == "" {
		return false
	}
	if xmsEdov == nil {
		return true
	}
	switch v := xmsEdov.(type) {
	case bool:
		return v
	case string:
		b, err := strconv.ParseBool(v)
		return err == nil && b
	}
	return false
}

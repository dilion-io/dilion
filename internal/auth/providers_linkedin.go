package auth

// LinkedIn (OIDC, id_token) — upstream internal/api/provider/linkedin_oidc.go
// and the parseLinkedinIDToken branch of provider/oidc.go. Registered as
// "linkedin_oidc".
//
// The legacy "linkedin" provider (LinkedIn's deprecated v2 REST API) is NOT
// implemented; LinkedIn shut down those endpoints in favour of Sign In with
// LinkedIn using OpenID Connect, which is this driver.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func init() { registerProvider("linkedin_oidc", newLinkedinOIDCProvider) }

// IssuerLinkedin is upstream's provider.IssuerLinkedin.
const IssuerLinkedin = "https://www.linkedin.com/oauth"

type linkedinOIDCProvider struct {
	a      *api
	oauth  oauthConfig
	issuer string
}

func newLinkedinOIDCProvider(_ context.Context, a *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}
	ep := endpointsFor(name, providerEndpoints{
		AuthURL:  IssuerLinkedin + "/oauth/v2/authorization",
		TokenURL: IssuerLinkedin + "/oauth/v2/accessToken",
		Issuer:   IssuerLinkedin,
	})
	return &linkedinOIDCProvider{
		a:      a,
		issuer: ep.Issuer,
		oauth: oauthConfig{
			ClientID:     cfg.ClientID[0],
			ClientSecret: cfg.Secret,
			AuthURL:      ep.AuthURL,
			TokenURL:     ep.TokenURL,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       scopesWithDefaults([]string{"openid", "email", "profile"}, scopes),
		},
	}, nil
}

func (p *linkedinOIDCProvider) authCodeURL(state string, extra url.Values) string {
	return p.oauth.authCodeURL(state, extra)
}

func (p *linkedinOIDCProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return p.oauth.exchangeCode(ctx, hc, code, nil)
}

func (p *linkedinOIDCProvider) userData(ctx context.Context, _ *http.Client, tok *oauthToken) (*userProvidedData, error) {
	if tok.IDToken == "" {
		return nil, fmt.Errorf("linkedin_oidc: token response has no id_token")
	}
	idt, err := p.a.verifyIDToken(ctx, p.issuer, tok.IDToken, idTokenOptions{
		AccessToken:          tok.AccessToken,
		SkipAccessTokenCheck: tok.AccessToken == "",
	})
	if err != nil {
		return nil, err
	}
	if !containsString(idt.Audience, p.oauth.ClientID) {
		return nil, fmt.Errorf("linkedin_oidc: id token audience %v does not contain the configured client id", idt.Audience)
	}
	return parseLinkedinIDToken(idt), nil
}

// parseLinkedinIDToken is upstream's provider.parseLinkedinIDToken.
func parseLinkedinIDToken(t *idToken) *userProvidedData {
	claims := t.Claims
	given := claimString(claims, "given_name")
	family := claimString(claims, "family_name")
	name := strings.TrimSpace(given + " " + family)

	// LinkedIn sends email_verified as a STRING ("true"/"false").
	verified, _ := strconv.ParseBool(claimString(claims, "email_verified"))

	var data userProvidedData
	email := claimString(claims, "email")
	if email != "" {
		data.Emails = append(data.Emails, providerEmail{Email: email, Verified: verified, Primary: true})
	}
	data.Metadata = &providerClaims{
		Issuer:     t.Issuer,
		Subject:    t.Subject,
		Name:       name,
		GivenName:  given,
		FamilyName: family,
		Locale:     claimString(claims, "locale"),
		Picture:    claimString(claims, "picture"),
		Email:      email,

		// To be deprecated upstream, still emitted.
		AvatarURL:  claimString(claims, "picture"),
		FullName:   name,
		ProviderID: t.Subject,
	}
	return &data
}

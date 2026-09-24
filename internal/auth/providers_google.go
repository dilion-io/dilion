package auth

// Google (OpenID Connect) — upstream internal/api/provider/google.go and the
// parseGoogleIDToken branch of provider/oidc.go.
//
// The authorization and token endpoints come from Google's discovery document
// (upstream does the same through go-oidc); the user-info endpoint is the fixed
// URL upstream hardcodes. When Google returns an id_token — which it always
// does — the profile is read from the VERIFIED token and the user-info call is
// skipped, exactly as upstream does.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

func init() { registerProvider("google", newGoogleProvider) }

// IssuerGoogle is upstream's provider.IssuerGoogle.
const IssuerGoogle = "https://accounts.google.com"

// userInfoEndpointGoogle is upstream's provider.UserInfoEndpointGoogle.
const userInfoEndpointGoogle = "https://www.googleapis.com/userinfo/v2/me"

type googleProvider struct {
	a           *api
	oauth       oauthConfig
	issuer      string
	userInfoURL string
}

func newGoogleProvider(ctx context.Context, a *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}
	ep := endpointsFor(name, providerEndpoints{
		Issuer:      IssuerGoogle,
		UserInfoURL: userInfoEndpointGoogle,
	})
	if err := a.resolveOIDCEndpoints(ctx, &ep); err != nil {
		return nil, err
	}
	return &googleProvider{
		a:           a,
		issuer:      ep.Issuer,
		userInfoURL: ep.UserInfoURL,
		oauth: oauthConfig{
			ClientID:     cfg.ClientID[0],
			ClientSecret: cfg.Secret,
			AuthURL:      ep.AuthURL,
			TokenURL:     ep.TokenURL,
			RedirectURL:  cfg.RedirectURI,
			// Upstream's defaults.
			Scopes: scopesWithDefaults([]string{"email", "profile"}, scopes),
		},
	}, nil
}

func (g *googleProvider) authCodeURL(state string, extra url.Values) string {
	return g.oauth.authCodeURL(state, extra)
}

func (g *googleProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return g.oauth.exchangeCode(ctx, hc, code, nil)
}

func (g *googleProvider) userData(ctx context.Context, hc *http.Client, tok *oauthToken) (*userProvidedData, error) {
	if tok.IDToken != "" {
		idt, err := g.a.verifyIDToken(ctx, hc, g.issuer, tok.IDToken, idTokenOptions{
			AccessToken:          tok.AccessToken,
			SkipAccessTokenCheck: tok.AccessToken == "",
		})
		if err != nil {
			return nil, err
		}
		// oidc.Config{ClientID} in upstream: the token must be addressed to us.
		if !containsString(idt.Audience, g.oauth.ClientID) {
			return nil, fmt.Errorf("google: id token audience %v does not contain the configured client id", idt.Audience)
		}
		return parseGoogleIDToken(idt), nil
	}

	// Legacy path: no id_token, read the user-info endpoint instead.
	var u googleUser
	if err := getJSON(ctx, hc, g.userInfoURL, tok.AccessToken, &u); err != nil {
		return nil, err
	}
	if u.Subject != "" && u.ID == "" {
		u.ID = u.Subject
	}
	if u.ID == "" {
		return nil, errors.New("google: user info response has no subject")
	}

	data := &userProvidedData{}
	if u.Email != "" {
		data.Emails = append(data.Emails, providerEmail{
			Email:    u.Email,
			Verified: u.isEmailVerified(),
			Primary:  true,
		})
	}
	data.Metadata = &providerClaims{
		Issuer:        g.userInfoURL,
		Subject:       u.ID,
		Name:          u.Name,
		Picture:       u.AvatarURL,
		Email:         u.Email,
		EmailVerified: u.isEmailVerified(),

		// To be deprecated upstream, still emitted.
		AvatarURL:  u.AvatarURL,
		FullName:   u.Name,
		ProviderID: u.ID,
	}
	return data, nil
}

// googleUser is upstream's provider.googleUser.
type googleUser struct {
	ID            string `json:"id"`
	Subject       string `json:"sub"`
	Issuer        string `json:"iss"`
	Name          string `json:"name"`
	AvatarURL     string `json:"picture"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	EmailVerified bool   `json:"email_verified"`
	HostedDomain  string `json:"hd"`
}

func (u googleUser) isEmailVerified() bool { return u.VerifiedEmail || u.EmailVerified }

// parseGoogleIDToken is upstream's provider.parseGoogleIDToken.
func parseGoogleIDToken(t *idToken) *userProvidedData {
	claims := t.Claims
	email := claimString(claims, "email")
	verified := claimBool(claims, "email_verified") || claimBool(claims, "verified_email")

	var data userProvidedData
	if email != "" {
		data.Emails = append(data.Emails, providerEmail{Email: email, Verified: verified, Primary: true})
	}
	data.Metadata = &providerClaims{
		Issuer:  t.Issuer,
		Subject: t.Subject,
		Name:    claimString(claims, "name"),
		Picture: claimString(claims, "picture"),

		// To be deprecated upstream, still emitted.
		AvatarURL:  claimString(claims, "picture"),
		FullName:   claimString(claims, "name"),
		ProviderID: t.Subject,
	}
	if hd := claimString(claims, "hd"); hd != "" {
		data.Metadata.CustomClaims = map[string]any{"hd": hd}
	}
	return &data
}

// resolveOIDCEndpoints fills the authorization and token endpoints of an
// OIDC provider from its discovery document, unless both were overridden.
func (a *api) resolveOIDCEndpoints(ctx context.Context, ep *providerEndpoints) error {
	if ep.AuthURL != "" && ep.TokenURL != "" {
		return nil
	}
	doc, err := oidcCache.discover(ctx, a.httpClient(), ep.Issuer)
	if err != nil {
		return err
	}
	if ep.AuthURL == "" {
		ep.AuthURL = doc.AuthorizationEndpoint
	}
	if ep.TokenURL == "" {
		ep.TokenURL = doc.TokenEndpoint
	}
	if ep.UserInfoURL == "" {
		ep.UserInfoURL = doc.UserInfoEndpoint
	}
	if ep.AuthURL == "" || ep.TokenURL == "" {
		return fmt.Errorf("oidc: issuer %s publishes no authorization or token endpoint", ep.Issuer)
	}
	return nil
}

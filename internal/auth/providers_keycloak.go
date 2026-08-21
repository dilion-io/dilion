package auth

// Keycloak (OIDC, REST userinfo) — upstream
// internal/api/provider/keycloak.go.
//
// Keycloak is always self-hosted, so GOTRUE_EXTERNAL_KEYCLOAK_URL (the realm
// URL) is mandatory; every endpoint is derived from it. Upstream reads the
// profile from the userinfo endpoint rather than the id_token.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func init() { registerProvider("keycloak", newKeycloakProvider) }

type keycloakProvider struct {
	oauth       oauthConfig
	issuer      string
	userInfoURL string
}

func newKeycloakProvider(_ context.Context, _ *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.URL) == "" {
		return nil, errors.New("keycloak: missing realm URL (GOTRUE_EXTERNAL_KEYCLOAK_URL)")
	}
	host := strings.TrimSuffix(strings.TrimSpace(cfg.URL), "/")

	ep := endpointsFor(name, providerEndpoints{
		AuthURL:     host + "/protocol/openid-connect/auth",
		TokenURL:    host + "/protocol/openid-connect/token",
		UserInfoURL: host + "/protocol/openid-connect/userinfo",
		Issuer:      host,
	})
	return &keycloakProvider{
		issuer:      ep.Issuer,
		userInfoURL: ep.UserInfoURL,
		oauth: oauthConfig{
			ClientID:     cfg.ClientID[0],
			ClientSecret: cfg.Secret,
			AuthURL:      ep.AuthURL,
			TokenURL:     ep.TokenURL,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       scopesWithDefaults([]string{"profile", "email"}, scopes),
		},
	}, nil
}

func (p *keycloakProvider) authCodeURL(state string, extra url.Values) string {
	return p.oauth.authCodeURL(state, extra)
}

func (p *keycloakProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return p.oauth.exchangeCode(ctx, hc, code, nil)
}

func (p *keycloakProvider) userData(ctx context.Context, hc *http.Client, tok *oauthToken) (*userProvidedData, error) {
	var claims map[string]any
	if err := getJSON(ctx, hc, p.userInfoURL, tok.AccessToken, &claims); err != nil {
		return nil, err
	}
	sub := claimString(claims, "sub")
	if sub == "" {
		return nil, errors.New("keycloak: userinfo response has no sub")
	}

	data := &userProvidedData{
		Metadata: &providerClaims{
			Issuer:            p.issuer,
			Subject:           sub,
			Name:              claimString(claims, "name"),
			PreferredUsername: claimString(claims, "preferred_username"),
			Email:             claimString(claims, "email"),
			EmailVerified:     claimBool(claims, "email_verified"),

			// To be deprecated upstream, still emitted.
			FullName:   claimString(claims, "name"),
			ProviderID: sub,
		},
	}
	if email := data.Metadata.Email; email != "" {
		data.Emails = append(data.Emails, providerEmail{
			Email:    email,
			Verified: data.Metadata.EmailVerified,
			Primary:  true,
		})
	}
	return data, nil
}

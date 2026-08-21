package auth

// Fly.io (plain OAuth 2.0 + REST token info) — upstream
// internal/api/provider/fly.go.
//
// Fly only grants the `read` scope and exposes the profile through its token
// introspection endpoint (/oauth/token/info).

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

func init() { registerProvider("fly", newFlyProvider) }

const defaultFlyAuthHost = "oauth.fly.io"

type flyProvider struct {
	oauth   oauthConfig
	apiHost string
}

func newFlyProvider(_ context.Context, _ *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}
	authHost := chooseHost(cfg.URL, defaultFlyAuthHost)

	ep := endpointsFor(name, providerEndpoints{
		AuthURL:  authHost + "/oauth/authorize",
		TokenURL: authHost + "/oauth/token",
		APIHost:  authHost,
	})
	return &flyProvider{
		apiHost: ep.APIHost,
		oauth: oauthConfig{
			ClientID:     cfg.ClientID[0],
			ClientSecret: cfg.Secret,
			AuthURL:      ep.AuthURL,
			TokenURL:     ep.TokenURL,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       scopesWithDefaults([]string{"read"}, scopes),
		},
	}, nil
}

func (p *flyProvider) authCodeURL(state string, extra url.Values) string {
	return p.oauth.authCodeURL(state, extra)
}

func (p *flyProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return p.oauth.exchangeCode(ctx, hc, code, nil)
}

type flyUser struct {
	ResourceOwnerID string `json:"resource_owner_id"`
	UserID          string `json:"user_id"`
	UserName        string `json:"user_name"`
	Email           string `json:"email"`
	Organizations   any    `json:"organizations"`
	Application     any    `json:"application"`
	Scope           any    `json:"scope"`
	CreatedAt       any    `json:"created_at"`
}

func (p *flyProvider) userData(ctx context.Context, hc *http.Client, tok *oauthToken) (*userProvidedData, error) {
	var u flyUser
	if err := getJSON(ctx, hc, p.apiHost+"/oauth/token/info", tok.AccessToken, &u); err != nil {
		return nil, err
	}
	if u.UserID == "" {
		return nil, errors.New("fly: token info response has no user_id")
	}

	data := &userProvidedData{
		Metadata: &providerClaims{
			Issuer:  p.apiHost,
			Subject: u.UserID,
			Email:   u.Email,

			// To be deprecated upstream, still emitted.
			FullName:   u.UserName,
			ProviderID: u.UserID,
			CustomClaims: map[string]any{
				"resource_owner_id": u.ResourceOwnerID,
				"organizations":     u.Organizations,
				"application":       u.Application,
				"scope":             u.Scope,
				"created_at":        u.CreatedAt,
			},
		},
	}
	if u.Email != "" {
		data.Emails = append(data.Emails, providerEmail{Email: u.Email, Verified: true, Primary: true})
	}
	return data, nil
}

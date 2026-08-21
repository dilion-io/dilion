package auth

// Figma (plain OAuth 2.0 + REST user info) — upstream
// internal/api/provider/figma.go.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

func init() { registerProvider("figma", newFigmaProvider) }

const (
	defaultFigmaAuthHost = "www.figma.com"
	defaultFigmaAPIHost  = "api.figma.com"
)

type figmaProvider struct {
	oauth   oauthConfig
	apiHost string
}

func newFigmaProvider(_ context.Context, _ *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}
	authHost := chooseHost("", defaultFigmaAuthHost)
	apiHost := chooseHost("", defaultFigmaAPIHost)

	ep := endpointsFor(name, providerEndpoints{
		AuthURL:  authHost + "/oauth",
		TokenURL: apiHost + "/v1/oauth/token",
		APIHost:  apiHost,
	})
	return &figmaProvider{
		apiHost: ep.APIHost,
		oauth: oauthConfig{
			ClientID:     cfg.ClientID[0],
			ClientSecret: cfg.Secret,
			AuthURL:      ep.AuthURL,
			TokenURL:     ep.TokenURL,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       scopesWithDefaults([]string{"current_user:read"}, scopes),
		},
	}, nil
}

func (p *figmaProvider) authCodeURL(state string, extra url.Values) string {
	return p.oauth.authCodeURL(state, extra)
}

func (p *figmaProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return p.oauth.exchangeCode(ctx, hc, code, nil)
}

type figmaUser struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Handle    string `json:"handle"`
	AvatarURL string `json:"img_url"`
}

func (p *figmaProvider) userData(ctx context.Context, hc *http.Client, tok *oauthToken) (*userProvidedData, error) {
	var u figmaUser
	if err := getJSON(ctx, hc, p.apiHost+"/v1/me", tok.AccessToken, &u); err != nil {
		return nil, err
	}
	if u.ID == "" {
		return nil, errors.New("figma: user response has no id")
	}

	data := &userProvidedData{
		Metadata: &providerClaims{
			Issuer:  p.apiHost,
			Subject: u.ID,
			Name:    u.Handle,
			Picture: u.AvatarURL,
			Email:   u.Email,

			// To be deprecated upstream, still emitted.
			AvatarURL:  u.AvatarURL,
			FullName:   u.Handle,
			ProviderID: u.ID,
		},
	}
	if u.Email != "" {
		// Figma does not expose a verification flag; upstream trusts it.
		data.Emails = append(data.Emails, providerEmail{Email: u.Email, Verified: true, Primary: true})
	}
	return data, nil
}

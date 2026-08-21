package auth

// Zoom (plain OAuth 2.0 + REST user info) — upstream
// internal/api/provider/zoom.go.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func init() { registerProvider("zoom", newZoomProvider) }

const (
	defaultZoomAuthHost = "zoom.us"
	defaultZoomAPIHost  = "api.zoom.us"
)

type zoomProvider struct {
	oauth   oauthConfig
	apiHost string
}

func newZoomProvider(_ context.Context, _ *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}
	authHost := chooseHost("", defaultZoomAuthHost)
	apiHost := chooseHost("", defaultZoomAPIHost)

	ep := endpointsFor(name, providerEndpoints{
		AuthURL:  authHost + "/oauth/authorize",
		TokenURL: authHost + "/oauth/token",
		APIHost:  apiHost,
	})
	return &zoomProvider{
		apiHost: ep.APIHost,
		oauth: oauthConfig{
			ClientID:     cfg.ClientID[0],
			ClientSecret: cfg.Secret,
			AuthURL:      ep.AuthURL,
			TokenURL:     ep.TokenURL,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       scopesWithDefaults(nil, scopes),
		},
	}, nil
}

func (p *zoomProvider) authCodeURL(state string, extra url.Values) string {
	return p.oauth.authCodeURL(state, extra)
}

func (p *zoomProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return p.oauth.exchangeCode(ctx, hc, code, nil)
}

type zoomUser struct {
	ID        string `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Verified  int    `json:"verified"`
	LoginType int    `json:"login_type"`
	PicURL    string `json:"pic_url"`
}

func (p *zoomProvider) userData(ctx context.Context, hc *http.Client, tok *oauthToken) (*userProvidedData, error) {
	var u zoomUser
	if err := getJSON(ctx, hc, p.apiHost+"/v2/users/me", tok.AccessToken, &u); err != nil {
		return nil, err
	}
	if u.ID == "" {
		return nil, errors.New("zoom: user response has no id")
	}

	full := strings.TrimSpace(u.FirstName + " " + u.LastName)
	data := &userProvidedData{
		Metadata: &providerClaims{
			Issuer:  p.apiHost,
			Subject: u.ID,
			Name:    full,
			Picture: u.PicURL,
			Email:   u.Email,

			// To be deprecated upstream, still emitted.
			AvatarURL:  u.PicURL,
			FullName:   full,
			ProviderID: u.ID,
		},
	}
	if u.Email != "" {
		// Upstream: login_type 100 is an email/password Zoom account whose
		// address is confirmed only when `verified` is set; any other login type
		// is a federated identity and is trusted.
		verified := u.LoginType != 100 || u.Verified != 0
		data.Emails = append(data.Emails, providerEmail{Email: u.Email, Verified: verified, Primary: true})
	}
	return data, nil
}

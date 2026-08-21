package auth

// Spotify (plain OAuth 2.0 + REST user info) — upstream
// internal/api/provider/spotify.go.
//
// Spotify never says whether an address is verified, so upstream records it
// unverified.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

func init() { registerProvider("spotify", newSpotifyProvider) }

const (
	defaultSpotifyAuthHost = "accounts.spotify.com"
	defaultSpotifyAPIHost  = "api.spotify.com"
)

type spotifyProvider struct {
	oauth   oauthConfig
	apiHost string
}

func newSpotifyProvider(_ context.Context, _ *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}
	authHost := chooseHost("", defaultSpotifyAuthHost)
	apiHost := chooseHost("", defaultSpotifyAPIHost)

	ep := endpointsFor(name, providerEndpoints{
		AuthURL:  authHost + "/authorize",
		TokenURL: authHost + "/api/token",
		APIHost:  apiHost,
	})
	return &spotifyProvider{
		apiHost: ep.APIHost,
		oauth: oauthConfig{
			ClientID:     cfg.ClientID[0],
			ClientSecret: cfg.Secret,
			AuthURL:      ep.AuthURL,
			TokenURL:     ep.TokenURL,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       scopesWithDefaults([]string{"user-read-email"}, scopes),
		},
	}, nil
}

func (p *spotifyProvider) authCodeURL(state string, extra url.Values) string {
	return p.oauth.authCodeURL(state, extra)
}

func (p *spotifyProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return p.oauth.exchangeCode(ctx, hc, code, nil)
}

type spotifyUser struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
	Images      []struct {
		URL    string `json:"url"`
		Height int    `json:"height"`
		Width  int    `json:"width"`
	} `json:"images"`
}

func (p *spotifyProvider) userData(ctx context.Context, hc *http.Client, tok *oauthToken) (*userProvidedData, error) {
	var u spotifyUser
	if err := getJSON(ctx, hc, p.apiHost+"/v1/me", tok.AccessToken, &u); err != nil {
		return nil, err
	}
	if u.ID == "" {
		return nil, errors.New("spotify: user response has no id")
	}

	// Upstream picks the largest image by area.
	picture, area := "", -1
	for _, img := range u.Images {
		if a := img.Height * img.Width; a > area {
			area, picture = a, img.URL
		}
	}

	data := &userProvidedData{
		Metadata: &providerClaims{
			Issuer:  p.apiHost,
			Subject: u.ID,
			Name:    u.DisplayName,
			Picture: picture,
			Email:   u.Email,

			// To be deprecated upstream, still emitted.
			AvatarURL:  picture,
			FullName:   u.DisplayName,
			ProviderID: u.ID,
		},
	}
	if u.Email != "" {
		data.Emails = append(data.Emails, providerEmail{Email: u.Email, Verified: false, Primary: true})
	}
	return data, nil
}

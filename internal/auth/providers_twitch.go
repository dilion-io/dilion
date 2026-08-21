package auth

// Twitch (plain OAuth 2.0 + Helix user info) — upstream
// internal/api/provider/twitch.go.
//
// The Helix users endpoint additionally requires the app's Client-Id header.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

func init() { registerProvider("twitch", newTwitchProvider) }

const (
	defaultTwitchAuthHost = "id.twitch.tv/oauth2"
	defaultTwitchAPIHost  = "api.twitch.tv"
)

type twitchProvider struct {
	oauth    oauthConfig
	apiHost  string
	clientID string
}

func newTwitchProvider(_ context.Context, _ *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}
	authHost := chooseHost("", defaultTwitchAuthHost)
	apiHost := chooseHost("", defaultTwitchAPIHost)

	ep := endpointsFor(name, providerEndpoints{
		AuthURL:  authHost + "/authorize",
		TokenURL: authHost + "/token",
		APIHost:  apiHost,
	})
	return &twitchProvider{
		apiHost:  ep.APIHost,
		clientID: cfg.ClientID[0],
		oauth: oauthConfig{
			ClientID:     cfg.ClientID[0],
			ClientSecret: cfg.Secret,
			AuthURL:      ep.AuthURL,
			TokenURL:     ep.TokenURL,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       scopesWithDefaults([]string{"user:read:email"}, scopes),
		},
	}, nil
}

func (p *twitchProvider) authCodeURL(state string, extra url.Values) string {
	return p.oauth.authCodeURL(state, extra)
}

func (p *twitchProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return p.oauth.exchangeCode(ctx, hc, code, nil)
}

type twitchUsers struct {
	Data []struct {
		ID              string `json:"id"`
		Login           string `json:"login"`
		DisplayName     string `json:"display_name"`
		Email           string `json:"email"`
		ProfileImageURL string `json:"profile_image_url"`
	} `json:"data"`
}

func (p *twitchProvider) userData(ctx context.Context, hc *http.Client, tok *oauthToken) (*userProvidedData, error) {
	var resp twitchUsers
	if err := getJSONWithHeaders(ctx, hc, p.apiHost+"/helix/users", tok.AccessToken,
		map[string]string{"Client-Id": p.clientID}, &resp); err != nil {
		return nil, err
	}
	if len(resp.Data) == 0 || resp.Data[0].ID == "" {
		return nil, errors.New("twitch: user response has no data")
	}
	u := resp.Data[0]

	data := &userProvidedData{
		Metadata: &providerClaims{
			Issuer:   p.apiHost,
			Subject:  u.ID,
			Name:     u.Login,
			NickName: u.DisplayName,
			Picture:  u.ProfileImageURL,
			Email:    u.Email,

			// To be deprecated upstream, still emitted.
			AvatarURL:  u.ProfileImageURL,
			FullName:   u.Login,
			ProviderID: u.ID,
		},
	}
	if u.Email != "" {
		// Twitch only exposes a verified address; upstream trusts it.
		data.Emails = append(data.Emails, providerEmail{Email: u.Email, Verified: true, Primary: true})
	}
	return data, nil
}

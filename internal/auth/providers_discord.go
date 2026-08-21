package auth

// Discord (plain OAuth 2.0 + REST user info) — upstream
// internal/api/provider/discord.go.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func init() { registerProvider("discord", newDiscordProvider) }

const defaultDiscordAPIBase = "discord.com/api"

type discordProvider struct {
	oauth   oauthConfig
	apiHost string
}

func newDiscordProvider(_ context.Context, _ *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}
	apiHost := chooseHost(cfg.URL, defaultDiscordAPIBase)

	ep := endpointsFor(name, providerEndpoints{
		AuthURL:  apiHost + "/oauth2/authorize",
		TokenURL: apiHost + "/oauth2/token",
		APIHost:  apiHost,
	})
	return &discordProvider{
		apiHost: ep.APIHost,
		oauth: oauthConfig{
			ClientID:     cfg.ClientID[0],
			ClientSecret: cfg.Secret,
			AuthURL:      ep.AuthURL,
			TokenURL:     ep.TokenURL,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       scopesWithDefaults([]string{"identify", "email"}, scopes),
		},
	}, nil
}

func (p *discordProvider) authCodeURL(state string, extra url.Values) string {
	return p.oauth.authCodeURL(state, extra)
}

func (p *discordProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return p.oauth.exchangeCode(ctx, hc, code, nil)
}

type discordUser struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Discriminator string `json:"discriminator"`
	GlobalName    string `json:"global_name"`
	Avatar        string `json:"avatar"`
	Email         string `json:"email"`
	Verified      bool   `json:"verified"`
}

func (p *discordProvider) userData(ctx context.Context, hc *http.Client, tok *oauthToken) (*userProvidedData, error) {
	var u discordUser
	if err := getJSON(ctx, hc, p.apiHost+"/users/@me", tok.AccessToken, &u); err != nil {
		return nil, err
	}
	if u.ID == "" {
		return nil, errors.New("discord: user response has no id")
	}

	name := u.Username + "#" + u.Discriminator
	data := &userProvidedData{
		Metadata: &providerClaims{
			Issuer:  p.apiHost,
			Subject: u.ID,
			Name:    name,
			Picture: discordAvatarURL(u),

			// To be deprecated upstream, still emitted.
			AvatarURL:  discordAvatarURL(u),
			FullName:   name,
			ProviderID: u.ID,
		},
	}
	if u.GlobalName != "" {
		data.Metadata.CustomClaims = map[string]any{"global_name": u.GlobalName}
	}
	if u.Email != "" {
		data.Emails = append(data.Emails, providerEmail{Email: u.Email, Verified: u.Verified, Primary: true})
	}
	return data, nil
}

// discordAvatarURL is upstream's avatar construction: a fallback embed avatar
// when the user has none, otherwise the CDN URL (animated when the hash starts
// with a_).
func discordAvatarURL(u discordUser) string {
	if u.Avatar == "" {
		mod := int64(0)
		if d, err := strconv.ParseInt(u.Discriminator, 10, 64); err == nil {
			mod = d % 5
		}
		return fmt.Sprintf("https://cdn.discordapp.com/embed/avatars/%d.png", mod)
	}
	ext := "png"
	if strings.HasPrefix(u.Avatar, "a_") {
		ext = "gif"
	}
	return fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.%s", u.ID, u.Avatar, ext)
}

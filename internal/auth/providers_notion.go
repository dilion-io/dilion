package auth

// Notion (plain OAuth 2.0 + REST user info) — upstream
// internal/api/provider/notion.go.
//
// Notion pins an API version through the Notion-Version header and returns the
// profile nested under bot.owner.user.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

func init() { registerProvider("notion", newNotionProvider) }

const (
	defaultNotionAPIHost = "api.notion.com"
	notionAPIVersion     = "2021-08-16"
)

type notionProvider struct {
	oauth   oauthConfig
	apiHost string
}

func newNotionProvider(_ context.Context, _ *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}
	apiHost := chooseHost("", defaultNotionAPIHost)

	ep := endpointsFor(name, providerEndpoints{
		AuthURL:  apiHost + "/v1/oauth/authorize",
		TokenURL: apiHost + "/v1/oauth/token",
		APIHost:  apiHost,
	})
	return &notionProvider{
		apiHost: ep.APIHost,
		oauth: oauthConfig{
			ClientID:     cfg.ClientID[0],
			ClientSecret: cfg.Secret,
			AuthURL:      ep.AuthURL,
			TokenURL:     ep.TokenURL,
			RedirectURL:  cfg.RedirectURI,
			// Notion has no OAuth scopes; capabilities are set on the integration.
			Scopes: scopesWithDefaults(nil, scopes),
		},
	}, nil
}

func (p *notionProvider) authCodeURL(state string, extra url.Values) string {
	return p.oauth.authCodeURL(state, extra)
}

func (p *notionProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return p.oauth.exchangeCode(ctx, hc, code, nil)
}

type notionUser struct {
	Bot struct {
		Owner struct {
			User struct {
				ID        string `json:"id"`
				Name      string `json:"name"`
				AvatarURL string `json:"avatar_url"`
				Person    struct {
					Email string `json:"email"`
				} `json:"person"`
			} `json:"user"`
		} `json:"owner"`
	} `json:"bot"`
}

func (p *notionProvider) userData(ctx context.Context, hc *http.Client, tok *oauthToken) (*userProvidedData, error) {
	var u notionUser
	if err := getJSONWithHeaders(ctx, hc, p.apiHost+"/v1/users/me", tok.AccessToken,
		map[string]string{"Notion-Version": notionAPIVersion}, &u); err != nil {
		return nil, err
	}
	user := u.Bot.Owner.User
	if user.ID == "" {
		return nil, errors.New("notion: user response has no id")
	}

	data := &userProvidedData{
		Metadata: &providerClaims{
			Issuer:  p.apiHost,
			Subject: user.ID,
			Name:    user.Name,
			Picture: user.AvatarURL,
			Email:   user.Person.Email,

			// To be deprecated upstream, still emitted.
			AvatarURL:  user.AvatarURL,
			FullName:   user.Name,
			ProviderID: user.ID,
		},
	}
	if user.Person.Email != "" {
		// Notion does not expose a verification flag; upstream trusts it.
		data.Emails = append(data.Emails, providerEmail{Email: user.Person.Email, Verified: true, Primary: true})
	}
	return data, nil
}

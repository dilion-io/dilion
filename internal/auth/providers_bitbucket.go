package auth

// Bitbucket (plain OAuth 2.0 + REST user info) — upstream
// internal/api/provider/bitbucket.go.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

func init() { registerProvider("bitbucket", newBitbucketProvider) }

const (
	defaultBitbucketAuthHost = "bitbucket.org"
	defaultBitbucketAPIHost  = "api.bitbucket.org"
)

type bitbucketProvider struct {
	oauth   oauthConfig
	apiHost string
}

func newBitbucketProvider(_ context.Context, _ *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}
	authHost := chooseHost("", defaultBitbucketAuthHost)
	apiHost := chooseHost("", defaultBitbucketAPIHost)

	ep := endpointsFor(name, providerEndpoints{
		AuthURL:  authHost + "/site/oauth2/authorize",
		TokenURL: authHost + "/site/oauth2/access_token",
		APIHost:  apiHost,
	})
	return &bitbucketProvider{
		apiHost: ep.APIHost,
		oauth: oauthConfig{
			ClientID:     cfg.ClientID[0],
			ClientSecret: cfg.Secret,
			AuthURL:      ep.AuthURL,
			TokenURL:     ep.TokenURL,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       scopesWithDefaults([]string{"account", "email"}, scopes),
		},
	}, nil
}

func (p *bitbucketProvider) authCodeURL(state string, extra url.Values) string {
	return p.oauth.authCodeURL(state, extra)
}

func (p *bitbucketProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return p.oauth.exchangeCode(ctx, hc, code, nil)
}

type bitbucketUser struct {
	UUID        string `json:"uuid"`
	DisplayName string `json:"display_name"`
	Links       struct {
		Avatar struct {
			Href string `json:"href"`
		} `json:"avatar"`
	} `json:"links"`
}

type bitbucketEmails struct {
	Values []struct {
		Email       string `json:"email"`
		IsPrimary   bool   `json:"is_primary"`
		IsConfirmed bool   `json:"is_confirmed"`
	} `json:"values"`
}

func (p *bitbucketProvider) userData(ctx context.Context, hc *http.Client, tok *oauthToken) (*userProvidedData, error) {
	var u bitbucketUser
	if err := getJSON(ctx, hc, p.apiHost+"/2.0/user", tok.AccessToken, &u); err != nil {
		return nil, err
	}
	if u.UUID == "" {
		return nil, errors.New("bitbucket: user response has no uuid")
	}

	data := &userProvidedData{
		Metadata: &providerClaims{
			Issuer:  p.apiHost,
			Subject: u.UUID,
			Name:    u.DisplayName,
			Picture: u.Links.Avatar.Href,

			// To be deprecated upstream, still emitted.
			AvatarURL:  u.Links.Avatar.Href,
			FullName:   u.DisplayName,
			ProviderID: u.UUID,
		},
	}

	var emails bitbucketEmails
	if err := getJSON(ctx, hc, p.apiHost+"/2.0/user/emails", tok.AccessToken, &emails); err != nil {
		return nil, err
	}
	for _, e := range emails.Values {
		if e.Email != "" {
			data.Emails = append(data.Emails, providerEmail{Email: e.Email, Verified: e.IsConfirmed, Primary: e.IsPrimary})
		}
	}
	return data, nil
}

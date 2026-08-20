package auth

// GitHub (plain OAuth 2.0 + REST user info) — upstream
// internal/api/provider/github.go.
//
// GitHub is the reference NON-OIDC provider: there is no id_token, the profile
// comes from GET /user and the addresses from GET /user/emails, which is the
// only place the primary/verified flags live.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func init() { registerProvider("github", newGithubProvider) }

const (
	defaultGitHubAuthBase = "github.com"
	defaultGitHubAPIBase  = "api.github.com"
)

type githubProvider struct {
	oauth   oauthConfig
	apiHost string
}

func newGithubProvider(_ context.Context, _ *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}

	// GOTRUE_EXTERNAL_GITHUB_URL points at a GitHub Enterprise install, whose
	// API lives under /api/v3 (upstream NewGithubProvider).
	authHost := chooseHost(cfg.URL, defaultGitHubAuthBase)
	apiHost := chooseHost(cfg.URL, defaultGitHubAPIBase)
	if !strings.HasSuffix(apiHost, defaultGitHubAPIBase) {
		apiHost += "/api/v3"
	}

	ep := endpointsFor(name, providerEndpoints{
		AuthURL:  authHost + "/login/oauth/authorize",
		TokenURL: authHost + "/login/oauth/access_token",
		APIHost:  apiHost,
	})

	return &githubProvider{
		apiHost: ep.APIHost,
		oauth: oauthConfig{
			ClientID:     cfg.ClientID[0],
			ClientSecret: cfg.Secret,
			AuthURL:      ep.AuthURL,
			TokenURL:     ep.TokenURL,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       scopesWithDefaults([]string{"user:email"}, scopes),
		},
	}, nil
}

func (g *githubProvider) authCodeURL(state string, extra url.Values) string {
	return g.oauth.authCodeURL(state, extra)
}

func (g *githubProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return g.oauth.exchangeCode(ctx, hc, code, nil)
}

type githubUser struct {
	ID        int64  `json:"id"`
	UserName  string `json:"login"`
	Email     string `json:"email"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
}

type githubUserEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (g *githubProvider) userData(ctx context.Context, hc *http.Client, tok *oauthToken) (*userProvidedData, error) {
	var u githubUser
	if err := getJSON(ctx, hc, g.apiHost+"/user", tok.AccessToken, &u); err != nil {
		return nil, err
	}
	if u.ID == 0 {
		return nil, errors.New("github: user response has no id")
	}
	id := strconv.FormatInt(u.ID, 10)

	data := &userProvidedData{
		Metadata: &providerClaims{
			Issuer:            g.apiHost,
			Subject:           id,
			Name:              u.Name,
			PreferredUsername: u.UserName,

			// To be deprecated upstream, still emitted.
			AvatarURL:  u.AvatarURL,
			FullName:   u.Name,
			ProviderID: id,
			UserName:   u.UserName,
		},
	}

	var emails []githubUserEmail
	if err := getJSON(ctx, hc, g.apiHost+"/user/emails", tok.AccessToken, &emails); err != nil {
		return nil, err
	}
	for _, e := range emails {
		if e.Email != "" {
			data.Emails = append(data.Emails, providerEmail{Email: e.Email, Verified: e.Verified, Primary: e.Primary})
		}
	}
	return data, nil
}

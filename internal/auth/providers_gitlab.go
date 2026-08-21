package auth

// GitLab (plain OAuth 2.0 + REST user info) — upstream
// internal/api/provider/gitlab.go.
//
// GitLab issues OIDC id_tokens too, but upstream reads the profile from the
// REST API (GET /api/v4/user + /api/v4/user/emails), so Dilion does the same.
// GOTRUE_EXTERNAL_GITLAB_URL points at a self-hosted GitLab.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

func init() { registerProvider("gitlab", newGitlabProvider) }

const defaultGitLabHost = "gitlab.com"

type gitlabProvider struct {
	oauth   oauthConfig
	apiHost string
}

func newGitlabProvider(_ context.Context, _ *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}
	host := chooseHost(cfg.URL, defaultGitLabHost)

	ep := endpointsFor(name, providerEndpoints{
		AuthURL:  host + "/oauth/authorize",
		TokenURL: host + "/oauth/token",
		APIHost:  host,
	})
	return &gitlabProvider{
		apiHost: ep.APIHost,
		oauth: oauthConfig{
			ClientID:     cfg.ClientID[0],
			ClientSecret: cfg.Secret,
			AuthURL:      ep.AuthURL,
			TokenURL:     ep.TokenURL,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       scopesWithDefaults([]string{"read_user"}, scopes),
		},
	}, nil
}

func (p *gitlabProvider) authCodeURL(state string, extra url.Values) string {
	return p.oauth.authCodeURL(state, extra)
}

func (p *gitlabProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return p.oauth.exchangeCode(ctx, hc, code, nil)
}

type gitlabUser struct {
	ID          int64  `json:"id"`
	Email       string `json:"email"`
	Name        string `json:"name"`
	AvatarURL   string `json:"avatar_url"`
	ConfirmedAt string `json:"confirmed_at"`
}

type gitlabUserEmail struct {
	Email string `json:"email"`
}

func (p *gitlabProvider) userData(ctx context.Context, hc *http.Client, tok *oauthToken) (*userProvidedData, error) {
	var u gitlabUser
	if err := getJSON(ctx, hc, p.apiHost+"/api/v4/user", tok.AccessToken, &u); err != nil {
		return nil, err
	}
	if u.ID == 0 {
		return nil, errors.New("gitlab: user response has no id")
	}
	id := strconv.FormatInt(u.ID, 10)

	data := &userProvidedData{
		Metadata: &providerClaims{
			Issuer:  p.apiHost,
			Subject: id,
			Name:    u.Name,
			Picture: u.AvatarURL,
			Email:   u.Email,

			// To be deprecated upstream, still emitted.
			AvatarURL:  u.AvatarURL,
			FullName:   u.Name,
			ProviderID: id,
		},
	}
	if u.Email != "" {
		// Upstream marks the primary address verified iff confirmed_at is set.
		data.Emails = append(data.Emails, providerEmail{
			Email:    u.Email,
			Verified: u.ConfirmedAt != "",
			Primary:  true,
		})
	}

	var emails []gitlabUserEmail
	if err := getJSON(ctx, hc, p.apiHost+"/api/v4/user/emails", tok.AccessToken, &emails); err != nil {
		return nil, err
	}
	for _, e := range emails {
		if e.Email != "" && e.Email != u.Email {
			// The /emails endpoint carries no confirmation flag, so upstream
			// records these as unverified.
			data.Emails = append(data.Emails, providerEmail{Email: e.Email, Verified: false})
		}
	}
	return data, nil
}

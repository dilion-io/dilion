package auth

// Slack (OIDC, REST userinfo) — upstream
// internal/api/provider/slack_oidc.go, registered as "slack_oidc".
//
// The legacy "slack" provider (Slack's deprecated non-OIDC identity API) is NOT
// implemented; upstream deprecated it in favour of Sign in with Slack (OIDC),
// which is this driver.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
)

func init() { registerProvider("slack_oidc", newSlackOIDCProvider) }

// IssuerSlack is upstream's provider.IssuerSlack.
const IssuerSlack = "https://slack.com"

type slackOIDCProvider struct {
	oauth       oauthConfig
	issuer      string
	userInfoURL string
}

func newSlackOIDCProvider(_ context.Context, _ *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}
	ep := endpointsFor(name, providerEndpoints{
		AuthURL:     IssuerSlack + "/openid/connect/authorize",
		TokenURL:    IssuerSlack + "/api/openid.connect.token",
		UserInfoURL: IssuerSlack + "/api/openid.connect.userinfo",
		Issuer:      IssuerSlack,
	})
	return &slackOIDCProvider{
		issuer:      ep.Issuer,
		userInfoURL: ep.UserInfoURL,
		oauth: oauthConfig{
			ClientID:     cfg.ClientID[0],
			ClientSecret: cfg.Secret,
			AuthURL:      ep.AuthURL,
			TokenURL:     ep.TokenURL,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       scopesWithDefaults([]string{"profile", "email", "openid"}, scopes),
		},
	}, nil
}

func (p *slackOIDCProvider) authCodeURL(state string, extra url.Values) string {
	return p.oauth.authCodeURL(state, extra)
}

func (p *slackOIDCProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return p.oauth.exchangeCode(ctx, hc, code, nil)
}

type slackUser struct {
	UserID        string `json:"https://slack.com/user_id"`
	TeamID        string `json:"https://slack.com/team_id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

func (p *slackOIDCProvider) userData(ctx context.Context, hc *http.Client, tok *oauthToken) (*userProvidedData, error) {
	var u slackUser
	if err := getJSON(ctx, hc, p.userInfoURL, tok.AccessToken, &u); err != nil {
		return nil, err
	}
	if u.UserID == "" {
		return nil, errors.New("slack: userinfo response has no user id")
	}

	data := &userProvidedData{
		Metadata: &providerClaims{
			Issuer:        p.issuer,
			Subject:       u.UserID,
			Name:          u.Name,
			Picture:       u.Picture,
			Email:         u.Email,
			EmailVerified: u.EmailVerified,

			// To be deprecated upstream, still emitted.
			AvatarURL:    u.Picture,
			FullName:     u.Name,
			ProviderID:   u.UserID,
			CustomClaims: map[string]any{"https://slack.com/team_id": u.TeamID},
		},
	}
	if u.Email != "" {
		data.Emails = append(data.Emails, providerEmail{Email: u.Email, Verified: u.EmailVerified, Primary: true})
	}
	return data, nil
}

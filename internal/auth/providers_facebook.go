package auth

// Facebook (plain OAuth 2.0 + Graph API) — upstream
// internal/api/provider/facebook.go.
//
// The profile call carries an appsecret_proof: the HMAC-SHA256 of the access
// token keyed by the app secret, which Facebook requires so a leaked access
// token cannot be used without the app secret.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func init() { registerProvider("facebook", newFacebookProvider) }

const (
	defaultFacebookAuthHost = "www.facebook.com"
	defaultFacebookAPIHost  = "graph.facebook.com"
)

type facebookProvider struct {
	oauth   oauthConfig
	apiHost string
	secret  string
}

func newFacebookProvider(_ context.Context, _ *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}
	authHost := chooseHost(cfg.URL, defaultFacebookAuthHost)
	apiHost := chooseHost("", defaultFacebookAPIHost)

	ep := endpointsFor(name, providerEndpoints{
		AuthURL:  authHost + "/dialog/oauth",
		TokenURL: apiHost + "/oauth/access_token",
		APIHost:  apiHost,
	})
	return &facebookProvider{
		apiHost: ep.APIHost,
		secret:  cfg.Secret,
		oauth: oauthConfig{
			ClientID:     cfg.ClientID[0],
			ClientSecret: cfg.Secret,
			AuthURL:      ep.AuthURL,
			TokenURL:     ep.TokenURL,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       scopesWithDefaults([]string{"email"}, scopes),
		},
	}, nil
}

func (p *facebookProvider) authCodeURL(state string, extra url.Values) string {
	return p.oauth.authCodeURL(state, extra)
}

func (p *facebookProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return p.oauth.exchangeCode(ctx, hc, code, nil)
}

type facebookUser struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Name      string `json:"name"`
	Picture   struct {
		Data struct {
			URL string `json:"url"`
		} `json:"data"`
	} `json:"picture"`
}

func (p *facebookProvider) userData(ctx context.Context, hc *http.Client, tok *oauthToken) (*userProvidedData, error) {
	proof := hmac.New(sha256.New, []byte(p.secret))
	proof.Write([]byte(tok.AccessToken))
	profileURL := p.apiHost + "/me?fields=email,first_name,last_name,name,picture&appsecret_proof=" +
		hex.EncodeToString(proof.Sum(nil))

	var u facebookUser
	if err := getJSON(ctx, hc, profileURL, tok.AccessToken, &u); err != nil {
		return nil, err
	}
	if u.ID == "" {
		return nil, errors.New("facebook: user response has no id")
	}

	full := strings.TrimSpace(u.FirstName + " " + u.LastName)
	data := &userProvidedData{
		Metadata: &providerClaims{
			Issuer:   p.apiHost,
			Subject:  u.ID,
			Name:     full,
			NickName: u.Name,
			Picture:  u.Picture.Data.URL,
			Email:    u.Email,

			// To be deprecated upstream, still emitted.
			AvatarURL:  u.Picture.Data.URL,
			FullName:   full,
			ProviderID: u.ID,
		},
	}
	if u.Email != "" {
		// Upstream trusts a Facebook-returned address (Facebook only returns a
		// verified one).
		data.Emails = append(data.Emails, providerEmail{Email: u.Email, Verified: true, Primary: true})
	}
	return data, nil
}

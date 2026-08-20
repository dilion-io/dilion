package auth

// Kakao — upstream internal/api/provider/kakao.go and the parseKakaoIDToken
// branch of provider/oidc.go.
//
// Kakao is an OAuth 2.0 provider with a REST profile endpoint. It also issues
// OIDC id_tokens (IssuerKakao), which is what the id_token grant verifies; the
// authorization-code flow reads the profile from kapi.kakao.com like upstream.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
)

func init() { registerProvider("kakao", newKakaoProvider) }

const (
	defaultKakaoAuthBase = "kauth.kakao.com"
	defaultKakaoAPIBase  = "kapi.kakao.com"
	// IssuerKakao is upstream's provider.IssuerKakao.
	IssuerKakao = "https://kauth.kakao.com"
)

type kakaoProvider struct {
	oauth   oauthConfig
	apiHost string
}

func newKakaoProvider(_ context.Context, _ *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}
	authHost := chooseHost(cfg.URL, defaultKakaoAuthBase)
	apiHost := chooseHost(cfg.URL, defaultKakaoAPIBase)

	ep := endpointsFor(name, providerEndpoints{
		AuthURL:  authHost + "/oauth/authorize",
		TokenURL: authHost + "/oauth/token",
		APIHost:  apiHost,
	})

	return &kakaoProvider{
		apiHost: ep.APIHost,
		oauth: oauthConfig{
			ClientID:     cfg.ClientID[0],
			ClientSecret: cfg.Secret,
			AuthURL:      ep.AuthURL,
			TokenURL:     ep.TokenURL,
			RedirectURL:  cfg.RedirectURI,
			Scopes: scopesWithDefaults(
				[]string{"account_email", "profile_image", "profile_nickname"}, scopes),
		},
	}, nil
}

func (p *kakaoProvider) authCodeURL(state string, extra url.Values) string {
	return p.oauth.authCodeURL(state, extra)
}

func (p *kakaoProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return p.oauth.exchangeCode(ctx, hc, code, nil)
}

// kakaoUser is upstream's provider.kakaoUser.
type kakaoUser struct {
	ID      int64 `json:"id"`
	Account struct {
		Profile struct {
			Name            string `json:"nickname"`
			ProfileImageURL string `json:"profile_image_url"`
		} `json:"profile"`
		Email         string `json:"email"`
		EmailValid    bool   `json:"is_email_valid"`
		EmailVerified bool   `json:"is_email_verified"`
	} `json:"kakao_account"`
}

func (p *kakaoProvider) userData(ctx context.Context, hc *http.Client, tok *oauthToken) (*userProvidedData, error) {
	var u kakaoUser
	if err := getJSON(ctx, hc, p.apiHost+"/v2/user/me", tok.AccessToken, &u); err != nil {
		return nil, err
	}
	if u.ID == 0 {
		return nil, errors.New("kakao: user response has no id")
	}
	id := strconv.FormatInt(u.ID, 10)

	data := &userProvidedData{}
	if u.Account.Email != "" {
		data.Emails = []providerEmail{{
			Email: u.Account.Email,
			// Upstream requires BOTH flags.
			Verified: u.Account.EmailVerified && u.Account.EmailValid,
			Primary:  true,
		}}
	}
	data.Metadata = &providerClaims{
		Issuer:            p.apiHost,
		Subject:           id,
		Name:              u.Account.Profile.Name,
		PreferredUsername: u.Account.Profile.Name,

		// To be deprecated upstream, still emitted.
		AvatarURL:  u.Account.Profile.ProfileImageURL,
		FullName:   u.Account.Profile.Name,
		ProviderID: id,
		UserName:   u.Account.Profile.Name,
	}
	return data, nil
}

// parseKakaoIDToken is upstream's provider.parseKakaoIDToken (id_token grant).
func parseKakaoIDToken(t *idToken) *userProvidedData {
	claims := t.Claims
	var data userProvidedData
	if email := claimString(claims, "email"); email != "" {
		// Upstream trusts Kakao's id_token email unconditionally.
		data.Emails = append(data.Emails, providerEmail{Email: email, Verified: true, Primary: true})
	}
	nickname := claimString(claims, "nickname")
	data.Metadata = &providerClaims{
		Issuer:            t.Issuer,
		Subject:           t.Subject,
		Name:              nickname,
		PreferredUsername: nickname,
		ProviderID:        t.Subject,
		Picture:           claimString(claims, "picture"),
	}
	return &data
}

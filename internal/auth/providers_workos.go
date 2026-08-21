package auth

// WorkOS (plain OAuth 2.0, profile inline in the token response) — upstream
// internal/api/provider/workos.go.
//
// WorkOS returns the whole profile inside the token endpoint's JSON body (the
// `profile` member, which upstream reads through tok.Extra("profile")), so
// userData never makes a second call — it reads the raw token body captured by
// exchangeCode.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func init() { registerProvider("workos", newWorkOSProvider) }

const defaultWorkOSAPIHost = "api.workos.com"

type workosProvider struct {
	oauth   oauthConfig
	apiHost string
}

func newWorkOSProvider(_ context.Context, _ *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}
	apiHost := chooseHost(cfg.URL, defaultWorkOSAPIHost)

	ep := endpointsFor(name, providerEndpoints{
		AuthURL:  apiHost + "/sso/authorize",
		TokenURL: apiHost + "/sso/token",
		APIHost:  apiHost,
	})
	return &workosProvider{
		apiHost: ep.APIHost,
		oauth: oauthConfig{
			ClientID:     cfg.ClientID[0],
			ClientSecret: cfg.Secret,
			AuthURL:      ep.AuthURL,
			TokenURL:     ep.TokenURL,
			RedirectURL:  cfg.RedirectURI,
			// WorkOS has no OAuth scopes; the connection/organization is selected
			// through the authorization request parameters instead.
			Scopes: scopesWithDefaults(nil, scopes),
		},
	}, nil
}

func (p *workosProvider) authCodeURL(state string, extra url.Values) string {
	return p.oauth.authCodeURL(state, extra)
}

func (p *workosProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	return p.oauth.exchangeCode(ctx, hc, code, nil)
}

type workosUser struct {
	ID             string `json:"id"`
	ConnectionID   string `json:"connection_id"`
	OrganizationID string `json:"organization_id"`
	Email          string `json:"email"`
	FirstName      string `json:"first_name"`
	LastName       string `json:"last_name"`
}

func (p *workosProvider) userData(_ context.Context, _ *http.Client, tok *oauthToken) (*userProvidedData, error) {
	var body struct {
		Profile workosUser `json:"profile"`
	}
	if len(tok.raw) == 0 || json.Unmarshal(tok.raw, &body) != nil || body.Profile.ID == "" {
		return nil, errors.New("workos: token response has no profile")
	}
	u := body.Profile

	full := strings.TrimSpace(u.FirstName + " " + u.LastName)
	data := &userProvidedData{
		Metadata: &providerClaims{
			Issuer:  p.apiHost,
			Subject: u.ID,
			Name:    full,
			Email:   u.Email,

			// To be deprecated upstream, still emitted.
			FullName:   full,
			ProviderID: u.ID,
			CustomClaims: map[string]any{
				"connection_id":   u.ConnectionID,
				"organization_id": u.OrganizationID,
			},
		},
	}
	if u.Email != "" {
		data.Emails = append(data.Emails, providerEmail{Email: u.Email, Verified: true, Primary: true})
	}
	return data, nil
}

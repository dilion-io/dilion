package auth

// Sign in with Apple — upstream internal/api/provider/apple.go and the
// parseAppleIDToken branch of provider/oidc.go.
//
// Three things make Apple different from every other provider:
//
//  1. response_mode=form_post — Apple POSTs the callback, which is why
//     /callback is registered for GET and POST alike;
//  2. the profile lives ONLY in the id_token, plus a `user` form field that is
//     sent exactly once, on the user's first authorization (parseCallbackUser);
//  3. the "client secret" is not a secret at all but a short-lived ES256 JWT
//     the server signs with the developer's private key.
//
// Upstream requires the operator to pre-build that JWT and put it in
// GOTRUE_EXTERNAL_APPLE_SECRET. Dilion accepts that verbatim, and ALSO accepts
// the private key itself as a JSON document
//
//	{"team_id": "...", "key_id": "...", "private_key": "-----BEGIN PRIVATE KEY-----..."}
//
// in which case a fresh client secret is signed for every token exchange
// (crypto/ecdsa via golang-jwt, no new dependency). That is a DILION EXTENSION,
// added because a pre-built secret expires after at most six months and turns
// into a silent outage; the upstream format keeps working unchanged.

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func init() { registerProvider("apple", newAppleProvider) }

const (
	// DefaultAppleIssuer / OtherAppleIssuer are upstream's two Apple issuers.
	DefaultAppleIssuer = "https://appleid.apple.com"
	OtherAppleIssuer   = "https://account.apple.com"
)

// appleClientSecretTTL is how long a Dilion-signed client secret lives. Apple
// caps it at six months; an hour is plenty since it is minted per exchange.
const appleClientSecretTTL = time.Hour

// isAppleIssuer is upstream's provider.IsAppleIssuer.
func isAppleIssuer(issuer string) bool {
	return issuer == DefaultAppleIssuer || issuer == OtherAppleIssuer
}

type appleProvider struct {
	a      *api
	oauth  oauthConfig
	issuer string
	secret appleSecret
}

// appleSecret is either a ready-made client secret or the material to sign one.
type appleSecret struct {
	static string

	teamID string
	keyID  string
	key    *ecdsa.PrivateKey
}

func newAppleProvider(ctx context.Context, a *api, name string, cfg ProviderConfig, scopes string) (externalProvider, error) {
	if err := validateOAuth(cfg); err != nil {
		return nil, err
	}
	secret, err := parseAppleSecret(cfg.Secret)
	if err != nil {
		return nil, err
	}
	ep := endpointsFor(name, providerEndpoints{Issuer: DefaultAppleIssuer})
	if err := a.resolveOIDCEndpoints(ctx, &ep); err != nil {
		return nil, err
	}
	return &appleProvider{
		a:      a,
		issuer: ep.Issuer,
		secret: secret,
		oauth: oauthConfig{
			ClientID:    cfg.ClientID[0],
			AuthURL:     ep.AuthURL,
			TokenURL:    ep.TokenURL,
			RedirectURL: cfg.RedirectURI,
			// Upstream's fixed scope list; `scopes` is accepted for parity but
			// Apple rejects unknown scopes, so extras are appended only when
			// the caller asked for them.
			Scopes: scopesWithDefaults([]string{"email", "name"}, scopes),
		},
	}, nil
}

// parseAppleSecret classifies GOTRUE_EXTERNAL_APPLE_SECRET.
func parseAppleSecret(secret string) (appleSecret, error) {
	secret = strings.TrimSpace(secret)
	if strings.HasPrefix(secret, "{") {
		var doc struct {
			TeamID     string `json:"team_id"`
			KeyID      string `json:"key_id"`
			PrivateKey string `json:"private_key"`
		}
		if err := json.Unmarshal([]byte(secret), &doc); err != nil {
			return appleSecret{}, errors.New("apple: secret is not a valid signing-key document")
		}
		if doc.TeamID == "" || doc.KeyID == "" || doc.PrivateKey == "" {
			return appleSecret{}, errors.New("apple: signing-key document needs team_id, key_id and private_key")
		}
		key, err := parseECPrivateKey(doc.PrivateKey)
		if err != nil {
			return appleSecret{}, err
		}
		return appleSecret{teamID: doc.TeamID, keyID: doc.KeyID, key: key}, nil
	}
	// Upstream format: the operator supplies the finished client-secret JWT.
	return appleSecret{static: secret}, nil
}

func parseECPrivateKey(pemText string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(strings.ReplaceAll(pemText, `\n`, "\n")))
	if block == nil {
		return nil, errors.New("apple: private_key is not PEM encoded")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("apple: private_key is not an EC key")
		}
		return ec, nil
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("apple: unusable private_key: %w", err)
	}
	return key, nil
}

// clientSecret returns the value to send as client_secret.
func (s appleSecret) clientSecret(clientID string, now time.Time) (string, error) {
	if s.key == nil {
		return s.static, nil
	}
	return signAppleClientSecret(s.teamID, s.keyID, clientID, s.key, now, appleClientSecretTTL)
}

// signAppleClientSecret builds the ES256 client-secret JWT Apple's token
// endpoint expects (Apple: "Generate and validate tokens").
func signAppleClientSecret(teamID, keyID, clientID string, key *ecdsa.PrivateKey, now time.Time, ttl time.Duration) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": teamID,
		"iat": now.Unix(),
		"exp": now.Add(ttl).Unix(),
		"aud": DefaultAppleIssuer,
		"sub": clientID,
	})
	tok.Header["kid"] = keyID
	return tok.SignedString(key)
}

// authCodeURL adds response_mode=form_post, which Apple requires whenever the
// `name` or `email` scope is requested (upstream AppleProvider.AuthCodeURL).
func (p *appleProvider) authCodeURL(state string, extra url.Values) string {
	if extra == nil {
		extra = url.Values{}
	} else {
		extra = cloneValues(extra)
	}
	extra.Set("response_mode", "form_post")
	return p.oauth.authCodeURL(state, extra)
}

func (p *appleProvider) exchange(ctx context.Context, hc *http.Client, code string) (*oauthToken, error) {
	secret, err := p.secret.clientSecret(p.oauth.ClientID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	cfg := p.oauth
	cfg.ClientSecret = secret
	// Upstream also repeats client_id / secret as explicit parameters.
	return cfg.exchangeCode(ctx, hc, code, url.Values{"secret": {secret}})
}

func (p *appleProvider) userData(ctx context.Context, hc *http.Client, tok *oauthToken) (*userProvidedData, error) {
	if tok.AccessToken == "" || tok.IDToken == "" {
		// Apple returns the profile only on the first authorization.
		return &userProvidedData{Metadata: &providerClaims{}}, nil
	}
	idt, err := p.a.verifyIDToken(ctx, hc, p.issuer, tok.IDToken, idTokenOptions{
		// Apple signs with either of its two issuer hosts.
		AcceptableIssuers: []string{DefaultAppleIssuer, OtherAppleIssuer},
		AccessToken:       tok.AccessToken,
	})
	if err != nil {
		return nil, err
	}
	if !containsString(idt.Audience, p.oauth.ClientID) {
		return nil, fmt.Errorf("apple: id token audience %v does not contain the configured client id", idt.Audience)
	}
	return parseAppleIDToken(idt), nil
}

// parseCallbackUser is upstream's AppleProvider.ParseUser: the `user` form field
// of the FIRST callback carries the only name Apple will ever send.
func (p *appleProvider) parseCallbackUser(raw string, data *userProvidedData) error {
	var u struct {
		Name struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		} `json:"name"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal([]byte(raw), &u); err != nil {
		return err
	}
	if data.Metadata == nil {
		data.Metadata = &providerClaims{}
	}
	full := strings.TrimSpace(u.Name.FirstName + " " + u.Name.LastName)
	data.Metadata.Name = full
	data.Metadata.FullName = full
	return nil
}

// parseAppleIDToken is upstream's provider.parseAppleIDToken.
func parseAppleIDToken(t *idToken) *userProvidedData {
	claims := t.Claims
	var data userProvidedData

	// Upstream appends the address unconditionally and marks it verified: an
	// Apple id_token is only ever issued for an address Apple owns.
	data.Emails = append(data.Emails, providerEmail{
		Email:    claimString(claims, "email"),
		Verified: true,
		Primary:  true,
	})

	data.Metadata = &providerClaims{
		Issuer:       t.Issuer,
		Subject:      t.Subject,
		ProviderID:   t.Subject,
		CustomClaims: map[string]any{},
	}
	if v, ok := claims["is_private_email"]; ok {
		data.Metadata.CustomClaims["is_private_email"] = appleBool(v)
	}
	if v, ok := claims["auth_time"]; ok {
		data.Metadata.CustomClaims["auth_time"] = v
	}
	if v := claimString(claims, "transfer_sub"); v != "" {
		data.Metadata.CustomClaims["transfer_sub"] = v
	}
	if len(data.Metadata.CustomClaims) == 0 {
		data.Metadata.CustomClaims = nil
	}
	return &data
}

// appleBool normalizes Apple's is_private_email, which is a bool in some
// responses and a stringified bool in others (upstream IsPrivateEmail).
func appleBool(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		b, err := strconv.ParseBool(t)
		return err == nil && b
	}
	return false
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vals := range v {
		out[k] = append([]string(nil), vals...)
	}
	return out
}

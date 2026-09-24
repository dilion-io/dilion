package auth

// OpenID Connect discovery, JWKS caching and ID-token verification.
//
// # Upstream parity
//
// github.com/supabase/auth delegates this to github.com/coreos/go-oidc/v3
// (provider.OIDCProviderCache, oidc.Provider.Verifier, oidc.IDToken). Dilion
// has no go-oidc dependency, so the pieces gotrue actually relies on are
// implemented here on top of golang-jwt/jwt/v5 (already a dependency):
//
//   - the issuer's /.well-known/openid-configuration is fetched once and cached
//     (authorization_endpoint, token_endpoint, jwks_uri, userinfo_endpoint);
//   - the JWKS behind jwks_uri is cached with a TTL and refreshed on an unknown
//     `kid`, which is how key rotation is picked up;
//   - verification enforces the SIGNATURE, the algorithm allow-list (RS*/ES*
//     only — never `none`, never HS*, which would turn a public key into a
//     signing secret), the issuer and the expiry. The AUDIENCE is deliberately
//     NOT checked here: upstream checks it against the configured client-id
//     LIST at the call site (token_oidc.go), and so does oidc_grant.go.
//
// Everything in this file is per-process shared state guarded by a mutex, since
// the caches outlive a request.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Cache lifetimes. Discovery documents are effectively static; key sets rotate,
// so they are re-fetched every jwksTTL and immediately on an unknown kid.
const (
	discoveryTTL = time.Hour
	jwksTTL      = 10 * time.Minute
)

// oidcDiscovery is the subset of an OpenID Provider Metadata document
// (OpenID Connect Discovery 1.0 §3) this package uses.
type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type discoveryEntry struct {
	doc       *oidcDiscovery
	fetchedAt time.Time
}

type jwksEntry struct {
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
}

// oidcCache is the process-wide discovery + JWKS cache (upstream's
// provider.OIDCProviderCache).
type oidcCacheType struct {
	mu        sync.Mutex
	discovery map[string]discoveryEntry
	jwks      map[string]jwksEntry
	now       func() time.Time
}

var oidcCache = &oidcCacheType{
	discovery: map[string]discoveryEntry{},
	jwks:      map[string]jwksEntry{},
	now:       func() time.Time { return time.Now().UTC() },
}

// resetOIDCCache drops every cached document (tests only).
func resetOIDCCache() {
	oidcCache.mu.Lock()
	defer oidcCache.mu.Unlock()
	oidcCache.discovery = map[string]discoveryEntry{}
	oidcCache.jwks = map[string]jwksEntry{}
}

// discover returns the issuer's metadata document, from cache when fresh.
func (c *oidcCacheType) discover(ctx context.Context, hc *http.Client, issuer string) (*oidcDiscovery, error) {
	issuer = strings.TrimSuffix(strings.TrimSpace(issuer), "/")
	if issuer == "" {
		return nil, errors.New("oidc: empty issuer")
	}

	c.mu.Lock()
	if e, ok := c.discovery[issuer]; ok && c.now().Sub(e.fetchedAt) < discoveryTTL {
		c.mu.Unlock()
		return e.doc, nil
	}
	c.mu.Unlock()

	doc := &oidcDiscovery{}
	if err := getJSON(ctx, hc, issuer+"/.well-known/openid-configuration", "", doc); err != nil {
		return nil, fmt.Errorf("oidc: discovery for %s: %w", issuer, err)
	}
	// The document must claim the issuer it was served for (Discovery §4.3),
	// otherwise a compromised discovery host could redirect trust elsewhere.
	if strings.TrimSuffix(doc.Issuer, "/") != issuer {
		return nil, fmt.Errorf("oidc: discovery document for %s declares issuer %q", issuer, doc.Issuer)
	}

	c.mu.Lock()
	c.discovery[issuer] = discoveryEntry{doc: doc, fetchedAt: c.now()}
	c.mu.Unlock()
	return doc, nil
}

// keys returns the issuer's key set, refreshing when stale or when `force`.
func (c *oidcCacheType) keys(ctx context.Context, hc *http.Client, jwksURI string, force bool) (map[string]crypto.PublicKey, error) {
	c.mu.Lock()
	if e, ok := c.jwks[jwksURI]; ok && !force && c.now().Sub(e.fetchedAt) < jwksTTL {
		c.mu.Unlock()
		return e.keys, nil
	}
	c.mu.Unlock()

	var doc struct {
		Keys []jsonWebKey `json:"keys"`
	}
	if err := getJSON(ctx, hc, jwksURI, "", &doc); err != nil {
		return nil, fmt.Errorf("oidc: fetching key set: %w", err)
	}

	keys := map[string]crypto.PublicKey{}
	for _, k := range doc.Keys {
		pub, err := k.publicKey()
		if err != nil || pub == nil {
			continue // unsupported key type: ignore, as go-oidc does
		}
		keys[k.KeyID] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("oidc: key set has no usable keys")
	}

	c.mu.Lock()
	c.jwks[jwksURI] = jwksEntry{keys: keys, fetchedAt: c.now()}
	c.mu.Unlock()
	return keys, nil
}

// jsonWebKey is one RFC 7517 key. Only the members needed to rebuild an RSA or
// EC public key are decoded.
type jsonWebKey struct {
	KeyType string `json:"kty"`
	KeyID   string `json:"kid"`
	Alg     string `json:"alg"`
	Use     string `json:"use"`

	// RSA
	N string `json:"n"`
	E string `json:"e"`

	// EC
	Curve string `json:"crv"`
	X     string `json:"x"`
	Y     string `json:"y"`
}

func (k jsonWebKey) publicKey() (crypto.PublicKey, error) {
	if k.Use != "" && k.Use != "sig" {
		return nil, nil
	}
	switch strings.ToUpper(k.KeyType) {
	case "RSA":
		n, err := b64uint(k.N)
		if err != nil {
			return nil, err
		}
		e, err := b64uint(k.E)
		if err != nil {
			return nil, err
		}
		if !e.IsInt64() || e.Int64() <= 0 {
			return nil, errors.New("oidc: bad RSA exponent")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Curve {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, nil
		}
		x, err := b64uint(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64uint(k.Y)
		if err != nil {
			return nil, err
		}
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("oidc: EC point is not on the curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	}
	return nil, nil
}

func b64uint(v string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(v, "="))
	if err != nil {
		return nil, fmt.Errorf("oidc: not base64url: %w", err)
	}
	return new(big.Int).SetBytes(b), nil
}

// ---- ID tokens -------------------------------------------------------------

// idTokenAlgorithms is the signature allow-list. `none` and the HMAC family are
// absent on purpose: an attacker who knows the (public) verification key must
// not be able to mint a token by using it as an HMAC secret.
var idTokenAlgorithms = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}

// idToken is upstream's oidc.IDToken, reduced to the claims gotrue reads.
type idToken struct {
	Issuer          string
	Subject         string
	Audience        []string
	Nonce           string
	AccessTokenHash string
	Algorithm       string
	IssuedAt        float64
	Expires         float64
	Claims          map[string]any
}

// idTokenOptions mirrors go-oidc's oidc.Config plus upstream's
// provider.ParseIDTokenOptions.
type idTokenOptions struct {
	// AcceptableIssuers are the issuer values the `iss` claim may take. Empty
	// means "the issuer the key set was discovered from".
	AcceptableIssuers []string
	// AccessToken, when set, is checked against the token's at_hash claim.
	AccessToken string
	// SkipAccessTokenCheck disables that check (upstream sets it when the
	// caller supplied no access token).
	SkipAccessTokenCheck bool
}

// unverifiedIDTokenIssuer reads `iss` WITHOUT verifying anything. It exists for
// the one upstream case that needs it — telling Apple's two issuer hosts apart
// before a key set can be chosen (provider.DetectAppleIDTokenIssuer).
func unverifiedIDTokenIssuer(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid ID token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid ID token: %w", err)
	}
	var claims struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("invalid ID token: %w", err)
	}
	return claims.Issuer, nil
}

// verifyIDToken verifies `raw` against the key set published by `issuer`.
//
// The audience is NOT checked here — see the file comment.
func (a *api) verifyIDToken(ctx context.Context, hc *http.Client, issuer, raw string, opts idTokenOptions) (*idToken, error) {
	doc, err := oidcCache.discover(ctx, hc, issuer)
	if err != nil {
		return nil, err
	}
	if doc.JWKSURI == "" {
		return nil, fmt.Errorf("oidc: issuer %s publishes no jwks_uri", issuer)
	}

	var usedAlg string
	keyfunc := func(t *jwt.Token) (any, error) {
		usedAlg, _ = t.Header["alg"].(string)
		kid, _ := t.Header["kid"].(string)

		keys, kerr := oidcCache.keys(ctx, hc, doc.JWKSURI, false)
		if kerr != nil {
			return nil, kerr
		}
		if k, ok := pickKey(keys, kid); ok {
			return k, nil
		}
		// Unknown kid: the provider may have rotated. Refresh once.
		keys, kerr = oidcCache.keys(ctx, hc, doc.JWKSURI, true)
		if kerr != nil {
			return nil, kerr
		}
		if k, ok := pickKey(keys, kid); ok {
			return k, nil
		}
		return nil, fmt.Errorf("oidc: no key for kid %q", kid)
	}

	claims := jwt.MapClaims{}
	parser := jwt.NewParser(
		jwt.WithValidMethods(idTokenAlgorithms),
		jwt.WithExpirationRequired(),
	)
	if _, err := parser.ParseWithClaims(raw, claims, keyfunc); err != nil {
		return nil, err
	}

	tok := &idToken{
		Issuer:          claimString(claims, "iss"),
		Subject:         claimString(claims, "sub"),
		Audience:        claimAudience(claims),
		Nonce:           claimString(claims, "nonce"),
		AccessTokenHash: claimString(claims, "at_hash"),
		Algorithm:       usedAlg,
		IssuedAt:        claimFloat(claims, "iat"),
		Expires:         claimFloat(claims, "exp"),
		Claims:          claims,
	}

	acceptable := opts.AcceptableIssuers
	if len(acceptable) == 0 {
		acceptable = []string{issuer}
	}
	if !containsString(acceptable, tok.Issuer) {
		return nil, fmt.Errorf("oidc: id token issued by %q, expected one of %v", tok.Issuer, acceptable)
	}

	if !opts.SkipAccessTokenCheck && tok.AccessTokenHash != "" {
		if err := verifyAccessTokenHash(tok.AccessTokenHash, opts.AccessToken, tok.Algorithm); err != nil {
			return nil, err
		}
	}
	return tok, nil
}

// pickKey resolves the key a token names. A token WITHOUT a kid is allowed to
// match a single-key set (go-oidc behaves the same); a token WITH a kid must
// match exactly, so that a rotated-away kid forces a key-set refresh instead of
// silently verifying against the stale key.
func pickKey(keys map[string]crypto.PublicKey, kid string) (crypto.PublicKey, bool) {
	if kid != "" {
		k, ok := keys[kid]
		return k, ok
	}
	if len(keys) == 1 {
		for _, k := range keys {
			return k, true
		}
	}
	return nil, false
}

// verifyAccessTokenHash is go-oidc's IDToken.VerifyAccessToken: the left half of
// the hash of the access token, base64url encoded, must equal at_hash. It binds
// an ID token to the access token it was issued with.
func verifyAccessTokenHash(atHash, accessToken, alg string) error {
	if accessToken == "" {
		return errors.New("oidc: id token has at_hash but no access token was provided")
	}
	var h crypto.Hash
	switch {
	case strings.HasSuffix(alg, "256"):
		h = crypto.SHA256
	case strings.HasSuffix(alg, "384"):
		h = crypto.SHA384
	case strings.HasSuffix(alg, "512"):
		h = crypto.SHA512
	default:
		return fmt.Errorf("oidc: cannot verify at_hash for algorithm %q", alg)
	}
	hasher := h.New()
	_, _ = hasher.Write([]byte(accessToken))
	sum := hasher.Sum(nil)
	want := base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
	if want != atHash {
		return errors.New("oidc: access token does not match at_hash")
	}
	return nil
}

// ---- small claim helpers ---------------------------------------------------

func claimString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func claimBool(m map[string]any, key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

func claimFloat(m map[string]any, key string) float64 {
	switch v := m[key].(type) {
	case float64:
		return v
	case int64:
		return float64(v)
	}
	return 0
}

// claimAudience accepts both shapes RFC 7519 allows for `aud`.
func claimAudience(m map[string]any) []string {
	switch v := m["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	}
	return nil
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

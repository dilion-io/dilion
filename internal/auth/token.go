package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dilion-io/dilion/ports"
)

const (
	// RoleAuthenticated is the role claim of a signed-in end user.
	RoleAuthenticated = "authenticated"
	// RoleAnon is the role claim of the unauthenticated/public token.
	RoleAnon = "anon"
	// RoleServiceRole is the role claim that admits the /admin/* endpoints
	// unconditionally.
	RoleServiceRole = "service_role"

	// ActorTypeUser is the ports.Actor.Type of a regular user access token
	// acting through management-plane RBAC (mirrors iam.ActorTypeUser).
	ActorTypeUser = "user"
	// ActorTypeServiceRole is the ports.Actor.Type recorded for a service_role
	// JWT acting on /admin/* (mirrors iam.ActorTypeServiceRole).
	ActorTypeServiceRole = "service_role"
	// PermUsersAdmin is the RBAC permission that admits a user access token to
	// /admin/* (mirrors iam.PermUsersAdmin, seeded by migration 0303).
	PermUsersAdmin = "users.admin"

	// AudienceAuthenticated is gotrue's default `aud`.
	AudienceAuthenticated = "authenticated"

	// DefaultAccessTokenTTL matches gotrue's default JWT_EXP (3600s).
	DefaultAccessTokenTTL = time.Hour

	// AlgES256 is the asymmetric signing algorithm Dilion uses. Upstream also
	// supports RS256/RS512/EdDSA; Dilion deliberately ships ES256 only — one
	// curve, small keys, small tokens (project decision, not upstream parity).
	AlgES256 = "ES256"
	// AlgHS256 is the legacy symmetric algorithm (GOTRUE_JWT_SECRET).
	AlgHS256 = "HS256"

	// IssuerPathSuffix is appended to SiteURL to build the default OIDC issuer
	// when GOTRUE_JWT_ISSUER / DILION_AUTH_JWT_ISSUER is not set. Upstream
	// defaults the issuer to API_EXTERNAL_URL + "/auth/v1"; Dilion has no
	// separate external-API URL, so SiteURL takes that role.
	IssuerPathSuffix = "/auth/v1"
)

// reservedClaims cannot be overwritten by Claims.Extra (i.e. by a TokenClaims
// hook). A hook must not be able to forge identity, role, audience or lifetime.
var reservedClaims = map[string]struct{}{
	"sub":   {},
	"aud":   {},
	"exp":   {},
	"iat":   {},
	"iss":   {},
	"role":  {},
	"email": {},
}

// ---- key material ----------------------------------------------------------

// ecKey is one parsed EC (P-256) key of Config.JWT.Keys. priv is nil for a
// verify-only key (no `d` member, or key_ops without "sign").
type ecKey struct {
	kid  string
	priv *ecdsa.PrivateKey
	pub  *ecdsa.PublicKey
}

// PublicJWK is one key of GET /.well-known/jwks.json. Only PUBLIC members are
// ever declared here — the private scalar `d` has no field on purpose, so no
// code path can leak it, and the HS256 secret is never represented at all.
type PublicJWK struct {
	KeyID     string   `json:"kid"`
	KeyType   string   `json:"kty"`
	Curve     string   `json:"crv"`
	X         string   `json:"x"`
	Y         string   `json:"y"`
	Algorithm string   `json:"alg"`
	Use       string   `json:"use"`
	KeyOps    []string `json:"key_ops"`
}

// TokenService signs and verifies gotrue-compatible access tokens.
//
// # Signing
//
// When Config.JWT.Keys contains an ES256 key whose key_ops include "sign"
// (upstream's GOTRUE_JWT_KEYS contract), tokens are signed ES256 and carry that
// key's `kid` in the JOSE header. Otherwise the service falls back to HS256 with
// Config.JWT.Secret — the zero-configuration developer path, where only
// DILION_JWT_SECRET is set.
//
// # Verifying
//
// Verification accepts BOTH: an ES256 token is checked against the public part
// of the configured key set (selected by `kid`, or tried against every key when
// the header carries none), and an HS256 token against the legacy secret. That
// is what makes a rotation from HS256 to ES256 non-breaking: tokens issued
// before the switch keep verifying until they expire. WithValidMethods is
// restricted to exactly the algorithms the configuration can actually verify,
// so `alg: none` and key-confusion attacks are rejected.
//
// # Key rotation runbook
//
// Config.JWT.Keys is an ordered set; exactly one member carries key_ops
// ["sign"] (enforced by Config.Validate). To rotate:
//
//  1. Mint a new key (`go run ./cmd/genkey`) and append it to
//     DILION_AUTH_JWT_KEYS with key_ops ["verify"]. Deploy. The new key
//     is now published in JWKS and accepted by every replica, but nothing signs
//     with it yet.
//  2. Once every replica runs step 1, flip the new key to key_ops ["sign"] and
//     the old key to ["verify"]. Deploy. New tokens carry the new `kid`; tokens
//     signed by the old key still verify.
//  3. After the old tokens have expired (Config.JWT.Exp, plus your refresh
//     window), drop the old key from the environment. Deploy.
//
// Retiring the legacy HS256 secret is the same dance: keep JWT_SECRET set while
// old tokens are alive, then unset it.
//
// It implements both ports.TokenSigner and ports.TokenVerifier; internal/api
// consumes it through those interfaces.
type TokenService struct {
	// secret is the legacy HS256 key: the signing key when no ES256 key set is
	// configured, and always a verification key when it is set.
	secret []byte
	// sign is the active ES256 signing key; nil in HS256 mode.
	sign *ecKey
	// verify holds every configured EC key, in configuration order.
	verify []ecKey

	ttl    time.Duration
	aud    string
	issuer string
	clock  ports.Clock
}

var (
	_ ports.TokenSigner   = (*TokenService)(nil)
	_ ports.TokenVerifier = (*TokenService)(nil)
)

// NewTokenService builds the token service from the /auth/v1 configuration:
// ES256 when cfg.JWT.Keys holds a signing key, HS256 with cfg.JWT.Secret
// otherwise. A nil cfg means DefaultConfig().
//
// It fails when the key set is present but unusable (non-EC curve, malformed
// coordinates, signing key without a private scalar). A configuration with
// neither an ES256 key nor a secret is accepted here — Sign and Verify then
// report the missing key — because tests and read-only mounts legitimately
// construct one.
func NewTokenService(cfg *Config) (*TokenService, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	s := &TokenService{
		secret: []byte(cfg.JWT.Secret),
		ttl:    cfg.JWT.ExpDuration(),
		aud:    cfg.JWT.Aud,
		issuer: cfg.JWT.Issuer,
		clock:  ports.SystemClock{},
	}
	if s.ttl <= 0 {
		s.ttl = DefaultAccessTokenTTL
	}
	if s.aud == "" {
		s.aud = AudienceAuthenticated
	}

	for _, kid := range cfg.JWT.Keys.Order {
		jwk := cfg.JWT.Keys.Keys[kid]
		if !strings.EqualFold(jwk.KeyType, "EC") {
			// oct (the HS256 secret expressed as a JWK) and RSA keys are not
			// signing material for Dilion and are never published.
			continue
		}
		k, err := parseECJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("auth: JWT_KEYS: key %q: %w", jwk.KeyID, err)
		}
		s.verify = append(s.verify, k)
	}
	if signing, ok := cfg.JWT.Keys.SigningKey(); ok && strings.EqualFold(signing.KeyType, "EC") {
		for i := range s.verify {
			if s.verify[i].kid == signing.KeyID {
				if s.verify[i].priv == nil {
					return nil, fmt.Errorf("auth: JWT_KEYS: signing key %q has no private scalar (\"d\")", signing.KeyID)
				}
				s.sign = &s.verify[i]
				break
			}
		}
		if s.sign == nil {
			return nil, fmt.Errorf("auth: JWT_KEYS: signing key %q is not a usable EC key", signing.KeyID)
		}
	}
	return s, nil
}

// NewTokenServiceHS is the symmetric-only constructor: HS256 with the given
// secret and every other setting at its default. It is the compatibility
// shortcut for embedders and tests that predate the key-set configuration.
func NewTokenServiceHS(secret []byte) *TokenService {
	return &TokenService{
		secret: append([]byte(nil), secret...),
		ttl:    DefaultAccessTokenTTL,
		aud:    AudienceAuthenticated,
		clock:  ports.SystemClock{},
	}
}

// parseECJWK converts one configured JWK into an EC key pair. Only P-256 is
// accepted: Dilion signs ES256 and nothing else.
func parseECJWK(k JWK) (ecKey, error) {
	if k.Curve != "" && k.Curve != "P-256" {
		return ecKey{}, fmt.Errorf("unsupported curve %q, Dilion signs ES256 (P-256)", k.Curve)
	}
	if k.Algorithm != "" && k.Algorithm != AlgES256 {
		return ecKey{}, fmt.Errorf("unsupported alg %q, Dilion signs %s", k.Algorithm, AlgES256)
	}
	x, err := decodeCoordinate(k.X)
	if err != nil {
		return ecKey{}, fmt.Errorf("member \"x\": %w", err)
	}
	y, err := decodeCoordinate(k.Y)
	if err != nil {
		return ecKey{}, fmt.Errorf("member \"y\": %w", err)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return ecKey{}, errors.New("public point is not on P-256")
	}
	out := ecKey{kid: k.KeyID, pub: pub}
	if k.D != "" {
		d, err := decodeCoordinate(k.D)
		if err != nil {
			return ecKey{}, fmt.Errorf("member \"d\": %w", err)
		}
		if d.Sign() <= 0 || d.Cmp(elliptic.P256().Params().N) >= 0 {
			return ecKey{}, errors.New("member \"d\": private scalar out of range")
		}
		out.priv = &ecdsa.PrivateKey{PublicKey: *pub, D: d}
	}
	return out, nil
}

func decodeCoordinate(v string) (*big.Int, error) {
	if v == "" {
		return nil, errors.New("missing")
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(v, "="))
	if err != nil {
		return nil, fmt.Errorf("not base64url: %w", err)
	}
	return new(big.Int).SetBytes(b), nil
}

// WithTTL returns a copy using a different access-token lifetime. Zero or
// negative durations fall back to DefaultAccessTokenTTL.
func (s *TokenService) WithTTL(ttl time.Duration) *TokenService {
	c := *s
	if ttl <= 0 {
		ttl = DefaultAccessTokenTTL
	}
	c.ttl = ttl
	return &c
}

// WithClock returns a copy using an injectable clock (tests).
func (s *TokenService) WithClock(clk ports.Clock) *TokenService {
	c := *s
	if clk != nil {
		c.clock = clk
	}
	return &c
}

// TTL reports the access-token lifetime, i.e. the `expires_in` of a session.
func (s *TokenService) TTL() time.Duration { return s.ttl }

// Algorithm reports the algorithm this service signs with: ES256 when a key set
// is configured, HS256 otherwise, and "" when it cannot sign at all.
func (s *TokenService) Algorithm() string {
	switch {
	case s == nil:
		return ""
	case s.sign != nil:
		return AlgES256
	case len(s.secret) > 0:
		return AlgHS256
	}
	return ""
}

// KeyID reports the `kid` of the active signing key, empty in HS256 mode.
func (s *TokenService) KeyID() string {
	if s == nil || s.sign == nil {
		return ""
	}
	return s.sign.kid
}

// PublicJWKS returns the public half of every configured EC key, in
// configuration order — exactly what /.well-known/jwks.json publishes. It never
// contains a private scalar and never the HS256 secret.
func (s *TokenService) PublicJWKS() []PublicJWK {
	out := []PublicJWK{}
	if s == nil {
		return out
	}
	for _, k := range s.verify {
		out = append(out, PublicJWK{
			KeyID:     k.kid,
			KeyType:   "EC",
			Curve:     "P-256",
			X:         encodeCoordinate(k.pub.X),
			Y:         encodeCoordinate(k.pub.Y),
			Algorithm: AlgES256,
			Use:       "sig",
			// Published keys are verification keys, whatever the private key's
			// key_ops said locally.
			KeyOps: []string{"verify"},
		})
	}
	return out
}

// encodeCoordinate renders an EC coordinate as the fixed-width 32 byte
// base64url string RFC 7518 §6.2.1.2 requires (left-padded, no padding chars).
func encodeCoordinate(v *big.Int) string {
	b := make([]byte, 32)
	v.FillBytes(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// validMethods is the exact allow-list handed to the parser: only the
// algorithms this configuration can verify.
func (s *TokenService) validMethods() []string {
	methods := make([]string, 0, 2)
	if len(s.verify) > 0 {
		methods = append(methods, AlgES256)
	}
	if len(s.secret) > 0 {
		methods = append(methods, AlgHS256)
	}
	return methods
}

// Sign issues a JWT. Claims.Extra is merged in first so custom claims (typically
// produced by the ports.TokenClaims hook) land in the token, then the canonical
// claims are written on top — Extra can never override them.
//
// The `iss` claim is emitted only when Config.JWT.Issuer is configured, which is
// upstream's GOTRUE_JWT_ISSUER semantics as documented on JWTConfig. The OIDC
// discovery document falls back to SiteURL + /auth/v1 when it is unset, so a
// deployment that wants a verifiable issuer must set it explicitly.
func (s *TokenService) Sign(_ context.Context, c ports.Claims) (string, error) {
	if s.sign == nil && len(s.secret) == 0 {
		return "", errors.New("auth: token service has no signing key")
	}
	if c.Subject == "" {
		return "", errors.New("auth: cannot sign a token without a subject")
	}

	claims := jwt.MapClaims{}
	for k, v := range c.Extra {
		if _, reserved := reservedClaims[k]; reserved {
			continue
		}
		claims[k] = v
	}

	now := s.clock.Now()
	exp := c.ExpiresAt
	if exp.IsZero() {
		exp = now.Add(s.ttl)
	}
	role := c.Role
	if role == "" {
		role = RoleAuthenticated
	}
	aud := c.Audience
	if aud == "" {
		aud = s.aud
	}
	if aud == "" {
		aud = AudienceAuthenticated
	}

	claims["sub"] = c.Subject
	claims["aud"] = aud
	claims["role"] = role
	claims["email"] = c.Email
	claims["iat"] = now.Unix()
	claims["exp"] = exp.Unix()
	if s.issuer != "" {
		claims["iss"] = s.issuer
	}

	if s.sign != nil {
		tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		tok.Header["kid"] = s.sign.kid
		return tok.SignedString(s.sign.priv)
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
}

// Verify parses and validates an access token. Only the algorithms this
// configuration can actually verify are accepted (`alg: none` and
// asymmetric/symmetric key confusion are rejected): ES256 against the configured
// key set, HS256 against the legacy secret. An ES256 token naming a `kid` is
// checked against that key alone; without a `kid` every configured key is tried,
// which is what keeps a rotation working for tokens minted before the new key
// existed. Every non-canonical claim is returned in Claims.Extra.
func (s *TokenService) Verify(_ context.Context, token string) (*ports.Claims, error) {
	methods := s.validMethods()
	if len(methods) == 0 {
		return nil, errors.New("auth: token service has no verification key")
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods(methods),
		jwt.WithTimeFunc(s.clock.Now),
	)

	var (
		parsed  *jwt.Token
		lastErr error
	)
	for _, key := range s.candidateKeys(token) {
		t, err := parser.Parse(token, func(*jwt.Token) (any, error) { return key, nil })
		if err == nil {
			parsed = t
			break
		}
		lastErr = err
		// A malformed token or an expired/invalid claim will fail identically
		// for every candidate; only a signature mismatch is worth retrying.
		if !errors.Is(err, jwt.ErrSignatureInvalid) {
			break
		}
	}
	if parsed == nil {
		if lastErr == nil {
			lastErr = errors.New("no key matches the token's alg/kid")
		}
		return nil, fmt.Errorf("auth: invalid JWT: %w", lastErr)
	}

	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("auth: invalid JWT: unexpected claims type")
	}

	out := &ports.Claims{Extra: map[string]any{}}
	for k, v := range mc {
		switch k {
		case "sub":
			out.Subject, _ = v.(string)
		case "role":
			out.Role, _ = v.(string)
		case "email":
			out.Email, _ = v.(string)
		case "aud":
			out.Audience = audienceString(v)
		case "exp":
			if f, ok := toFloat(v); ok {
				out.ExpiresAt = time.Unix(int64(f), 0).UTC()
			}
		default:
			out.Extra[k] = v
		}
	}

	if out.Subject == "" {
		return nil, errors.New("auth: invalid claim: missing sub claim")
	}
	return out, nil
}

// candidateKeys returns the keys worth trying for this token, narrowed by the
// UNVERIFIED header. The header only selects candidates; the signature check
// downstream is what establishes trust, and validMethods still pins the alg.
func (s *TokenService) candidateKeys(token string) []any {
	alg, kid := peekHeader(token)

	var keys []any
	switch alg {
	case AlgHS256:
		if len(s.secret) > 0 {
			keys = append(keys, s.secret)
		}
	case AlgES256:
		keys = append(keys, s.ecCandidates(kid)...)
	default:
		// Unknown or unreadable header: offer everything and let
		// WithValidMethods reject what it must.
		keys = append(keys, s.ecCandidates(kid)...)
		if len(s.secret) > 0 {
			keys = append(keys, s.secret)
		}
	}
	return keys
}

func (s *TokenService) ecCandidates(kid string) []any {
	if kid != "" {
		for _, k := range s.verify {
			if k.kid == kid {
				return []any{k.pub}
			}
		}
		// An unknown kid is not fatal: fall through to every key, so a replica
		// that has not picked up a newly published key yet still tries.
	}
	out := make([]any, 0, len(s.verify))
	for _, k := range s.verify {
		out = append(out, k.pub)
	}
	return out
}

// peekHeader decodes the JOSE header WITHOUT verifying anything.
func peekHeader(token string) (alg, kid string) {
	first, _, found := strings.Cut(token, ".")
	if !found {
		return "", ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil {
		return "", ""
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return "", ""
	}
	return h.Alg, h.Kid
}

// issuerURL is the issuer advertised by OIDC discovery: the configured
// GOTRUE_JWT_ISSUER, or SiteURL + /auth/v1 — the Dilion equivalent of upstream's
// API_EXTERNAL_URL + /auth/v1 default. The result never ends in a slash.
func issuerURL(cfg *Config) string {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	iss := strings.TrimSpace(cfg.JWT.Issuer)
	if iss == "" {
		iss = strings.TrimRight(strings.TrimSpace(cfg.SiteURL), "/") + IssuerPathSuffix
	}
	return strings.TrimRight(iss, "/")
}

// audienceString flattens the `aud` claim, which JWT allows to be either a
// string or an array of strings.
func audienceString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []string:
		if len(t) > 0 {
			return t[0]
		}
	case []any:
		if len(t) > 0 {
			s, _ := t[0].(string)
			return s
		}
	}
	return ""
}

func toFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int64:
		return float64(t), true
	case int:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	}
	return 0, false
}

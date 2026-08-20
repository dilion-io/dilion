package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"github.com/dilion-io/dilion/ports"
)

// ---- helpers ---------------------------------------------------------------

func b64u(v *big.Int) string {
	b := make([]byte, 32)
	v.FillBytes(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// newTestJWK mints an ES256 key and returns its JWK JSON plus the private key.
func newTestJWK(t *testing.T, kid string, ops ...string) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	m := map[string]any{
		"kty": "EC", "kid": kid, "crv": "P-256", "alg": "ES256", "use": "sig",
		"key_ops": ops,
		"x":       b64u(key.X), "y": b64u(key.Y), "d": b64u(key.D),
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	return string(b), key
}

// configWithKeys builds a validated Config carrying the given JWK JSON blobs.
func configWithKeys(t *testing.T, secret string, jwks ...string) *Config {
	t.Helper()
	cfg := DefaultConfig()
	cfg.JWT.Secret = secret
	if len(jwks) > 0 {
		set, err := parseJWKSet("[" + strings.Join(jwks, ",") + "]")
		if err != nil {
			t.Fatalf("parseJWKSet: %v", err)
		}
		cfg.JWT.Keys = set
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return cfg
}

func mustTokenService(t *testing.T, cfg *Config) *TokenService {
	t.Helper()
	ts, err := NewTokenService(cfg)
	if err != nil {
		t.Fatalf("NewTokenService: %v", err)
	}
	return ts
}

// ---- signing ---------------------------------------------------------------

func TestTokenES256RoundTripCarriesKid(t *testing.T) {
	signing, _ := newTestJWK(t, "active-key", "sign")
	ts := mustTokenService(t, configWithKeys(t, "", signing))

	if got := ts.Algorithm(); got != AlgES256 {
		t.Fatalf("Algorithm() = %q, want ES256", got)
	}
	if got := ts.KeyID(); got != "active-key" {
		t.Errorf("KeyID() = %q, want active-key", got)
	}

	token, err := ts.Sign(context.Background(), ports.Claims{Subject: "u1", Email: "a@example.com"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	alg, kid := peekHeader(token)
	if alg != "ES256" {
		t.Errorf("header alg = %q, want ES256", alg)
	}
	if kid != "active-key" {
		t.Errorf("header kid = %q, want active-key", kid)
	}

	out, err := ts.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.Subject != "u1" || out.Role != RoleAuthenticated || out.Audience != AudienceAuthenticated {
		t.Errorf("claims = %+v", out)
	}
}

// A key set with several keys must sign with the key_ops:["sign"] member and
// verify tokens issued by every member — that is what makes rotation work.
func TestTokenES256MultiKeyVerify(t *testing.T) {
	oldKey, oldPriv := newTestJWK(t, "old-key", "verify")
	newKey, _ := newTestJWK(t, "new-key", "sign")
	cfg := configWithKeys(t, "", oldKey, newKey)
	ts := mustTokenService(t, cfg)

	if ts.KeyID() != "new-key" {
		t.Fatalf("signing kid = %q, want new-key", ts.KeyID())
	}

	// A token minted by the retired key (kid present) still verifies.
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "u1", "exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "old-key"
	signed, err := tok.SignedString(oldPriv)
	if err != nil {
		t.Fatalf("sign with old key: %v", err)
	}
	if _, err := ts.Verify(context.Background(), signed); err != nil {
		t.Fatalf("Verify(old kid): %v", err)
	}

	// So does one with no kid at all: every configured key is tried.
	noKid, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "u1", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(oldPriv)
	if err != nil {
		t.Fatalf("sign kid-less: %v", err)
	}
	if _, err := ts.Verify(context.Background(), noKid); err != nil {
		t.Fatalf("Verify(no kid): %v", err)
	}

	// A foreign ES256 key is rejected.
	foreign, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": "u1", "exp": time.Now().Add(time.Hour).Unix(),
	}).SignedString(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ts.Verify(context.Background(), bad); err == nil {
		t.Fatal("expected a token signed by an unknown key to be rejected")
	}
}

// Tokens issued before an ES256 rotation must keep verifying against the legacy
// HS256 secret, and the wrong algorithm must never be accepted.
func TestTokenES256AcceptsLegacyHS256AndRejectsWrongAlg(t *testing.T) {
	signing, _ := newTestJWK(t, "active-key", "sign")

	t.Run("legacy secret still verifies", func(t *testing.T) {
		ts := mustTokenService(t, configWithKeys(t, string(testSecret()), signing))
		legacy, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "u1", "exp": time.Now().Add(time.Hour).Unix(),
		}).SignedString(testSecret())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ts.Verify(context.Background(), legacy); err != nil {
			t.Fatalf("Verify(HS256 legacy): %v", err)
		}
		// ...but it is not what new tokens are signed with.
		fresh, err := ts.Sign(context.Background(), ports.Claims{Subject: "u1"})
		if err != nil {
			t.Fatal(err)
		}
		if alg, _ := peekHeader(fresh); alg != "ES256" {
			t.Errorf("fresh token alg = %q, want ES256", alg)
		}
	})

	t.Run("HS256 rejected once the secret is retired", func(t *testing.T) {
		ts := mustTokenService(t, configWithKeys(t, "", signing))
		legacy, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "u1", "exp": time.Now().Add(time.Hour).Unix(),
		}).SignedString(testSecret())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ts.Verify(context.Background(), legacy); err == nil {
			t.Fatal("expected HS256 to be rejected in ES256-only mode")
		}
		if got, want := ts.validMethods(), []string{AlgES256}; strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("validMethods = %v, want %v", got, want)
		}
	})

	t.Run("alg none rejected", func(t *testing.T) {
		ts := mustTokenService(t, configWithKeys(t, string(testSecret()), signing))
		none, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
			"sub": "u1", "exp": time.Now().Add(time.Hour).Unix(),
		}).SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ts.Verify(context.Background(), none); err == nil {
			t.Fatal("expected alg=none to be rejected")
		}
	})

	t.Run("HMAC forged with the public key is rejected", func(t *testing.T) {
		// Classic key-confusion: sign HS256 using the published public key as
		// the shared secret. WithValidMethods must make this impossible.
		ts := mustTokenService(t, configWithKeys(t, "", signing))
		pub := ts.PublicJWKS()[0]
		forged, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "u1", "exp": time.Now().Add(time.Hour).Unix(),
		}).SignedString([]byte(pub.X + pub.Y))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ts.Verify(context.Background(), forged); err == nil {
			t.Fatal("expected key-confusion token to be rejected")
		}
	})
}

// The HS256-only path is the dev-server default (only DILION_JWT_SECRET set).
func TestTokenServiceHS256FallbackFromConfig(t *testing.T) {
	cfg := DefaultConfig()
	cfg.JWT.Secret = string(testSecret())
	cfg.JWT.Exp = 120
	cfg.JWT.Aud = "custom-aud"
	cfg.JWT.Issuer = "https://issuer.example/auth/v1"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	ts := mustTokenService(t, cfg)

	if ts.Algorithm() != AlgHS256 {
		t.Errorf("Algorithm() = %q, want HS256", ts.Algorithm())
	}
	if ts.KeyID() != "" {
		t.Errorf("KeyID() = %q, want empty in HS256 mode", ts.KeyID())
	}
	if ts.TTL() != 2*time.Minute {
		t.Errorf("TTL() = %v, want 2m (from JWT_EXP)", ts.TTL())
	}
	if len(ts.PublicJWKS()) != 0 {
		t.Errorf("PublicJWKS() = %v, want empty for a symmetric key", ts.PublicJWKS())
	}

	token, err := ts.Sign(context.Background(), ports.Claims{Subject: "u1"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if alg, _ := peekHeader(token); alg != "HS256" {
		t.Errorf("alg = %q, want HS256", alg)
	}
	claims := decodeClaims(t, token)
	if claims["aud"] != "custom-aud" {
		t.Errorf("aud = %v, want custom-aud (from JWT_AUD)", claims["aud"])
	}
	if claims["iss"] != "https://issuer.example/auth/v1" {
		t.Errorf("iss = %v, want the configured issuer", claims["iss"])
	}
	if _, err := ts.Verify(context.Background(), token); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// An unset JWT_ISSUER keeps upstream's semantics: no `iss` claim at all.
func TestTokenNoIssuerClaimWhenUnconfigured(t *testing.T) {
	ts := mustTokenService(t, configWithKeys(t, string(testSecret())))
	token, err := ts.Sign(context.Background(), ports.Claims{Subject: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := decodeClaims(t, token)["iss"]; ok {
		t.Error("iss claim present although JWT_ISSUER is unset")
	}
}

func TestNewTokenServiceRejectsUnusableKeys(t *testing.T) {
	t.Run("non P-256 curve", func(t *testing.T) {
		raw := `{"kty":"EC","kid":"k","crv":"P-384","x":"AA","y":"AA","d":"AA","key_ops":["sign"]}`
		if _, err := NewTokenService(configWithKeys(t, "", raw)); err == nil {
			t.Fatal("expected a non-P-256 key to be rejected")
		}
	})
	t.Run("signing key without private scalar", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		raw := `{"kty":"EC","kid":"k","crv":"P-256","alg":"ES256","key_ops":["sign"],"x":"` +
			b64u(key.X) + `","y":"` + b64u(key.Y) + `"}`
		if _, err := NewTokenService(configWithKeys(t, "", raw)); err == nil {
			t.Fatal("expected a signing key without \"d\" to be rejected")
		}
	})
	t.Run("point off the curve", func(t *testing.T) {
		raw := `{"kty":"EC","kid":"k","crv":"P-256","alg":"ES256","key_ops":["sign"],"x":"AQ","y":"AQ","d":"AQ"}`
		if _, err := NewTokenService(configWithKeys(t, "", raw)); err == nil {
			t.Fatal("expected an off-curve point to be rejected")
		}
	})
}

// ---- JWKS ------------------------------------------------------------------

func jsonRequest(t *testing.T, ts *TokenService, cfg *Config, path string) (int, []byte) {
	t.Helper()
	r := chi.NewRouter()
	Register(r, Deps{Tokens: ts, Config: cfg})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec.Code, rec.Body.Bytes()
}

func TestJWKSPublishesPublicKeysOnly(t *testing.T) {
	signing, priv := newTestJWK(t, "active-key", "sign")
	verifyOnly, _ := newTestJWK(t, "next-key", "verify")
	cfg := configWithKeys(t, string(testSecret()), signing, verifyOnly)
	ts := mustTokenService(t, cfg)

	code, body := jsonRequest(t, ts, cfg, "/.well-known/jwks.json")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}

	// Nothing private may appear anywhere in the document.
	raw := string(body)
	if strings.Contains(raw, `"d"`) {
		t.Fatalf("JWKS leaks the private scalar: %s", raw)
	}
	if strings.Contains(raw, string(testSecret())) || strings.Contains(raw, b64u(priv.D)) {
		t.Fatalf("JWKS leaks secret material: %s", raw)
	}

	var got struct {
		Keys []PublicJWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Keys) != 2 {
		t.Fatalf("published %d keys, want 2", len(got.Keys))
	}
	if got.Keys[0].KeyID != "active-key" || got.Keys[1].KeyID != "next-key" {
		t.Errorf("key order = %q, %q; want configuration order", got.Keys[0].KeyID, got.Keys[1].KeyID)
	}
	for _, k := range got.Keys {
		if k.KeyType != "EC" || k.Curve != "P-256" || k.Algorithm != "ES256" || k.Use != "sig" {
			t.Errorf("key %q = %+v, want EC/P-256/ES256/sig", k.KeyID, k)
		}
		if len(k.KeyOps) != 1 || k.KeyOps[0] != "verify" {
			t.Errorf("key %q key_ops = %v, want [verify]", k.KeyID, k.KeyOps)
		}
		if k.X == "" || k.Y == "" {
			t.Errorf("key %q is missing its coordinates", k.KeyID)
		}
	}

	// The published key really is the verification key of the issued token.
	token, err := ts.Sign(context.Background(), ports.Claims{Subject: "u1"})
	if err != nil {
		t.Fatal(err)
	}
	x, _ := decodeCoordinate(got.Keys[0].X)
	y, _ := decodeCoordinate(got.Keys[0].Y)
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if _, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"ES256"})); err != nil {
		t.Fatalf("token does not verify against the published key: %v", err)
	}
	if !pub.Equal(&priv.PublicKey) {
		t.Error("published key is not the public half of the signing key")
	}
}

// The symmetric-only deployment publishes an empty set, never the secret.
func TestJWKSEmptyForHS256(t *testing.T) {
	cfg := configWithKeys(t, string(testSecret()))
	code, body := jsonRequest(t, mustTokenService(t, cfg), cfg, "/.well-known/jwks.json")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if got := strings.TrimSpace(string(body)); got != `{"keys":[]}` {
		t.Errorf("body = %s, want {\"keys\":[]}", got)
	}
}

// ---- discovery -------------------------------------------------------------

func TestWellKnownOpenIDConfiguration(t *testing.T) {
	signing, _ := newTestJWK(t, "active-key", "sign")
	cfg := configWithKeys(t, "", signing)
	cfg.SiteURL = "https://app.example.com/"

	code, body := jsonRequest(t, mustTokenService(t, cfg), cfg, "/.well-known/openid-configuration")
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}

	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	const iss = "https://app.example.com/auth/v1"
	want := map[string]any{
		"issuer":                 iss,
		"authorization_endpoint": iss + "/oauth/authorize",
		"token_endpoint":         iss + "/oauth/token",
		"jwks_uri":               iss + "/.well-known/jwks.json",
		"userinfo_endpoint":      iss + "/oauth/userinfo",
	}
	for k, v := range want {
		if doc[k] != v {
			t.Errorf("%s = %v, want %v", k, doc[k], v)
		}
	}
	if got := doc["id_token_signing_alg_values_supported"]; !equalStrings(got, []string{"ES256"}) {
		t.Errorf("id_token_signing_alg_values_supported = %v, want [ES256]", got)
	}
	if got := doc["response_types_supported"]; !equalStrings(got, []string{"code"}) {
		t.Errorf("response_types_supported = %v, want [code]", got)
	}
	if got := doc["subject_types_supported"]; !equalStrings(got, []string{"public"}) {
		t.Errorf("subject_types_supported = %v, want [public]", got)
	}
	for _, key := range []string{"grant_types_supported", "token_endpoint_auth_methods_supported",
		"code_challenge_methods_supported", "scopes_supported", "claims_supported"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("%s missing from the discovery document", key)
		}
	}
}

// While the legacy secret is still accepted, discovery must say so.
func TestWellKnownOpenIDReportsBothAlgsDuringRotation(t *testing.T) {
	signing, _ := newTestJWK(t, "active-key", "sign")
	cfg := configWithKeys(t, string(testSecret()), signing)
	_, body := jsonRequest(t, mustTokenService(t, cfg), cfg, "/.well-known/openid-configuration")

	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if got := doc["id_token_signing_alg_values_supported"]; !equalStrings(got, []string{"ES256", "HS256"}) {
		t.Errorf("algs = %v, want [ES256 HS256]", got)
	}

	// HS256-only deployment.
	hsCfg := configWithKeys(t, string(testSecret()))
	_, body = jsonRequest(t, mustTokenService(t, hsCfg), hsCfg, "/.well-known/openid-configuration")
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if got := doc["id_token_signing_alg_values_supported"]; !equalStrings(got, []string{"HS256"}) {
		t.Errorf("algs = %v, want [HS256]", got)
	}
	// The default issuer is derived from SiteURL.
	if doc["issuer"] != DefaultSiteURL+"/auth/v1" {
		t.Errorf("issuer = %v, want %s/auth/v1", doc["issuer"], DefaultSiteURL)
	}
}

func equalStrings(got any, want []string) bool {
	arr, ok := got.([]any)
	if !ok || len(arr) != len(want) {
		return false
	}
	for i, v := range arr {
		if s, _ := v.(string); s != want[i] {
			return false
		}
	}
	return true
}

// ---- cmd/genkey ------------------------------------------------------------

// The generator's first block must be a valid DILION_AUTH_JWT_KEYS value: it is
// loaded through the real configuration path and used to sign.
func TestGenkeyOutputLoadsAsConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles and runs cmd/genkey")
	}
	out, err := exec.Command("go", "run", "../../cmd/genkey", "-kid", "generated-key").CombinedOutput()
	if err != nil {
		t.Fatalf("go run ./cmd/genkey: %v\n%s", err, out)
	}

	var keysJSON string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "[") {
			keysJSON = strings.TrimSpace(line)
			break
		}
	}
	if keysJSON == "" {
		t.Fatalf("no JWK array in genkey output:\n%s", out)
	}

	t.Setenv("DILION_AUTH_JWT_KEYS", keysJSON)
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig with the generated key set: %v", err)
	}
	if cfg.JWT.Keys.Len() != 1 {
		t.Fatalf("loaded %d keys, want 1", cfg.JWT.Keys.Len())
	}

	ts := mustTokenService(t, cfg)
	if ts.Algorithm() != AlgES256 || ts.KeyID() != "generated-key" {
		t.Fatalf("alg=%q kid=%q, want ES256/generated-key", ts.Algorithm(), ts.KeyID())
	}
	token, err := ts.Sign(context.Background(), ports.Claims{Subject: "u1"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := ts.Verify(context.Background(), token); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

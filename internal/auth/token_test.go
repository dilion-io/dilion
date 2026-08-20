package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dilion-project/dilion/ports"
)

type fixedClock struct{ t time.Time }

func (c *fixedClock) Now() time.Time { return c.t }

func testSecret() []byte { return []byte("super-secret-jwt-token-with-at-least-32-characters") }

func TestTokenSignVerifyRoundTrip(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)}
	ts := NewTokenServiceHS(testSecret()).WithClock(clk)

	in := ports.Claims{
		Subject: "0d3f6b2a-1111-4222-8333-444455556666",
		Role:    RoleAuthenticated,
		Email:   "user@example.com",
		Extra: map[string]any{
			"session_id":    "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
			"is_anonymous":  false,
			"app_metadata":  map[string]any{"provider": "email"},
			"user_metadata": map[string]any{"name": "Kim"},
		},
	}

	token, err := ts.Sign(context.Background(), in)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	out, err := ts.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}

	if out.Subject != in.Subject {
		t.Errorf("sub = %q, want %q", out.Subject, in.Subject)
	}
	if out.Role != RoleAuthenticated {
		t.Errorf("role = %q, want %q", out.Role, RoleAuthenticated)
	}
	if out.Email != in.Email {
		t.Errorf("email = %q, want %q", out.Email, in.Email)
	}
	if out.Audience != AudienceAuthenticated {
		t.Errorf("aud = %q, want %q", out.Audience, AudienceAuthenticated)
	}
	if want := clk.t.Add(DefaultAccessTokenTTL); !out.ExpiresAt.Equal(want) {
		t.Errorf("exp = %v, want %v", out.ExpiresAt, want)
	}
	if got := out.Extra["session_id"]; got != in.Extra["session_id"] {
		t.Errorf("session_id claim = %v, want %v", got, in.Extra["session_id"])
	}
	if _, ok := out.Extra["iat"]; !ok {
		t.Error("iat claim missing from token")
	}
}

// The default role/audience must be gotrue's, so a token issued without an
// explicit role still passes PostgREST's `authenticated` checks.
func TestTokenSignDefaults(t *testing.T) {
	ts := NewTokenServiceHS(testSecret())

	token, err := ts.Sign(context.Background(), ports.Claims{Subject: "u1"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	claims := decodeClaims(t, token)

	if claims["role"] != RoleAuthenticated {
		t.Errorf("role = %v, want %q", claims["role"], RoleAuthenticated)
	}
	if claims["aud"] != AudienceAuthenticated {
		t.Errorf("aud = %v, want %q", claims["aud"], AudienceAuthenticated)
	}
	if claims["email"] != "" {
		t.Errorf("email = %v, want empty string (always present per gotrue)", claims["email"])
	}
}

// A TokenClaims hook feeds Claims.Extra; it must not be able to escalate the
// role or extend the lifetime of the token.
func TestTokenSignExtraCannotOverrideReservedClaims(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)}
	ts := NewTokenServiceHS(testSecret()).WithClock(clk)

	token, err := ts.Sign(context.Background(), ports.Claims{
		Subject: "u1",
		Role:    RoleAuthenticated,
		Email:   "real@example.com",
		Extra: map[string]any{
			"sub":    "attacker",
			"role":   RoleServiceRole,
			"email":  "attacker@example.com",
			"aud":    "elevated",
			"exp":    time.Now().Add(1000 * time.Hour).Unix(),
			"tenant": "acme", // legitimate custom claim, must survive
		},
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	claims := decodeClaims(t, token)
	if claims["sub"] != "u1" {
		t.Errorf("sub = %v, want u1", claims["sub"])
	}
	if claims["role"] != RoleAuthenticated {
		t.Errorf("role = %v, want %q", claims["role"], RoleAuthenticated)
	}
	if claims["email"] != "real@example.com" {
		t.Errorf("email = %v, want real@example.com", claims["email"])
	}
	if claims["aud"] != AudienceAuthenticated {
		t.Errorf("aud = %v, want %q", claims["aud"], AudienceAuthenticated)
	}
	if got, want := int64(claims["exp"].(float64)), clk.t.Add(DefaultAccessTokenTTL).Unix(); got != want {
		t.Errorf("exp = %d, want %d", got, want)
	}
	if claims["tenant"] != "acme" {
		t.Errorf("custom claim tenant = %v, want acme", claims["tenant"])
	}
}

func TestTokenVerifyRejectsBadInput(t *testing.T) {
	clk := &fixedClock{t: time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC)}
	ts := NewTokenServiceHS(testSecret()).WithClock(clk)

	valid, err := ts.Sign(context.Background(), ports.Claims{Subject: "u1"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	t.Run("wrong secret", func(t *testing.T) {
		other := NewTokenServiceHS([]byte("a-completely-different-secret-value!!")).WithClock(clk)
		if _, err := other.Verify(context.Background(), valid); err == nil {
			t.Fatal("expected verification against a different secret to fail")
		}
	})

	t.Run("expired", func(t *testing.T) {
		later := NewTokenServiceHS(testSecret()).
			WithClock(&fixedClock{t: clk.t.Add(DefaultAccessTokenTTL + time.Minute)})
		if _, err := later.Verify(context.Background(), valid); err == nil {
			t.Fatal("expected expired token to be rejected")
		}
	})

	t.Run("alg none", func(t *testing.T) {
		none, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
			"sub": "u1", "exp": clk.t.Add(time.Hour).Unix(),
		}).SignedString(jwt.UnsafeAllowNoneSignatureType)
		if err != nil {
			t.Fatalf("build alg=none token: %v", err)
		}
		if _, err := ts.Verify(context.Background(), none); err == nil {
			t.Fatal("expected alg=none token to be rejected")
		}
	})

	t.Run("garbage", func(t *testing.T) {
		if _, err := ts.Verify(context.Background(), "not-a-jwt"); err == nil {
			t.Fatal("expected malformed token to be rejected")
		}
	})

	t.Run("missing sub", func(t *testing.T) {
		noSub, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"exp": clk.t.Add(time.Hour).Unix(), "role": RoleAuthenticated,
		}).SignedString(testSecret())
		if err != nil {
			t.Fatalf("build token: %v", err)
		}
		if _, err := ts.Verify(context.Background(), noSub); err == nil {
			t.Fatal("expected token without sub to be rejected")
		}
	})
}

func TestTokenSignRequiresSubjectAndSecret(t *testing.T) {
	if _, err := NewTokenServiceHS(testSecret()).Sign(context.Background(), ports.Claims{}); err == nil {
		t.Error("expected signing without a subject to fail")
	}
	if _, err := NewTokenServiceHS(nil).Sign(context.Background(), ports.Claims{Subject: "u1"}); err == nil {
		t.Error("expected signing without a secret to fail")
	}
}

func TestTokenServiceImplementsPorts(t *testing.T) {
	var (
		signer   ports.TokenSigner   = NewTokenServiceHS(testSecret())
		verifier ports.TokenVerifier = NewTokenServiceHS(testSecret())
	)
	if signer == nil || verifier == nil {
		t.Fatal("TokenService must satisfy ports.TokenSigner and ports.TokenVerifier")
	}
}

func TestAudienceString(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{"authenticated", "authenticated"},
		{[]any{"authenticated", "other"}, "authenticated"},
		{[]string{"authenticated"}, "authenticated"},
		{[]any{}, ""},
		{42, ""},
	}
	for _, c := range cases {
		if got := audienceString(c.in); got != c.want {
			t.Errorf("audienceString(%#v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// decodeClaims reads the JWT payload without verifying it.
func decodeClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token does not have 3 segments: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims
}

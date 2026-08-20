package iam

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dilion-project/dilion/httpapi"
	"github.com/dilion-project/dilion/ports"
)

func TestValidateCustomPermission(t *testing.T) {
	valid := []string{
		"myapp.orders.refund",
		"acme.billing.read",
		"my-app.thing-1.do",
		"a.b",
	}
	for _, name := range valid {
		if err := ValidateCustomPermission(name); err != nil {
			t.Errorf("ValidateCustomPermission(%q) = %v, want nil", name, err)
		}
	}

	invalid := []string{
		"",                        // empty
		"orders",                  // not namespaced
		"MyApp.orders",            // uppercase
		"1app.orders",             // must start with a letter
		".orders",                 // empty namespace
		"myapp.orders refund",     // space
		"users.read",              // builtin collision
		"pii.reveal",              // builtin collision
		"privacy.requests.manage", // builtin collision
		"audit.read",              // builtin collision
	}
	for _, name := range invalid {
		err := ValidateCustomPermission(name)
		if err == nil {
			t.Errorf("ValidateCustomPermission(%q) = nil, want error", name)
			continue
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("ValidateCustomPermission(%q) error = %v, want ErrInvalid", name, err)
		}
	}
}

func TestBuiltinPermissionsAreNotNamespacedCustom(t *testing.T) {
	for _, p := range BuiltinPermissions {
		if err := ValidateCustomPermission(p); err == nil {
			t.Errorf("builtin %q must not be registrable as a custom permission", p)
		}
	}
}

func TestNewTokenFormat(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		tok := NewToken()
		if !strings.HasPrefix(tok, TokenPrefix) {
			t.Fatalf("token %q missing %q prefix", tok, TokenPrefix)
		}
		if got := len(tok) - len(TokenPrefix); got != tokenRandomLen {
			t.Fatalf("random part = %d chars, want %d", got, tokenRandomLen)
		}
		if !ValidTokenFormat(tok) {
			t.Fatalf("ValidTokenFormat(%q) = false", tok)
		}
		if seen[tok] {
			t.Fatalf("duplicate token generated: %q", tok)
		}
		seen[tok] = true
	}
}

func TestValidTokenFormatRejectsJunk(t *testing.T) {
	bad := []string{
		"",
		"dk_",
		"dk_short",
		"sk_" + strings.Repeat("a", 48),
		strings.Repeat("a", 48),
		"dk_" + strings.Repeat("a", 47),
		"dk_" + strings.Repeat("a", 49),
		"dk_" + strings.Repeat("*", 48),
	}
	for _, tok := range bad {
		if ValidTokenFormat(tok) {
			t.Errorf("ValidTokenFormat(%q) = true, want false", tok)
		}
	}
}

func TestHashTokenIsSHA256(t *testing.T) {
	tok := "dk_" + strings.Repeat("a", 48)
	want := sha256.Sum256([]byte(tok))
	got := HashToken(tok)
	if len(got) != 32 {
		t.Fatalf("hash length = %d, want 32", len(got))
	}
	if string(got) != string(want[:]) {
		t.Error("HashToken is not SHA-256 of the full token")
	}
	if string(HashToken(tok+"x")) == string(got) {
		t.Error("different tokens hashed to the same value")
	}
}

func TestCursorRoundTrip(t *testing.T) {
	for _, v := range []string{"", "abc", "role_0000", "a/b+c=", "42"} {
		enc := encodeCursor(v)
		if enc != "" && strings.ContainsAny(enc, "+/=") {
			t.Errorf("cursor %q is not url-safe", enc)
		}
		got, err := decodeCursor(enc)
		if err != nil {
			t.Fatalf("decodeCursor(%q) = %v", enc, err)
		}
		if got != v {
			t.Errorf("round trip = %q, want %q", got, v)
		}
	}
}

func TestDecodeCursorRejectsGarbage(t *testing.T) {
	if _, err := decodeCursor("!!!not base64!!!"); !errors.Is(err, ErrInvalid) {
		t.Errorf("decodeCursor(garbage) = %v, want ErrInvalid", err)
	}
	// A well-formed empty cursor means "first page".
	if got, err := decodeCursor(""); err != nil || got != "" {
		t.Errorf("decodeCursor(\"\") = (%q,%v)", got, err)
	}
}

func TestPaginate(t *testing.T) {
	key := func(s string) string { return s }

	// Fewer results than the limit: no next cursor.
	page := paginate([]string{"a", "b"}, 5, key)
	if len(page.Items) != 2 || page.NextCursor != nil {
		t.Errorf("page = %+v, want 2 items and no cursor", page)
	}

	// Exactly limit+1 results: the probe row is trimmed and becomes the cursor.
	page = paginate([]string{"a", "b", "c"}, 2, key)
	if len(page.Items) != 2 {
		t.Fatalf("items = %d, want 2", len(page.Items))
	}
	if page.NextCursor == nil {
		t.Fatal("next cursor = nil, want the last returned key")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(*page.NextCursor)
	if err != nil {
		t.Fatalf("cursor not base64url: %v", err)
	}
	if string(decoded) != "b" {
		t.Errorf("cursor points at %q, want b", decoded)
	}

	// Empty result sets must still serialize as [] not null.
	page = paginate([]string{}, 10, key)
	if page.Items == nil {
		t.Error("empty page items must be non-nil")
	}
}

func TestListParamsNormClamps(t *testing.T) {
	if got := (httpapi.ListParams{}).Norm().Limit; got != httpapi.DefaultLimit {
		t.Errorf("default limit = %d, want %d", got, httpapi.DefaultLimit)
	}
	if got := (httpapi.ListParams{Limit: 1000}).Norm().Limit; got != httpapi.MaxLimit {
		t.Errorf("clamped limit = %d, want %d", got, httpapi.MaxLimit)
	}
}

func TestAPIKeyActive(t *testing.T) {
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	cases := []struct {
		name string
		key  APIKey
		want bool
	}{
		{"no expiry", APIKey{}, true},
		{"future expiry", APIKey{ExpiresAt: &future}, true},
		{"past expiry", APIKey{ExpiresAt: &past}, false},
		{"expiring now", APIKey{ExpiresAt: &now}, false},
		{"revoked", APIKey{RevokedAt: &past}, false},
		{"revoked and unexpired", APIKey{RevokedAt: &past, ExpiresAt: &future}, false},
	}
	for _, tc := range cases {
		if got := tc.key.Active(now); got != tc.want {
			t.Errorf("%s: Active = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAuthorizerServiceRoleAlwaysAllowedWithoutDB(t *testing.T) {
	a := NewAuthorizer(nil)
	ok, err := a.Can(context.Background(),
		ports.Actor{ID: "svc", Type: ActorTypeServiceRole, ProjectID: DefaultProjectID},
		PermPIIReveal, "")
	if err != nil || !ok {
		t.Fatalf("service_role Can = (%v,%v), want (true,nil)", ok, err)
	}
}

func TestAuthorizerFailsClosedWithoutDB(t *testing.T) {
	a := NewAuthorizer(nil)
	ok, err := a.Can(context.Background(),
		ports.Actor{ID: "admin", Type: ActorTypeAdmin}, PermUsersRead, "")
	if ok {
		t.Error("Can = true without a database, want deny")
	}
	if err == nil {
		t.Error("expected an error when the pool is missing")
	}
}

func TestDedupe(t *testing.T) {
	got := dedupe([]string{"b", "a", "b", "", "  ", " c ", "a"})
	want := []string{"b", "a", "c"}
	if len(got) != len(want) {
		t.Fatalf("dedupe = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("dedupe = %v, want %v", got, want)
		}
	}
}

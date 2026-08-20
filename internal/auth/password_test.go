package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/dilion-io/dilion/ports"
)

func TestHashPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$2a$") {
		t.Errorf("hash = %q, want a bcrypt $2a$ hash", hash)
	}
	if err := ComparePassword(hash, "correct horse battery staple"); err != nil {
		t.Errorf("ComparePassword with the right password: %v", err)
	}
	if err := ComparePassword(hash, "wrong password"); err == nil {
		t.Error("ComparePassword accepted a wrong password")
	}
}

// The cost must stay 10 so hashes remain interchangeable with upstream gotrue.
func TestHashPasswordUsesUpstreamCost(t *testing.T) {
	hash, err := HashPassword("hunter22")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		t.Fatalf("bcrypt.Cost: %v", err)
	}
	if BcryptCost != 10 {
		t.Errorf("BcryptCost = %d, want 10 (gotrue's default)", BcryptCost)
	}
	if cost != BcryptCost {
		t.Errorf("bcrypt cost = %d, want %d", cost, BcryptCost)
	}
}

func TestHashPasswordSaltsEachHash(t *testing.T) {
	a, _ := HashPassword("same-password")
	b, _ := HashPassword("same-password")
	if a == b {
		t.Error("two hashes of the same password are identical: salt is not applied")
	}
}

func TestPasswordLengthLimits(t *testing.T) {
	long := strings.Repeat("a", 73)
	if _, err := HashPassword(long); err != ErrPasswordTooLong {
		t.Errorf("HashPassword(73 bytes) err = %v, want ErrPasswordTooLong", err)
	}
	if err := ComparePassword("$2a$10$abcdefghijklmnopqrstuv", long); err != ErrPasswordTooLong {
		t.Errorf("ComparePassword(73 bytes) err = %v, want ErrPasswordTooLong", err)
	}
	if err := ComparePassword("", "anything"); err == nil {
		t.Error("ComparePassword with an empty hash must fail (passwordless account)")
	}
}

func TestCheckPasswordStrengthDefaults(t *testing.T) {
	a := newSecurityTestAPI(t, DefaultConfig())
	ctx := context.Background()

	if herr := a.checkPasswordStrength(ctx, "short"); herr == nil {
		t.Error("expected a 5-character password to be rejected")
	} else if herr.HTTPStatus != http.StatusUnprocessableEntity || herr.ErrorCode != ErrorCodeWeakPassword {
		t.Errorf("got %d/%s, want 422/%s", herr.HTTPStatus, herr.ErrorCode, ErrorCodeWeakPassword)
	}
	if herr := a.checkPasswordStrength(ctx, "123456"); herr != nil {
		t.Errorf("6 characters is the upstream minimum, got %v", herr)
	}
	if herr := a.checkPasswordStrength(ctx, strings.Repeat("x", 73)); herr == nil {
		t.Error("expected a >72 byte password to be rejected")
	}
}

// Refresh tokens must match upstream's legacy shape `^[a-z0-9]{12}$`, which
// gotrue-js and the Supabase CLI validate client-side.
func TestNewRefreshTokenShape(t *testing.T) {
	re := regexp.MustCompile(`^[a-z0-9]{12}$`)
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		tok, err := newRefreshToken()
		if err != nil {
			t.Fatalf("newRefreshToken: %v", err)
		}
		if !re.MatchString(tok) {
			t.Fatalf("refresh token %q does not match ^[a-z0-9]{12}$", tok)
		}
		if seen[tok] {
			t.Fatalf("duplicate refresh token generated: %q", tok)
		}
		seen[tok] = true
	}
}

func TestObfuscateMatchesUpstreamShape(t *testing.T) {
	const id = "0d3f6b2a-1111-4222-8333-444455556666"

	e1 := obfuscateEmail(id, "user@example.com")
	e2 := obfuscateEmail(id, "user@example.com")
	if e1 != e2 {
		t.Error("obfuscateEmail must be deterministic")
	}
	if e1 == "user@example.com" || strings.Contains(e1, "@") {
		t.Errorf("obfuscated email %q still looks like an address", e1)
	}
	if other := obfuscateEmail("11111111-2222-4333-8444-555555555555", "user@example.com"); other == e1 {
		t.Error("obfuscation must be scoped to the user id")
	}

	// Upstream truncates the phone digest to 15 chars (legacy VARCHAR(15)).
	if got := obfuscatePhone(id, "+821012345678"); len(got) != 15 {
		t.Errorf("obfuscatePhone length = %d, want 15", len(got))
	}
}

// The error body must be gotrue's {"code":..,"error_code":..,"msg":..}.
func TestHTTPErrorJSONShape(t *testing.T) {
	b, err := json.Marshal(badRequestError(ErrorCodeValidationFailed, "Signup requires a valid password"))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"code":400,"error_code":"validation_failed","msg":"Signup requires a valid password"}`
	if string(b) != want {
		t.Errorf("error body =\n  %s\nwant\n  %s", b, want)
	}

	// error_code is omitted when empty; msg never is.
	b, _ = json.Marshal(&HTTPError{HTTPStatus: 500, Message: "boom"})
	if string(b) != `{"code":500,"msg":"boom"}` {
		t.Errorf("error body = %s", b)
	}
}

func TestHealthEndpoint(t *testing.T) {
	r := chi.NewRouter()
	// Pool is nil on purpose: /health must not touch the database.
	Register(r, Deps{Tokens: NewTokenServiceHS(testSecret())})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body HealthCheckResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Name != "GoTrue" {
		t.Errorf("name = %q, want GoTrue (clients match on this string)", body.Name)
	}
	if body.Description == "" || body.Version == "" {
		t.Errorf("health body incomplete: %+v", body)
	}
}

// HS256 keys are symmetric, so the published key set must be empty — and must
// never contain the signing secret.
func TestJWKSIsEmptyAndLeaksNothing(t *testing.T) {
	r := chi.NewRouter()
	Register(r, Deps{Tokens: NewTokenServiceHS(testSecret())})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != `{"keys":[]}` {
		t.Errorf("body = %s, want {\"keys\":[]}", got)
	}
	if strings.Contains(rec.Body.String(), string(testSecret())) {
		t.Fatal("the signing secret leaked into the JWKS response")
	}
}

func TestUnauthenticatedRequestsAreRejected(t *testing.T) {
	r := chi.NewRouter()
	Register(r, Deps{Tokens: NewTokenServiceHS(testSecret())})

	for _, tc := range []struct {
		method, path string
		wantStatus   int
		wantCode     string
	}{
		{http.MethodGet, "/user", http.StatusUnauthorized, ErrorCodeNoAuthorization},
		{http.MethodPost, "/logout", http.StatusUnauthorized, ErrorCodeNoAuthorization},
		{http.MethodGet, "/admin/users", http.StatusUnauthorized, ErrorCodeNoAuthorization},
	} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))

		if rec.Code != tc.wantStatus {
			t.Errorf("%s %s status = %d, want %d", tc.method, tc.path, rec.Code, tc.wantStatus)
		}
		var body HTTPError
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s %s: unmarshal %q: %v", tc.method, tc.path, rec.Body.String(), err)
		}
		if body.ErrorCode != tc.wantCode {
			t.Errorf("%s %s error_code = %q, want %q", tc.method, tc.path, body.ErrorCode, tc.wantCode)
		}
	}
}

// A user (authenticated) token must not reach the admin surface, and the
// rejection must be gotrue's 403 not_admin.
func TestAdminRequiresServiceRole(t *testing.T) {
	ts := NewTokenServiceHS(testSecret())
	r := chi.NewRouter()
	Register(r, Deps{Tokens: ts})

	token, err := ts.Sign(context.Background(), ports.Claims{
		Subject: "0d3f6b2a-1111-4222-8333-444455556666",
		Role:    RoleAuthenticated,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	var body HTTPError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.ErrorCode != ErrorCodeNotAdmin || body.Message != "User not allowed" {
		t.Errorf("body = %+v, want error_code=not_admin msg=\"User not allowed\"", body)
	}
}

package auth

// Database-backed tests for the MFA (TOTP) surface and for the real aal/amr
// claims it produces. They run only with DILION_TEST_DB set, like every other
// *_db_test.go in this package.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"

	"github.com/dilion-io/dilion/internal/hooks"
	"github.com/dilion-io/dilion/ports"
)

// ---- harness ---------------------------------------------------------------

type mfaEnv struct {
	*testEnv
	clock *stepClock
}

// newMFAEnv builds a /auth/v1 mount on a STUBBED clock. The clock matters
// twice here: TOTP codes are generated against it, and it lets a test step past
// the challenge expiry without sleeping.
func newMFAEnv(t *testing.T, cfg *Config) *mfaEnv {
	t.Helper()

	dsn := os.Getenv("DILION_TEST_DB")
	if dsn == "" {
		t.Skip("DILION_TEST_DB not set; skipping database-backed tests")
	}
	if !strings.HasPrefix(dsn, "postgres") {
		dsn = defaultTestDSN
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect %s: %v", dsn, err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping %s: %v", dsn, err)
	}

	applySchema(t, pool)
	applyMFASchema(t, pool)
	truncateAll(t, pool)

	env := &mfaEnv{
		testEnv: &testEnv{
			pool:   pool,
			tokens: NewTokenServiceHS(testSecret()),
			hooks:  hooks.NewRegistry(),
			mailer: &captureMailer{},
		},
		// Truncated to the second so a TOTP step boundary is never straddled
		// mid-test by sub-second drift.
		clock: &stepClock{t: time.Now().UTC().Truncate(time.Second)},
	}
	env.router = chi.NewRouter()
	Register(env.router, Deps{
		Pool:   pool,
		Tokens: env.tokens,
		Mailer: env.mailer,
		Hooks:  env.hooks,
		Config: cfg,
		Clock:  env.clock,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return env
}

// applyMFASchema installs migration 0112, which the shared harness (0100 only)
// does not apply.
func applyMFASchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if !firstApply("applyMFASchema") {
		return
	}
	path := filepath.Join("..", "..", "migrations", "0112_auth_mfa.sql")
	sql, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read 0112_auth_mfa.sql: %v", err)
	}
	if _, err := pool.Exec(context.Background(), string(sql)); err != nil {
		t.Fatalf("apply 0112_auth_mfa.sql: %v", err)
	}
}

// ---- claim helpers ---------------------------------------------------------

func (e *mfaEnv) claims(t *testing.T, token string) *ports.Claims {
	t.Helper()
	c, err := e.tokens.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	return c
}

func (e *mfaEnv) aal(t *testing.T, token string) string {
	t.Helper()
	aal, _ := e.claims(t, token).Extra["aal"].(string)
	return aal
}

// amrMethods returns the `amr` claim's methods in wire order.
func (e *mfaEnv) amrMethods(t *testing.T, token string) []string {
	t.Helper()
	raw, _ := e.claims(t, token).Extra["amr"].([]any)
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		m, _ := entry.(map[string]any)
		method, _ := m["method"].(string)
		out = append(out, method)
	}
	return out
}

func equalMethods(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---- flow helpers ----------------------------------------------------------

func (e *mfaEnv) signupUser(t *testing.T, email string) AccessTokenResponse {
	t.Helper()
	rec := e.do(t, http.MethodPost, "/signup",
		map[string]any{"email": email, "password": "correct-horse-battery"}, "")
	return decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
}

func (e *mfaEnv) enroll(t *testing.T, token, name string) EnrollFactorResponse {
	t.Helper()
	rec := e.do(t, http.MethodPost, "/factors",
		map[string]any{"factor_type": "totp", "friendly_name": name}, token)
	return decodeInto[EnrollFactorResponse](t, rec, http.StatusOK)
}

func (e *mfaEnv) challenge(t *testing.T, token, factorID string) ChallengeFactorResponse {
	t.Helper()
	rec := e.do(t, http.MethodPost, "/factors/"+factorID+"/challenge", map[string]any{}, token)
	return decodeInto[ChallengeFactorResponse](t, rec, http.StatusOK)
}

func (e *mfaEnv) totpCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, e.clock.Now())
	if err != nil {
		t.Fatalf("generate totp code: %v", err)
	}
	return code
}

func (e *mfaEnv) refresh(t *testing.T, refreshToken string) AccessTokenResponse {
	t.Helper()
	rec := e.do(t, http.MethodPost, "/token?grant_type=refresh_token",
		map[string]any{"refresh_token": refreshToken}, "")
	return decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
}

// errorBody decodes a gotrue error envelope.
type errorBody struct {
	Code      int    `json:"code"`
	ErrorCode string `json:"error_code"`
	Msg       string `json:"msg"`
}

// ---- tests -----------------------------------------------------------------

// TestMFAEnrollChallengeVerifyProducesAAL2 is the whole happy path, plus the
// aal/amr assertions that are the point of the feature.
func TestMFAEnrollChallengeVerifyProducesAAL2(t *testing.T) {
	env := newMFAEnv(t, nil)

	session := env.signupUser(t, "mfa-happy@dilion.test")

	// A fresh password session is aal1 and carries exactly one amr entry.
	if got := env.aal(t, session.Token); got != AAL1 {
		t.Fatalf("signup aal = %q, want aal1", got)
	}
	if got := env.amrMethods(t, session.Token); !equalMethods(got, []string{AMRMethodPassword}) {
		t.Fatalf("signup amr = %v, want [password]", got)
	}

	enrolled := env.enroll(t, session.Token, "Authenticator")
	if enrolled.Type != FactorTypeTOTP || enrolled.TOTP == nil {
		t.Fatalf("enroll response = %+v", enrolled)
	}
	if enrolled.TOTP.Secret == "" {
		t.Fatal("enroll returned no TOTP secret")
	}
	if !strings.HasPrefix(enrolled.TOTP.URI, "otpauth://totp/") {
		t.Fatalf("otpauth uri = %q", enrolled.TOTP.URI)
	}
	if !strings.HasPrefix(enrolled.TOTP.QRCode, `<?xml version="1.0"?>`) ||
		!strings.Contains(enrolled.TOTP.QRCode, "<rect ") {
		t.Fatalf("qr_code is not an SVG document: %.60q", enrolled.TOTP.QRCode)
	}

	ch := env.challenge(t, session.Token, enrolled.ID)
	if want := env.clock.Now().Add(mfaChallengeExpiryDuration).Unix(); ch.ExpiresAt != want {
		t.Fatalf("expires_at = %d, want %d", ch.ExpiresAt, want)
	}

	// Step the clock so the totp AMR claim is strictly newer than the password
	// one and the `amr` ordering (most recent first) is unambiguous.
	env.clock.advance(2 * time.Second)

	rec := env.do(t, http.MethodPost, "/factors/"+enrolled.ID+"/verify",
		map[string]any{"challenge_id": ch.ID, "code": env.totpCode(t, enrolled.TOTP.Secret)}, session.Token)
	upgraded := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	if got := env.aal(t, upgraded.Token); got != AAL2 {
		t.Fatalf("post-verify aal = %q, want aal2", got)
	}
	if got := env.amrMethods(t, upgraded.Token); !equalMethods(got, []string{AMRMethodTOTP, AMRMethodPassword}) {
		t.Fatalf("post-verify amr = %v, want [totp password]", got)
	}
	if upgraded.RefreshToken == session.RefreshToken {
		t.Fatal("verify must issue a NEW refresh token")
	}
	if env.claims(t, upgraded.Token).Extra["session_id"] != env.claims(t, session.Token).Extra["session_id"] {
		t.Fatal("verify must upgrade the CURRENT session, not create a new one")
	}

	// The factor is now verified and visible on the user object built by the
	// MFA feature's own loader.
	var status string
	if err := env.pool.QueryRow(context.Background(),
		`select status::text from auth.mfa_factors where id = $1::uuid`, enrolled.ID).Scan(&status); err != nil {
		t.Fatalf("read factor: %v", err)
	}
	if status != FactorStateVerified {
		t.Fatalf("factor status = %q, want verified", status)
	}

	// ---- a refresh preserves aal2 and the amr chain --------------------
	env.clock.advance(time.Second)
	refreshed := env.refresh(t, upgraded.RefreshToken)
	if got := env.aal(t, refreshed.Token); got != AAL2 {
		t.Fatalf("refreshed aal = %q, want aal2", got)
	}
	if got := env.amrMethods(t, refreshed.Token); !equalMethods(got, []string{AMRMethodTOTP, AMRMethodPassword}) {
		t.Fatalf("refreshed amr = %v, want [totp password]", got)
	}

	// ---- unenrolling drops the session back to aal1 on the NEXT refresh --
	del := env.do(t, http.MethodDelete, "/factors/"+enrolled.ID, nil, refreshed.Token)
	unenrolled := decodeInto[UnenrollFactorResponse](t, del, http.StatusOK)
	if unenrolled.ID != enrolled.ID {
		t.Fatalf("unenroll id = %q, want %q", unenrolled.ID, enrolled.ID)
	}

	env.clock.advance(time.Second)
	after := env.refresh(t, refreshed.RefreshToken)
	if got := env.aal(t, after.Token); got != AAL1 {
		t.Fatalf("post-unenroll aal = %q, want aal1", got)
	}
	if got := env.amrMethods(t, after.Token); !equalMethods(got, []string{AMRMethodPassword}) {
		t.Fatalf("post-unenroll amr = %v, want [password]", got)
	}
}

// TestMFAVerifyRejectsBadCodeAndExpiredChallenge covers the two failure modes a
// client can hit with a legitimate challenge in hand.
func TestMFAVerifyRejectsBadCodeAndExpiredChallenge(t *testing.T) {
	env := newMFAEnv(t, nil)
	session := env.signupUser(t, "mfa-bad@dilion.test")
	f := env.enroll(t, session.Token, "Authenticator")

	ch := env.challenge(t, session.Token, f.ID)

	rec := env.do(t, http.MethodPost, "/factors/"+f.ID+"/verify",
		map[string]any{"challenge_id": ch.ID, "code": "000000"}, session.Token)
	body := decodeInto[errorBody](t, rec, http.StatusUnprocessableEntity)
	if body.ErrorCode != ErrorCodeMFAVerificationFailed {
		t.Fatalf("error_code = %q, want %q", body.ErrorCode, ErrorCodeMFAVerificationFailed)
	}

	// Missing code is a plain validation failure, before any lookup.
	rec = env.do(t, http.MethodPost, "/factors/"+f.ID+"/verify",
		map[string]any{"challenge_id": ch.ID}, session.Token)
	if body = decodeInto[errorBody](t, rec, http.StatusBadRequest); body.ErrorCode != ErrorCodeValidationFailed {
		t.Fatalf("empty-code error_code = %q", body.ErrorCode)
	}

	// Past the expiry the challenge is destroyed and reported as expired.
	env.clock.advance(mfaChallengeExpiryDuration + time.Second)
	rec = env.do(t, http.MethodPost, "/factors/"+f.ID+"/verify",
		map[string]any{"challenge_id": ch.ID, "code": env.totpCode(t, f.TOTP.Secret)}, session.Token)
	body = decodeInto[errorBody](t, rec, http.StatusUnprocessableEntity)
	if body.ErrorCode != ErrorCodeMFAChallengeExpired {
		t.Fatalf("error_code = %q, want %q", body.ErrorCode, ErrorCodeMFAChallengeExpired)
	}

	var n int
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from auth.mfa_challenges where id = $1::uuid`, ch.ID).Scan(&n); err != nil {
		t.Fatalf("count challenges: %v", err)
	}
	if n != 0 {
		t.Fatal("an expired challenge must be deleted")
	}
}

// TestMFAFactorIsolatedPerUser: another user's factor must be indistinguishable
// from one that does not exist.
func TestMFAFactorIsolatedPerUser(t *testing.T) {
	env := newMFAEnv(t, nil)

	alice := env.signupUser(t, "mfa-alice@dilion.test")
	bob := env.signupUser(t, "mfa-bob@dilion.test")
	f := env.enroll(t, alice.Token, "Alice phone")

	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/factors/" + f.ID + "/challenge", map[string]any{}},
		{http.MethodPost, "/factors/" + f.ID + "/verify", map[string]any{"challenge_id": f.ID, "code": "123456"}},
		{http.MethodDelete, "/factors/" + f.ID, nil},
	} {
		rec := env.do(t, tc.method, tc.path, tc.body, bob.Token)
		body := decodeInto[errorBody](t, rec, http.StatusNotFound)
		if body.ErrorCode != ErrorCodeMFAFactorNotFound {
			t.Fatalf("%s %s error_code = %q, want %q", tc.method, tc.path, body.ErrorCode, ErrorCodeMFAFactorNotFound)
		}
	}

	// An unknown id answers identically.
	rec := env.do(t, http.MethodDelete, "/factors/00000000-0000-4000-8000-0000000000ff", nil, bob.Token)
	if body := decodeInto[errorBody](t, rec, http.StatusNotFound); body.ErrorCode != ErrorCodeMFAFactorNotFound {
		t.Fatalf("unknown factor error_code = %q", body.ErrorCode)
	}
}

// TestMFAEnrollLimitsAndGates covers MaxEnrolledFactors, the friendly-name
// conflict and the enroll/verify feature switches.
func TestMFAEnrollLimitsAndGates(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MFA.MaxEnrolledFactors = 1
	env := newMFAEnv(t, cfg)

	session := env.signupUser(t, "mfa-limits@dilion.test")
	env.enroll(t, session.Token, "First")

	rec := env.do(t, http.MethodPost, "/factors",
		map[string]any{"factor_type": "totp", "friendly_name": "Second"}, session.Token)
	if body := decodeInto[errorBody](t, rec, http.StatusUnprocessableEntity); body.ErrorCode != ErrorCodeTooManyEnrolledMFAFactors {
		t.Fatalf("error_code = %q, want %q", body.ErrorCode, ErrorCodeTooManyEnrolledMFAFactors)
	}

	// Same friendly name -> conflict (checked before the budget).
	rec = env.do(t, http.MethodPost, "/factors",
		map[string]any{"factor_type": "totp", "friendly_name": "First"}, session.Token)
	if body := decodeInto[errorBody](t, rec, http.StatusUnprocessableEntity); body.ErrorCode != ErrorCodeMFAFactorNameConflict {
		t.Fatalf("error_code = %q, want %q", body.ErrorCode, ErrorCodeMFAFactorNameConflict)
	}

	// Unknown factor types are a validation failure; phone/webauthn report the
	// "not enabled" codes upstream uses for a default deployment.
	rec = env.do(t, http.MethodPost, "/factors", map[string]any{"factor_type": "carrier-pigeon"}, session.Token)
	if body := decodeInto[errorBody](t, rec, http.StatusBadRequest); body.ErrorCode != ErrorCodeValidationFailed {
		t.Fatalf("error_code = %q", body.ErrorCode)
	}
	rec = env.do(t, http.MethodPost, "/factors", map[string]any{"factor_type": "phone", "phone": "+15551234567"}, session.Token)
	if body := decodeInto[errorBody](t, rec, http.StatusUnprocessableEntity); body.ErrorCode != ErrorCodeMFAPhoneEnrollDisabled {
		t.Fatalf("error_code = %q", body.ErrorCode)
	}
}

func TestMFAEnrollDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MFA.TOTP.EnrollEnabled = false
	env := newMFAEnv(t, cfg)

	session := env.signupUser(t, "mfa-off@dilion.test")
	rec := env.do(t, http.MethodPost, "/factors",
		map[string]any{"factor_type": "totp", "friendly_name": "Nope"}, session.Token)
	if body := decodeInto[errorBody](t, rec, http.StatusUnprocessableEntity); body.ErrorCode != ErrorCodeMFATOTPEnrollDisabled {
		t.Fatalf("error_code = %q, want %q", body.ErrorCode, ErrorCodeMFATOTPEnrollDisabled)
	}
}

// TestMFAUnenrollVerifiedFactorRequiresAAL2 is upstream's rule: an aal1 session
// may drop an unverified factor, never a verified one.
func TestMFAUnenrollVerifiedFactorRequiresAAL2(t *testing.T) {
	env := newMFAEnv(t, nil)
	session := env.signupUser(t, "mfa-aal@dilion.test")
	f := env.enroll(t, session.Token, "Authenticator")

	// Unverified: an aal1 session may remove it.
	if rec := env.do(t, http.MethodDelete, "/factors/"+f.ID, nil, session.Token); rec.Code != http.StatusOK {
		t.Fatalf("unenroll unverified factor: status %d, body %s", rec.Code, rec.Body.String())
	}

	// Verify a second factor, then try to unenroll it from a NEW aal1 session.
	f2 := env.enroll(t, session.Token, "Authenticator 2")
	ch := env.challenge(t, session.Token, f2.ID)
	env.clock.advance(2 * time.Second)
	rec := env.do(t, http.MethodPost, "/factors/"+f2.ID+"/verify",
		map[string]any{"challenge_id": ch.ID, "code": env.totpCode(t, f2.TOTP.Secret)}, session.Token)
	decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	// A brand new password sign-in is aal1 and must be refused.
	env.clock.advance(time.Second)
	fresh := decodeInto[AccessTokenResponse](t, env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"email": "mfa-aal@dilion.test", "password": "correct-horse-battery"}, ""), http.StatusOK)
	if got := env.aal(t, fresh.Token); got != AAL1 {
		t.Fatalf("new password session aal = %q, want aal1", got)
	}
	rec = env.do(t, http.MethodDelete, "/factors/"+f2.ID, nil, fresh.Token)
	if body := decodeInto[errorBody](t, rec, http.StatusUnprocessableEntity); body.ErrorCode != ErrorCodeInsufficientAAL {
		t.Fatalf("error_code = %q, want %q", body.ErrorCode, ErrorCodeInsufficientAAL)
	}

	// ...and so must enrolling another factor from that aal1 session.
	rec = env.do(t, http.MethodPost, "/factors",
		map[string]any{"factor_type": "totp", "friendly_name": "Third"}, fresh.Token)
	if body := decodeInto[errorBody](t, rec, http.StatusForbidden); body.ErrorCode != ErrorCodeInsufficientAAL {
		t.Fatalf("enroll error_code = %q, want %q", body.ErrorCode, ErrorCodeInsufficientAAL)
	}
}

// TestMFAChallengeSharesFrozenClock pins the migration's global-unique
// `last_challenged_at` oddity: two factors challenged on the very same
// microsecond must both succeed.
func TestMFAChallengeSharesFrozenClock(t *testing.T) {
	env := newMFAEnv(t, nil)

	alice := env.signupUser(t, "mfa-clock-a@dilion.test")
	bob := env.signupUser(t, "mfa-clock-b@dilion.test")
	fa := env.enroll(t, alice.Token, "A")
	fb := env.enroll(t, bob.Token, "B")

	// The clock never moves between these two calls.
	env.challenge(t, alice.Token, fa.ID)
	env.challenge(t, bob.Token, fb.ID)

	var a, b time.Time
	if err := env.pool.QueryRow(context.Background(),
		`select last_challenged_at from auth.mfa_factors where id = $1::uuid`, fa.ID).Scan(&a); err != nil {
		t.Fatalf("read A: %v", err)
	}
	if err := env.pool.QueryRow(context.Background(),
		`select last_challenged_at from auth.mfa_factors where id = $1::uuid`, fb.ID).Scan(&b); err != nil {
		t.Fatalf("read B: %v", err)
	}
	if a.Equal(b) {
		t.Fatal("the global unique on last_challenged_at should have forced distinct timestamps")
	}
}

// TestAdminFactorSurface covers the three /admin/users/{id}/factors endpoints.
func TestAdminFactorSurface(t *testing.T) {
	env := newMFAEnv(t, nil)
	admin := env.serviceRoleToken(t)

	session := env.signupUser(t, "mfa-admin@dilion.test")
	userID := env.claims(t, session.Token).Subject
	f := env.enroll(t, session.Token, "Original")

	// Verify it so the delete below exercises the AAL downgrade path too.
	ch := env.challenge(t, session.Token, f.ID)
	env.clock.advance(2 * time.Second)
	upgraded := decodeInto[AccessTokenResponse](t, env.do(t, http.MethodPost, "/factors/"+f.ID+"/verify",
		map[string]any{"challenge_id": ch.ID, "code": env.totpCode(t, f.TOTP.Secret)}, session.Token), http.StatusOK)

	list := decodeInto[[]Factor](t, env.do(t, http.MethodGet, "/admin/users/"+userID+"/factors", nil, admin), http.StatusOK)
	if len(list) != 1 || list[0].ID != f.ID || list[0].Status != FactorStateVerified {
		t.Fatalf("admin factor list = %+v", list)
	}
	if list[0].FriendlyName != "Original" {
		t.Fatalf("friendly_name = %q", list[0].FriendlyName)
	}

	updated := decodeInto[Factor](t, env.do(t, http.MethodPut, "/admin/users/"+userID+"/factors/"+f.ID,
		map[string]any{"friendly_name": "Renamed"}, admin), http.StatusOK)
	if updated.FriendlyName != "Renamed" {
		t.Fatalf("renamed friendly_name = %q", updated.FriendlyName)
	}

	// A non-admin caller is refused.
	if rec := env.do(t, http.MethodGet, "/admin/users/"+userID+"/factors", nil, session.Token); rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin status = %d", rec.Code)
	}

	deleted := decodeInto[Factor](t, env.do(t, http.MethodDelete, "/admin/users/"+userID+"/factors/"+f.ID, nil, admin), http.StatusOK)
	if deleted.ID != f.ID {
		t.Fatalf("deleted factor = %+v", deleted)
	}

	// The user's session falls back to aal1 on its next refresh.
	env.clock.advance(time.Second)
	after := env.refresh(t, upgraded.RefreshToken)
	if got := env.aal(t, after.Token); got != AAL1 {
		t.Fatalf("post admin-delete aal = %q, want aal1", got)
	}

	list = decodeInto[[]Factor](t, env.do(t, http.MethodGet, "/admin/users/"+userID+"/factors", nil, admin), http.StatusOK)
	if len(list) != 0 {
		t.Fatalf("admin factor list after delete = %+v", list)
	}
}

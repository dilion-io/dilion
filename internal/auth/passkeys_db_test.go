package auth

// Database-backed tests for the passkey (WebAuthn) surface. They run only with
// DILION_TEST_DB set, like every other *_db_test.go in this package:
//
//	docker exec dilion-db createdb -U dilion dilion_test_pk
//	DILION_TEST_DB=postgres://dilion:dilion@localhost:55432/dilion_test_pk \
//	  go test -run 'Passkey|WebAuthn' -race ./internal/auth/...
//
// The ceremonies are driven end to end by the software authenticator in
// passkey_authenticator_test.go: real P-256 signatures over the real challenge,
// verified by go-webauthn. Nothing is mocked below the HTTP boundary.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/internal/hooks"
)

// ---- harness ---------------------------------------------------------------

const (
	testRPID    = "example.test"
	testRPOrgin = "https://example.test"
)

type passkeyEnv struct {
	*testEnv
	clock *stepClock
}

// passkeyTestConfig is the configuration every passkey test starts from:
// the feature on, with an EXPLICIT relying party (so the tests also prove the
// configured RPID/RPOrigins are the ones actually used, not the SiteURL
// fallback).
func passkeyTestConfig() *Config {
	c := DefaultConfig()
	c.Passkeys.Enabled = true
	c.Passkeys.RPID = testRPID
	c.Passkeys.RPOrigins = []string{testRPOrgin}
	return c
}

func newPasskeyEnv(t *testing.T, cfg *Config) *passkeyEnv {
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
	applyWebAuthnSchema(t, pool)
	truncateAll(t, pool)

	if cfg == nil {
		cfg = passkeyTestConfig()
	}
	env := &passkeyEnv{
		testEnv: &testEnv{
			pool:   pool,
			tokens: NewTokenServiceHS(testSecret()),
			hooks:  hooks.NewRegistry(),
			mailer: &captureMailer{},
		},
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

// applyWebAuthnSchema installs migration 0115, which neither the shared harness
// (0100) nor the MFA harness (0112) applies.
func applyWebAuthnSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if !firstApply("applyWebAuthnSchema") {
		return
	}
	path := filepath.Join("..", "..", "migrations", "0115_auth_webauthn.sql")
	sql, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read 0115_auth_webauthn.sql: %v", err)
	}
	if _, err := pool.Exec(context.Background(), string(sql)); err != nil {
		t.Fatalf("apply 0115_auth_webauthn.sql: %v", err)
	}
}

// ---- ceremony helpers ------------------------------------------------------

// registerPasskey drives a whole registration ceremony and returns the created
// passkey's metadata.
func (e *passkeyEnv) registerPasskey(t *testing.T, token string, va *virtualAuthenticator) PasskeyMetadataResponse {
	t.Helper()
	options := e.registrationOptions(t, token)
	credential := va.createCredential(t, options.Options)
	rec := e.do(t, http.MethodPost, "/passkeys/registration/verify", map[string]any{
		"challenge_id": options.ChallengeID,
		"credential":   credential,
	}, token)
	return decodeInto[PasskeyMetadataResponse](t, rec, http.StatusOK)
}

func (e *passkeyEnv) registrationOptions(t *testing.T, token string) PasskeyRegistrationOptionsResponse {
	t.Helper()
	rec := e.do(t, http.MethodPost, "/passkeys/registration/options", map[string]any{}, token)
	return decodeInto[PasskeyRegistrationOptionsResponse](t, rec, http.StatusOK)
}

func (e *passkeyEnv) authenticationOptions(t *testing.T) PasskeyAuthenticationOptionsResponse {
	t.Helper()
	rec := e.do(t, http.MethodPost, "/passkeys/authentication/options", map[string]any{}, "")
	return decodeInto[PasskeyAuthenticationOptionsResponse](t, rec, http.StatusOK)
}

// signInWithPasskey drives a whole login ceremony and returns the raw recorder,
// so a test can assert on failures as easily as on the session.
func (e *passkeyEnv) signInWithPasskey(t *testing.T, va *virtualAuthenticator, signCount uint32) *httptest.ResponseRecorder {
	t.Helper()
	options := e.authenticationOptions(t)
	assertion := va.getAssertion(t, options.Options, signCount)
	return e.do(t, http.MethodPost, "/passkeys/authentication/verify", map[string]any{
		"challenge_id": options.ChallengeID,
		"credential":   assertion,
	}, "")
}

// assertAuthError checks the gotrue error envelope: the HTTP status, the
// mirrored `code` field and the `error_code`. All three are compatibility
// contract, so all three are asserted.
func assertAuthError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, status, rec.Body.String())
	}
	var body errorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal error body %q: %v", rec.Body.String(), err)
	}
	if body.ErrorCode != code {
		t.Fatalf("error_code = %q, want %q; body = %s", body.ErrorCode, code, rec.Body.String())
	}
	if body.Code != status {
		t.Errorf("body code = %d, want %d", body.Code, status)
	}
}

// amrMethodsOf reads the `amr` claim's methods in wire order.
func amrMethodsOf(t *testing.T, extra map[string]any) []string {
	t.Helper()
	raw, _ := extra["amr"].([]any)
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		m, _ := entry.(map[string]any)
		method, _ := m["method"].(string)
		out = append(out, method)
	}
	return out
}

// ---- DB probes -------------------------------------------------------------

type storedPasskeyRow struct {
	signCount    int64
	lastUsedAt   *time.Time
	friendlyName string
	aaguid       *string
	transports   string
	backupEli    bool
	backedUp     bool
}

func (e *passkeyEnv) passkeyRow(t *testing.T, id string) storedPasskeyRow {
	t.Helper()
	var row storedPasskeyRow
	err := e.pool.QueryRow(context.Background(), `
		select sign_count, last_used_at, friendly_name, aaguid::text, transports::text,
		       backup_eligible, backed_up
		  from auth.webauthn_credentials where id = $1::uuid`, id).
		Scan(&row.signCount, &row.lastUsedAt, &row.friendlyName, &row.aaguid, &row.transports,
			&row.backupEli, &row.backedUp)
	if err != nil {
		t.Fatalf("load passkey row %s: %v", id, err)
	}
	return row
}

func (e *passkeyEnv) countChallenges(t *testing.T) int {
	t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(),
		`select count(*) from auth.webauthn_challenges`).Scan(&n); err != nil {
		t.Fatalf("count challenges: %v", err)
	}
	return n
}

// ---- tests: happy path -----------------------------------------------------

// TestPasskeyRegistrationAndAuthenticationRoundTrip is the whole feature: a
// signed-in user adds a passkey, then signs in with it from a fresh,
// unauthenticated client.
func TestPasskeyRegistrationAndAuthenticationRoundTrip(t *testing.T) {
	env := newPasskeyEnv(t, nil)
	session := env.signup(t, "passkey-happy@dilion.test", "correct-horse-battery")

	va := newVirtualAuthenticator(testRPID, testRPOrgin).
		withAAGUID(t, "fbfc3007-154e-4ecc-8c0b-6e020557d7bd") // Apple Passwords

	created := env.registerPasskey(t, session.Token, va)
	if created.ID == "" {
		t.Fatal("registration returned no passkey id")
	}
	if created.FriendlyName != "Apple Passwords" {
		t.Errorf("friendly_name = %q, want %q (derived from the AAGUID)", created.FriendlyName, "Apple Passwords")
	}

	// Everything the credential row must carry after registration.
	row := env.passkeyRow(t, created.ID)
	if row.signCount != 0 {
		t.Errorf("sign_count after registration = %d, want 0", row.signCount)
	}
	if row.lastUsedAt != nil {
		t.Errorf("last_used_at after registration = %v, want NULL", row.lastUsedAt)
	}
	if row.aaguid == nil || *row.aaguid != "fbfc3007-154e-4ecc-8c0b-6e020557d7bd" {
		t.Errorf("aaguid = %v, want the authenticator's", row.aaguid)
	}
	if !strings.Contains(row.transports, "internal") {
		t.Errorf("transports = %s, want the authenticator's [\"internal\"]", row.transports)
	}
	if row.backupEli || row.backedUp {
		t.Errorf("backup flags = (%v, %v), want (false, false) for this authenticator", row.backupEli, row.backedUp)
	}

	// The challenge row is gone: consumed by the verify.
	if n := env.countChallenges(t); n != 0 {
		t.Errorf("webauthn_challenges holds %d rows after verify, want 0 (single-use)", n)
	}

	// ---- sign in with the passkey, no bearer token at all ----
	rec := env.signInWithPasskey(t, va, 1)
	got := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if got.User == nil || got.User.ID != session.User.ID {
		t.Fatalf("passkey login returned user %v, want %s", got.User, session.User.ID)
	}
	if got.RefreshToken == "" || got.Token == "" {
		t.Fatal("passkey login returned an incomplete session envelope")
	}

	// The session's amr says "passkey", and a passkey is an aal1 method.
	claims, err := env.tokens.Verify(context.Background(), got.Token)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if aal, _ := claims.Extra["aal"].(string); aal != AAL1 {
		t.Errorf("aal = %q, want aal1 (a passkey is a sign-in method, not a second factor)", aal)
	}
	methods := amrMethodsOf(t, claims.Extra)
	if len(methods) != 1 || methods[0] != AMRMethodPasskey {
		t.Errorf("amr = %v, want [passkey]", methods)
	}

	// sign_count and last_used_at moved.
	row = env.passkeyRow(t, created.ID)
	if row.signCount != 1 {
		t.Errorf("sign_count after login = %d, want 1", row.signCount)
	}
	if row.lastUsedAt == nil {
		t.Error("last_used_at after login is NULL, want a timestamp")
	}

	// ...and the list endpoint reports it.
	list := decodeInto[[]PasskeyListItem](t, env.do(t, http.MethodGet, "/passkeys", nil, session.Token), http.StatusOK)
	if len(list) != 1 || list[0].ID != created.ID || list[0].LastUsedAt == nil {
		t.Fatalf("GET /passkeys = %+v, want the one used passkey", list)
	}
}

// ---- tests: rejection paths ------------------------------------------------

// TestPasskeyRegistrationRejectsWrongOrigin proves the origin check is live: a
// credential produced for a different site does not register.
func TestPasskeyRegistrationRejectsWrongOrigin(t *testing.T) {
	env := newPasskeyEnv(t, nil)
	session := env.signup(t, "passkey-origin@dilion.test", "correct-horse-battery")

	evil := newVirtualAuthenticator(testRPID, "https://evil.test")
	options := env.registrationOptions(t, session.Token)
	credential := evil.createCredential(t, options.Options)

	rec := env.do(t, http.MethodPost, "/passkeys/registration/verify", map[string]any{
		"challenge_id": options.ChallengeID,
		"credential":   credential,
	}, session.Token)
	assertAuthError(t, rec, http.StatusBadRequest, ErrorCodeWebAuthnVerificationFailed)
}

// TestPasskeyRegistrationRejectsWrongRPID proves the RP ID hash is checked: a
// credential scoped to another relying party does not register.
func TestPasskeyRegistrationRejectsWrongRPID(t *testing.T) {
	env := newPasskeyEnv(t, nil)
	session := env.signup(t, "passkey-rpid@dilion.test", "correct-horse-battery")

	evil := newVirtualAuthenticator("evil.test", testRPOrgin)
	options := env.registrationOptions(t, session.Token)
	credential := evil.createCredential(t, options.Options)

	rec := env.do(t, http.MethodPost, "/passkeys/registration/verify", map[string]any{
		"challenge_id": options.ChallengeID,
		"credential":   credential,
	}, session.Token)
	assertAuthError(t, rec, http.StatusBadRequest, ErrorCodeWebAuthnVerificationFailed)
}

// TestPasskeyAuthenticationRejectsWrongOrigin is the same check on the login
// side: a correctly registered credential asserted from another origin fails.
func TestPasskeyAuthenticationRejectsWrongOrigin(t *testing.T) {
	env := newPasskeyEnv(t, nil)
	session := env.signup(t, "passkey-login-origin@dilion.test", "correct-horse-battery")

	va := newVirtualAuthenticator(testRPID, testRPOrgin)
	env.registerPasskey(t, session.Token, va)

	// Same key material, wrong origin in clientDataJSON.
	moved := &virtualAuthenticator{rpID: testRPID, origin: "https://evil.test", creds: va.creds}
	rec := env.signInWithPasskey(t, moved, 1)
	assertAuthError(t, rec, http.StatusBadRequest, ErrorCodeWebAuthnVerificationFailed)
}

// TestPasskeySignCountRegressionIsToleratedAndDoesNotAdvance pins upstream's
// step-17 behaviour: a counter that does not advance sets the library's clone
// warning but does NOT fail the ceremony, and the stored counter stays put.
func TestPasskeySignCountRegressionIsToleratedAndDoesNotAdvance(t *testing.T) {
	env := newPasskeyEnv(t, nil)
	session := env.signup(t, "passkey-counter@dilion.test", "correct-horse-battery")

	va := newVirtualAuthenticator(testRPID, testRPOrgin)
	created := env.registerPasskey(t, session.Token, va)

	// First login advances 0 -> 5.
	decodeInto[AccessTokenResponse](t, env.signInWithPasskey(t, va, 5), http.StatusOK)
	if row := env.passkeyRow(t, created.ID); row.signCount != 5 {
		t.Fatalf("sign_count after first login = %d, want 5", row.signCount)
	}

	// Second login REPLAYS the counter (5 <= 5) — accepted, counter unchanged.
	decodeInto[AccessTokenResponse](t, env.signInWithPasskey(t, va, 5), http.StatusOK)
	if row := env.passkeyRow(t, created.ID); row.signCount != 5 {
		t.Errorf("sign_count after equal counter = %d, want it to stay 5", row.signCount)
	}

	// A regression (2 < 5) behaves the same way.
	decodeInto[AccessTokenResponse](t, env.signInWithPasskey(t, va, 2), http.StatusOK)
	if row := env.passkeyRow(t, created.ID); row.signCount != 5 {
		t.Errorf("sign_count after regressed counter = %d, want it to stay 5", row.signCount)
	}
}

// ---- tests: challenge lifecycle -------------------------------------------

// TestPasskeyChallengeIsSingleUse proves the DELETE ... RETURNING consume: the
// same challenge cannot be redeemed twice.
func TestPasskeyChallengeIsSingleUse(t *testing.T) {
	env := newPasskeyEnv(t, nil)
	session := env.signup(t, "passkey-replay@dilion.test", "correct-horse-battery")

	va := newVirtualAuthenticator(testRPID, testRPOrgin)
	env.registerPasskey(t, session.Token, va)

	options := env.authenticationOptions(t)
	assertion := va.getAssertion(t, options.Options, 1)
	body := map[string]any{"challenge_id": options.ChallengeID, "credential": assertion}

	decodeInto[AccessTokenResponse](t, env.do(t, http.MethodPost, "/passkeys/authentication/verify", body, ""), http.StatusOK)

	rec := env.do(t, http.MethodPost, "/passkeys/authentication/verify", body, "")
	assertAuthError(t, rec, http.StatusBadRequest, ErrorCodeWebAuthnChallengeNotFound)
}

// TestPasskeyChallengeExpires drives the clock past the 5-minute challenge
// expiry between options and verify.
func TestPasskeyChallengeExpires(t *testing.T) {
	env := newPasskeyEnv(t, nil)
	session := env.signup(t, "passkey-expiry@dilion.test", "correct-horse-battery")

	va := newVirtualAuthenticator(testRPID, testRPOrgin)
	options := env.registrationOptions(t, session.Token)
	credential := va.createCredential(t, options.Options)

	env.clock.advance(passkeyChallengeExpiry + time.Second)

	rec := env.do(t, http.MethodPost, "/passkeys/registration/verify", map[string]any{
		"challenge_id": options.ChallengeID,
		"credential":   credential,
	}, session.Token)
	assertAuthError(t, rec, http.StatusBadRequest, ErrorCodeWebAuthnChallengeExpired)
}

// TestPasskeyChallengeIsScopedToItsCeremony proves the challenge_type +
// user_id predicate: a registration challenge cannot be redeemed as a login.
func TestPasskeyChallengeIsScopedToItsCeremony(t *testing.T) {
	env := newPasskeyEnv(t, nil)
	session := env.signup(t, "passkey-scope@dilion.test", "correct-horse-battery")

	va := newVirtualAuthenticator(testRPID, testRPOrgin)
	env.registerPasskey(t, session.Token, va)

	// A fresh REGISTRATION challenge, offered to the authentication endpoint.
	options := env.registrationOptions(t, session.Token)
	authOptions := env.authenticationOptions(t)
	assertion := va.getAssertion(t, authOptions.Options, 1)

	rec := env.do(t, http.MethodPost, "/passkeys/authentication/verify", map[string]any{
		"challenge_id": options.ChallengeID,
		"credential":   assertion,
	}, "")
	assertAuthError(t, rec, http.StatusBadRequest, ErrorCodeWebAuthnChallengeNotFound)
}

// TestPasskeyOptionsPurgeExpiredChallenges covers the cleanup gap this feature
// works around (see the header of passkeys.go): an abandoned ceremony's row is
// dropped by the next options call once it is past its expiry.
func TestPasskeyOptionsPurgeExpiredChallenges(t *testing.T) {
	env := newPasskeyEnv(t, nil)

	env.authenticationOptions(t)
	if n := env.countChallenges(t); n != 1 {
		t.Fatalf("challenge rows = %d, want 1", n)
	}

	env.clock.advance(passkeyChallengeExpiry + time.Minute)
	env.authenticationOptions(t)

	// The abandoned row is gone; only the one just issued remains.
	if n := env.countChallenges(t); n != 1 {
		t.Errorf("challenge rows after purge = %d, want 1 (the fresh one)", n)
	}
}

// ---- tests: registration policy -------------------------------------------

// TestPasskeyRegistrationExcludesExistingCredentials proves the exclusion list
// is built, and that re-registering the same credential is refused.
func TestPasskeyRegistrationExcludesExistingCredentials(t *testing.T) {
	env := newPasskeyEnv(t, nil)
	session := env.signup(t, "passkey-exclude@dilion.test", "correct-horse-battery")

	va := newVirtualAuthenticator(testRPID, testRPOrgin)
	env.registerPasskey(t, session.Token, va)

	options := env.registrationOptions(t, session.Token)
	if len(options.Options.CredentialExcludeList) != 1 {
		t.Fatalf("excludeCredentials = %d entries, want 1", len(options.Options.CredentialExcludeList))
	}
	if string(options.Options.CredentialExcludeList[0].CredentialID) != string(va.creds[0].id) {
		t.Error("excludeCredentials does not name the credential the user already has")
	}

	// A misbehaving authenticator that ignores the exclusion list is refused by
	// the unique index on credential_id.
	options2 := env.registrationOptions(t, session.Token)
	credential := va.recreateCredential(t, va.credential(t, 0), options2.Options)
	rec := env.do(t, http.MethodPost, "/passkeys/registration/verify", map[string]any{
		"challenge_id": options2.ChallengeID,
		"credential":   credential,
	}, session.Token)
	assertAuthError(t, rec, http.StatusUnprocessableEntity, ErrorCodeWebAuthnCredentialExists)
}

// TestPasskeyRegistrationRejectsAnonymousUser pins upstream's requireNotAnonymous.
func TestPasskeyRegistrationRejectsAnonymousUser(t *testing.T) {
	cfg := passkeyTestConfig()
	cfg.AnonymousUsersEnabled = true
	env := newPasskeyEnv(t, cfg)

	rec := env.do(t, http.MethodPost, "/signup", map[string]any{}, "")
	anon := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	rec = env.do(t, http.MethodPost, "/passkeys/registration/options", map[string]any{}, anon.Token)
	assertAuthError(t, rec, http.StatusForbidden, ErrorCodeNoAuthorization)
}

// TestPasskeyRegistrationRejectsSSOUser pins upstream's SSO refusal.
func TestPasskeyRegistrationRejectsSSOUser(t *testing.T) {
	env := newPasskeyEnv(t, nil)
	session := env.signup(t, "passkey-sso@dilion.test", "correct-horse-battery")

	if _, err := env.pool.Exec(context.Background(),
		`update auth.users set is_sso_user = true where id = $1::uuid`, session.User.ID); err != nil {
		t.Fatalf("mark user as SSO: %v", err)
	}

	rec := env.do(t, http.MethodPost, "/passkeys/registration/options", map[string]any{}, session.Token)
	assertAuthError(t, rec, http.StatusUnprocessableEntity, ErrorCodeValidationFailed)
}

// ---- tests: manage surface -------------------------------------------------

func TestPasskeyManageEndpoints(t *testing.T) {
	env := newPasskeyEnv(t, nil)
	alice := env.signup(t, "passkey-alice@dilion.test", "correct-horse-battery")
	bob := env.signup(t, "passkey-bob@dilion.test", "correct-horse-battery")

	va := newVirtualAuthenticator(testRPID, testRPOrgin)
	created := env.registerPasskey(t, alice.Token, va)

	t.Run("empty list is an array", func(t *testing.T) {
		rec := env.do(t, http.MethodGet, "/passkeys", nil, bob.Token)
		if body := strings.TrimSpace(rec.Body.String()); body != "[]" {
			t.Errorf("GET /passkeys for a user without passkeys = %s, want []", body)
		}
	})

	t.Run("rename", func(t *testing.T) {
		rec := env.do(t, http.MethodPatch, "/passkeys/"+created.ID,
			map[string]any{"friendly_name": "Work laptop"}, alice.Token)
		item := decodeInto[PasskeyListItem](t, rec, http.StatusOK)
		if item.FriendlyName != "Work laptop" {
			t.Errorf("friendly_name = %q, want %q", item.FriendlyName, "Work laptop")
		}
		if row := env.passkeyRow(t, created.ID); row.friendlyName != "Work laptop" {
			t.Errorf("stored friendly_name = %q, want %q", row.friendlyName, "Work laptop")
		}
	})

	t.Run("rename requires a name", func(t *testing.T) {
		rec := env.do(t, http.MethodPatch, "/passkeys/"+created.ID,
			map[string]any{"friendly_name": ""}, alice.Token)
		assertAuthError(t, rec, http.StatusBadRequest, ErrorCodeValidationFailed)
	})

	t.Run("rename caps the name length", func(t *testing.T) {
		rec := env.do(t, http.MethodPatch, "/passkeys/"+created.ID,
			map[string]any{"friendly_name": strings.Repeat("x", passkeyFriendlyNameMaxLength+1)}, alice.Token)
		assertAuthError(t, rec, http.StatusBadRequest, ErrorCodeValidationFailed)
	})

	t.Run("another user's passkey is not found", func(t *testing.T) {
		rec := env.do(t, http.MethodPatch, "/passkeys/"+created.ID,
			map[string]any{"friendly_name": "Mine now"}, bob.Token)
		assertAuthError(t, rec, http.StatusNotFound, ErrorCodeValidationFailed)

		rec = env.do(t, http.MethodDelete, "/passkeys/"+created.ID, nil, bob.Token)
		assertAuthError(t, rec, http.StatusNotFound, ErrorCodeValidationFailed)
	})

	t.Run("a malformed id is not found", func(t *testing.T) {
		rec := env.do(t, http.MethodDelete, "/passkeys/not-a-uuid", nil, alice.Token)
		assertAuthError(t, rec, http.StatusNotFound, ErrorCodeValidationFailed)
	})

	t.Run("delete", func(t *testing.T) {
		rec := env.do(t, http.MethodDelete, "/passkeys/"+created.ID, nil, alice.Token)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("DELETE status = %d, want 204; body = %s", rec.Code, rec.Body.String())
		}
		if body := rec.Body.String(); body != "" {
			t.Errorf("DELETE body = %q, want empty", body)
		}
		list := decodeInto[[]PasskeyListItem](t, env.do(t, http.MethodGet, "/passkeys", nil, alice.Token), http.StatusOK)
		if len(list) != 0 {
			t.Errorf("GET /passkeys after delete = %d entries, want 0", len(list))
		}
	})

	t.Run("deleting the last passkey is allowed", func(t *testing.T) {
		// Upstream imposes no last-credential rule; the delete above WAS the
		// last one and it succeeded. Re-deleting is simply not found.
		rec := env.do(t, http.MethodDelete, "/passkeys/"+created.ID, nil, alice.Token)
		assertAuthError(t, rec, http.StatusNotFound, ErrorCodeValidationFailed)
	})

	t.Run("the surface requires authentication", func(t *testing.T) {
		rec := env.do(t, http.MethodGet, "/passkeys", nil, "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("unauthenticated GET /passkeys = %d, want 401", rec.Code)
		}
	})
}

// ---- tests: admin surface --------------------------------------------------

func TestPasskeyAdminSurface(t *testing.T) {
	env := newPasskeyEnv(t, nil)
	user := env.signup(t, "passkey-admin-target@dilion.test", "correct-horse-battery")
	admin := env.serviceRoleToken(t)

	va := newVirtualAuthenticator(testRPID, testRPOrgin)
	created := env.registerPasskey(t, user.Token, va)

	list := decodeInto[[]PasskeyListItem](t,
		env.do(t, http.MethodGet, "/admin/users/"+user.User.ID+"/passkeys", nil, admin), http.StatusOK)
	if len(list) != 1 || list[0].ID != created.ID {
		t.Fatalf("admin list = %+v, want the one passkey", list)
	}

	t.Run("a regular user token is not admin", func(t *testing.T) {
		rec := env.do(t, http.MethodGet, "/admin/users/"+user.User.ID+"/passkeys", nil, user.Token)
		assertAuthError(t, rec, http.StatusForbidden, ErrorCodeNotAdmin)
	})

	t.Run("delete is scoped to the named user", func(t *testing.T) {
		other := env.signup(t, "passkey-admin-other@dilion.test", "correct-horse-battery")
		rec := env.do(t, http.MethodDelete,
			"/admin/users/"+other.User.ID+"/passkeys/"+created.ID, nil, admin)
		assertAuthError(t, rec, http.StatusNotFound, ErrorCodeValidationFailed)
	})

	t.Run("delete", func(t *testing.T) {
		rec := env.do(t, http.MethodDelete,
			"/admin/users/"+user.User.ID+"/passkeys/"+created.ID, nil, admin)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("admin DELETE status = %d, want 204; body = %s", rec.Code, rec.Body.String())
		}
		after := decodeInto[[]PasskeyListItem](t,
			env.do(t, http.MethodGet, "/admin/users/"+user.User.ID+"/passkeys", nil, admin), http.StatusOK)
		if len(after) != 0 {
			t.Errorf("admin list after delete = %d entries, want 0", len(after))
		}
	})
}

// TestPasskeyAdminSurfaceStaysUpWhenFeatureDisabled pins the deliberate
// asymmetry: revocation must keep working after passkeys are switched off.
func TestPasskeyAdminSurfaceStaysUpWhenFeatureDisabled(t *testing.T) {
	cfg := passkeyTestConfig()
	cfg.Passkeys.Enabled = false
	env := newPasskeyEnv(t, cfg)

	user := env.signup(t, "passkey-admin-disabled@dilion.test", "correct-horse-battery")
	admin := env.serviceRoleToken(t)

	rec := env.do(t, http.MethodGet, "/admin/users/"+user.User.ID+"/passkeys", nil, admin)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin list with passkeys disabled = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
}

// ---- tests: feature flag ---------------------------------------------------

// TestPasskeyDisabledAnswers404 pins upstream's requirePasskeyEnabled: 404 with
// passkey_disabled on every user-facing route, NOT 422.
func TestPasskeyDisabledAnswers404(t *testing.T) {
	cfg := passkeyTestConfig()
	cfg.Passkeys.Enabled = false
	env := newPasskeyEnv(t, cfg)
	session := env.signup(t, "passkey-off@dilion.test", "correct-horse-battery")

	cases := []struct {
		method, path string
		token        string
	}{
		{http.MethodPost, "/passkeys/authentication/options", ""},
		{http.MethodPost, "/passkeys/authentication/verify", ""},
		{http.MethodPost, "/passkeys/registration/options", session.Token},
		{http.MethodPost, "/passkeys/registration/verify", session.Token},
		{http.MethodGet, "/passkeys", session.Token},
		{http.MethodPatch, "/passkeys/" + session.User.ID, session.Token},
		{http.MethodDelete, "/passkeys/" + session.User.ID, session.Token},
	}
	for _, c := range cases {
		rec := env.do(t, c.method, c.path, map[string]any{}, c.token)
		assertAuthError(t, rec, http.StatusNotFound, ErrorCodePasskeyDisabled)
	}
}

// ---- tests: parameter validation -------------------------------------------

func TestPasskeyVerifyParameterValidation(t *testing.T) {
	env := newPasskeyEnv(t, nil)
	session := env.signup(t, "passkey-params@dilion.test", "correct-horse-battery")

	cases := []struct {
		name string
		body map[string]any
	}{
		{"missing challenge_id", map[string]any{"credential": json.RawMessage(`{}`)}},
		{"missing credential", map[string]any{"challenge_id": session.User.ID}},
		{"challenge_id is not a uuid", map[string]any{"challenge_id": "nope", "credential": json.RawMessage(`{}`)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := env.do(t, http.MethodPost, "/passkeys/registration/verify", c.body, session.Token)
			assertAuthError(t, rec, http.StatusBadRequest, ErrorCodeValidationFailed)

			rec = env.do(t, http.MethodPost, "/passkeys/authentication/verify", c.body, "")
			assertAuthError(t, rec, http.StatusBadRequest, ErrorCodeValidationFailed)
		})
	}
}

// TestPasskeyAuthenticationRejectsUnknownChallenge covers a challenge_id that is
// a valid UUID but names nothing.
func TestPasskeyAuthenticationRejectsUnknownChallenge(t *testing.T) {
	env := newPasskeyEnv(t, nil)
	session := env.signup(t, "passkey-unknown@dilion.test", "correct-horse-battery")

	rec := env.do(t, http.MethodPost, "/passkeys/authentication/verify", map[string]any{
		"challenge_id": session.User.ID, // a real UUID, not a real challenge
		"credential":   json.RawMessage(`{}`),
	}, "")
	assertAuthError(t, rec, http.StatusBadRequest, ErrorCodeWebAuthnChallengeNotFound)
}

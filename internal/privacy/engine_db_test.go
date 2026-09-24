package privacy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/internal/hooks"
	"github.com/dilion-io/dilion/internal/netguard"
	"github.com/dilion-io/dilion/ports"
)

// Integration tests. They run only with DILION_TEST_DB set:
//
//	docker exec dilion-pg createdb -U dilion dilion_test_c
//	DILION_TEST_DB=1 go test ./internal/privacy/...
//
// DSN override: DILION_TEST_DB_DSN.
// testWebhookSecret is a webhook destination secret of the required length.
const testWebhookSecret = "whsec_0123456789abcdef0123456789abcdef"

const defaultTestDSN = "postgres://dilion:dilion@localhost:55432/dilion_test_c"

// authDDL is a minimal stand-in for agent B's 0100_auth.sql: only the columns
// the erasure pipeline touches. auth.mfa_factors and auth.webauthn_credentials
// are deliberately absent so the "optional table" guard is exercised.
const authDDL = `
create extension if not exists pgcrypto;
create schema if not exists auth;
create table if not exists auth.users (
	id uuid primary key,
	email text,
	phone text,
	encrypted_password varchar(255),
	raw_user_meta_data jsonb default '{}'::jsonb,
	created_at timestamptz default now(),
	deleted_at timestamptz);
create table if not exists auth.refresh_tokens (
	id bigserial primary key,
	token varchar(255),
	user_id varchar(255));
create table if not exists auth.sessions (
	id uuid primary key,
	user_id uuid not null);
create table if not exists auth.identities (
	id uuid primary key,
	user_id uuid not null,
	provider text not null default 'google',
	identity_data jsonb not null);
alter table auth.identities add column if not exists provider_id text not null default '123';
alter table auth.identities add column if not exists updated_at timestamptz;
create schema if not exists dilion_authz;
create table if not exists dilion_authz.role_assignments (
	id bigserial primary key,
	actor_id text not null,
	role_id text not null,
	revoked_at timestamptz,
	revoked_by text);
create schema if not exists dilion_auth;
create table if not exists dilion_auth.opaque_credentials (
	user_id uuid primary key,
	record bytea not null);
`

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("DILION_TEST_DB") == "" {
		t.Skip("set DILION_TEST_DB=1 (and create the db) to run privacy DB tests")
	}
	dsn := os.Getenv("DILION_TEST_DB_DSN")
	if dsn == "" {
		dsn = defaultTestDSN
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v (create it with: docker exec dilion-pg createdb -U dilion dilion_test_c)", err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping %s: %v (create it with: docker exec dilion-pg createdb -U dilion dilion_test_c)", dsn, err)
	}
	if _, err := pool.Exec(ctx, authDDL); err != nil {
		t.Fatalf("auth ddl: %v", err)
	}
	for _, m := range []string{"0200_privacy.sql", "0201_pii_search_index.sql", "0202_consent_state.sql"} {
		body, err := os.ReadFile("../../migrations/" + m)
		if err != nil {
			t.Fatalf("read migration: %v", err)
		}
		if _, err := pool.Exec(ctx, string(body)); err != nil {
			t.Fatalf("apply %s: %v", m, err)
		}
	}
	resetDB(t, pool)
	t.Cleanup(pool.Close)
	return pool
}

func resetDB(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	stmts := []string{
		`delete from dilion_privacy.consent_state`,
		`alter table dilion_privacy.consent_events disable trigger user`,
		`delete from dilion_privacy.consent_events`,
		`alter table dilion_privacy.consent_events enable trigger user`,
		`delete from dilion_privacy.tasks`,
		`delete from dilion_privacy.destruction_logs`,
		`delete from dilion_privacy.personal_data_requests`,
		`delete from dilion_privacy.legal_holds`,
		`delete from dilion_privacy.destinations`,
		`delete from dilion_privacy.erasure_registry`,
		`delete from dilion_privacy.outbox`,
		`delete from dilion_privacy.subject_policies`,
		`delete from dilion_pii.subject_keys`,
		`delete from dilion_pii.user_profiles`,
		`delete from dilion_pii.profile_search_index`,
		`delete from auth.identities`,
		`delete from dilion_auth.opaque_credentials`,
		`delete from dilion_authz.role_assignments`,
		`delete from auth.sessions`,
		`delete from auth.refresh_tokens`,
		`delete from auth.users`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("reset (%s): %v", s, err)
		}
	}
}

// ---- test doubles ----------------------------------------------------------

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeKMS mirrors the storage behaviour of internal/kmslocal (rows in
// dilion_pii.subject_keys) without depending on that package.
type fakeKMS struct {
	pool      *pgxpool.Pool
	mu        sync.Mutex
	destroyed map[string]bool
}

func newFakeKMS(pool *pgxpool.Pool) *fakeKMS {
	return &fakeKMS{pool: pool, destroyed: map[string]bool{}}
}

func (k *fakeKMS) key(subject string, scope ports.KeyScope) string {
	return subject + "|" + string(scope)
}

func (k *fakeKMS) ensureRow(ctx context.Context, subject string, scope ports.KeyScope) error {
	if _, err := uuid.Parse(subject); err != nil {
		return nil // platform pseudo-subject ("system")
	}
	wrapped := make([]byte, 32)
	_, _ = rand.Read(wrapped)
	_, err := k.pool.Exec(ctx, `insert into dilion_pii.subject_keys (user_id, scope, wrapped_dek)
		values ($1::uuid, $2, $3) on conflict (user_id, scope) do nothing`, subject, string(scope), wrapped)
	return err
}

func (k *fakeKMS) Encrypt(ctx context.Context, subject string, scope ports.KeyScope, pt []byte) ([]byte, error) {
	k.mu.Lock()
	dead := k.destroyed[k.key(subject, scope)]
	k.mu.Unlock()
	if dead {
		return nil, fmt.Errorf("fakekms: key shredded")
	}
	if err := k.ensureRow(ctx, subject, scope); err != nil {
		return nil, err
	}
	return append([]byte("enc:"), pt...), nil
}

func (k *fakeKMS) Decrypt(ctx context.Context, subject string, scope ports.KeyScope, ct []byte) ([]byte, error) {
	k.mu.Lock()
	dead := k.destroyed[k.key(subject, scope)]
	k.mu.Unlock()
	if dead {
		return nil, fmt.Errorf("fakekms: key shredded")
	}
	return ct[len("enc:"):], nil
}

func (k *fakeKMS) DestroyDEK(ctx context.Context, subject string, scope ports.KeyScope) error {
	k.mu.Lock()
	k.destroyed[k.key(subject, scope)] = true
	k.mu.Unlock()
	if _, err := uuid.Parse(subject); err != nil {
		return nil
	}
	_, err := k.pool.Exec(ctx, `update dilion_pii.subject_keys
		set shredded_at = coalesce(shredded_at, now()) where user_id = $1::uuid and scope = $2`,
		subject, string(scope))
	return err
}

func (k *fakeKMS) isDestroyed(subject string, scope ports.KeyScope) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.destroyed[k.key(subject, scope)]
}

type testEnv struct {
	e     *Engine
	pool  *pgxpool.Pool
	kms   *fakeKMS
	clock *testClock
	hooks *hooks.Registry
	ctx   context.Context
}

func newTestEngine(t *testing.T, policyYAML string) *testEnv {
	t.Helper()
	return newTestEngineWith(t, policyYAML, "", nil)
}

// newTestEngineWith is newTestEngine for a named instance with connectors.
// testOutbound is what engines built by newTestEngineWith may reach besides
// the public internet: loopback, where the fake receivers listen. A test of
// the guard itself empties it first.
var testOutbound = netguard.MustParseNetworks("127.0.0.0/8,::1")

func newTestEngineWith(t *testing.T, policyYAML, instanceID string, connectors map[string]ports.Connector) *testEnv {
	t.Helper()
	pool := testPool(t)
	clock := &testClock{t: time.Date(2026, 8, 12, 9, 0, 0, 0, time.UTC)}
	kms := newFakeKMS(pool)
	reg := hooks.NewRegistry()
	e, err := NewEngine(EngineDeps{
		Pool:             pool,
		KMS:              kms,
		Hooks:            reg,
		Clock:            clock,
		PolicyYAML:       []byte(policyYAML),
		TombstoneKey:     []byte("test-tombstone-key"),
		OutboundNetworks: testOutbound,
		InstanceID:       instanceID,
		Connectors:       connectors,
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return &testEnv{e: e, pool: pool, kms: kms, clock: clock, hooks: reg, ctx: context.Background()}
}

// newUser seeds a user with sessions, tokens and an oauth identity.
func (env *testEnv) newUser(t *testing.T) string {
	t.Helper()
	id := uuid.NewString()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := env.pool.Exec(env.ctx, q, args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	exec(`insert into auth.users (id, email, phone, encrypted_password, raw_user_meta_data)
		values ($1::uuid, $2, '+821000000000', 'hashed', '{"name":"홍길동"}'::jsonb)`,
		id, "u"+id[:8]+"@example.test")
	exec(`insert into auth.refresh_tokens (token, user_id) values ($1, $2)`, "rt-"+id[:8], id)
	exec(`insert into auth.sessions (id, user_id) values ($1::uuid, $2::uuid)`, uuid.NewString(), id)
	exec(`insert into auth.identities (id, user_id, provider, identity_data)
		values ($1::uuid, $2::uuid, 'google', '{"email":"x@example.test","sub":"123"}'::jsonb)`,
		uuid.NewString(), id)
	exec(`insert into dilion_auth.opaque_credentials (user_id, record) values ($1::uuid, $2)`,
		id, []byte("opaque-record"))
	exec(`insert into dilion_authz.role_assignments (actor_id, role_id) values ($1, 'role_owner')`, id)
	exec(`insert into dilion_pii.user_profiles (user_id, enc_profile) values ($1::uuid, $2)`,
		id, []byte("enc:profile"))
	if _, err := env.kms.Encrypt(env.ctx, id, ports.KeyScopeDefault, []byte("pii")); err != nil {
		t.Fatalf("seed dek: %v", err)
	}
	return id
}

func (env *testEnv) setPolicy(t *testing.T, userID, policyID string) {
	t.Helper()
	if _, err := env.pool.Exec(env.ctx, `insert into dilion_privacy.subject_policies
		(user_id, policy_id, source) values ($1::uuid, $2, 'explicit')
		on conflict (user_id) do update set policy_id = excluded.policy_id`, userID, policyID); err != nil {
		t.Fatalf("set policy: %v", err)
	}
}

// drain advances every worker until the pipeline settles.
func (env *testEnv) drain(t *testing.T, rounds int) {
	t.Helper()
	for i := 0; i < rounds; i++ {
		if err := env.e.dispatchOutboxOnce(env.ctx); err != nil {
			t.Fatalf("outbox: %v", err)
		}
		if err := env.e.runPipelineOnce(env.ctx); err != nil {
			t.Fatalf("pipeline: %v", err)
		}
		if err := env.e.runTasksOnce(env.ctx); err != nil {
			t.Fatalf("tasks: %v", err)
		}
	}
}

func (env *testEnv) status(t *testing.T, requestID string) (RequestStatus, *string) {
	t.Helper()
	var s RequestStatus
	var reason *string
	if err := env.pool.QueryRow(env.ctx, `select status, manual_review_reason
		from dilion_privacy.personal_data_requests where id = $1`, requestID).Scan(&s, &reason); err != nil {
		t.Fatalf("status: %v", err)
	}
	return s, reason
}

func (env *testEnv) destructionLogs(t *testing.T, requestID string) map[string]string {
	t.Helper()
	rows, err := env.pool.Query(env.ctx,
		`select domain, action from dilion_privacy.destruction_logs where request_id = $1`, requestID)
	if err != nil {
		t.Fatalf("destruction logs: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var d, a string
		if err := rows.Scan(&d, &a); err != nil {
			t.Fatal(err)
		}
		out[d] = a
	}
	return out
}

// ---- tests -----------------------------------------------------------------

func TestCreateRequestGraceImmediateAndDuplicates(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)

	req, err := env.e.CreateRequest(env.ctx, CreateRequestInput{UserID: user, Type: RequestDeletion})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if req.Status != StatusRequested || req.PolicyID != "gdpr" {
		t.Fatalf("request = %+v", req)
	}
	if want := env.clock.Now().AddDate(0, 0, 30); !req.ScheduledAt.Equal(want) {
		t.Errorf("scheduled_at = %s, want grace deadline %s", req.ScheduledAt, want)
	}
	if !httpapi.ValidID(req.ID) {
		t.Errorf("id %q does not match the resource id convention", req.ID)
	}

	// Duplicate active DELETION.
	if _, err := env.e.CreateRequest(env.ctx, CreateRequestInput{UserID: user, Type: RequestDeletion}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate deletion err = %v, want ErrConflict", err)
	}

	// Cancel restores the ability to request again; immediate skips the grace.
	if _, err := env.e.CancelRequest(env.ctx, req.ID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := env.e.CancelRequest(env.ctx, req.ID); !errors.Is(err, ErrConflict) {
		t.Errorf("second cancel err = %v, want ErrConflict", err)
	}
	if _, err := env.e.CancelRequest(env.ctx, "pr_deadbeef"); !errors.Is(err, ErrNotFound) {
		t.Errorf("cancel unknown err = %v, want ErrNotFound", err)
	}

	imm, err := env.e.CreateRequest(env.ctx, CreateRequestInput{UserID: user, Type: RequestDeletion, Immediate: true})
	if err != nil {
		t.Fatalf("immediate create: %v", err)
	}
	if !imm.ScheduledAt.Equal(env.clock.Now()) {
		t.Errorf("immediate scheduled_at = %s, want now", imm.ScheduledAt)
	}

	if _, err := env.e.CreateRequest(env.ctx, CreateRequestInput{UserID: "not-a-uuid", Type: RequestDeletion}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("bad uuid err = %v", err)
	}
	if _, err := env.e.CreateRequest(env.ctx, CreateRequestInput{UserID: user, Type: "PURGE"}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("bad type err = %v", err)
	}
}

func TestCreateRequestIdempotency(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)
	other := env.newUser(t)

	in := CreateRequestInput{UserID: user, Type: RequestDeletion, IdempotencyKey: "key-1"}
	first, err := env.e.CreateRequest(env.ctx, in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	replay, err := env.e.CreateRequest(env.ctx, in)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if replay.ID != first.ID {
		t.Errorf("replay returned %s, want the original %s", replay.ID, first.ID)
	}

	in2 := CreateRequestInput{UserID: other, Type: RequestDeletion, IdempotencyKey: "key-1"}
	if _, err := env.e.CreateRequest(env.ctx, in2); !errors.Is(err, ErrIdempotencyReplay) {
		t.Errorf("same key different body err = %v, want ErrIdempotencyReplay", err)
	}
}

func TestManualReviewPolicyParksRequest(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)
	env.setPolicy(t, user, "hipaa")

	req, err := env.e.CreateRequest(env.ctx, CreateRequestInput{UserID: user, Type: RequestDeletion, Immediate: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if req.Status != StatusManualReview || req.PolicyID != "hipaa" {
		t.Fatalf("request = %+v, want MANUAL_REVIEW under hipaa", req)
	}
	env.drain(t, 2)
	if s, reason := env.status(t, req.ID); s != StatusManualReview || reason == nil || *reason != "POLICY" {
		t.Fatalf("status = %s (%v), the runner must not advance MANUAL_REVIEW", s, reason)
	}
	if logs := env.destructionLogs(t, req.ID); len(logs) != 0 {
		t.Fatalf("no step may run for a parked request: %+v", logs)
	}
}

func TestErasurePipelineEndToEnd(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)

	// Consent evidence exists -> a CONSENT scope key exists.
	if _, err := env.e.UpdateConsent(env.ctx, user, ConsentChange{
		Purpose: "marketing.email", Granted: true, PolicyVersion: "v1.4", Source: "ui"}); err != nil {
		t.Fatalf("consent: %v", err)
	}

	var gotSig, gotIdem, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		gotBody, gotSig, gotIdem = string(buf), r.Header.Get("Dilion-Signature"), r.Header.Get("Idempotency-Key")
		var doc map[string]any
		_ = json.Unmarshal(buf, &doc)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"request_id":%q,"status":"completed"}`, doc["request_id"])
	}))
	defer srv.Close()

	dst, err := env.e.CreateDestination(env.ctx, CreateDestinationInput{
		Type: DestinationWebhook, Name: "primary-app",
		Config: map[string]any{"url": srv.URL, "identity_field": "user_id"},
		Secret: testWebhookSecret,
	})
	if err != nil {
		t.Fatalf("destination: %v", err)
	}
	if _, leaked := dst.Config["secret"]; leaked {
		t.Error("destination projection must not expose the secret")
	}

	req, err := env.e.CreateRequest(env.ctx, CreateRequestInput{
		UserID: user, Type: RequestDeletion, Immediate: true, RequestedBy: "admin_1"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// One pass creates the tasks and halts; the sender delivers; the next pass finishes.
	env.drain(t, 3)

	if s, _ := env.status(t, req.ID); s != StatusDone {
		t.Fatalf("status = %s, want DONE", s)
	}

	logs := env.destructionLogs(t, req.ID)
	want := map[string]string{
		DomainCredential: "DELETE", DomainRefreshToken: "DELETE", DomainSession: "DELETE",
		DomainMFAFactor: "DELETE", DomainPasskey: "DELETE", DomainOAuthIdentity: "ANONYMIZE",
		DomainExternalSystem: "EXECUTE", DomainAuditLog: "ANONYMIZE",
		DomainSubjectKey: "CRYPTO_SHRED", DomainAccount: "ANONYMIZE",
	}
	if len(logs) != len(want) {
		t.Fatalf("destruction_logs = %+v, want %d domains", logs, len(want))
	}
	for d, a := range want {
		if logs[d] != a {
			t.Errorf("destruction_logs[%s] = %q, want %q", d, logs[d], a)
		}
	}

	// Webhook delivery, signature and idempotency key.
	if !strings.HasPrefix(gotIdem, "tsk_") {
		t.Errorf("Idempotency-Key = %q, want the task id", gotIdem)
	}
	if err := verifySignature(testWebhookSecret, gotSig, []byte(gotBody), env.clock.Now(), time.Minute); err != nil {
		t.Errorf("webhook signature: %v (header %q)", err, gotSig)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("webhook body: %v", err)
	}
	if body["event"] != "privacy.delete" || body["user_id"] != user || body["request_id"] != req.ID {
		t.Errorf("webhook body = %v", body)
	}
	if id, _ := body["id"].(string); !strings.HasPrefix(id, "evt_") {
		t.Errorf("webhook event id = %v", body["id"])
	}

	var taskStatus string
	var evidence []byte
	if err := env.pool.QueryRow(env.ctx, `select status, evidence from dilion_privacy.tasks
		where request_id = $1 and destination_id = $2`, req.ID, dst.ID).Scan(&taskStatus, &evidence); err != nil {
		t.Fatalf("task: %v", err)
	}
	if taskStatus != "completed" {
		t.Errorf("task status = %s", taskStatus)
	}
	var ev map[string]any
	_ = json.Unmarshal(evidence, &ev)
	if ev["receipt_status"] != "completed" || ev["receipt_verified"] != true {
		t.Errorf("task evidence must record the execution receipt, got %v", ev)
	}

	// auth.* projections
	var email, phone *string
	var pw string
	var deletedAt *time.Time
	var meta []byte
	if err := env.pool.QueryRow(env.ctx, `select email, phone, encrypted_password, deleted_at, raw_user_meta_data
		from auth.users where id = $1::uuid`, user).Scan(&email, &phone, &pw, &deletedAt, &meta); err != nil {
		t.Fatalf("user: %v", err)
	}
	if email != nil || phone != nil || pw != "" || deletedAt == nil || string(meta) != "{}" {
		t.Errorf("auth.users not erased: email=%v phone=%v pw=%q deleted=%v meta=%s", email, phone, pw, deletedAt, meta)
	}

	counts := map[string]int{}
	for _, q := range []struct{ name, sql string }{
		{"refresh_tokens", `select count(*) from auth.refresh_tokens where user_id = $1`},
		{"sessions", `select count(*) from auth.sessions where user_id = $1::uuid`},
		{"profiles", `select count(*) from dilion_pii.user_profiles where user_id = $1::uuid`},
		{"identities_with_data", `select count(*) from auth.identities where user_id = $1::uuid and identity_data <> '{}'::jsonb`},
		// Still naming the provider account, signing up with it again would
		// land in this erased user.
		{"identities_still_linked", `select count(*) from auth.identities where user_id = $1::uuid and provider_id = '123'`},
		{"opaque_credentials", `select count(*) from dilion_auth.opaque_credentials where user_id = $1::uuid`},
		{"active_role_assignments", `select count(*) from dilion_authz.role_assignments where actor_id = $1 and revoked_at is null`},
	} {
		var n int
		if err := env.pool.QueryRow(env.ctx, q.sql, user).Scan(&n); err != nil {
			t.Fatalf("%s: %v", q.name, err)
		}
		counts[q.name] = n
	}
	for name, n := range counts {
		if n != 0 {
			t.Errorf("%s: %d rows remain", name, n)
		}
	}
	// The released provider_id is the one auth's soft delete writes
	// (obfuscateIdentityProviderID), so both paths leave the same trace.
	var released string
	if err := env.pool.QueryRow(env.ctx, `select provider_id from auth.identities where user_id = $1::uuid`,
		user).Scan(&released); err != nil {
		t.Fatalf("identity: %v", err)
	}
	sum := sha256.Sum256([]byte(user + "google:123"))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); released != want {
		t.Errorf("released provider_id = %q, want auth's obfuscation %q", released, want)
	}

	// Keys: DEFAULT shredded now, CONSENT retained until shred_after (gdpr P3Y).
	if !env.kms.isDestroyed(user, ports.KeyScopeDefault) {
		t.Error("DEFAULT dek must be destroyed")
	}
	if env.kms.isDestroyed(user, ports.KeyScopeConsent) {
		t.Error("CONSENT dek must survive the pipeline (retention P3Y from erasure)")
	}
	var shredAfter *time.Time
	if err := env.pool.QueryRow(env.ctx, `select shred_after from dilion_pii.subject_keys
		where user_id = $1::uuid and scope = 'CONSENT'`, user).Scan(&shredAfter); err != nil {
		t.Fatalf("consent key: %v", err)
	}
	if shredAfter == nil || !shredAfter.Equal(env.clock.Now().AddDate(3, 0, 0)) {
		t.Errorf("consent shred_after = %v, want now+P3Y", shredAfter)
	}

	// Erasure registry keeps only a keyed tombstone.
	var tomb, reason string
	if err := env.pool.QueryRow(env.ctx,
		`select tombstone_id, reason from dilion_privacy.erasure_registry where request_id = $1`, req.ID).
		Scan(&tomb, &reason); err != nil {
		t.Fatalf("erasure registry: %v", err)
	}
	if tomb != env.e.tombstoneID(user) || strings.Contains(tomb, user) {
		t.Errorf("tombstone = %q, want HMAC of the subject id", tomb)
	}

	// Re-running is a no-op (crash safety).
	env.drain(t, 2)
	if got := env.destructionLogs(t, req.ID); len(got) != len(want) {
		t.Errorf("re-run added rows: %+v", got)
	}
	var completedAt *time.Time
	if err := env.pool.QueryRow(env.ctx,
		`select completed_at from dilion_privacy.personal_data_requests where id = $1`, req.ID).
		Scan(&completedAt); err != nil {
		t.Fatal(err)
	}
	if completedAt == nil {
		t.Error("completed_at must be set")
	}
}

func TestPolicyKeepDomainStillLogged(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)
	env.setPolicy(t, user, "kr")

	req, err := env.e.CreateRequest(env.ctx, CreateRequestInput{UserID: user, Type: RequestDeletion, Immediate: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if req.PolicyID != "kr" {
		t.Fatalf("policy = %s, want the explicitly assigned kr", req.PolicyID)
	}
	env.drain(t, 2)

	logs := env.destructionLogs(t, req.ID)
	if logs[DomainAuditLog] != string(ActionKeep) {
		t.Errorf("kr audit-log action = %q, want KEEP", logs[DomainAuditLog])
	}
	var basis *string
	if err := env.pool.QueryRow(env.ctx, `select basis from dilion_privacy.destruction_logs
		where request_id = $1 and domain = $2`, req.ID, DomainAuditLog).Scan(&basis); err != nil {
		t.Fatalf("basis: %v", err)
	}
	if basis == nil || !strings.Contains(*basis, "안전성 확보조치") {
		t.Errorf("KEEP row must copy the policy basis, got %v", basis)
	}
	if s, _ := env.status(t, req.ID); s != StatusDone {
		t.Errorf("status = %s, want DONE", s)
	}
}

func TestLegalHoldGatesPipelineAndResumes(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)

	hold, err := env.e.CreateHold(env.ctx, CreateHoldInput{
		UserID: user, Reason: "litigation", Basis: "45 CFR §164.308", CreatedBy: "admin_1"})
	if err != nil {
		t.Fatalf("hold: %v", err)
	}
	req, err := env.e.CreateRequest(env.ctx, CreateRequestInput{UserID: user, Type: RequestDeletion, Immediate: true})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	env.drain(t, 2)
	s, reason := env.status(t, req.ID)
	if s != StatusManualReview || reason == nil || *reason != "LEGAL_HOLD" {
		t.Fatalf("status = %s (%v), want MANUAL_REVIEW/LEGAL_HOLD", s, reason)
	}
	if logs := env.destructionLogs(t, req.ID); len(logs) != 0 {
		t.Fatalf("held request must not run steps: %+v", logs)
	}

	page, err := env.e.ListHolds(env.ctx, HoldFilter{UserID: &user}, httpapi.ListParams{})
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != hold.ID {
		t.Fatalf("list holds = %+v (%v)", page, err)
	}

	if _, err := env.e.ReleaseHold(env.ctx, hold.ID, "admin_2"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if s, _ := env.status(t, req.ID); s != StatusRequested {
		t.Fatalf("status after release = %s, want REQUESTED (auto-resume)", s)
	}
	if _, err := env.e.ReleaseHold(env.ctx, hold.ID, "admin_2"); !errors.Is(err, ErrConflict) {
		t.Errorf("double release err = %v, want ErrConflict", err)
	}

	env.drain(t, 2)
	if s, _ := env.status(t, req.ID); s != StatusDone {
		t.Fatalf("status = %s, want DONE after the hold was lifted", s)
	}
}

func TestOutboxUserDeletedCreatesRequest(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)

	insert := func() string {
		var id string
		payload := fmt.Sprintf(`{"user_id":%q,"requested_by":"admin"}`, user)
		if err := env.pool.QueryRow(env.ctx, `insert into dilion_privacy.outbox
			(event_type, aggregate_id, payload) values ('user.deleted', $1, $2::jsonb) returning id::text`,
			user, payload).Scan(&id); err != nil {
			t.Fatalf("outbox insert: %v", err)
		}
		return id
	}
	first := insert()
	if err := env.e.dispatchOutboxOnce(env.ctx); err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	var count int
	var status RequestStatus
	var requestedBy *string
	if err := env.pool.QueryRow(env.ctx, `select count(*) from dilion_privacy.personal_data_requests
		where user_id = $1::uuid`, user).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("requests created = %d, want 1", count)
	}
	if err := env.pool.QueryRow(env.ctx, `select status, requested_by
		from dilion_privacy.personal_data_requests where user_id = $1::uuid`, user).
		Scan(&status, &requestedBy); err != nil {
		t.Fatal(err)
	}
	if status != StatusRequested || requestedBy == nil || *requestedBy != "admin" {
		t.Errorf("request = %s / %v", status, requestedBy)
	}

	var published *time.Time
	if err := env.pool.QueryRow(env.ctx,
		`select published_at from dilion_privacy.outbox where id = $1::uuid`, first).Scan(&published); err != nil {
		t.Fatal(err)
	}
	if published == nil {
		t.Error("outbox row must be marked published")
	}

	// A duplicate event for the same subject must not create a second request.
	insert()
	if err := env.e.dispatchOutboxOnce(env.ctx); err != nil {
		t.Fatalf("dispatch 2: %v", err)
	}
	if err := env.pool.QueryRow(env.ctx, `select count(*) from dilion_privacy.personal_data_requests
		where user_id = $1::uuid`, user).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("requests after duplicate event = %d, want 1", count)
	}
	var unpublished int
	if err := env.pool.QueryRow(env.ctx,
		`select count(*) from dilion_privacy.outbox where published_at is null`).Scan(&unpublished); err != nil {
		t.Fatal(err)
	}
	if unpublished != 0 {
		t.Errorf("unpublished outbox rows = %d", unpublished)
	}
}

func TestConsentLedger(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)
	env.setPolicy(t, user, "kr")

	if _, err := env.e.UpdateConsent(env.ctx, user, ConsentChange{
		Purpose: "terms", Granted: true, PolicyVersion: "v1", Source: "ui"}); err != nil {
		t.Fatalf("grant terms: %v", err)
	}
	env.clock.Advance(time.Hour)
	if _, err := env.e.UpdateConsent(env.ctx, user, ConsentChange{
		Purpose: "marketing.email", Granted: true, PolicyVersion: "v1.3", Source: "ui"}); err != nil {
		t.Fatalf("grant marketing: %v", err)
	}
	env.clock.Advance(time.Hour)
	st, err := env.e.UpdateConsent(env.ctx, user, ConsentChange{
		Purpose: "marketing.email", Granted: false, PolicyVersion: "v1.4", Source: "api"})
	if err != nil {
		t.Fatalf("withdraw marketing: %v", err)
	}
	if st.Granted || st.ReconfirmDue != nil {
		t.Errorf("withdrawn state = %+v", st)
	}

	// Required keys cannot be withdrawn (policy data, not code).
	if _, err := env.e.UpdateConsent(env.ctx, user, ConsentChange{
		Purpose: "terms", Granted: false}); !errors.Is(err, ErrPolicyViolation) {
		t.Errorf("withdraw required key err = %v, want ErrPolicyViolation", err)
	}

	states, err := env.e.GetConsents(env.ctx, user)
	if err != nil {
		t.Fatalf("get consents: %v", err)
	}
	byPurpose := map[string]ConsentState{}
	for _, s := range states {
		byPurpose[s.Purpose] = s
	}
	if len(states) != 2 {
		t.Fatalf("states = %+v, want one row per purpose", states)
	}
	if !byPurpose["terms"].Granted || byPurpose["marketing.email"].Granted {
		t.Errorf("projection wrong: %+v", byPurpose)
	}
	if byPurpose["marketing.email"].PolicyVersion != "v1.4" {
		t.Errorf("latest event must win: %+v", byPurpose["marketing.email"])
	}

	// The ledger keeps every event.
	var n int
	if err := env.pool.QueryRow(env.ctx,
		`select count(*) from dilion_privacy.consent_events where user_id = $1::uuid`, user).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("ledger rows = %d, want 3", n)
	}

	// Evidence is sealed with the CONSENT scope key.
	var evidence []byte
	if err := env.pool.QueryRow(env.ctx, `select evidence from dilion_privacy.consent_events
		where user_id = $1::uuid order by id limit 1`, user).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(evidence, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["scope"] != "CONSENT" || doc["ciphertext"] == nil {
		t.Errorf("consent evidence must be encrypted: %v", doc)
	}
}

func TestConsentLedgerIsAppendOnly(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)
	if _, err := env.e.UpdateConsent(env.ctx, user, ConsentChange{
		Purpose: "terms", Granted: true, Source: "ui"}); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(env.ctx,
		`update dilion_privacy.consent_events set action = 'GRANT' where user_id = $1::uuid`, user); err == nil {
		t.Error("UPDATE on the consent ledger must raise")
	}
	if _, err := env.pool.Exec(env.ctx,
		`delete from dilion_privacy.consent_events where user_id = $1::uuid`, user); err == nil {
		t.Error("DELETE on the consent ledger must raise")
	}
}

func TestReconfirmScannerEmitsNoticeAndOutbox(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)
	env.setPolicy(t, user, "kr") // marketing.* : P2Y

	if _, err := env.e.UpdateConsent(env.ctx, user, ConsentChange{
		Purpose: "marketing.email", Granted: true, PolicyVersion: "v1.3", Source: "ui"}); err != nil {
		t.Fatal(err)
	}
	if err := env.e.scanReconfirmDue(env.ctx); err != nil {
		t.Fatalf("scan: %v", err)
	}
	var notices int
	if err := env.pool.QueryRow(env.ctx, `select count(*) from dilion_privacy.consent_events
		where user_id = $1::uuid and action = 'RECONFIRM_NOTICE'`, user).Scan(&notices); err != nil {
		t.Fatal(err)
	}
	if notices != 0 {
		t.Fatalf("notice emitted before the period elapsed (%d)", notices)
	}

	env.clock.Advance(2*365*24*time.Hour + 48*time.Hour)
	if err := env.e.scanReconfirmDue(env.ctx); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if err := env.pool.QueryRow(env.ctx, `select count(*) from dilion_privacy.consent_events
		where user_id = $1::uuid and action = 'RECONFIRM_NOTICE'`, user).Scan(&notices); err != nil {
		t.Fatal(err)
	}
	if notices != 1 {
		t.Fatalf("notices = %d, want 1", notices)
	}

	var outboxCount int
	if err := env.pool.QueryRow(env.ctx, `select count(*) from dilion_privacy.outbox
		where event_type = 'consent.reconfirm_due' and aggregate_id = $1`, user).Scan(&outboxCount); err != nil {
		t.Fatal(err)
	}
	if outboxCount != 1 {
		t.Fatalf("outbox events = %d, want 1", outboxCount)
	}

	// Consent is never auto-expired (§2.8) and the notice resets the clock.
	states, err := env.e.GetConsents(env.ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || !states[0].Granted {
		t.Fatalf("consent must stay granted: %+v", states)
	}
	if states[0].ReconfirmDue == nil || !states[0].ReconfirmDue.After(env.clock.Now()) {
		t.Errorf("reconfirm_due = %v, want a future date after the notice", states[0].ReconfirmDue)
	}
	if err := env.e.scanReconfirmDue(env.ctx); err != nil {
		t.Fatal(err)
	}
	if err := env.pool.QueryRow(env.ctx, `select count(*) from dilion_privacy.consent_events
		where user_id = $1::uuid and action = 'RECONFIRM_NOTICE'`, user).Scan(&notices); err != nil {
		t.Fatal(err)
	}
	if notices != 1 {
		t.Errorf("scanner must not re-notify inside the period (%d)", notices)
	}
}

func TestReconfirmScannerDoesNotStarveDueRowsBehindNotDueRows(t *testing.T) {
	env := newTestEngine(t, "compliance:\n  retention-batch-size: 1\n")
	due := "00000000-0000-4000-8000-000000000002"
	notDue := "00000000-0000-4000-8000-000000000001"
	for _, user := range []string{due, notDue} {
		env.setPolicy(t, user, "kr")
	}
	if _, err := env.e.UpdateConsent(env.ctx, due, ConsentChange{
		Purpose: "marketing.email", Granted: true, Source: "ui"}); err != nil {
		t.Fatal(err)
	}
	env.clock.Advance(2*365*24*time.Hour + 48*time.Hour)
	if _, err := env.e.UpdateConsent(env.ctx, notDue, ConsentChange{
		Purpose: "marketing.email", Granted: true, Source: "ui"}); err != nil {
		t.Fatal(err)
	}

	if err := env.e.scanReconfirmDue(env.ctx); err != nil {
		t.Fatal(err)
	}
	var noticed string
	if err := env.pool.QueryRow(env.ctx, `select user_id::text from dilion_privacy.consent_events
		where action = 'RECONFIRM_NOTICE'`).Scan(&noticed); err != nil {
		t.Fatal(err)
	}
	if noticed != due {
		t.Errorf("noticed user = %s, want due user %s", noticed, due)
	}
}

func TestReconfirmOutboxFansOutToWebhook(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)

	var gotEvent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		var doc map[string]any
		_ = json.Unmarshal(buf, &doc)
		gotEvent, _ = doc["event"].(string)
		if p, ok := doc["purpose"].(string); !ok || p != "marketing.email" {
			t.Errorf("reconfirm payload must carry the purpose: %v", doc)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if _, err := env.e.CreateDestination(env.ctx, CreateDestinationInput{
		Type: DestinationWebhook, Name: "crm", Config: map[string]any{"url": srv.URL}, Secret: testWebhookSecret}); err != nil {
		t.Fatal(err)
	}
	payload := fmt.Sprintf(`{"user_id":%q,"purpose":"marketing.email"}`, user)
	if _, err := env.pool.Exec(env.ctx, `insert into dilion_privacy.outbox (event_type, aggregate_id, payload)
		values ('consent.reconfirm_due', $1, $2::jsonb)`, user, payload); err != nil {
		t.Fatal(err)
	}

	if err := env.e.dispatchOutboxOnce(env.ctx); err != nil {
		t.Fatal(err)
	}
	if err := env.e.runTasksOnce(env.ctx); err != nil {
		t.Fatal(err)
	}
	if gotEvent != "consent.reconfirm_due" {
		t.Fatalf("delivered event = %q", gotEvent)
	}
	var status string
	if err := env.pool.QueryRow(env.ctx,
		`select status from dilion_privacy.tasks where action = $1`, TaskActionReconfirm).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "completed" {
		t.Errorf("task status = %s", status)
	}
}

func TestWebhookRetriesThenDeadLettersAndParksRequest(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		http.Error(w, `{"error":"boom"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := env.e.CreateDestination(env.ctx, CreateDestinationInput{
		Type: DestinationWebhook, Name: "flaky", Config: map[string]any{"url": srv.URL}, Secret: testWebhookSecret}); err != nil {
		t.Fatal(err)
	}
	req, err := env.e.CreateRequest(env.ctx, CreateRequestInput{UserID: user, Type: RequestDeletion, Immediate: true})
	if err != nil {
		t.Fatal(err)
	}

	if err := env.e.runPipelineOnce(env.ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxTaskAttempts; i++ {
		if err := env.e.runTasksOnce(env.ctx); err != nil {
			t.Fatal(err)
		}
		// Retries are scheduled with exponential backoff; jump the clock.
		env.clock.Advance(backoffCap * 2)
	}
	var status, errCode string
	var attempts int
	if err := env.pool.QueryRow(env.ctx, `select status, coalesce(error_code,''), attempt_count
		from dilion_privacy.tasks where request_id = $1`, req.ID).Scan(&status, &errCode, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "dead" || attempts != maxTaskAttempts {
		t.Fatalf("task = %s after %d attempts (want dead after %d)", status, attempts, maxTaskAttempts)
	}
	if errCode != "HTTP_500" {
		t.Errorf("error_code = %s", errCode)
	}
	if calls != maxTaskAttempts {
		t.Errorf("delivery attempts = %d, want %d", calls, maxTaskAttempts)
	}

	if err := env.e.runPipelineOnce(env.ctx); err != nil {
		t.Fatal(err)
	}
	s, reason := env.status(t, req.ID)
	if s != StatusManualReview || reason == nil || *reason != "TASK_FAILED" {
		t.Fatalf("status = %s (%v), want MANUAL_REVIEW/TASK_FAILED", s, reason)
	}
	// The account step must not have run while delivery is unresolved.
	if logs := env.destructionLogs(t, req.ID); logs[DomainAccount] != "" {
		t.Errorf("account step ran despite the dead-lettered task: %+v", logs)
	}
}

func TestStuckRunningTaskIsReclaimed(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		var doc map[string]any
		_ = json.Unmarshal(buf, &doc)
		fmt.Fprintf(w, `{"request_id":%q,"status":"completed"}`, doc["request_id"])
	}))
	defer srv.Close()
	if _, err := env.e.CreateDestination(env.ctx, CreateDestinationInput{
		Type: DestinationWebhook, Name: "app", Config: map[string]any{"url": srv.URL}, Secret: testWebhookSecret}); err != nil {
		t.Fatal(err)
	}
	req, err := env.e.CreateRequest(env.ctx, CreateRequestInput{UserID: user, Type: RequestDeletion, Immediate: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.e.runPipelineOnce(env.ctx); err != nil {
		t.Fatal(err)
	}

	// Simulate a worker that died mid-delivery.
	if _, err := env.pool.Exec(env.ctx, `update dilion_privacy.tasks
		set status = 'running', started_at = $2 where request_id = $1`,
		req.ID, env.clock.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := env.e.runTasksOnce(env.ctx); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := env.pool.QueryRow(env.ctx,
		`select status from dilion_privacy.tasks where request_id = $1`, req.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "completed" {
		t.Fatalf("stuck task status = %s, want completed after re-claim", status)
	}
}

func TestRetentionScannerShredsConsentKeys(t *testing.T) {
	env := newTestEngine(t, "")
	due := env.newUser(t)
	held := env.newUser(t)
	future := env.newUser(t)

	for _, u := range []string{due, held, future} {
		if _, err := env.e.UpdateConsent(env.ctx, u, ConsentChange{
			Purpose: "marketing.email", Granted: true, Source: "ui"}); err != nil {
			t.Fatal(err)
		}
	}
	set := func(u string, at time.Time) {
		if _, err := env.pool.Exec(env.ctx, `update dilion_pii.subject_keys set shred_after = $2
			where user_id = $1::uuid and scope = 'CONSENT'`, u, at); err != nil {
			t.Fatal(err)
		}
	}
	set(due, env.clock.Now().Add(-time.Hour))
	set(held, env.clock.Now().Add(-time.Hour))
	set(future, env.clock.Now().Add(24*time.Hour))

	if _, err := env.e.CreateHold(env.ctx, CreateHoldInput{
		UserID: held, Reason: "regulatory preservation order"}); err != nil {
		t.Fatal(err)
	}

	if err := env.e.runRetentionOnce(env.ctx); err != nil {
		t.Fatalf("retention: %v", err)
	}
	if !env.kms.isDestroyed(due, ports.KeyScopeConsent) {
		t.Error("due consent key must be shredded")
	}
	if env.kms.isDestroyed(held, ports.KeyScopeConsent) {
		t.Error("legal hold must block the retention sweep (gate 2)")
	}
	if env.kms.isDestroyed(future, ports.KeyScopeConsent) {
		t.Error("key with a future shred_after must be untouched")
	}
	var shredded *time.Time
	if err := env.pool.QueryRow(env.ctx, `select shredded_at from dilion_pii.subject_keys
		where user_id = $1::uuid and scope = 'CONSENT'`, due).Scan(&shredded); err != nil {
		t.Fatal(err)
	}
	if shredded == nil {
		t.Error("shredded_at must be recorded")
	}
}

func TestRetentionBatchExcludesHeldRowsBeforeLimit(t *testing.T) {
	env := newTestEngine(t, "")
	held := env.newUser(t)
	due := env.newUser(t)
	for _, user := range []string{held, due} {
		if _, err := env.e.UpdateConsent(env.ctx, user, ConsentChange{
			Purpose: "marketing.email", Granted: true, Source: "ui"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := env.pool.Exec(env.ctx, `update dilion_pii.subject_keys
		set shred_after = case when user_id = $1::uuid then $3::timestamptz else $4::timestamptz end
		where user_id = any($2::uuid[]) and scope = 'CONSENT'`, held, []string{held, due},
		env.clock.Now().Add(-2*time.Hour), env.clock.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := env.e.CreateHold(env.ctx, CreateHoldInput{UserID: held, Reason: "preserve"}); err != nil {
		t.Fatal(err)
	}

	if err := env.e.sweepConsentShredDue(env.ctx, env.clock.Now(), 1); err != nil {
		t.Fatal(err)
	}
	if env.kms.isDestroyed(held, ports.KeyScopeConsent) {
		t.Error("held key was shredded")
	}
	if !env.kms.isDestroyed(due, ports.KeyScopeConsent) {
		t.Error("eligible key behind held row was starved")
	}
}

func TestCreatedRetentionBatchExcludesHeldRowsBeforeLimit(t *testing.T) {
	env := newTestEngine(t, "")
	users := []string{env.newUser(t), env.newUser(t)}
	sort.Strings(users)
	held, due := users[0], users[1]
	for _, user := range users {
		if _, err := env.e.UpdateConsent(env.ctx, user, ConsentChange{
			Purpose: "analytics", Granted: true, Source: "ui"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := env.e.CreateHold(env.ctx, CreateHoldInput{UserID: held, Reason: "preserve"}); err != nil {
		t.Fatal(err)
	}

	if err := env.e.sweepConsentFromCreated(env.ctx, env.e.policies.DefaultPolicy,
		Duration{Days: 1}, env.clock.Now().AddDate(0, 0, 2), 1); err != nil {
		t.Fatal(err)
	}
	if env.kms.isDestroyed(held, ports.KeyScopeConsent) {
		t.Error("held key was shredded")
	}
	if !env.kms.isDestroyed(due, ports.KeyScopeConsent) {
		t.Error("eligible key behind held row was starved")
	}
}

func TestDestinationsCRUDAndListing(t *testing.T) {
	env := newTestEngine(t, "")

	if _, err := env.e.CreateDestination(env.ctx, CreateDestinationInput{
		Type: DestinationWebhook, Name: "bad", Config: map[string]any{"url": "not-a-url"}}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("invalid url err = %v", err)
	}
	if _, err := env.e.CreateDestination(env.ctx, CreateDestinationInput{
		Type: DestinationConnector, Name: "crm", Config: map[string]any{"connector": "salesforce"}}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("unregistered connector err = %v, want ErrInvalidInput", err)
	}

	var created []string
	for i := 0; i < 3; i++ {
		d, err := env.e.CreateDestination(env.ctx, CreateDestinationInput{
			Type: DestinationWebhook, Name: fmt.Sprintf("app-%d", i),
			Config: map[string]any{"url": "https://example.test/hook", "secret": "leak-me"},
			Secret: testWebhookSecret,
		})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if _, leaked := d.Config["secret"]; leaked {
			t.Fatal("config must never carry the secret back out")
		}
		created = append(created, d.ID)
	}

	first, err := env.e.ListDestinations(env.ctx, httpapi.ListParams{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 2 || first.NextCursor == nil {
		t.Fatalf("page 1 = %+v", first)
	}
	second, err := env.e.ListDestinations(env.ctx, httpapi.ListParams{Limit: 2, Cursor: *first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Items) != 1 || second.NextCursor != nil {
		t.Fatalf("page 2 = %+v", second)
	}

	off := false
	upd, err := env.e.UpdateDestination(env.ctx, created[0], &off,
		map[string]any{"url": "https://example.test/v2"})
	if err != nil {
		t.Fatal(err)
	}
	if upd.Enabled || upd.Config["url"] != "https://example.test/v2" {
		t.Fatalf("update = %+v", upd)
	}
	if err := env.e.DeleteDestination(env.ctx, created[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := env.e.GetDestination(env.ctx, created[0]); !errors.Is(err, ErrNotFound) {
		t.Errorf("get deleted err = %v", err)
	}
	if err := env.e.DeleteDestination(env.ctx, created[0]); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete twice err = %v", err)
	}
}

func TestListRequestsPagingAndFilter(t *testing.T) {
	env := newTestEngine(t, "")
	var ids []string
	for i := 0; i < 3; i++ {
		u := env.newUser(t)
		r, err := env.e.CreateRequest(env.ctx, CreateRequestInput{UserID: u, Type: RequestDeletion})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.ID)
		env.clock.Advance(time.Second)
	}
	if _, err := env.e.CancelRequest(env.ctx, ids[0]); err != nil {
		t.Fatal(err)
	}

	p1, err := env.e.ListRequests(env.ctx, RequestFilter{}, httpapi.ListParams{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(p1.Items) != 2 || p1.NextCursor == nil {
		t.Fatalf("page 1 = %+v", p1)
	}
	if p1.Items[0].RequestedAt.Before(p1.Items[1].RequestedAt) {
		t.Error("requests must be newest first")
	}
	p2, err := env.e.ListRequests(env.ctx, RequestFilter{}, httpapi.ListParams{Limit: 2, Cursor: *p1.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(p2.Items) != 1 || p2.NextCursor != nil {
		t.Fatalf("page 2 = %+v", p2)
	}

	canceled := StatusCanceled
	filtered, err := env.e.ListRequests(env.ctx, RequestFilter{Status: &canceled}, httpapi.ListParams{})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered.Items) != 1 || filtered.Items[0].ID != ids[0] {
		t.Fatalf("status filter = %+v", filtered)
	}

	got, err := env.e.GetRequest(env.ctx, ids[1])
	if err != nil || got.ID != ids[1] {
		t.Fatalf("get = %+v (%v)", got, err)
	}
}

func TestBeforeErasureHookCanPark(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)
	env.hooks.Register(ports.BeforeErasureStep, func(_ context.Context, p map[string]any) (map[string]any, error) {
		if p["domain"] == DomainAccount {
			return nil, errors.New("finance sign-off missing")
		}
		return nil, nil
	})

	req, err := env.e.CreateRequest(env.ctx, CreateRequestInput{UserID: user, Type: RequestDeletion, Immediate: true})
	if err != nil {
		t.Fatal(err)
	}
	env.drain(t, 2)

	s, reason := env.status(t, req.ID)
	if s != StatusManualReview || reason == nil || *reason != "HOOK_REJECTED" {
		t.Fatalf("status = %s (%v), want MANUAL_REVIEW/HOOK_REJECTED", s, reason)
	}
	logs := env.destructionLogs(t, req.ID)
	if logs[DomainSubjectKey] == "" {
		t.Error("steps before the rejected one must still be recorded")
	}
	if logs[DomainAccount] != "" {
		t.Error("the rejected step must not be recorded")
	}
}

func TestBeforeUserDeleteHookRejectsCreation(t *testing.T) {
	env := newTestEngine(t, "")
	user := env.newUser(t)
	env.hooks.Register(ports.BeforeUserDelete, func(_ context.Context, _ map[string]any) (map[string]any, error) {
		return nil, errors.New("subscription still active")
	})
	if _, err := env.e.CreateRequest(env.ctx, CreateRequestInput{UserID: user, Type: RequestDeletion}); !errors.Is(err, ErrPolicyViolation) {
		t.Fatalf("err = %v, want ErrPolicyViolation", err)
	}
}

// recordingConnector keeps every task it is asked to execute.
type recordingConnector struct {
	mu    sync.Mutex
	tasks []ports.ConnectorTask
}

func (c *recordingConnector) Execute(_ context.Context, task ports.ConnectorTask) (ports.ConnectorReceipt, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tasks = append(c.tasks, task)
	return ports.ConnectorReceipt{TaskID: task.TaskID, Status: "completed"}, nil
}

// Connectors are shared by every instance's engine and a webhook receiver may
// be too, so everything an engine sends out names the instance it serves: the
// webhook body (inside the signed document) and the connector task. A task's
// own payload cannot claim a different instance.
func TestOutgoingEventsCarryInstance(t *testing.T) {
	if got := newTestEngine(t, "").e.instanceID; got != ports.DefaultInstanceID {
		t.Errorf("unnamed engine instance = %q, want %q", got, ports.DefaultInstanceID)
	}

	conn := &recordingConnector{}
	env := newTestEngineWith(t, "", "tenant-a", map[string]ports.Connector{"crm": conn})
	user := env.newUser(t)

	var (
		mu      sync.Mutex
		webhook map[string]any
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var doc map[string]any
		_ = json.NewDecoder(r.Body).Decode(&doc)
		mu.Lock()
		webhook = doc
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if _, err := env.e.CreateDestination(env.ctx, CreateDestinationInput{
		Type: DestinationWebhook, Name: "hook", Config: map[string]any{"url": srv.URL}, Secret: testWebhookSecret}); err != nil {
		t.Fatal(err)
	}
	connDst, err := env.e.CreateDestination(env.ctx, CreateDestinationInput{
		Type: DestinationConnector, Name: "crm", Config: map[string]any{"connector": "crm"}})
	if err != nil {
		t.Fatal(err)
	}

	// The webhook: a reconfirm event whose payload tries to name another
	// instance.
	payload := fmt.Sprintf(`{"user_id":%q,"purpose":"marketing.email","instance_id":"tenant-b"}`, user)
	if _, err := env.pool.Exec(env.ctx, `insert into dilion_privacy.outbox (event_type, aggregate_id, payload)
		values ('consent.reconfirm_due', $1, $2::jsonb)`, user, payload); err != nil {
		t.Fatal(err)
	}
	if err := env.e.dispatchOutboxOnce(env.ctx); err != nil {
		t.Fatal(err)
	}

	// The connector: an erasure task addressed to its destination.
	if _, err := env.pool.Exec(env.ctx, `insert into dilion_privacy.tasks
		(id, request_id, user_id, destination_id, action, status, created_at, next_attempt_at, payload)
		values ('tsk_instance_test', 'req_instance_test', $1::uuid, $2, 'DELETE', 'pending', $3, $3, '{}'::jsonb)`,
		user, connDst.ID, env.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if err := env.e.runTasksOnce(env.ctx); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if webhook == nil {
		t.Fatal("the webhook was not delivered")
	}
	if got := webhook["instance_id"]; got != "tenant-a" {
		t.Errorf("webhook instance_id = %v, want tenant-a (the payload's tenant-b must not win)", got)
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if len(conn.tasks) != 1 {
		t.Fatalf("connector tasks = %d, want 1", len(conn.tasks))
	}
	if got := conn.tasks[0].InstanceID; got != "tenant-a" {
		t.Errorf("connector task instance = %q, want tenant-a", got)
	}
}

// A webhook destination is set by an instance admin; delivering to it must
// not reach the server's own network unless the operator allowed that
// network.
func TestWebhookDestinationCannotReachPrivateNetwork(t *testing.T) {
	prev := testOutbound
	testOutbound = netguard.Networks{}
	t.Cleanup(func() { testOutbound = prev })
	env := newTestEngine(t, "")
	user := env.newUser(t)

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	if _, err := env.e.CreateDestination(env.ctx, CreateDestinationInput{
		Type: DestinationWebhook, Name: "internal", Config: map[string]any{"url": srv.URL}, Secret: testWebhookSecret}); err != nil {
		t.Fatal(err)
	}
	payload := fmt.Sprintf(`{"user_id":%q,"purpose":"marketing.email"}`, user)
	if _, err := env.pool.Exec(env.ctx, `insert into dilion_privacy.outbox (event_type, aggregate_id, payload)
		values ('consent.reconfirm_due', $1, $2::jsonb)`, user, payload); err != nil {
		t.Fatal(err)
	}
	if err := env.e.dispatchOutboxOnce(env.ctx); err != nil {
		t.Fatal(err)
	}
	if err := env.e.runTasksOnce(env.ctx); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Fatalf("delivery reached a loopback receiver %d times", n)
	}
}

// A webhook's signature is only as good as its key.
func TestWebhookDestinationNeedsASecret(t *testing.T) {
	env := newTestEngine(t, "")
	for _, secret := range []string{"", "short"} {
		if _, err := env.e.CreateDestination(env.ctx, CreateDestinationInput{
			Type: DestinationWebhook, Name: "weak", Config: map[string]any{"url": "https://example.com/hook"}, Secret: secret}); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("secret %q: err = %v, want ErrInvalidInput", secret, err)
		}
	}
}

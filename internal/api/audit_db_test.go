package api

// Database-backed tests for GET /iam/v1/audit/events[/{eventId}]. Enable with:
//
//	docker exec dilion-pg createdb -U dilion dilion_test_d
//	DILION_TEST_DB=1 go test ./internal/api/...
//
// Override the DSN with DILION_TEST_DSN.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-project/dilion/httpapi"
	"github.com/dilion-project/dilion/internal/audit"
	"github.com/dilion-project/dilion/internal/iam"
	"github.com/dilion-project/dilion/ports"
)

const defaultTestDSN = "postgres://dilion:dilion@localhost:55432/dilion_test_d"

// migrationFiles: 0300 creates the audit tables, 0301 adds the reason column
// and the read-path indexes, 0302 seeds pii.write.
var migrationFiles = []string{
	"../../migrations/0300_iam_audit.sql",
	"../../migrations/0301_audit_reason.sql",
	"../../migrations/0302_pii_write_permission.sql",
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if os.Getenv("DILION_TEST_DB") == "" {
		t.Skip("DILION_TEST_DB not set; skipping database tests")
	}
	dsn := os.Getenv("DILION_TEST_DSN")
	if dsn == "" {
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
	applyMigrations(t, pool)
	// internal/audit runs its own tests against the same database and truncates
	// these tables; 730002 keeps the two packages from interleaving.
	lockAuditTables(t, pool)
	if _, err := pool.Exec(ctx, `truncate dilion_audit.events, dilion_audit.subjects`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	return pool
}

func applyMigrations(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()
	// `create schema if not exists` is not race-safe across packages.
	if _, err := conn.Exec(ctx, `select pg_advisory_lock(730001)`); err != nil {
		t.Fatalf("lock: %v", err)
	}
	defer conn.Exec(ctx, `select pg_advisory_unlock(730001)`) //nolint:errcheck
	for _, f := range migrationFiles {
		migration, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read migration %s: %v", f, err)
		}
		if _, err := conn.Exec(ctx, string(migration)); err != nil {
			t.Fatalf("apply migration %s: %v", f, err)
		}
	}
}

func lockAuditTables(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if _, err := conn.Exec(ctx, `select pg_advisory_lock(730002)`); err != nil {
		conn.Release()
		t.Fatalf("lock audit tables: %v", err)
	}
	t.Cleanup(func() {
		conn.Exec(ctx, `select pg_advisory_unlock(730002)`) //nolint:errcheck
		conn.Release()
	})
}

const otherUserID = "7b2f3c4d-5e6f-4a81-9203-b4c5d6e7f8a9"

// seedAuditEvents writes three events through the real sink, oldest first.
func seedAuditEvents(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	sink := audit.NewSink(pool)
	base := time.Date(2026, 8, 12, 3, 0, 0, 0, time.UTC)
	events := []ports.AuditEvent{
		{
			ActorID: "admin_alice", ActorType: "admin", Action: audit.ActionPIIFullRead,
			Resource: "user_profile:" + testUserID, AccessLevel: audit.AccessFull, ResultCount: 1,
			SubjectIDs: []string{testUserID}, Reason: "CS ticket #4417", OccurredAt: base,
		},
		{
			ActorID: "admin_bob", ActorType: "admin", Action: audit.ActionPrivacyRequestListRead,
			Resource: "privacy_requests", AccessLevel: audit.AccessMasked, ResultCount: 2,
			SubjectIDs: []string{testUserID, otherUserID}, OccurredAt: base.Add(time.Minute),
		},
		{
			ActorID: "admin_alice", ActorType: "admin", Action: audit.ActionPIIMaskedRead,
			Resource: "user_profile:" + otherUserID, AccessLevel: audit.AccessMasked, ResultCount: 1,
			SubjectIDs: []string{otherUserID}, OccurredAt: base.Add(2 * time.Minute),
		},
	}
	for i, e := range events {
		if err := sink.Append(ctx, e); err != nil {
			t.Fatalf("seed event %d: %v", i, err)
		}
	}
}

// auditAPI mounts the API with a real pool. The sink is in-memory so the
// assertions below see exactly the seeded rows.
func auditAPI(t *testing.T, pool *pgxpool.Pool) (humatest.TestAPI, *recordingSink) {
	t.Helper()
	sink := &recordingSink{}
	d := serviceRoleDeps(sink)
	d.Pool = pool
	return newAPI(t, &fakePrivacy{}, d), sink
}

func listEvents(t *testing.T, tapi humatest.TestAPI, query url.Values) AuditEventPage {
	t.Helper()
	path := "/iam/v1/audit/events"
	if len(query) > 0 {
		path += "?" + query.Encode()
	}
	resp := tapi.Get(path, bearer)
	if resp.Code != http.StatusOK {
		t.Fatalf("GET %s: status = %d (body=%s)", path, resp.Code, resp.Body.String())
	}
	var page AuditEventPage
	if err := json.Unmarshal(resp.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, resp.Body.String())
	}
	return page
}

func TestListAuditEventsFilters(t *testing.T) {
	pool := testPool(t)
	seedAuditEvents(t, pool)
	tapi, _ := auditAPI(t, pool)

	all := listEvents(t, tapi, nil)
	if len(all.Items) != 3 {
		t.Fatalf("items = %d, want 3", len(all.Items))
	}
	if all.Items[0].Action != audit.ActionPIIMaskedRead {
		t.Errorf("first item = %q, want the newest event", all.Items[0].Action)
	}
	if all.NextCursor != nil {
		t.Errorf("next_cursor = %v, want null", *all.NextCursor)
	}

	byActor := listEvents(t, tapi, url.Values{"actor_id": {"admin_alice"}})
	if len(byActor.Items) != 2 {
		t.Errorf("actor filter = %d items, want 2", len(byActor.Items))
	}

	byAction := listEvents(t, tapi, url.Values{"action": {audit.ActionPIIFullRead}})
	if len(byAction.Items) != 1 {
		t.Fatalf("action filter = %d items, want 1", len(byAction.Items))
	}
	ev := byAction.Items[0]
	if ev.Reason == nil || *ev.Reason != "CS ticket #4417" {
		t.Errorf("reason = %v, want the recorded justification", ev.Reason)
	}
	if ev.AccessLevel == nil || *ev.AccessLevel != audit.AccessFull {
		t.Errorf("access_level = %v, want full", ev.AccessLevel)
	}
	if ev.CreatedAt.IsZero() {
		t.Error("created_at missing")
	}
	if !httpapi.ValidID(ev.ID) {
		t.Errorf("event id %q violates the id convention", ev.ID)
	}
}

// The reverse lookup of §5.3, over HTTP: "who accessed subject X".
func TestListAuditEventsBySubjectID(t *testing.T) {
	pool := testPool(t)
	seedAuditEvents(t, pool)
	tapi, _ := auditAPI(t, pool)

	page := listEvents(t, tapi, url.Values{"subject_id": {testUserID}})
	if len(page.Items) != 2 {
		t.Fatalf("subject filter = %d items, want 2", len(page.Items))
	}
	seen := map[string]bool{}
	for _, e := range page.Items {
		if seen[e.ID] {
			t.Fatalf("event %s returned twice", e.ID)
		}
		seen[e.ID] = true
		// List rows never inline the manifest (§5.3).
		if len(e.SubjectIDs) != 0 {
			t.Errorf("event %s inlined subjects %v", e.ID, e.SubjectIDs)
		}
	}

	combined := listEvents(t, tapi, url.Values{
		"subject_id": {testUserID}, "actor_id": {"admin_alice"},
	})
	if len(combined.Items) != 1 || combined.Items[0].Action != audit.ActionPIIFullRead {
		t.Errorf("alice→subject events = %d items", len(combined.Items))
	}

	empty := listEvents(t, tapi, url.Values{"subject_id": {"no-such-subject"}})
	if len(empty.Items) != 0 {
		t.Errorf("unknown subject = %d items, want 0", len(empty.Items))
	}
	if empty.NextCursor != nil {
		t.Errorf("next_cursor = %v, want null", *empty.NextCursor)
	}
}

func TestListAuditEventsPagination(t *testing.T) {
	pool := testPool(t)
	seedAuditEvents(t, pool)
	tapi, _ := auditAPI(t, pool)

	first := listEvents(t, tapi, url.Values{"limit": {"2"}})
	if len(first.Items) != 2 || first.NextCursor == nil {
		t.Fatalf("first page = %d items, cursor %v", len(first.Items), first.NextCursor)
	}
	second := listEvents(t, tapi, url.Values{"limit": {"2"}, "cursor": {*first.NextCursor}})
	if len(second.Items) != 1 || second.NextCursor != nil {
		t.Fatalf("second page = %d items, cursor %v", len(second.Items), second.NextCursor)
	}
	for _, e := range first.Items {
		if e.ID == second.Items[0].ID {
			t.Error("pages overlap")
		}
	}

	resp := tapi.Get("/iam/v1/audit/events?cursor=!!not-base64!!", bearer)
	if resp.Code != http.StatusUnprocessableEntity {
		t.Fatalf("malformed cursor: status = %d, want 422 (body=%s)", resp.Code, resp.Body.String())
	}
	if p := decodeProblem(t, resp.Body.Bytes()); p.Code != httpapi.CodeValidationFailed {
		t.Errorf("code = %q, want validation_failed", p.Code)
	}
}

func TestGetAuditEventReturnsSubjectManifest(t *testing.T) {
	pool := testPool(t)
	seedAuditEvents(t, pool)
	tapi, _ := auditAPI(t, pool)

	listed := listEvents(t, tapi, url.Values{"action": {audit.ActionPrivacyRequestListRead}})
	if len(listed.Items) != 1 {
		t.Fatalf("seed lookup returned %d items", len(listed.Items))
	}
	id := listed.Items[0].ID

	resp := tapi.Get("/iam/v1/audit/events/"+id, bearer)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.Code, resp.Body.String())
	}
	var ev AuditEvent
	if err := json.Unmarshal(resp.Body.Bytes(), &ev); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(ev.SubjectIDs) != 2 {
		t.Errorf("subject manifest = %v, want both subjects", ev.SubjectIDs)
	}
	if ev.ActorID == nil || *ev.ActorID != "admin_bob" {
		t.Errorf("actor_id = %v", ev.ActorID)
	}
	if ev.ResultCount == nil || *ev.ResultCount != 2 {
		t.Errorf("result_count = %v", ev.ResultCount)
	}
	if ev.Reason != nil {
		t.Errorf("reason = %v, want null", *ev.Reason)
	}

	// Unknown id → 404; malformed id → 422 (never a 500).
	if resp := tapi.Get("/iam/v1/audit/events/"+httpapi.NewID("evt"), bearer); resp.Code != http.StatusNotFound {
		t.Errorf("unknown event: status = %d, want 404", resp.Code)
	}
	if resp := tapi.Get("/iam/v1/audit/events/not-an-id", bearer); resp.Code != http.StatusUnprocessableEntity {
		t.Errorf("malformed id: status = %d, want 422", resp.Code)
	}
}

// Reading the audit log must not append to it (no recursion, §5).
func TestAuditReadsAreNotThemselvesAudited(t *testing.T) {
	pool := testPool(t)
	seedAuditEvents(t, pool)
	tapi, sink := auditAPI(t, pool)

	before := countEvents(t, pool)
	listed := listEvents(t, tapi, nil)
	if resp := tapi.Get("/iam/v1/audit/events/"+listed.Items[0].ID, bearer); resp.Code != http.StatusOK {
		t.Fatalf("get: status = %d", resp.Code)
	}
	if after := countEvents(t, pool); after != before {
		t.Errorf("audit table grew from %d to %d rows while reading it", before, after)
	}
	// The guard still records the use of the all-powerful service_role key
	// (§2.11) — what must not appear is a read event for the read itself.
	for _, a := range sink.actions() {
		if a != audit.ActionServiceRoleUse {
			t.Errorf("unexpected audit action %q emitted by an audit read", a)
		}
	}
}

func countEvents(t *testing.T, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `select count(*) from dilion_audit.events`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// IAM configuration reads are auditable as IAM_READ (§5.2). The IAM handlers
// need a real pool, so this is a database test.
func TestIAMReadIsAudited(t *testing.T) {
	pool := testPool(t)
	tapi, sink := auditAPI(t, pool)

	resp := tapi.Get("/iam/v1/permissions", bearer)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.Code, resp.Body.String())
	}
	ev, ok := sink.find(audit.ActionIAMRead)
	if !ok {
		t.Fatalf("missing IAM_READ, got %v", sink.actions())
	}
	if ev.Resource != "permissions" {
		t.Errorf("resource = %q, want %q", ev.Resource, "permissions")
	}
	if ev.AccessLevel != audit.AccessNA {
		t.Errorf("access level = %q, want n/a", ev.AccessLevel)
	}
	if ev.ResultCount == 0 {
		t.Errorf("result_count = 0, want the seeded builtin permissions")
	}
	if len(ev.SubjectIDs) != 0 {
		t.Errorf("subject manifest = %v, want empty (IAM config is not subject data)", ev.SubjectIDs)
	}
}

// The holders report lists ACTOR ids; they must never land in the data-subject
// manifest (§5.3).
func TestPermissionHoldersReadKeepsSubjectManifestEmpty(t *testing.T) {
	pool := testPool(t)
	tapi, sink := auditAPI(t, pool)

	resp := tapi.Get("/iam/v1/permissions/"+iam.PermUsersRead+"/holders", bearer)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.Code, resp.Body.String())
	}
	ev, ok := sink.find(audit.ActionIAMRead)
	if !ok {
		t.Fatalf("missing IAM_READ, got %v", sink.actions())
	}
	if ev.Resource != "permission:"+iam.PermUsersRead+" holders" {
		t.Errorf("resource = %q", ev.Resource)
	}
	if len(ev.SubjectIDs) != 0 {
		t.Errorf("subject manifest = %v, want empty (holders are actors, not subjects)", ev.SubjectIDs)
	}
}

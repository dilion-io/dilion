package audit

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/ports"
)

func TestNopSink(t *testing.T) {
	if err := (NopSink{}).Append(context.Background(), ports.AuditEvent{Action: ActionUserListRead}); err != nil {
		t.Fatalf("NopSink.Append = %v", err)
	}
}

func TestSinkRequiresPoolAndAction(t *testing.T) {
	s := NewSink(nil)
	if err := s.Append(context.Background(), ports.AuditEvent{Action: ActionUserListRead}); err == nil {
		t.Error("expected an error with a nil pool")
	}
}

func TestActionConstantsAreUpperSnake(t *testing.T) {
	actions := []string{
		ActionUserListRead, ActionUserDetailRead, ActionPIIMaskedRead, ActionPIIFullRead,
		ActionPIIUpdate, ActionPIIExport, ActionPrivacyRequestCreated, ActionPrivacyRequestCanceled,
		ActionConsentChanged, ActionHoldCreated, ActionHoldReleased, ActionDestinationChanged,
		ActionRoleGranted, ActionRoleRevoked, ActionRoleCreated, ActionPermissionCreated,
		ActionAPIKeyCreated, ActionAPIKeyRevoked, ActionServiceRoleUse, ActionPermissionDenied,
	}
	seen := map[string]bool{}
	for _, a := range actions {
		if a == "" {
			t.Fatal("empty action constant")
		}
		for _, r := range a {
			if !(r >= 'A' && r <= 'Z') && r != '_' {
				t.Errorf("action %q is not UPPER_SNAKE_CASE", a)
				break
			}
		}
		if seen[a] {
			t.Errorf("duplicate action constant %q", a)
		}
		seen[a] = true
	}
}

// ---- database-backed ----

const defaultTestDSN = "postgres://dilion:dilion@localhost:55432/dilion_test_d"

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
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	applyMigration(t, pool)
	lockAuditTables(t, pool)
	if _, err := pool.Exec(ctx, `truncate dilion_audit.events, dilion_audit.subjects`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	return pool
}

// migrationFiles are applied in order by the package tests. 0301 adds the
// reason column and the read-path indexes; 0302 seeds the pii.write permission.
var migrationFiles = []string{
	"../../migrations/0300_iam_audit.sql",
	"../../migrations/0301_audit_reason.sql",
	"../../migrations/0302_pii_write_permission.sql",
}

// applyMigration runs the 03xx migrations under an advisory lock: `create
// schema if not exists` is not race-safe, and test packages run in parallel
// against the same database.
func applyMigration(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()
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

// lockAuditTables serializes tests that truncate dilion_audit.* — internal/api
// runs its own database-backed audit tests against the same database, and Go
// runs the two packages concurrently. The session lock is held for the whole
// test.
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

func TestAppendWritesEventAndSubjectManifest(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	sink := NewSink(pool)

	err := sink.Append(ctx, ports.AuditEvent{
		ActorID:     "admin_alice",
		ActorType:   "admin",
		Action:      ActionUserListRead,
		Resource:    "privacy_requests",
		AccessLevel: AccessMasked,
		RequestID:   "req_1",
		ResultCount: 2,
		SubjectIDs:  []string{"user-1", "user-2", "user-1", ""},
		IP:          "203.0.113.7",
		UserAgent:   "dilion-test",
		OccurredAt:  time.Date(2026, 8, 12, 3, 4, 5, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}

	var (
		eventID     string
		action      string
		resultCount int
		accessLevel string
		ip          string
	)
	if err := pool.QueryRow(ctx, `
		select event_id, action, result_count, access_level, ip from dilion_audit.events`).
		Scan(&eventID, &action, &resultCount, &accessLevel, &ip); err != nil {
		t.Fatalf("read event: %v", err)
	}
	if action != ActionUserListRead || resultCount != 2 || accessLevel != AccessMasked || ip != "203.0.113.7" {
		t.Errorf("event = %s/%d/%s/%s", action, resultCount, accessLevel, ip)
	}
	if len(eventID) != 4+32 || eventID[:4] != "evt_" {
		t.Errorf("event id %q does not follow the id convention", eventID)
	}

	rows, err := pool.Query(ctx, `select subject_id from dilion_audit.subjects where event_id = $1 order by subject_id`, eventID)
	if err != nil {
		t.Fatalf("read subjects: %v", err)
	}
	defer rows.Close()
	var subjects []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("scan: %v", err)
		}
		subjects = append(subjects, s)
	}
	if len(subjects) != 2 || subjects[0] != "user-1" || subjects[1] != "user-2" {
		t.Errorf("subject manifest = %v, want deduped [user-1 user-2] with blanks dropped", subjects)
	}
}

func TestAppendDefaultsProjectAndTimestamp(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	sink := NewSink(pool)

	if err := sink.Append(ctx, ports.AuditEvent{Action: ActionServiceRoleUse}); err != nil {
		t.Fatalf("append: %v", err)
	}
	var (
		createdAt time.Time
		actorID   *string
	)
	if err := pool.QueryRow(ctx, `select created_at, actor_id from dilion_audit.events`).
		Scan(&createdAt, &actorID); err != nil {
		t.Fatalf("read: %v", err)
	}
	if createdAt.IsZero() {
		t.Error("created_at not set")
	}
	if actorID != nil {
		t.Errorf("actor_id = %v, want NULL for system events", *actorID)
	}
}

func TestAppendRejectsEmptyAction(t *testing.T) {
	pool := testPool(t)
	if err := NewSink(pool).Append(context.Background(), ports.AuditEvent{}); err == nil {
		t.Error("expected an error for an event with no action")
	}
}

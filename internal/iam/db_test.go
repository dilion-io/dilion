package iam

import (
	"context"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/ports"
)

// These tests need Postgres. Enable with:
//
//	docker exec dilion-pg createdb -U dilion dilion_test_d
//	DILION_TEST_DB=1 go test ./internal/iam/...
//
// Override the DSN with DILION_TEST_DSN.
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
		t.Fatalf("connect %s: %v", dsn, err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping %s: %v", dsn, err)
	}

	applyMigration(t, pool)
	// Start from a clean, seed-only state.
	if _, err := pool.Exec(ctx, `
		truncate dilion_authz.role_assignments, dilion_authz.api_keys restart identity;
		delete from dilion_authz.roles where not builtin;
		delete from dilion_authz.permissions where not builtin;`); err != nil {
		t.Fatalf("reset: %v", err)
	}
	return pool
}

// migrationFiles are the 03xx migrations this package's schema depends on:
// 0300 (RBAC + audit tables), 0301 (audit reason column), 0302 (the pii.write
// builtin permission and its role bundles), 0303 (users.admin).
var migrationFiles = []string{
	"../../migrations/0300_iam_audit.sql",
	"../../migrations/0301_audit_reason.sql",
	"../../migrations/0302_pii_write_permission.sql",
	"../../migrations/0303_users_admin_permission.sql",
}

// applyMigration runs them under an advisory lock: `create schema if not
// exists` is not race-safe, and test packages run in parallel against the same
// database.
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

func newTestService(t *testing.T, pool *pgxpool.Pool) *Service {
	t.Helper()
	return New(pool)
}

func TestSeededBuiltins(t *testing.T) {
	pool := testPool(t)
	svc := newTestService(t, pool)
	ctx := context.Background()

	perms, err := svc.ListPermissions(ctx, DefaultProjectID, httpapi.ListParams{Limit: 100})
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	got := map[string]bool{}
	for _, p := range perms.Items {
		if !p.Builtin {
			t.Errorf("permission %q should be builtin", p.Name)
		}
		got[p.Name] = true
	}
	for _, want := range BuiltinPermissions {
		if !got[want] {
			t.Errorf("builtin permission %q not seeded", want)
		}
	}

	roles, err := svc.ListRoles(ctx, DefaultProjectID, httpapi.ListParams{Limit: 100})
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	byName := map[string]Role{}
	for _, r := range roles.Items {
		byName[r.Name] = r
	}
	for _, want := range []string{"viewer", "support", "privacy-officer", "security-admin", "owner"} {
		r, ok := byName[want]
		if !ok {
			t.Errorf("builtin role %q not seeded", want)
			continue
		}
		if !httpapi.ValidID(r.ID) {
			t.Errorf("role %q id %q does not match the id convention", want, r.ID)
		}
	}
	if owner := byName["owner"]; len(owner.Permissions) != len(BuiltinPermissions) {
		t.Errorf("owner holds %d permissions, want all %d", len(owner.Permissions), len(BuiltinPermissions))
	}
	if viewer := byName["viewer"]; len(viewer.Permissions) != 1 || viewer.Permissions[0] != PermUsersRead {
		t.Errorf("viewer permissions = %v, want [users.read]", byName["viewer"].Permissions)
	}
}

// Migration 0302 seeds pii.write and adds it to exactly three builtin bundles.
func TestPIIWriteSeededIntoBuiltinRoles(t *testing.T) {
	pool := testPool(t)
	svc := newTestService(t, pool)
	ctx := context.Background()

	perms, err := svc.ListPermissions(ctx, DefaultProjectID, httpapi.ListParams{Limit: 100})
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	found := false
	for _, p := range perms.Items {
		if p.Name == PermPIIWrite {
			found = true
			if !p.Builtin {
				t.Error("pii.write must be seeded as a builtin permission")
			}
		}
	}
	if !found {
		t.Fatal("pii.write not seeded by migration 0302")
	}
	// Being builtin makes the name reserved for custom permissions.
	if err := ValidateCustomPermission(PermPIIWrite); !errors.Is(err, ErrInvalid) {
		t.Errorf("ValidateCustomPermission(pii.write) = %v, want ErrInvalid", err)
	}

	roles, err := svc.ListRoles(ctx, DefaultProjectID, httpapi.ListParams{Limit: 100})
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	want := map[string]bool{
		"support": true, "privacy-officer": true, "owner": true,
		"viewer": false, "security-admin": false,
	}
	for _, r := range roles.Items {
		expected, ok := want[r.Name]
		if !ok {
			continue
		}
		if got := slices.Contains(r.Permissions, PermPIIWrite); got != expected {
			t.Errorf("role %q holds pii.write = %v, want %v (%v)", r.Name, got, expected, r.Permissions)
		}
		// Idempotence: re-applying 0302 must not duplicate the entry.
		n := 0
		for _, p := range r.Permissions {
			if p == PermPIIWrite {
				n++
			}
		}
		if n > 1 {
			t.Errorf("role %q lists pii.write %d times", r.Name, n)
		}
	}
}

// Migration 0303 seeds users.admin and bundles it into `owner` only.
func TestUsersAdminSeededIntoOwnerOnly(t *testing.T) {
	pool := testPool(t)
	svc := newTestService(t, pool)
	ctx := context.Background()

	perms, err := svc.ListPermissions(ctx, DefaultProjectID, httpapi.ListParams{Limit: 100})
	if err != nil {
		t.Fatalf("list permissions: %v", err)
	}
	found := false
	for _, p := range perms.Items {
		if p.Name == PermUsersAdmin {
			found = true
			if !p.Builtin {
				t.Error("users.admin must be seeded as a builtin permission")
			}
		}
	}
	if !found {
		t.Fatal("users.admin not seeded by migration 0303")
	}
	if err := ValidateCustomPermission(PermUsersAdmin); !errors.Is(err, ErrInvalid) {
		t.Errorf("ValidateCustomPermission(users.admin) = %v, want ErrInvalid", err)
	}

	roles, err := svc.ListRoles(ctx, DefaultProjectID, httpapi.ListParams{Limit: 100})
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	for _, r := range roles.Items {
		n := 0
		for _, p := range r.Permissions {
			if p == PermUsersAdmin {
				n++
			}
		}
		want := 0
		if r.Name == "owner" {
			want = 1
		}
		if n != want {
			t.Errorf("role %q lists users.admin %d times, want %d (%v)", r.Name, n, want, r.Permissions)
		}
	}
}

// A regular user access token is an ordinary RBAC actor: authority comes from
// role_assignments keyed by the user UUID, nothing else (§2.11).
func TestAuthorizerGrantsUserActorByAssignment(t *testing.T) {
	pool := testPool(t)
	svc := newTestService(t, pool)
	authz := NewAuthorizer(pool)
	ctx := context.Background()

	const userID = "6a1f2b3c-4d5e-4f70-8192-a3b4c5d6e7f8"
	actor := ports.Actor{ID: userID, Type: ActorTypeUser, ProjectID: DefaultProjectID}

	if ok, err := authz.Can(ctx, actor, PermUsersAdmin, "auth/admin"); err != nil || ok {
		t.Fatalf("unassigned user Can = (%v,%v), want (false,nil)", ok, err)
	}

	a, err := svc.GrantRole(ctx, DefaultProjectID, RoleOwner, userID, "admin_root")
	if err != nil {
		t.Fatalf("grant owner: %v", err)
	}
	if ok, err := authz.Can(ctx, actor, PermUsersAdmin, "auth/admin"); err != nil || !ok {
		t.Errorf("owner should hold users.admin, got (%v,%v)", ok, err)
	}

	if _, err := svc.RevokeAssignment(ctx, DefaultProjectID, a.ID, "admin_root"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if ok, err := authz.Can(ctx, actor, PermUsersAdmin, "auth/admin"); err != nil || ok {
		t.Errorf("revoked user Can = (%v,%v), want (false,nil)", ok, err)
	}
}

func TestAuthorizerUsesActiveAssignments(t *testing.T) {
	pool := testPool(t)
	svc := newTestService(t, pool)
	authz := NewAuthorizer(pool)
	ctx := context.Background()

	actor := ports.Actor{ID: "admin_alice", Type: ActorTypeAdmin, ProjectID: DefaultProjectID}

	// Deny by default.
	if ok, err := authz.Can(ctx, actor, PermUsersRead, ""); err != nil || ok {
		t.Fatalf("unassigned actor Can = (%v,%v), want (false,nil)", ok, err)
	}

	a, err := svc.GrantRole(ctx, DefaultProjectID, RoleSupport, actor.ID, "admin_root")
	if err != nil {
		t.Fatalf("grant: %v", err)
	}

	if ok, err := authz.Can(ctx, actor, PermPIIRead, ""); err != nil || !ok {
		t.Errorf("support should hold pii.read, got (%v,%v)", ok, err)
	}
	if ok, err := authz.Can(ctx, actor, PermPIIReveal, ""); err != nil || ok {
		t.Errorf("support must not hold pii.reveal, got (%v,%v)", ok, err)
	}
	// Cross-project isolation: no permission leaks into another project.
	other := ports.Actor{ID: actor.ID, Type: ActorTypeAdmin, ProjectID: "other"}
	if ok, err := authz.Can(ctx, other, PermPIIRead, ""); err != nil || ok {
		t.Errorf("cross-project Can = (%v,%v), want (false,nil)", ok, err)
	}

	// Revoking preserves history but removes authority.
	if _, err := svc.RevokeAssignment(ctx, DefaultProjectID, a.ID, "admin_root"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if ok, err := authz.Can(ctx, actor, PermPIIRead, ""); err != nil || ok {
		t.Errorf("revoked actor Can = (%v,%v), want (false,nil)", ok, err)
	}

	active, err := svc.ListAssignments(ctx, DefaultProjectID, AssignmentFilter{ActorID: actor.ID}, httpapi.ListParams{})
	if err != nil {
		t.Fatalf("list assignments: %v", err)
	}
	if len(active.Items) != 0 {
		t.Errorf("active assignments = %d, want 0", len(active.Items))
	}
	history, err := svc.ListAssignments(ctx, DefaultProjectID,
		AssignmentFilter{ActorID: actor.ID, IncludeRevoked: true}, httpapi.ListParams{})
	if err != nil {
		t.Fatalf("list history: %v", err)
	}
	if len(history.Items) != 1 {
		t.Fatalf("history rows = %d, want 1 (권한 이력 보존)", len(history.Items))
	}
	h := history.Items[0]
	if h.RevokedAt == nil || h.RevokedBy == nil || *h.RevokedBy != "admin_root" {
		t.Errorf("revocation metadata missing: %+v", h)
	}
	if h.GrantedBy == nil || *h.GrantedBy != "admin_root" {
		t.Errorf("grant metadata missing: %+v", h)
	}
}

func TestGrantRoleErrors(t *testing.T) {
	pool := testPool(t)
	svc := newTestService(t, pool)
	ctx := context.Background()

	if _, err := svc.GrantRole(ctx, DefaultProjectID, "role_ffffffffffffffffffffffffffffffff", "a", "root"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown role: err = %v, want ErrNotFound", err)
	}
	if _, err := svc.GrantRole(ctx, DefaultProjectID, RoleViewer, "  ", "root"); !errors.Is(err, ErrInvalid) {
		t.Errorf("blank actor: err = %v, want ErrInvalid", err)
	}
	if _, err := svc.GrantRole(ctx, DefaultProjectID, RoleViewer, "dup", "root"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if _, err := svc.GrantRole(ctx, DefaultProjectID, RoleViewer, "dup", "root"); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate grant: err = %v, want ErrConflict", err)
	}
}

func TestRevokeAssignmentErrors(t *testing.T) {
	pool := testPool(t)
	svc := newTestService(t, pool)
	ctx := context.Background()

	if _, err := svc.RevokeAssignment(ctx, DefaultProjectID, 999999, "root"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown assignment: err = %v, want ErrNotFound", err)
	}
	a, err := svc.GrantRole(ctx, DefaultProjectID, RoleViewer, "bob", "root")
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if _, err := svc.RevokeAssignment(ctx, DefaultProjectID, a.ID, "root"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.RevokeAssignment(ctx, DefaultProjectID, a.ID, "root"); !errors.Is(err, ErrConflict) {
		t.Errorf("double revoke: err = %v, want ErrConflict", err)
	}
}

func TestCustomPermissionsAndRoles(t *testing.T) {
	pool := testPool(t)
	svc := newTestService(t, pool)
	ctx := context.Background()

	if _, err := svc.CreatePermission(ctx, DefaultProjectID, "orders"); !errors.Is(err, ErrInvalid) {
		t.Errorf("un-namespaced permission: err = %v, want ErrInvalid", err)
	}
	if _, err := svc.CreatePermission(ctx, DefaultProjectID, PermUsersRead); !errors.Is(err, ErrInvalid) {
		t.Errorf("builtin collision: err = %v, want ErrInvalid", err)
	}
	p, err := svc.CreatePermission(ctx, DefaultProjectID, "myapp.orders.refund")
	if err != nil {
		t.Fatalf("create permission: %v", err)
	}
	if p.Builtin {
		t.Error("custom permission marked builtin")
	}
	if _, err := svc.CreatePermission(ctx, DefaultProjectID, "myapp.orders.refund"); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate permission: err = %v, want ErrConflict", err)
	}

	if _, err := svc.CreateRole(ctx, DefaultProjectID, "refunder", []string{"myapp.nope"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown permission in role: err = %v, want ErrInvalid", err)
	}
	if _, err := svc.CreateRole(ctx, DefaultProjectID, "refunder", nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty role: err = %v, want ErrInvalid", err)
	}
	role, err := svc.CreateRole(ctx, DefaultProjectID, "refunder",
		[]string{"myapp.orders.refund", PermUsersRead, "myapp.orders.refund"})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if len(role.Permissions) != 2 {
		t.Errorf("permissions = %v, want deduped pair", role.Permissions)
	}
	if !httpapi.ValidID(role.ID) {
		t.Errorf("role id %q violates the id convention", role.ID)
	}
	if _, err := svc.CreateRole(ctx, DefaultProjectID, "refunder", []string{PermUsersRead}); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate role name: err = %v, want ErrConflict", err)
	}

	// The custom permission is decidable by the Authorizer.
	authz := NewAuthorizer(pool)
	actor := ports.Actor{ID: "admin_carol", Type: ActorTypeAdmin, ProjectID: DefaultProjectID}
	if _, err := svc.GrantRole(ctx, DefaultProjectID, role.ID, actor.ID, "root"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if ok, err := authz.Can(ctx, actor, "myapp.orders.refund", ""); err != nil || !ok {
		t.Errorf("custom permission Can = (%v,%v), want (true,nil)", ok, err)
	}
}

func TestRecertification(t *testing.T) {
	pool := testPool(t)
	svc := newTestService(t, pool)
	ctx := context.Background()

	if _, err := svc.GrantRole(ctx, DefaultProjectID, RoleOwner, "admin_dana", "root"); err != nil {
		t.Fatalf("grant owner: %v", err)
	}
	if _, err := svc.GrantRole(ctx, DefaultProjectID, RoleViewer, "admin_erin", "root"); err != nil {
		t.Fatalf("grant viewer: %v", err)
	}

	holders, err := svc.Recertification(ctx, DefaultProjectID, PermPIIReveal)
	if err != nil {
		t.Fatalf("recertification: %v", err)
	}
	if len(holders) != 1 || holders[0].ActorID != "admin_dana" {
		t.Fatalf("pii.reveal holders = %+v, want only admin_dana", holders)
	}
	if holders[0].RoleName != "owner" || holders[0].GrantedBy == nil || *holders[0].GrantedBy != "root" {
		t.Errorf("grant metadata = %+v", holders[0])
	}

	readers, err := svc.Recertification(ctx, DefaultProjectID, PermUsersRead)
	if err != nil {
		t.Fatalf("recertification: %v", err)
	}
	if len(readers) != 2 {
		t.Errorf("users.read holders = %d, want 2", len(readers))
	}

	if _, err := svc.Recertification(ctx, DefaultProjectID, " "); !errors.Is(err, ErrInvalid) {
		t.Errorf("blank permission: err = %v, want ErrInvalid", err)
	}
}

func TestAPIKeyLifecycle(t *testing.T) {
	pool := testPool(t)
	svc := newTestService(t, pool)
	authz := NewAuthorizer(pool)
	ctx := context.Background()

	token, key, err := svc.CreateKey(ctx, DefaultProjectID, "ci", []string{PermUsersRead, PermPIIRead}, nil)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	if !ValidTokenFormat(token) {
		t.Errorf("token %q does not match dk_<48>", token)
	}
	if !httpapi.ValidID(key.ID) {
		t.Errorf("key id %q violates the id convention", key.ID)
	}
	if key.LastUsedAt != nil {
		t.Error("last_used_at should be null before first use")
	}

	// The plaintext token must not be recoverable from storage.
	var stored []byte
	if err := pool.QueryRow(ctx, `select key_hash from dilion_authz.api_keys where id = $1`, key.ID).Scan(&stored); err != nil {
		t.Fatalf("read hash: %v", err)
	}
	if string(stored) != string(HashToken(token)) {
		t.Error("stored hash is not SHA-256 of the issued token")
	}

	actor, scopes, err := svc.VerifyKey(ctx, token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if actor.ID != key.ID || actor.Type != ActorTypeAPIKey || actor.ProjectID != DefaultProjectID {
		t.Errorf("actor = %+v", actor)
	}
	if len(scopes) != 2 {
		t.Errorf("scopes = %v", scopes)
	}

	// last_used_at is bumped.
	var lastUsed *time.Time
	if err := pool.QueryRow(ctx, `select last_used_at from dilion_authz.api_keys where id = $1`, key.ID).Scan(&lastUsed); err != nil {
		t.Fatalf("read last_used_at: %v", err)
	}
	if lastUsed == nil {
		t.Error("last_used_at not bumped by VerifyKey")
	}

	// The key's scopes decide authorization, without any role assignment.
	if ok, err := authz.Can(ctx, *actor, PermPIIRead, ""); err != nil || !ok {
		t.Errorf("in-scope Can = (%v,%v), want (true,nil)", ok, err)
	}
	if ok, err := authz.Can(ctx, *actor, PermPIIReveal, ""); err != nil || ok {
		t.Errorf("out-of-scope Can = (%v,%v), want (false,nil)", ok, err)
	}

	// Unknown and malformed tokens are rejected identically.
	if _, _, err := svc.VerifyKey(ctx, NewToken()); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("unknown token: err = %v, want ErrUnauthenticated", err)
	}
	if _, _, err := svc.VerifyKey(ctx, "not-a-token"); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("malformed token: err = %v, want ErrUnauthenticated", err)
	}

	// Revocation is immediate and not repeatable.
	if _, err := svc.RevokeKey(ctx, DefaultProjectID, key.ID, "root"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, _, err := svc.VerifyKey(ctx, token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("revoked token: err = %v, want ErrUnauthenticated", err)
	}
	if ok, err := authz.Can(ctx, *actor, PermPIIRead, ""); err != nil || ok {
		t.Errorf("revoked key Can = (%v,%v), want (false,nil)", ok, err)
	}
	if _, err := svc.RevokeKey(ctx, DefaultProjectID, key.ID, "root"); !errors.Is(err, ErrConflict) {
		t.Errorf("double revoke: err = %v, want ErrConflict", err)
	}
	if _, err := svc.RevokeKey(ctx, DefaultProjectID, "key_ffffffffffffffffffffffffffffffff", "root"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown key revoke: err = %v, want ErrNotFound", err)
	}
}

func TestAPIKeyExpiry(t *testing.T) {
	pool := testPool(t)
	svc := newTestService(t, pool)
	ctx := context.Background()

	past := time.Now().UTC().Add(-time.Minute)
	if _, _, err := svc.CreateKey(ctx, DefaultProjectID, "stale", []string{PermUsersRead}, &past); !errors.Is(err, ErrInvalid) {
		t.Errorf("past expiry: err = %v, want ErrInvalid", err)
	}
	if _, _, err := svc.CreateKey(ctx, DefaultProjectID, "noscope", nil, nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("no scopes: err = %v, want ErrInvalid", err)
	}
	if _, _, err := svc.CreateKey(ctx, DefaultProjectID, "bogus", []string{"myapp.unknown"}, nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("unregistered scope: err = %v, want ErrInvalid", err)
	}

	soon := time.Now().UTC().Add(time.Hour)
	token, _, err := svc.CreateKey(ctx, DefaultProjectID, "short", []string{PermUsersRead}, &soon)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	if _, _, err := svc.VerifyKey(ctx, token); err != nil {
		t.Fatalf("verify before expiry: %v", err)
	}
	// Move the service clock past the expiry instead of sleeping.
	svc.now = func() time.Time { return soon.Add(time.Second) }
	if _, _, err := svc.VerifyKey(ctx, token); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("expired token: err = %v, want ErrUnauthenticated", err)
	}
}

func TestListPaginationAcrossPages(t *testing.T) {
	pool := testPool(t)
	svc := newTestService(t, pool)
	ctx := context.Background()

	for _, actor := range []string{"a1", "a2", "a3"} {
		if _, err := svc.GrantRole(ctx, DefaultProjectID, RoleViewer, actor, "root"); err != nil {
			t.Fatalf("grant: %v", err)
		}
	}
	first, err := svc.ListAssignments(ctx, DefaultProjectID, AssignmentFilter{}, httpapi.ListParams{Limit: 2})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(first.Items) != 2 || first.NextCursor == nil {
		t.Fatalf("first page = %d items, cursor %v", len(first.Items), first.NextCursor)
	}
	second, err := svc.ListAssignments(ctx, DefaultProjectID, AssignmentFilter{},
		httpapi.ListParams{Limit: 2, Cursor: *first.NextCursor})
	if err != nil {
		t.Fatalf("list page 2: %v", err)
	}
	if len(second.Items) != 1 || second.NextCursor != nil {
		t.Fatalf("second page = %d items, cursor %v", len(second.Items), second.NextCursor)
	}
	if second.Items[0].ID <= first.Items[1].ID {
		t.Error("pages overlap")
	}
}

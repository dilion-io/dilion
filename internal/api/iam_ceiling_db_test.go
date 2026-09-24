package api

// Database-backed tests for the grant ceiling: nobody can hand out a
// permission they do not hold. Enable with:
//
//	DILION_TEST_DB=1 go test ./internal/api/...

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/internal/iam"
	"github.com/dilion-io/dilion/internal/store"
	"github.com/dilion-io/dilion/ports"
)

// ceilingEnv is the IAM API as one user sees it, authorized by the real RBAC
// Authorizer from that user's role assignments.
type ceilingEnv struct {
	api  humatest.TestAPI
	pool *pgxpool.Pool
	svc  *iam.Service
	user string
}

func newCeilingEnv(t *testing.T, roles ...string) *ceilingEnv {
	t.Helper()
	pool := testPool(t)
	ctx := context.Background()
	if err := store.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	svc := iam.New(pool)
	user := uuid.NewString()
	for _, role := range roles {
		if _, err := svc.GrantRole(ctx, role, user, "root"); err != nil {
			t.Fatalf("grant %s: %v", role, err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `delete from dilion_authz.role_assignments where actor_id = $1 or granted_by = $1`, user)
		_, _ = pool.Exec(bg, `delete from dilion_authz.api_keys where created_by = $1`, user)
		_, _ = pool.Exec(bg, `delete from dilion_authz.roles where not builtin and name like 'ceiling-%'`)
	})
	_, tapi := humatest.New(t, NewConfig())
	RegisterIAMAPI(tapi, Deps{
		Pool:     pool,
		Verifier: fakeVerifier{claims: &ports.Claims{Subject: user, Role: "authenticated"}},
		Authz:    iam.NewAuthorizer(pool),
		Audit:    &recordingSink{},
	})
	return &ceilingEnv{api: tapi, pool: pool, svc: svc, user: user}
}

func (e *ceilingEnv) activeRoles(t *testing.T, actor string) []string {
	t.Helper()
	var roles []string
	if err := e.pool.QueryRow(context.Background(), `select coalesce(array_agg(role_id), '{}')
		from dilion_authz.role_assignments where actor_id = $1 and revoked_at is null`, actor).Scan(&roles); err != nil {
		t.Fatalf("roles: %v", err)
	}
	return roles
}

func wantDenied(t *testing.T, what string, code int, body string, missing string) {
	t.Helper()
	if code != http.StatusForbidden || !strings.Contains(body, missing) {
		t.Errorf("%s = %d %s, want 403 naming %s", what, code, body, missing)
	}
}

// A security-admin administers roles, but cannot use that to rise above
// itself: not by granting itself owner, nor by bundling or minting what it
// lacks.
func TestGrantCeilingStopsSecurityAdminEscalating(t *testing.T) {
	e := newCeilingEnv(t, iam.RoleSecurityAdmin)

	resp := e.api.Post("/iam/v1/roles/"+iam.RoleOwner+"/assignments", bearer, map[string]any{"actor_id": e.user})
	wantDenied(t, "granting itself owner", resp.Code, resp.Body.String(), iam.PermUsersAdmin)
	for _, r := range e.activeRoles(t, e.user) {
		if r == iam.RoleOwner {
			t.Fatal("security-admin now holds owner")
		}
	}

	resp = e.api.Post("/iam/v1/roles", bearer, map[string]any{
		"name": "ceiling-admin", "permissions": []string{iam.PermUsersRead, iam.PermUsersAdmin}})
	wantDenied(t, "creating a role with users.admin", resp.Code, resp.Body.String(), iam.PermUsersAdmin)

	resp = e.api.Post("/iam/v1/api-keys", bearer, map[string]any{"scopes": []string{iam.PermPIIReveal}})
	wantDenied(t, "minting a pii.reveal key", resp.Code, resp.Body.String(), iam.PermPIIReveal)

	// Within its own permissions it still works.
	if resp = e.api.Post("/iam/v1/roles", bearer, map[string]any{
		"name": "ceiling-reader", "permissions": []string{iam.PermUsersRead, iam.PermAuditRead}}); resp.Code != http.StatusCreated {
		t.Fatalf("creating a role within its permissions = %d %s", resp.Code, resp.Body.String())
	}
	if resp = e.api.Post("/iam/v1/api-keys", bearer, map[string]any{"scopes": []string{iam.PermUsersRead}}); resp.Code != http.StatusCreated {
		t.Fatalf("minting a key within its permissions = %d %s", resp.Code, resp.Body.String())
	}
	if resp = e.api.Post("/iam/v1/roles/"+iam.RoleViewer+"/assignments", bearer,
		map[string]any{"actor_id": uuid.NewString()}); resp.Code != http.StatusCreated {
		t.Fatalf("granting viewer = %d %s", resp.Code, resp.Body.String())
	}
}

// Taking owner away from someone is also beyond a security-admin: it would let
// it lock out those above it.
func TestGrantCeilingCoversRevocation(t *testing.T) {
	e := newCeilingEnv(t, iam.RoleSecurityAdmin)
	owner := uuid.NewString()
	a, err := e.svc.GrantRole(context.Background(), iam.RoleOwner, owner, e.user)
	if err != nil {
		t.Fatalf("grant owner: %v", err)
	}
	t.Cleanup(func() {
		_, _ = e.pool.Exec(context.Background(), `delete from dilion_authz.role_assignments where actor_id = $1`, owner)
	})
	resp := e.api.Delete("/iam/v1/assignments/"+strconv.FormatInt(a.ID, 10), bearer)
	wantDenied(t, "revoking an owner", resp.Code, resp.Body.String(), iam.PermUsersAdmin)
	if len(e.activeRoles(t, owner)) != 1 {
		t.Fatal("the owner assignment was revoked")
	}
}

// keys.manage no longer administers roles: that is roles.manage's job.
func TestRoleAdministrationNeedsRolesManage(t *testing.T) {
	e := newCeilingEnv(t)
	keysOnly, err := e.svc.CreateRole(context.Background(), "ceiling-keys-only",
		[]string{iam.PermKeysManage, iam.PermUsersRead})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if _, err := e.svc.GrantRole(context.Background(), keysOnly.ID, e.user, "root"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	resp := e.api.Post("/iam/v1/roles/"+iam.RoleViewer+"/assignments", bearer, map[string]any{"actor_id": uuid.NewString()})
	wantDenied(t, "granting a role with keys.manage only", resp.Code, resp.Body.String(), iam.PermRolesManage)
	if resp = e.api.Post("/iam/v1/api-keys", bearer, map[string]any{"scopes": []string{iam.PermUsersRead}}); resp.Code != http.StatusCreated {
		t.Errorf("minting a key with keys.manage = %d %s", resp.Code, resp.Body.String())
	}
}

// A custom role's permissions can be replaced — by someone holding both the
// old and the new set — and a builtin role's cannot.
func TestUpdateRole(t *testing.T) {
	e := newCeilingEnv(t, iam.RoleSecurityAdmin)
	resp := e.api.Post("/iam/v1/roles", bearer, map[string]any{
		"name": "ceiling-editable", "permissions": []string{iam.PermUsersRead}})
	if resp.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", resp.Code, resp.Body.String())
	}
	var role Role
	_ = json.Unmarshal(resp.Body.Bytes(), &role)

	resp = e.api.Patch("/iam/v1/roles/"+role.ID, bearer, map[string]any{
		"permissions": []string{iam.PermUsersRead, iam.PermAuditRead}})
	if resp.Code != http.StatusOK {
		t.Fatalf("update = %d %s", resp.Code, resp.Body.String())
	}
	resp = e.api.Get("/iam/v1/roles/"+role.ID, bearer)
	var got Role
	_ = json.Unmarshal(resp.Body.Bytes(), &got)
	if resp.Code != http.StatusOK || len(got.Permissions) != 2 {
		t.Fatalf("get after update = %d %s", resp.Code, resp.Body.String())
	}

	resp = e.api.Patch("/iam/v1/roles/"+role.ID, bearer, map[string]any{
		"permissions": []string{iam.PermUsersAdmin}})
	wantDenied(t, "adding users.admin", resp.Code, resp.Body.String(), iam.PermUsersAdmin)

	// Stripping a role that holds more than the caller is refused too: it
	// changes what that role's holders can do.
	stronger, err := e.svc.CreateRole(context.Background(), "ceiling-stronger",
		[]string{iam.PermUsersRead, iam.PermUsersAdmin})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	resp = e.api.Patch("/iam/v1/roles/"+stronger.ID, bearer, map[string]any{
		"permissions": []string{iam.PermUsersRead}})
	wantDenied(t, "removing users.admin", resp.Code, resp.Body.String(), iam.PermUsersAdmin)

	resp = e.api.Patch("/iam/v1/roles/"+iam.RoleViewer, bearer, map[string]any{
		"permissions": []string{iam.PermUsersRead, iam.PermAuditRead}})
	if resp.Code != http.StatusUnprocessableEntity {
		t.Errorf("updating a builtin role = %d %s, want 422", resp.Code, resp.Body.String())
	}
}

// Configuration lists page up to 1000 at a time; lists of people stay at 100.
func TestCatalogListLimit(t *testing.T) {
	e := newCeilingEnv(t, iam.RoleSecurityAdmin)
	for _, path := range []string{"/iam/v1/roles", "/iam/v1/permissions", "/iam/v1/api-keys"} {
		if resp := e.api.Get(path+"?limit=1000", bearer); resp.Code != http.StatusOK {
			t.Errorf("%s?limit=1000 = %d %s", path, resp.Code, resp.Body.String())
		}
		if resp := e.api.Get(path+"?limit=1001", bearer); resp.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s?limit=1001 = %d, want 422", path, resp.Code)
		}
	}
	if resp := e.api.Get("/iam/v1/roles/"+iam.RoleViewer+"/assignments?limit=101", bearer); resp.Code != http.StatusUnprocessableEntity {
		t.Errorf("assignments?limit=101 = %d, want 422", resp.Code)
	}
}

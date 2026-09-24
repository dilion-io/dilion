package auth

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/dilion-io/dilion/internal/iam"
)

// grantRole assigns a builtin or custom role to a user id.
func grantRole(t *testing.T, e *testEnv, userID, roleID string) {
	t.Helper()
	if _, err := e.pool.Exec(context.Background(), `
		insert into dilion_authz.role_assignments (actor_id, role_id, granted_by) values ($1, $2, 'test')`,
		userID, roleID); err != nil {
		t.Fatalf("grant %s: %v", roleID, err)
	}
	t.Cleanup(func() {
		_, _ = e.pool.Exec(context.Background(), `delete from dilion_authz.role_assignments where actor_id = $1`, userID)
	})
}

// adminOnly creates a custom role holding users.admin alone — a help desk.
func adminOnly(t *testing.T, e *testEnv) string {
	t.Helper()
	role, err := iam.New(e.pool).CreateRole(context.Background(), "helpdesk-"+uuid.NewString()[:8], []string{PermUsersAdmin})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	t.Cleanup(func() {
		_, _ = e.pool.Exec(context.Background(), `delete from dilion_authz.roles where id = $1`, role.ID)
	})
	return role.ID
}

// users.admin administers accounts; it is not a way to the owner's.
func TestUsersAdminCannotTakeOverAStrongerAccount(t *testing.T) {
	env := newTestEnv(t)
	applyAuthzSchema(t, env.pool)
	r := env.routerWith(iam.NewAuthorizer(env.pool))
	env.router = r

	helpdesk := uuid.NewString()
	grantRole(t, env, helpdesk, adminOnly(t, env))
	token := env.userToken(t, helpdesk)

	owner := env.signup(t, "the-owner@example.com", "correct-horse-battery")
	grantRole(t, env, owner.User.ID, iam.RoleOwner)
	plain := env.signup(t, "plain-user@example.com", "correct-horse-battery")

	for name, rec := range map[string]int{
		"reset the owner's password": env.do(t, http.MethodPut, "/admin/users/"+owner.User.ID,
			map[string]any{"password": "attacker-chosen-1"}, token).Code,
		"mint a recovery link for the owner": env.do(t, http.MethodPost, "/admin/generate_link",
			map[string]any{"type": "recovery", "email": "the-owner@example.com"}, token).Code,
		"delete the owner": env.do(t, http.MethodDelete, "/admin/users/"+owner.User.ID, nil, token).Code,
	} {
		if rec != http.StatusForbidden {
			t.Errorf("%s = %d, want 403", name, rec)
		}
	}
	if code := env.do(t, http.MethodPut, "/admin/users/"+plain.User.ID,
		map[string]any{"user_metadata": map[string]any{"note": "ok"}}, token).Code; code != http.StatusOK {
		t.Errorf("updating an account without roles = %d, want 200", code)
	}

	// Recreating an account under the id of one holding roles would inherit
	// them.
	orphan := uuid.NewString()
	grantRole(t, env, orphan, iam.RoleOwner)
	if code := env.do(t, http.MethodPost, "/admin/users",
		map[string]any{"id": orphan, "email": "reborn@example.com", "password": "correct-horse-battery"}, token).Code; code != http.StatusForbidden {
		t.Errorf("creating a user under an owner's id = %d, want 403", code)
	}
}

// The instance's auth configuration is the owner's alone, and audit reading
// needs audit.read on top of users.admin.
func TestAuthSettingsAreOwnerOnly(t *testing.T) {
	env := newTestEnv(t)
	applyAuthzSchema(t, env.pool)
	env.router = env.routerWith(iam.NewAuthorizer(env.pool))

	helpdesk := uuid.NewString()
	grantRole(t, env, helpdesk, adminOnly(t, env))
	owner := uuid.NewString()
	grantRole(t, env, owner, iam.RoleOwner)

	for _, path := range []string{"/admin/hooks", "/admin/custom-providers", "/admin/sso/providers", "/admin/audit"} {
		if code := env.do(t, http.MethodGet, path, nil, env.userToken(t, helpdesk)).Code; code != http.StatusForbidden {
			t.Errorf("GET %s as users.admin only = %d, want 403", path, code)
		}
	}
	if code := env.do(t, http.MethodGet, "/admin/hooks", nil, env.userToken(t, owner)).Code; code != http.StatusOK {
		t.Errorf("GET /admin/hooks as owner = %d, want 200", code)
	}
	if code := env.do(t, http.MethodGet, "/admin/hooks", nil, env.serviceRoleToken(t)).Code; code != http.StatusOK {
		t.Errorf("GET /admin/hooks as service_role = %d, want 200", code)
	}

	svc := iam.New(env.pool)
	if _, err := svc.CreateRole(context.Background(), "settings-"+uuid.NewString()[:8],
		[]string{PermAuthSettingsManage}); err == nil {
		t.Error("a custom role could bundle auth.settings.manage")
	}
	if _, _, err := svc.CreateKey(context.Background(), "settings", []string{PermAuthSettingsManage}, nil); err == nil {
		t.Error("an API key could be scoped to auth.settings.manage")
	}
}

package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/internal/iam"
	"github.com/dilion-io/dilion/ports"
)

// The compat surface mirrors two iam constants instead of importing the
// management plane. This test is the guard against drift.
func TestRBACConstantsMirrorIAM(t *testing.T) {
	if PermAuthSettingsManage != iam.PermAuthSettingsManage || PermAuditRead != iam.PermAuditRead {
		t.Errorf("auth mirrors of iam permissions drifted")
	}
	if PermUsersAdmin != iam.PermUsersAdmin {
		t.Errorf("PermUsersAdmin = %q, want %q", PermUsersAdmin, iam.PermUsersAdmin)
	}
	if ActorTypeUser != iam.ActorTypeUser {
		t.Errorf("ActorTypeUser = %q, want %q", ActorTypeUser, iam.ActorTypeUser)
	}
	if RoleAuthenticated != iam.RoleAuthenticated {
		t.Errorf("RoleAuthenticated = %q, want %q", RoleAuthenticated, iam.RoleAuthenticated)
	}
}

func TestAdminUserRoleRejectsMachineCredentials(t *testing.T) {
	for _, role := range []string{RoleServiceRole, "SERVICE_ROLE", "supabase_admin"} {
		if _, err := validateAdminUserRole(role); err == nil {
			t.Errorf("validateAdminUserRole(%q) accepted a reserved role", role)
		}
	}
	for _, role := range []string{"", RoleAuthenticated, "custom_rls_role"} {
		got, err := validateAdminUserRole(role)
		if err != nil {
			t.Errorf("validateAdminUserRole(%q): %v", role, err)
		}
		if role == "" && got != RoleAuthenticated {
			t.Errorf("empty role = %q, want %q", got, RoleAuthenticated)
		}
	}
}

func TestAdminRoleEscalationRejectedWithoutMutation(t *testing.T) {
	env := newTestEnv(t)
	user := env.signup(t, "role-target@example.test", "hunter22").User
	env.router = env.routerWith(&stubAuthorizer{allow: map[string]bool{PermUsersAdmin: true}})
	for _, bearer := range []string{env.userToken(t, user.ID), env.serviceRoleToken(t)} {
		for _, role := range []string{"service_role", "supabase_admin", " SERVICE_ROLE "} {
			for _, method := range []string{http.MethodPost, http.MethodPut} {
				path := "/admin/users"
				if method == http.MethodPut {
					path += "/" + user.ID
				}
				rec := env.do(t, method, path, map[string]any{
					"email": "role-escalation@example.test", "role": role,
				}, bearer)
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("%s %s role %q: %d %s", method, path, role, rec.Code, rec.Body.String())
				}
			}
		}
	}
	var email, role string
	if err := env.pool.QueryRow(context.Background(), "select email, role from auth.users where id=$1", user.ID).Scan(&email, &role); err != nil {
		t.Fatal(err)
	}
	if email != user.Email || role != RoleAuthenticated {
		t.Fatalf("rejected update changed user: %s %s", email, role)
	}
	var n int
	if err := env.pool.QueryRow(context.Background(), "select count(*) from auth.users where email='role-escalation@example.test'").Scan(&n); err != nil || n != 0 {
		t.Fatalf("rejected create persisted user: %d %v", n, err)
	}
}

func TestLegacyMachineRoleCannotEscapeThroughUserTokens(t *testing.T) {
	env := newTestEnv(t)
	first := env.signup(t, "legacy-role@example.test", "hunter22")
	for _, role := range []string{"service_role", "supabase_admin", " SERVICE_ROLE "} {
		if _, err := env.pool.Exec(context.Background(), "update auth.users set role=$1 where id=$2", role, first.User.ID); err != nil {
			t.Fatal(err)
		}
		login := decodeInto[AccessTokenResponse](t, env.do(t, http.MethodPost, "/token?grant_type=password",
			map[string]any{"email": first.User.Email, "password": "hunter22"}, ""), http.StatusOK)
		refreshed := decodeInto[AccessTokenResponse](t, env.do(t, http.MethodPost, "/token?grant_type=refresh_token",
			map[string]any{"refresh_token": login.RefreshToken}, ""), http.StatusOK)
		a := newAPI(Deps{Pool: env.pool, Tokens: env.tokens, Hooks: env.hooks})
		legacy := *first.User
		legacy.Role = role
		oauthToken, _, err := a.issueOAuthAccessToken(context.Background(), env.pool, &legacy,
			"00000000-0000-4000-8000-000000000099", "test-client", "openid")
		if err != nil {
			t.Fatal(err)
		}
		for _, token := range []string{login.Token, refreshed.Token, oauthToken} {
			claims, err := env.tokens.Verify(context.Background(), token)
			if err != nil || claims.Role != RoleAuthenticated {
				t.Fatalf("legacy role escaped: claims=%+v err=%v", claims, err)
			}
		}
	}
}

// ---- stub Authorizer ------------------------------------------------------

type stubAuthorizer struct {
	allow map[string]bool
	err   error
	seen  []ports.Actor
}

func (s *stubAuthorizer) Can(_ context.Context, actor ports.Actor, permission, _ string) (bool, error) {
	s.seen = append(s.seen, actor)
	if s.err != nil {
		return false, s.err
	}
	return s.allow[permission], nil
}

// routerWith re-registers the auth surface over the same pool with a specific
// Authorizer, so one test env can exercise several gate configurations.
func (e *testEnv) routerWith(authz ports.Authorizer) chi.Router {
	r := chi.NewRouter()
	Register(r, Deps{
		Pool:   e.pool,
		Tokens: e.tokens,
		Mailer: e.mailer,
		Hooks:  e.hooks,
		Authz:  authz,
		Config: testConfig(),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return r
}

// userToken signs a regular end-user access token for sub, backed by a real
// user and an open aal2 session: the admin gate admits nothing less.
func (e *testEnv) userToken(t *testing.T, sub string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := e.pool.Exec(ctx, `insert into auth.users (id, aud, role, email, created_at, updated_at)
		values ($1::uuid, 'authenticated', 'authenticated', $2, now(), now()) on conflict (id) do nothing`,
		sub, "user-"+sub[:8]+"@dilion.test"); err != nil {
		t.Fatalf("user: %v", err)
	}
	sessionID := uuid.NewString()
	if err := insertSession(ctx, e.pool, sessionID, sub, "", nil, time.Now()); err != nil {
		t.Fatalf("session: %v", err)
	}
	if err := addAMRClaimToSession(ctx, e.pool, sessionID, AMRMethodTOTP, time.Now()); err != nil {
		t.Fatalf("amr: %v", err)
	}
	token, err := e.tokens.Sign(ctx, ports.Claims{
		Subject: sub,
		Role:    RoleAuthenticated,
		Email:   "user@dilion.test",
		Extra:   map[string]any{"session_id": sessionID},
	})
	if err != nil {
		t.Fatalf("sign user token: %v", err)
	}
	return token
}

func (e *testEnv) anonToken(t *testing.T) string {
	t.Helper()
	token, err := e.tokens.Sign(context.Background(), ports.Claims{
		Subject: "00000000-0000-4000-8000-0000000000aa",
		Role:    RoleAnon,
	})
	if err != nil {
		t.Fatalf("sign anon token: %v", err)
	}
	return token
}

// getAdminUsers runs GET /admin/users through an arbitrary router.
func getAdminUsers(t *testing.T, e *testEnv, r chi.Router, bearer string) int {
	t.Helper()
	prev := e.router
	e.router = r
	defer func() { e.router = prev }()
	return e.do(t, http.MethodGet, "/admin/users", nil, bearer).Code
}

// ---- the gate -------------------------------------------------------------

func TestAdminGateAcceptsUserTokenWithUsersAdmin(t *testing.T) {
	env := newTestEnv(t)
	const sub = "6a1f2b3c-4d5e-4f70-8192-a3b4c5d6e7f8"

	authz := &stubAuthorizer{allow: map[string]bool{PermUsersAdmin: true}}
	r := env.routerWith(authz)

	if code := getAdminUsers(t, env, r, env.userToken(t, sub)); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if len(authz.seen) == 0 {
		t.Fatal("authorizer was not consulted")
	}
	got := authz.seen[0]
	if got.ID != sub || got.Type != ActorTypeUser {
		t.Errorf("actor = %+v, want {ID:%s Type:user}", got, sub)
	}
}

func TestAdminGateDeniesUserTokenWithoutUsersAdmin(t *testing.T) {
	env := newTestEnv(t)
	const sub = "6a1f2b3c-4d5e-4f70-8192-a3b4c5d6e7f8"

	// Holding an unrelated permission is not enough.
	env.router = env.routerWith(&stubAuthorizer{allow: map[string]bool{"users.read": true}})
	res := env.do(t, http.MethodGet, "/admin/users", nil, env.userToken(t, sub))
	if res.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", res.Code, res.Body.String())
	}
	// The rejection stays byte-compatible with gotrue's not_admin error.
	body := decodeInto[HTTPError](t, res, http.StatusForbidden)
	if body.ErrorCode != ErrorCodeNotAdmin || body.Message != "User not allowed" {
		t.Errorf("error body = %+v, want not_admin/User not allowed", body)
	}
}

// A failing Authorizer must not open the gate.
func TestAdminGateFailsClosedOnAuthorizerError(t *testing.T) {
	env := newTestEnv(t)
	r := env.routerWith(&stubAuthorizer{err: errors.New("boom")})
	if code := getAdminUsers(t, env, r, env.userToken(t, "6a1f2b3c-4d5e-4f70-8192-a3b4c5d6e7f8")); code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", code)
	}
}

// An anon token is never admitted, whatever the Authorizer says.
func TestAdminGateRejectsAnonToken(t *testing.T) {
	env := newTestEnv(t)
	authz := &stubAuthorizer{allow: map[string]bool{PermUsersAdmin: true}}
	r := env.routerWith(authz)
	if code := getAdminUsers(t, env, r, env.anonToken(t)); code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", code)
	}
	if len(authz.seen) != 0 {
		t.Errorf("authorizer consulted for an anon token: %+v", authz.seen)
	}
}

// Embedder compatibility: with no Authorizer the surface stays service_role-only.
func TestAdminGateWithoutAuthorizerStaysServiceRoleOnly(t *testing.T) {
	env := newTestEnv(t) // registered with Authz: nil
	if code := getAdminUsers(t, env, env.router, env.userToken(t, "6a1f2b3c-4d5e-4f70-8192-a3b4c5d6e7f8")); code != http.StatusForbidden {
		t.Fatalf("user token status = %d, want 403", code)
	}
	if code := getAdminUsers(t, env, env.router, env.serviceRoleToken(t)); code != http.StatusOK {
		t.Fatalf("service_role status = %d, want 200", code)
	}
}

// service_role is admitted even when RBAC would deny it (unchanged contract).
func TestAdminGateServiceRoleBypassesRBAC(t *testing.T) {
	env := newTestEnv(t)
	authz := &stubAuthorizer{} // denies everything
	r := env.routerWith(authz)
	if code := getAdminUsers(t, env, r, env.serviceRoleToken(t)); code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if len(authz.seen) != 0 {
		t.Errorf("authorizer consulted for service_role: %+v", authz.seen)
	}
}

// ---- integration: the real iam Authorizer over real RBAC rows -------------

func TestAdminGateWithRealAuthorizerAndRoleAssignment(t *testing.T) {
	env := newTestEnv(t)
	applyAuthzSchema(t, env.pool)

	const sub = "6a1f2b3c-4d5e-4f70-8192-a3b4c5d6e7f8"
	r := env.routerWith(iam.NewAuthorizer(env.pool))
	token := env.userToken(t, sub)

	// Deny by default: no assignment yet.
	if code := getAdminUsers(t, env, r, token); code != http.StatusForbidden {
		t.Fatalf("unassigned user status = %d, want 403", code)
	}

	ctx := context.Background()
	var assignmentID int64
	if err := env.pool.QueryRow(ctx, `
		insert into dilion_authz.role_assignments (actor_id, role_id, granted_by)
		values ($1, $2, 'test') returning id`,
		sub, iam.RoleOwner).Scan(&assignmentID); err != nil {
		t.Fatalf("grant owner: %v", err)
	}
	t.Cleanup(func() {
		_, _ = env.pool.Exec(context.Background(),
			`delete from dilion_authz.role_assignments where id = $1`, assignmentID)
	})

	if code := getAdminUsers(t, env, r, token); code != http.StatusOK {
		t.Fatalf("granted user status = %d, want 200", code)
	}

	// Revoking removes the authority (history row is preserved).
	if _, err := env.pool.Exec(ctx, `
		update dilion_authz.role_assignments set revoked_at = now(), revoked_by = 'test'
		where id = $1`, assignmentID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if code := getAdminUsers(t, env, r, token); code != http.StatusForbidden {
		t.Fatalf("revoked user status = %d, want 403", code)
	}
}

// applyAuthzSchema installs the 03xx migrations this test needs. They are owned
// by internal/iam; applying them here only makes the auth test database
// self-sufficient.
func applyAuthzSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if !firstApply("applyAuthzSchema") {
		return
	}
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

	for _, f := range []string{
		"0300_iam_audit.sql",
		"0301_audit_reason.sql",
		"0302_pii_write_permission.sql",
		"0303_users_admin_permission.sql",
		"0304_consents_write_permission.sql",
		"0305_roles_manage_permission.sql",
		"0306_auth_settings_permission.sql",
	} {
		sql, rerr := os.ReadFile(filepath.Join("..", "..", "migrations", f))
		if rerr != nil {
			t.Fatalf("read %s: %v", f, rerr)
		}
		if _, eerr := conn.Exec(ctx, string(sql)); eerr != nil {
			t.Fatalf("apply %s: %v", f, eerr)
		}
	}
}

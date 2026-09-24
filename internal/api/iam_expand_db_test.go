package api

// Database-backed tests for `expand=actor` on the grant reports. Enable with:
//
//	DILION_TEST_DB=1 go test ./internal/api/...

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/internal/auth"
	"github.com/dilion-io/dilion/internal/iam"
	"github.com/dilion-io/dilion/internal/store"
	"github.com/dilion-io/dilion/ports"
)

// expandEnv is an API over a real database, which the grant reports need: they
// read through iam.Service rather than an injected fake.
type expandEnv struct {
	api   humatest.TestAPI
	sink  *recordingSink
	pool  *pgxpool.Pool
	user  string
	keyID string
}

func newExpandEnv(t *testing.T, perms ...string) *expandEnv {
	t.Helper()
	pool := testPool(t)
	ctx := context.Background()
	// The reports resolve actors out of auth.users, which the audit-only
	// migration list does not create.
	if err := store.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	svc := iam.New(pool)
	user := uuid.NewString()
	// created_at is written by the signup path, not by a column default, so a
	// row inserted directly has to set it like a real one would.
	if _, err := pool.Exec(ctx, `
		insert into auth.users (id, aud, role, email, created_at, updated_at)
		values ($1::uuid,'authenticated','authenticated','operator@example.com',now(),now())`, user); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	_, key, err := svc.CreateKey(ctx, "expand-report", []string{iam.PermUsersRead}, nil)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	for _, actor := range []string{user, key.ID} {
		if _, err := svc.GrantRole(ctx, iam.RoleViewer, actor, "root"); err != nil {
			t.Fatalf("grant to %s: %v", actor, err)
		}
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `delete from dilion_authz.role_assignments where actor_id = any($1::text[])`,
			[]string{user, key.ID})
		_, _ = pool.Exec(bg, `delete from dilion_authz.api_keys where id = $1`, key.ID)
		_, _ = pool.Exec(bg, `delete from auth.users where id = $1::uuid`, user)
	})

	sink := &recordingSink{}
	d := Deps{Pool: pool, Audit: sink}
	if len(perms) == 0 {
		d.Verifier = fakeVerifier{claims: &ports.Claims{Subject: "svc-1", Role: "service_role"}}
		d.Authz = fakeAuthorizer{}
	} else {
		allow := map[string]bool{}
		for _, p := range perms {
			allow[p] = true
		}
		d.Verifier = fakeVerifier{claims: &ports.Claims{Subject: testUserID, Role: "authenticated"}}
		d.Authz = fakeAuthorizer{allow: allow}
		// These tests are about the reports, not sign-in sessions.
		d.SessionLookup = func(context.Context, string, string) (auth.SessionAssurance, error) {
			return auth.SessionAssurance{AAL: auth.AAL2, Active: true}, nil
		}
	}
	_, tapi := humatest.New(t, NewConfig())
	RegisterIAMAPI(tapi, d)
	return &expandEnv{api: tapi, sink: sink, pool: pool, user: user, keyID: key.ID}
}

func (e *expandEnv) assignments(t *testing.T, query string) []RoleAssignment {
	t.Helper()
	resp := e.api.Get("/iam/v1/roles/"+iam.RoleViewer+"/assignments?limit=100"+query, bearer)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.Code, resp.Body.String())
	}
	var page RoleAssignmentPage
	if err := json.Unmarshal(resp.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, resp.Body.String())
	}
	return page.Items
}

func (e *expandEnv) find(t *testing.T, items []RoleAssignment, actor string) RoleAssignment {
	t.Helper()
	for _, it := range items {
		if it.ActorID == actor {
			return it
		}
	}
	t.Fatalf("actor %q not in the report", actor)
	return RoleAssignment{}
}

// expand=actor resolves both actor kinds and says whether the grant is still
// usable, without inlining any personal data.
func TestAssignmentsExpandActor(t *testing.T) {
	env := newExpandEnv(t)

	plain := env.assignments(t, "")
	if a := env.find(t, plain, env.user); a.Actor != nil {
		t.Error("actor was expanded without expand=actor")
	}

	items := env.assignments(t, "&expand=actor")
	user := env.find(t, items, env.user)
	if user.Actor == nil {
		t.Fatal("user actor was not expanded")
	}
	if user.Actor.ActorType != iam.ActorTypeUser || !user.Actor.Active {
		t.Errorf("user actor = %+v, want an active user", user.Actor)
	}
	if user.Actor.CreatedAt == nil {
		t.Error("user actor has no created_at")
	}
	key := env.find(t, items, env.keyID)
	if key.Actor == nil || key.Actor.ActorType != iam.ActorTypeAPIKey || !key.Actor.Active {
		t.Errorf("key actor = %+v, want an active api_key", key.Actor)
	}
	if key.Actor.BannedUntil != nil || key.Actor.LastSignInAt != nil {
		t.Errorf("key actor carries user-only fields: %+v", key.Actor)
	}

	// No personal data is inlined: the serialised report must not contain the
	// operator's email address anywhere.
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "operator@example.com") {
		t.Errorf("the report inlined an email address: %s", raw)
	}

	// The expansion touched data subjects, so it leaves an access record naming
	// them — and only the user, never the API key.
	var found bool
	for _, e := range env.sink.events {
		if e.Action != audit.ActionUserListRead {
			continue
		}
		found = true
		if len(e.SubjectIDs) != 1 || e.SubjectIDs[0] != env.user {
			t.Errorf("subject manifest = %v, want only the user actor", e.SubjectIDs)
		}
		if e.AccessLevel != audit.AccessMasked {
			t.Errorf("access level = %q, want masked", e.AccessLevel)
		}
	}
	if !found {
		t.Error("expand=actor left no USER_LIST_READ access record")
	}
}

// A banned user keeps the grant in the ledger but can no longer use it, which
// is the whole question a recertification review asks.
func TestHoldersExpandActorReportsInactive(t *testing.T) {
	env := newExpandEnv(t)
	if _, err := env.pool.Exec(context.Background(),
		`update auth.users set banned_until = now() + interval '1 day' where id = $1::uuid`,
		env.user); err != nil {
		t.Fatalf("ban user: %v", err)
	}

	resp := env.api.Get("/iam/v1/permissions/"+iam.PermUsersRead+"/holders?expand=actor", bearer)
	if resp.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", resp.Code, resp.Body.String())
	}
	var page PermissionHolderPage
	if err := json.Unmarshal(resp.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var seen bool
	for _, h := range page.Items {
		if h.ActorID != env.user {
			continue
		}
		seen = true
		if h.Actor == nil || h.Actor.Active {
			t.Errorf("banned holder = %+v, want inactive", h.Actor)
		}
		if h.Actor != nil && h.Actor.BannedUntil == nil {
			t.Error("banned holder has no banned_until")
		}
	}
	if !seen {
		t.Fatalf("user %q is not among the holders", env.user)
	}
}

// Reading the grant ledger is not authority to learn whether an operator is
// banned or dormant: expand=actor needs users.read on top, and a refusal costs
// nothing and records nothing but the denial.
func TestExpandActorRequiresUsersRead(t *testing.T) {
	env := newExpandEnv(t, iam.PermAuditRead)

	if items := env.assignments(t, ""); len(items) == 0 {
		t.Fatal("the plain report must still work with audit.read alone")
	}

	resp := env.api.Get("/iam/v1/roles/"+iam.RoleViewer+"/assignments?expand=actor", bearer)
	if resp.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%s)", resp.Code, resp.Body.String())
	}
	for _, e := range env.sink.events {
		if e.Action == audit.ActionUserListRead {
			t.Error("a refused expansion still recorded a user read")
		}
	}
	var denied bool
	for _, e := range env.sink.events {
		if e.Action == audit.ActionPermissionDenied {
			denied = true
		}
	}
	if !denied {
		t.Error("the refusal was not recorded")
	}
}

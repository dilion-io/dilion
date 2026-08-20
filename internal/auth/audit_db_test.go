package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/dilion-project/dilion/internal/audit"
	"github.com/dilion-project/dilion/ports"
)

// ---- stub AuditSink -------------------------------------------------------

type stubAuditSink struct {
	mu     sync.Mutex
	events []ports.AuditEvent
	err    error
}

func (s *stubAuditSink) Append(_ context.Context, e ports.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return s.err
}

func (s *stubAuditSink) all() []ports.AuditEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ports.AuditEvent, len(s.events))
	copy(out, s.events)
	return out
}

// last returns the most recent event with the given action.
func (s *stubAuditSink) last(t *testing.T, action string) ports.AuditEvent {
	t.Helper()
	events := s.all()
	for i := len(events) - 1; i >= 0; i-- {
		if events[i].Action == action {
			return events[i]
		}
	}
	t.Fatalf("no %s event recorded; got %v", action, actionsOf(events))
	return ports.AuditEvent{}
}

func actionsOf(events []ports.AuditEvent) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.Action)
	}
	return out
}

// routerWithAudit registers the surface with an audit sink (and optional
// Authorizer) over the same pool.
func (e *testEnv) routerWithAudit(sink ports.AuditSink, authz ports.Authorizer) chi.Router {
	r := chi.NewRouter()
	Register(r, Deps{
		Pool:   e.pool,
		Tokens: e.tokens,
		Mailer: e.mailer,
		Hooks:  e.hooks,
		Authz:  authz,
		Audit:  sink,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return r
}

// useRouter swaps e.router for the duration of the test.
func (e *testEnv) useRouter(t *testing.T, r chi.Router) {
	t.Helper()
	prev := e.router
	e.router = r
	t.Cleanup(func() { e.router = prev })
}

const auditTestEmail = "audited@example.com"

// ---- the event matrix -----------------------------------------------------

func TestAdminUsersEmitAuditEvents(t *testing.T) {
	env := newTestEnv(t)
	sink := &stubAuditSink{}
	env.useRouter(t, env.routerWithAudit(sink, nil))
	token := env.serviceRoleToken(t)

	// POST /admin/users -> USER_CREATED
	created := decodeInto[User](t, env.do(t, http.MethodPost, "/admin/users",
		map[string]any{"email": auditTestEmail, "password": "hunter22", "email_confirm": true},
		token), http.StatusOK)
	if created.ID == "" {
		t.Fatal("created user has no id")
	}

	// GET /admin/users -> USER_LIST_READ
	if code := env.do(t, http.MethodGet, "/admin/users", nil, token).Code; code != http.StatusOK {
		t.Fatalf("list status = %d, want 200", code)
	}
	// GET /admin/users/{id} -> USER_DETAIL_READ
	if code := env.do(t, http.MethodGet, "/admin/users/"+created.ID, nil, token).Code; code != http.StatusOK {
		t.Fatalf("get status = %d, want 200", code)
	}
	// PUT /admin/users/{id} -> USER_UPDATED
	if code := env.do(t, http.MethodPut, "/admin/users/"+created.ID,
		map[string]any{"user_metadata": map[string]any{"tier": "gold"}}, token).Code; code != http.StatusOK {
		t.Fatalf("update status = %d, want 200", code)
	}
	// DELETE /admin/users/{id} -> USER_DELETED
	if code := env.do(t, http.MethodDelete, "/admin/users/"+created.ID, nil, token).Code; code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200", code)
	}

	cases := []struct {
		action   string
		access   string
		resource string
		count    int
	}{
		{audit.ActionUserCreated, audit.AccessNA, auditResourceUser(created.ID), 1},
		{audit.ActionUserDetailRead, audit.AccessFull, auditResourceUser(created.ID), 1},
		{audit.ActionUserUpdated, audit.AccessNA, auditResourceUser(created.ID), 1},
		{audit.ActionUserDeleted, audit.AccessNA, auditResourceUser(created.ID), 1},
	}
	for _, c := range cases {
		ev := sink.last(t, c.action)
		if ev.AccessLevel != c.access {
			t.Errorf("%s access_level = %q, want %q", c.action, ev.AccessLevel, c.access)
		}
		if ev.Resource != c.resource {
			t.Errorf("%s resource = %q, want %q", c.action, ev.Resource, c.resource)
		}
		if ev.ResultCount != c.count {
			t.Errorf("%s result_count = %d, want %d", c.action, ev.ResultCount, c.count)
		}
		if len(ev.SubjectIDs) != 1 || ev.SubjectIDs[0] != created.ID {
			t.Errorf("%s subject manifest = %v, want [%s]", c.action, ev.SubjectIDs, created.ID)
		}
	}

	// The listing carries the whole page as its manifest (§5.3).
	list := sink.last(t, audit.ActionUserListRead)
	if list.AccessLevel != audit.AccessFull {
		t.Errorf("list access_level = %q, want full", list.AccessLevel)
	}
	if list.Resource != auditResourceUsers {
		t.Errorf("list resource = %q, want %q", list.Resource, auditResourceUsers)
	}
	if list.ResultCount != 1 || len(list.SubjectIDs) != 1 || list.SubjectIDs[0] != created.ID {
		t.Errorf("list result_count/manifest = %d/%v, want 1/[%s]", list.ResultCount, list.SubjectIDs, created.ID)
	}

	// Every event carries the service_role actor and the request metadata.
	for _, ev := range sink.all() {
		if ev.ActorType != ActorTypeServiceRole {
			t.Errorf("%s actor_type = %q, want service_role", ev.Action, ev.ActorType)
		}
		if ev.ActorID != "00000000-0000-4000-8000-000000000001" {
			t.Errorf("%s actor_id = %q, want the token sub", ev.Action, ev.ActorID)
		}
		if ev.ProjectID != DefaultProjectID {
			t.Errorf("%s project_id = %q, want %q", ev.Action, ev.ProjectID, DefaultProjectID)
		}
		if ev.IP != "203.0.113.7" {
			t.Errorf("%s ip = %q, want 203.0.113.7", ev.Action, ev.IP)
		}
		if ev.OccurredAt.IsZero() {
			t.Errorf("%s occurred_at is zero", ev.Action)
		}
	}
	if got := len(sink.all()); got != 5 {
		t.Errorf("recorded %d events (%v), want 5", got, actionsOf(sink.all()))
	}
}

// The event records the fact of the access, never a personal-data value (§5.1).
func TestAdminAuditEventsCarryNoPII(t *testing.T) {
	env := newTestEnv(t)
	sink := &stubAuditSink{}
	env.useRouter(t, env.routerWithAudit(sink, nil))
	token := env.serviceRoleToken(t)

	created := decodeInto[User](t, env.do(t, http.MethodPost, "/admin/users",
		map[string]any{"email": auditTestEmail, "password": "hunter22"}, token), http.StatusOK)
	env.do(t, http.MethodGet, "/admin/users", nil, token)
	env.do(t, http.MethodGet, "/admin/users/"+created.ID, nil, token)
	env.do(t, http.MethodPut, "/admin/users/"+created.ID,
		map[string]any{"email": "renamed@example.com", "email_confirm": true}, token)
	env.do(t, http.MethodDelete, "/admin/users/"+created.ID, nil, token)

	pii := []string{auditTestEmail, "renamed@example.com", "audited", "example.com", "hunter22"}
	for _, ev := range sink.all() {
		fields := append([]string{ev.Resource, ev.Reason, ev.ActorID, ev.ActorType,
			ev.Action, ev.AccessLevel, ev.RequestID, ev.IP, ev.UserAgent}, ev.SubjectIDs...)
		blob := strings.ToLower(strings.Join(fields, "\x00"))
		for _, needle := range pii {
			if strings.Contains(blob, strings.ToLower(needle)) {
				t.Errorf("%s event leaks %q into %v", ev.Action, needle, fields)
			}
		}
	}
	if len(sink.all()) != 5 {
		t.Fatalf("recorded %v, want 5 events", actionsOf(sink.all()))
	}
}

// An RBAC-admitted user token is recorded as the user it is, not as service_role.
func TestAdminAuditActorIsTheAdmittedUserToken(t *testing.T) {
	env := newTestEnv(t)
	const sub = "6a1f2b3c-4d5e-4f70-8192-a3b4c5d6e7f8"
	sink := &stubAuditSink{}
	env.useRouter(t, env.routerWithAudit(sink,
		&stubAuthorizer{allow: map[string]bool{PermUsersAdmin: true}}))

	if code := env.do(t, http.MethodGet, "/admin/users", nil, env.userToken(t, sub)).Code; code != http.StatusOK {
		t.Fatalf("list status = %d, want 200", code)
	}
	ev := sink.last(t, audit.ActionUserListRead)
	if ev.ActorType != ActorTypeUser || ev.ActorID != sub {
		t.Errorf("actor = %s/%s, want user/%s", ev.ActorType, ev.ActorID, sub)
	}
}

// Embedder compatibility: no sink configured is a no-op, not a failure.
func TestAdminUsersWithoutAuditSinkStillWork(t *testing.T) {
	env := newTestEnv(t) // registered with Audit: nil
	token := env.serviceRoleToken(t)
	created := decodeInto[User](t, env.do(t, http.MethodPost, "/admin/users",
		map[string]any{"email": "nosink@example.com", "password": "hunter22"}, token), http.StatusOK)
	for _, c := range []struct {
		method, path string
	}{
		{http.MethodGet, "/admin/users"},
		{http.MethodGet, "/admin/users/" + created.ID},
		{http.MethodPut, "/admin/users/" + created.ID},
		{http.MethodDelete, "/admin/users/" + created.ID},
	} {
		if code := env.do(t, c.method, c.path, map[string]any{}, token).Code; code != http.StatusOK {
			t.Errorf("%s %s status = %d, want 200", c.method, c.path, code)
		}
	}
}

// Fail-open: auditing is an observability dependency, so a broken sink is
// logged and the request still succeeds — an audit outage is not an auth outage.
func TestAdminUsersSucceedWhenAuditSinkFails(t *testing.T) {
	env := newTestEnv(t)
	sink := &stubAuditSink{err: errors.New("audit store is down")}
	env.useRouter(t, env.routerWithAudit(sink, nil))
	token := env.serviceRoleToken(t)

	created := decodeInto[User](t, env.do(t, http.MethodPost, "/admin/users",
		map[string]any{"email": "failopen@example.com", "password": "hunter22"}, token), http.StatusOK)
	if code := env.do(t, http.MethodGet, "/admin/users", nil, token).Code; code != http.StatusOK {
		t.Errorf("list status = %d, want 200", code)
	}
	if code := env.do(t, http.MethodDelete, "/admin/users/"+created.ID, nil, token).Code; code != http.StatusOK {
		t.Errorf("delete status = %d, want 200", code)
	}
	// The erasure is durable even though its audit event could not be stored.
	var n int
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from auth.users where id = $1`, created.ID).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if n != 0 {
		t.Errorf("user still present after delete with a failing audit sink")
	}
	var outbox int
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from dilion_privacy.outbox where aggregate_id = $1`, created.ID).Scan(&outbox); err != nil {
		t.Fatalf("count outbox: %v", err)
	}
	if outbox != 1 {
		t.Errorf("outbox rows = %d, want 1 (deletion must not roll back)", outbox)
	}
}

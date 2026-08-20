package auth

// Database-backed tests for GET /admin/audit (admin_audit.go). Like the other
// *_db_test.go files they need a real Postgres and run only when
// DILION_TEST_DB is set:
//
//	docker exec dilion-pg createdb -U dilion dilion_test_b
//	DILION_TEST_DB=postgres://dilion:dilion@localhost:55432/dilion_test_b \
//	  go test -run AdminAudit ./internal/auth/...

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/internal/audit"
)

// ---- fixtures -------------------------------------------------------------

const (
	auditActorA = "11111111-1111-4111-8111-111111111111"
	auditActorB = "22222222-2222-4222-8222-222222222222"
)

// applyAuditSchema installs the audit store (0300/0301) plus the upstream
// compatibility table (0114) this endpoint deliberately never touches, then
// empties them.
func applyAuditSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	for _, name := range []string{
		"0300_iam_audit.sql",
		"0301_audit_reason.sql",
		"0114_auth_audit_log_entries.sql",
	} {
		sql, err := os.ReadFile(filepath.Join("..", "..", "migrations", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
	if _, err := pool.Exec(ctx,
		`truncate dilion_audit.events, dilion_audit.subjects, auth.audit_log_entries`); err != nil {
		t.Fatalf("truncate audit tables: %v", err)
	}
}

type seedEvent struct {
	id          string
	actorID     string
	actorType   string
	action      string
	resource    string
	accessLevel string
	reason      string
	resultCount int
	ip          string
	at          time.Time
	subjects    []string
}

func seedAuditEvents(t *testing.T, pool *pgxpool.Pool, events ...seedEvent) {
	t.Helper()
	ctx := context.Background()
	for _, e := range events {
		if _, err := pool.Exec(ctx, `
			insert into dilion_audit.events
			  (event_id, actor_id, actor_type, action, resource,
			   access_level, reason, result_count, ip, user_agent, created_at)
			values ($1, $2, $3, $4, $5, $6, nullif($7,''), $8, $9, 'go-test', $10)`,
			e.id, e.actorID, e.actorType, e.action, e.resource, e.accessLevel,
			e.reason, e.resultCount, e.ip, e.at); err != nil {
			t.Fatalf("seed event %s: %v", e.id, err)
		}
		for _, s := range e.subjects {
			if _, err := pool.Exec(ctx,
				`insert into dilion_audit.subjects (event_id, subject_id) values ($1,$2)`,
				e.id, s); err != nil {
				t.Fatalf("seed subject %s/%s: %v", e.id, s, err)
			}
		}
	}
}

// seedStandardAuditLog installs a deterministic five-event log, newest last.
func seedStandardAuditLog(t *testing.T, env *testEnv) {
	t.Helper()
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	seedAuditEvents(t, env.pool,
		seedEvent{id: "evt_1", actorID: auditActorA, actorType: ActorTypeUser,
			action: audit.ActionUserCreated, resource: auditResourceUsers,
			accessLevel: audit.AccessNA, resultCount: 1, ip: "203.0.113.7",
			at: base, subjects: []string{"sub-1"}},
		seedEvent{id: "evt_2", actorID: auditActorA, actorType: ActorTypeUser,
			action: audit.ActionUserListRead, resource: auditResourceUsers,
			accessLevel: audit.AccessFull, resultCount: 2, ip: "203.0.113.7",
			at: base.Add(1 * time.Minute), subjects: []string{"sub-1", "sub-2"}},
		seedEvent{id: "evt_3", actorID: auditActorB, actorType: ActorTypeServiceRole,
			action: audit.ActionUserUpdated, resource: auditResourceUser("sub-2"),
			accessLevel: audit.AccessNA, resultCount: 1, ip: "198.51.100.4",
			at: base.Add(2 * time.Minute), subjects: []string{"sub-2"}},
		seedEvent{id: "evt_4", actorID: auditActorB, actorType: ActorTypeServiceRole,
			action: audit.ActionUserDeleted, resource: auditResourceUser("sub-2"),
			accessLevel: audit.AccessNA, resultCount: 1, ip: "198.51.100.4",
			at: base.Add(3 * time.Minute), subjects: []string{"sub-2"}},
		seedEvent{id: "evt_5", actorID: auditActorA, actorType: ActorTypeUser,
			action: audit.ActionPIIFullRead, resource: "privacy/v1/subjects/sub-1",
			accessLevel: audit.AccessFull, reason: "지원 티켓 #42", resultCount: 1,
			ip: "203.0.113.7", at: base.Add(4 * time.Minute),
			subjects: []string{"sub-1"}},
	)
}

func auditEnv(t *testing.T) *testEnv {
	t.Helper()
	env := newTestEnv(t)
	applyAuditSchema(t, env.pool)
	seedStandardAuditLog(t, env)
	return env
}

func getAudit(t *testing.T, env *testEnv, path string) *httptest.ResponseRecorder {
	t.Helper()
	return env.do(t, http.MethodGet, path, nil, env.serviceRoleToken(t))
}

func decodeAuditList(t *testing.T, rec *httptest.ResponseRecorder) []map[string]any {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal %q: %v", rec.Body.String(), err)
	}
	return out
}

func auditActionsOf(entries []map[string]any) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		p, _ := e["payload"].(map[string]any)
		s, _ := p["action"].(string)
		out = append(out, s)
	}
	return out
}

// ---- tests ----------------------------------------------------------------

// The body is upstream's []AuditLogEntry: the field names are the contract.
func TestAdminAuditListShape(t *testing.T) {
	env := auditEnv(t)

	entries := decodeAuditList(t, getAudit(t, env, "/admin/audit"))
	if len(entries) != 5 {
		t.Fatalf("len(entries) = %d, want 5", len(entries))
	}

	// Newest first, like upstream's ORDER BY created_at DESC.
	if got := auditActionsOf(entries); got[0] != audit.ActionPIIFullRead {
		t.Errorf("first action = %q, want the newest event (%s); order = %v",
			got[0], audit.ActionPIIFullRead, got)
	}

	first := entries[0]
	for _, k := range []string{"id", "payload", "created_at", "ip_address"} {
		if _, ok := first[k]; !ok {
			t.Errorf("entry is missing %q; got %v", k, keysOf(first))
		}
	}
	// id is a uuid (upstream types it as one) and is stable across calls.
	wantID := auditEntryID("evt_5").String()
	if first["id"] != wantID {
		t.Errorf("id = %v, want the uuidv5 of the event id (%s)", first["id"], wantID)
	}
	if first["ip_address"] != "203.0.113.7" {
		t.Errorf("ip_address = %v", first["ip_address"])
	}
	if s, _ := first["created_at"].(string); s == "" {
		t.Errorf("created_at = %v, want an RFC 3339 timestamp", first["created_at"])
	} else if _, err := time.Parse(time.RFC3339, s); err != nil {
		t.Errorf("created_at = %q is not RFC 3339: %v", s, err)
	}

	payload := first["payload"].(map[string]any)
	for _, k := range []string{"actor_id", "actor_username", "actor_via_sso", "action", "log_type", "traits"} {
		if _, ok := payload[k]; !ok {
			t.Errorf("payload is missing %q; got %v", k, keysOf(payload))
		}
	}
	if payload["actor_id"] != auditActorA {
		t.Errorf("actor_id = %v, want %s", payload["actor_id"], auditActorA)
	}
	// Dilion records no personal-data values in the audit store, so the
	// username upstream would carry is deliberately empty (admin_audit.go).
	if payload["actor_username"] != "" {
		t.Errorf("actor_username = %v, want the empty string", payload["actor_username"])
	}
	if payload["actor_via_sso"] != false {
		t.Errorf("actor_via_sso = %v, want false", payload["actor_via_sso"])
	}

	traits := payload["traits"].(map[string]any)
	if traits["resource"] != "privacy/v1/subjects/sub-1" {
		t.Errorf("traits.resource = %v", traits["resource"])
	}
	if traits["access_level"] != audit.AccessFull {
		t.Errorf("traits.access_level = %v, want %s", traits["access_level"], audit.AccessFull)
	}
	if traits["reason"] != "지원 티켓 #42" {
		t.Errorf("traits.reason = %v", traits["reason"])
	}
	if traits["subject_count"] != float64(1) {
		t.Errorf("traits.subject_count = %v, want 1", traits["subject_count"])
	}
	// The subject ids themselves are never inlined (§5.3).
	if _, ok := traits["subject_ids"]; ok {
		t.Error("traits must not inline the subject manifest")
	}
	if traits["dilion_action"] != audit.ActionPIIFullRead {
		t.Errorf("traits.dilion_action = %v", traits["dilion_action"])
	}
}

// Actions with an upstream equivalent are presented under the upstream name and
// log type; everything else passes through verbatim.
func TestAdminAuditActionMapping(t *testing.T) {
	env := auditEnv(t)
	entries := decodeAuditList(t, getAudit(t, env, "/admin/audit"))

	byDilion := map[string]map[string]any{}
	for _, e := range entries {
		p := e["payload"].(map[string]any)
		byDilion[p["traits"].(map[string]any)["dilion_action"].(string)] = p
	}

	for _, tc := range []struct{ dilion, action, logType string }{
		{audit.ActionUserCreated, "user_signedup", "team"},
		{audit.ActionUserUpdated, "user_modified", "user"},
		{audit.ActionUserDeleted, "user_deleted", "team"},
		{audit.ActionUserListRead, audit.ActionUserListRead, ""},
		{audit.ActionPIIFullRead, audit.ActionPIIFullRead, ""},
	} {
		p, ok := byDilion[tc.dilion]
		if !ok {
			t.Fatalf("no entry for %s", tc.dilion)
		}
		if p["action"] != tc.action {
			t.Errorf("%s: action = %v, want %q", tc.dilion, p["action"], tc.action)
		}
		if p["log_type"] != tc.logType {
			t.Errorf("%s: log_type = %v, want %q", tc.dilion, p["log_type"], tc.logType)
		}
	}
}

// page / per_page with the X-Total-Count and Link headers gotrue emits.
func TestAdminAuditPaginationHeaders(t *testing.T) {
	env := auditEnv(t)

	rec := getAudit(t, env, "/admin/audit?per_page=2")
	entries := decodeAuditList(t, rec)
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2", len(entries))
	}
	if got := rec.Header().Get("X-Total-Count"); got != "5" {
		t.Errorf("X-Total-Count = %q, want 5", got)
	}
	link := rec.Header().Get("Link")
	if !strings.Contains(link, `rel="next"`) || !strings.Contains(link, `rel="last"`) {
		t.Errorf("Link = %q, want next and last relations", link)
	}
	if !strings.Contains(link, "page=3") { // 5 events / 2 per page = 3 pages
		t.Errorf("Link = %q, want the last page to be 3", link)
	}

	// The last page holds the remainder and offers no `next`.
	rec = getAudit(t, env, "/admin/audit?per_page=2&page=3")
	last := decodeAuditList(t, rec)
	if len(last) != 1 {
		t.Fatalf("last page len = %d, want 1", len(last))
	}
	if l := rec.Header().Get("Link"); strings.Contains(l, `rel="next"`) {
		t.Errorf("last page Link = %q, want no next relation", l)
	}
	// Pages must not overlap: the oldest event is the only one on page 3.
	if got := auditActionsOf(last)[0]; got != "user_signedup" {
		t.Errorf("last page action = %q, want the oldest event (user_signedup)", got)
	}

	// Upstream's validation error for a bad page.
	if rec := getAudit(t, env, "/admin/audit?page=0"); rec.Code != http.StatusBadRequest {
		t.Errorf("page=0 status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
}

// ?query=<scope>:<value>, upstream's filter syntax.
func TestAdminAuditQueryFilters(t *testing.T) {
	env := auditEnv(t)

	t.Run("author", func(t *testing.T) {
		entries := decodeAuditList(t, getAudit(t, env, "/admin/audit?query=author:"+auditActorB))
		if len(entries) != 2 {
			t.Fatalf("len = %d, want 2; actions = %v", len(entries), auditActionsOf(entries))
		}
		for _, e := range entries {
			if got := e["payload"].(map[string]any)["actor_id"]; got != auditActorB {
				t.Errorf("actor_id = %v, want %s", got, auditActorB)
			}
		}
	})

	t.Run("action_upstream_name", func(t *testing.T) {
		entries := decodeAuditList(t, getAudit(t, env, "/admin/audit?query=action:user_signedup"))
		if len(entries) != 1 || auditActionsOf(entries)[0] != "user_signedup" {
			t.Fatalf("actions = %v, want [user_signedup]", auditActionsOf(entries))
		}
	})

	t.Run("action_passthrough_name", func(t *testing.T) {
		entries := decodeAuditList(t, getAudit(t, env, "/admin/audit?query=action:"+audit.ActionPIIFullRead))
		if len(entries) != 1 || auditActionsOf(entries)[0] != audit.ActionPIIFullRead {
			t.Fatalf("actions = %v, want [%s]", auditActionsOf(entries), audit.ActionPIIFullRead)
		}
	})

	t.Run("action_is_matched_against_the_translated_name", func(t *testing.T) {
		// USER_CREATED is presented as user_signedup, so filtering on the raw
		// Dilion constant must NOT match — the payload never carries it.
		entries := decodeAuditList(t, getAudit(t, env, "/admin/audit?query=action:"+audit.ActionUserCreated))
		if len(entries) != 0 {
			t.Fatalf("actions = %v, want none", auditActionsOf(entries))
		}
	})

	t.Run("type", func(t *testing.T) {
		entries := decodeAuditList(t, getAudit(t, env, "/admin/audit?query=type:team"))
		if len(entries) != 2 {
			t.Fatalf("actions = %v, want the two team events", auditActionsOf(entries))
		}
		for _, e := range entries {
			if got := e["payload"].(map[string]any)["log_type"]; got != "team" {
				t.Errorf("log_type = %v, want team", got)
			}
		}
	})

	t.Run("no_match", func(t *testing.T) {
		entries := decodeAuditList(t, getAudit(t, env, "/admin/audit?query=author:nobody"))
		if len(entries) != 0 {
			t.Fatalf("len = %d, want 0", len(entries))
		}
		if got := getAudit(t, env, "/admin/audit?query=author:nobody").Header().Get("X-Total-Count"); got != "0" {
			t.Errorf("X-Total-Count = %q, want 0", got)
		}
	})

	t.Run("wildcards_are_literal", func(t *testing.T) {
		// `%` must be a literal, not "match everything".
		entries := decodeAuditList(t, getAudit(t, env, "/admin/audit?query=author:%25"))
		if len(entries) != 0 {
			t.Fatalf("len = %d, want 0 (the %% is a literal)", len(entries))
		}
	})

	t.Run("invalid_scope", func(t *testing.T) {
		for _, q := range []string{"nonsense:x", "author"} {
			rec := getAudit(t, env, "/admin/audit?query="+q)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("query=%s status = %d, want 400; body = %s", q, rec.Code, rec.Body.String())
			}
		}
	})
}

// The endpoint is gated exactly like /admin/users.
func TestAdminAuditRequiresAdmin(t *testing.T) {
	env := auditEnv(t)

	// No credential at all.
	if rec := env.do(t, http.MethodGet, "/admin/audit", nil, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous status = %d, want 401; body = %s", rec.Code, rec.Body.String())
	}

	// A regular user token without `users.admin` (no Authorizer installed).
	session := env.signup(t, "auditor@example.com", "hunter22")
	rec := env.do(t, http.MethodGet, "/admin/audit", nil, session.Token)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("user status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error_code"] != ErrorCodeNotAdmin {
		t.Errorf("error_code = %v, want %s", body["error_code"], ErrorCodeNotAdmin)
	}
}

// Reading the audit log writes nothing: not a new event (no recursion), and not
// a row into the upstream compatibility table.
func TestAdminAuditIsReadOnly(t *testing.T) {
	env := auditEnv(t)
	sink := &stubAuditSink{}
	env.useRouter(t, env.routerWithAudit(sink, nil))

	before := countRows(t, env.pool, "dilion_audit.events")

	for _, p := range []string{
		"/admin/audit",
		"/admin/audit?per_page=2&page=2",
		"/admin/audit?query=action:user_deleted",
	} {
		if rec := getAudit(t, env, p); rec.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d; body = %s", p, rec.Code, rec.Body.String())
		}
	}

	if after := countRows(t, env.pool, "dilion_audit.events"); after != before {
		t.Errorf("dilion_audit.events grew from %d to %d; reads must not be audited", before, after)
	}
	if n := countRows(t, env.pool, "dilion_audit.subjects"); n != 6 {
		t.Errorf("dilion_audit.subjects = %d rows, want the 6 seeded", n)
	}
	if n := countRows(t, env.pool, "auth.audit_log_entries"); n != 0 {
		t.Errorf("auth.audit_log_entries = %d rows, want 0: nothing writes the upstream table", n)
	}
	if evs := sink.all(); len(evs) != 0 {
		t.Errorf("audit sink recorded %v; the audit read path must not emit events", actionsOf(evs))
	}
}

func countRows(t *testing.T, pool *pgxpool.Pool, table string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `select count(*) from `+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

package auth

// GET /admin/audit — the Supabase-compatible audit-log surface (upstream
// internal/api/audit.go adminAuditLog), served as a READ-ONLY compatibility
// VIEW over Dilion's own audit store.
//
// Why a view and not the upstream table
// -------------------------------------
// auth.audit_log_entries exists (migration 0114) for byte-level schema
// compatibility with existing Supabase databases, but NOTHING in Dilion writes
// it. The authoritative access records live in dilion_audit.* (project.md §5),
// which is what satisfies 안전성 확보조치 기준 제8조 (접속기록): those rows carry the
// actor, the subject manifest, the access level and the justification that the
// upstream payload has no place for. Writing a second, lossier copy into
// auth.audit_log_entries would create two disagreeing evidence stores, so this
// endpoint TRANSLATES dilion_audit.events into upstream's JSON on read instead.
// auth.audit_log_entries is never read and never written here.
//
// No recursion
// ------------
// Reading the audit log is deliberately NOT itself an audited action — the same
// rule the management plane's read path states (internal/audit/read.go): an
// access record for every access record recurses without adding evidence. This
// handler therefore never calls a.emitAudit, and it issues SELECTs only: no
// statement in this file writes to any table.

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/dilion-project/dilion/internal/audit"
)

func init() {
	registerFeature("admin_audit", func(a *api, r chi.Router) {
		// Gated exactly like /admin/users (auth.go): service_role JWT, or an
		// access token that RBAC grants `users.admin`.
		r.Group(func(r chi.Router) {
			r.Use(a.requireAdmin)
			r.Get("/admin/audit", a.handle(a.adminAuditLog))
		})
	})
}

// ---- upstream action mapping ----------------------------------------------
//
// Dilion action constants (internal/audit) are graded for §5.2 and are a
// superset of gotrue's vocabulary. Where an obvious upstream equivalent exists
// the event is presented under the upstream name (so a Supabase client that
// switches on `payload.action` keeps working); where none exists the Dilion
// constant is passed through VERBATIM rather than squeezed into an approximate upstream
// name — accuracy over invention. `log_type` follows upstream's
// ActionLogTypeMap for mapped actions and is "" for passed-through ones, which
// is exactly what upstream writes for an action it has no mapping for.
//
//	Dilion action        upstream action   log_type   note
//	-------------------  ----------------  ---------  ------------------------
//	USER_CREATED         user_signedup     team       admin-created account
//	USER_UPDATED         user_modified     user
//	USER_DELETED         user_deleted      team
//	USER_LIST_READ       (verbatim)        ""         no upstream equivalent:
//	USER_DETAIL_READ     (verbatim)        ""         gotrue does not audit
//	                                                  reads at all
//	PII_*, CONSENT_*,    (verbatim)        ""         management-plane actions
//	ROLE_*, HOLD_*, …                                 outside gotrue's model
//
// The original Dilion constant is always preserved in
// payload.traits.dilion_action, so a translation is never lossy.
type upstreamAction struct {
	action  string
	logType string
}

var dilionToUpstreamAction = map[string]upstreamAction{
	audit.ActionUserCreated: {action: "user_signedup", logType: "team"},
	audit.ActionUserUpdated: {action: "user_modified", logType: "user"},
	audit.ActionUserDeleted: {action: "user_deleted", logType: "team"},
}

// mapAuditAction returns the upstream action name and log type for a Dilion
// action, falling back to the Dilion constant verbatim with an empty log type.
func mapAuditAction(a string) (string, string) {
	if m, ok := dilionToUpstreamAction[a]; ok {
		return m.action, m.logType
	}
	return a, ""
}

// auditIDNamespace turns a Dilion event id (an opaque text primary key) into
// the uuid upstream's `id` field is typed as. uuidv5 is deterministic, so the
// same event always presents the same id across calls and across replicas —
// a random id would break client-side de-duplication.
var auditIDNamespace = uuid.MustParse("7f9d1c2a-3b4e-5f60-8a71-9b2c3d4e5f60")

func auditEntryID(eventID string) uuid.UUID {
	return uuid.NewSHA1(auditIDNamespace, []byte(eventID))
}

// ---- response model -------------------------------------------------------

// AdminAuditLogEntry is upstream's models.AuditLogEntry on the wire: the field
// names, order and types are the compatibility contract.
type AdminAuditLogEntry struct {
	ID        uuid.UUID      `json:"id"`
	Payload   map[string]any `json:"payload"`
	CreatedAt time.Time      `json:"created_at"`
	IPAddress string         `json:"ip_address"`
}

// auditRow is one dilion_audit.events row as this file reads it.
type auditRow struct {
	eventID      string
	actorID      *string
	actorType    *string
	action       string
	resource     *string
	accessLevel  *string
	reason       *string
	requestID    *string
	resultCount  *int
	ip           *string
	userAgent    *string
	createdAt    time.Time
	subjectCount int
}

// toEntry translates one Dilion event into the upstream envelope.
//
// actor_username is ALWAYS "": upstream fills it with the actor's email or
// phone, and Dilion deliberately does not record personal-data VALUES in the
// audit store (§5.1 값이 아닌 행위) — the actor is identified by UUID only.
// Clients that need a display name must resolve actor_id through
// /admin/users/{id}, which is itself audited. actor_via_sso is likewise always
// false: SSO actors are out of wave-1 scope, so the field is reported as the
// truthful "not via SSO" rather than guessed.
func (r auditRow) toEntry() AdminAuditLogEntry {
	action, logType := mapAuditAction(r.action)

	traits := map[string]any{
		// The untranslated Dilion action, so the mapping above is never lossy.
		"dilion_action":   r.action,
		"dilion_event_id": r.eventID,
	}
	putIfSet(traits, "resource", r.resource)
	putIfSet(traits, "access_level", r.accessLevel)
	putIfSet(traits, "reason", r.reason)
	putIfSet(traits, "actor_type", r.actorType)
	putIfSet(traits, "request_id", r.requestID)
	putIfSet(traits, "user_agent", r.userAgent)
	if r.resultCount != nil {
		traits["result_count"] = *r.resultCount
	}
	// Only the COUNT of the subject manifest: a list response must not inline
	// N subject ids per row (§5.3), and the ids are personal identifiers.
	traits["subject_count"] = r.subjectCount

	payload := map[string]any{
		"actor_id":       derefOr(r.actorID, ""),
		"actor_username": "",
		"actor_via_sso":  false,
		"action":         action,
		"log_type":       logType,
		"traits":         traits,
	}

	return AdminAuditLogEntry{
		ID:        auditEntryID(r.eventID),
		Payload:   payload,
		CreatedAt: r.createdAt.UTC(),
		IPAddress: derefOr(r.ip, ""),
	}
}

func putIfSet(m map[string]any, key string, v *string) {
	if v != nil && *v != "" {
		m[key] = *v
	}
}

func derefOr(v *string, def string) string {
	if v == nil {
		return def
	}
	return *v
}

// ---- handler --------------------------------------------------------------

// adminAuditLog implements GET /admin/audit.
//
// Pagination is upstream's: ?page / ?per_page in, X-Total-Count and the
// next/last Link header out (the very same helpers /admin/users uses).
//
// ?query=<scope>:<value> supports upstream's three scopes; an unknown scope or
// a missing value is upstream's 400 "Invalid query scope: …".
func (a *api) adminAuditLog(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	page, perPage, err := paginationParams(r)
	if err != nil {
		return err
	}

	filter, ferr := parseAuditQuery(r.URL.Query().Get("query"))
	if ferr != nil {
		return ferr
	}

	project := actorFrom(ctx).ProjectID
	if project == "" {
		project = DefaultProjectID
	}

	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}

	where, args := filter.sql(project)

	var total int64
	if err := pool.QueryRow(ctx,
		`select count(*) from dilion_audit.events e where `+where, args...,
	).Scan(&total); err != nil {
		return internalServerError("Error searching for audit logs").withInternal(err)
	}

	entries, lerr := queryAuditEntries(ctx, pool, where, args, perPage, (page-1)*perPage)
	if lerr != nil {
		return internalServerError("Error searching for audit logs").withInternal(lerr)
	}

	addPaginationHeaders(w, r, page, perPage, total)

	// No emitAudit here — see the no-recursion note at the top of this file.
	return sendJSON(w, http.StatusOK, entries)
}

func queryAuditEntries(ctx context.Context, q querier, where string, args []any, limit, offset int64) ([]AdminAuditLogEntry, error) {
	args = append(append([]any(nil), args...), limit, offset)
	sql := `
		select e.event_id, e.actor_id, e.actor_type, e.action, e.resource,
		       e.access_level, e.reason, e.request_id, e.result_count,
		       e.ip, e.user_agent, e.created_at,
		       (select count(*) from dilion_audit.subjects s
		         where s.event_id = e.event_id)
		from dilion_audit.events e
		where ` + where + `
		order by e.created_at desc, e.event_id desc
		limit $` + fmt.Sprint(len(args)-1) + ` offset $` + fmt.Sprint(len(args))

	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Upstream answers an empty page with `[]`, never `null`.
	entries := []AdminAuditLogEntry{}
	for rows.Next() {
		var row auditRow
		if err := rows.Scan(&row.eventID, &row.actorID, &row.actorType, &row.action,
			&row.resource, &row.accessLevel, &row.reason, &row.requestID,
			&row.resultCount, &row.ip, &row.userAgent, &row.createdAt,
			&row.subjectCount); err != nil {
			return nil, err
		}
		entries = append(entries, row.toEntry())
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// ---- ?query= --------------------------------------------------------------

// auditFilter is the parsed ?query= scope.
//
// Upstream matches `payload->>'<column>' ILIKE '%value%'`. Dilion stores the
// UNtranslated event, so the same substring semantics are applied to the value
// the payload WOULD carry:
//
//	author:<v>  → upstream matches actor_username / actor_name. Dilion records
//	              no usernames (§5.1), so this matches actor_id instead. A full
//	              UUID therefore works; a display name never will.
//	action:<v>  → matched against the TRANSLATED action, so both
//	              `action:user_signedup` and `action:USER_LIST_READ` work.
//	type:<v>    → matched against the derived log_type. Only actions with an
//	              upstream mapping have one, so e.g. `type:team` selects
//	              USER_CREATED / USER_DELETED.
type auditFilter struct {
	// authorLike, when non-empty, is an ILIKE pattern for e.actor_id.
	authorLike string
	// actionLike is an ILIKE pattern applied to pass-through actions only.
	actionLike string
	// actionIn, when non-nil, is an explicit set of Dilion actions whose
	// TRANSLATED action (or log_type) matched. A non-nil empty set means
	// "nothing can match".
	actionIn []string
	// actionSet is true when actionIn is meaningful.
	actionSet bool
	// excludeMapped drops rows whose raw action has a translation, so an
	// `action:` pattern is never matched against a name the payload does not
	// actually carry.
	excludeMapped bool
}

func parseAuditQuery(q string) (auditFilter, error) {
	var f auditFilter
	if q == "" {
		return f, nil
	}
	scope, value, ok := strings.Cut(q, ":")
	switch {
	case !ok:
		return f, badRequestError(ErrorCodeValidationFailed, "Invalid query scope: %s", q)
	case scope == "author":
		if value != "" {
			f.authorLike = "%" + escapeLike(value) + "%"
		}
	case scope == "action":
		if value != "" {
			f.actionLike = "%" + escapeLike(value) + "%"
			f.excludeMapped = true
			f.actionIn = dilionActionsMatching(value, func(u upstreamAction) string { return u.action })
			f.actionSet = true
		}
	case scope == "type":
		if value != "" {
			// Only mapped actions carry a log_type, so this is an explicit set.
			f.actionIn = dilionActionsMatching(value, func(u upstreamAction) string { return u.logType })
			f.actionSet = true
			f.excludeMapped = true
			f.actionLike = "" // pass-through rows have log_type "" — never match
		}
	default:
		return f, badRequestError(ErrorCodeValidationFailed, "Invalid query scope: %s", q)
	}
	return f, nil
}

// dilionActionsMatching returns the Dilion actions whose projected upstream
// field contains value, case-insensitively (Postgres ILIKE '%value%').
func dilionActionsMatching(value string, project func(upstreamAction) string) []string {
	needle := strings.ToLower(value)
	out := []string{}
	for dilionAction, up := range dilionToUpstreamAction {
		if p := project(up); p != "" && strings.Contains(strings.ToLower(p), needle) {
			out = append(out, dilionAction)
		}
	}
	return out
}

// mappedDilionActions is the key set of dilionToUpstreamAction.
func mappedDilionActions() []string {
	out := make([]string, 0, len(dilionToUpstreamAction))
	for a := range dilionToUpstreamAction {
		out = append(out, a)
	}
	return out
}

// escapeLike neutralises the LIKE wildcards in a user-supplied value so that
// `author:%` is a literal search, not "everything".
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// sql renders the filter as a WHERE clause over `dilion_audit.events e` plus
// its positional arguments. Every value is a bound parameter.
func (f auditFilter) sql(project string) (string, []any) {
	conds := []string{"e.project_id = $1"}
	args := []any{project}

	next := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	if f.authorLike != "" {
		conds = append(conds, "e.actor_id ilike "+next(f.authorLike))
	}

	if f.actionSet {
		var or []string
		if f.actionLike != "" {
			c := "e.action ilike " + next(f.actionLike)
			if f.excludeMapped {
				c += " and not (e.action = any(" + next(mappedDilionActions()) + "))"
			}
			or = append(or, "("+c+")")
		}
		if len(f.actionIn) > 0 {
			or = append(or, "e.action = any("+next(f.actionIn)+")")
		}
		if len(or) == 0 {
			// The scope matched no possible action at all.
			conds = append(conds, "false")
		} else {
			conds = append(conds, "("+strings.Join(or, " or ")+")")
		}
	}

	return strings.Join(conds, " and "), args
}

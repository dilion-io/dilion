package auth

// Access records for the Supabase-compatible admin surface (project.md §5,
// 안전성 확보조치 기준 제8조 접속기록).
//
// /auth/v1/admin/users is the account directory itself: its reads return real
// email addresses, so every list/detail read is recorded at access level
// "full", and the create/update/delete operations are recorded as the graded
// changes they are (§5.2 "매우 민감"). Only the FACT of the access is recorded —
// never a personal-data value (§5.1 값이 아닌 행위): the event carries the
// subject's UUID in the manifest, never the email, phone or metadata.

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/ports"
)

// Resource strings recorded on the events. Stable, route-shaped, never a value.
const (
	auditResourceUsers = "auth/admin/users"
)

func auditResourceUser(id string) string { return auditResourceUsers + ":" + id }

// auditOpts is the part of an audit event a handler decides; actor, request id,
// IP and user agent are filled in from the request.
type auditOpts struct {
	Action      string
	Resource    string
	AccessLevel string
	ResultCount int
	SubjectIDs  []string
}

// emitAudit appends one access event for the current admin request.
//
// FAIL-OPEN by design, matching the policy for observability sinks elsewhere in
// this package (hooks, mail): a nil sink is a no-op for embedders that mount
// /auth/v1 standalone, and a sink error is logged at WARN and swallowed. The
// alternative — failing the request — would turn an audit-store outage into an
// auth outage. A missing access record is still a compliance defect, hence the
// loud log; durability of the record is the sink's responsibility (§5.4).
func (a *api) emitAudit(r *http.Request, o auditOpts) {
	if a.audit == nil {
		return
	}
	ctx := r.Context()
	level := o.AccessLevel
	if level == "" {
		level = audit.AccessNA
	}
	actor := actorFrom(ctx)
	project := actor.ProjectID
	if project == "" {
		project = DefaultProjectID
	}
	ev := ports.AuditEvent{
		ProjectID:   project,
		ActorID:     actor.ID,
		ActorType:   actor.Type,
		Action:      o.Action,
		Resource:    o.Resource,
		AccessLevel: level,
		RequestID:   auditRequestID(r),
		ResultCount: o.ResultCount,
		SubjectIDs:  o.SubjectIDs,
		IP:          auditClientIP(r),
		UserAgent:   r.UserAgent(),
		OccurredAt:  a.now(),
	}
	if err := a.audit.Append(ctx, ev); err != nil {
		a.log.WarnContext(ctx, "auth: audit append failed",
			slog.String("action", o.Action),
			slog.String("actor_id", actor.ID),
			slog.String("request_id", ev.RequestID),
			slog.String("error", err.Error()))
	}
}

// auditRequestID mirrors the management plane: the inbound X-Request-Id wins,
// otherwise the id chi's RequestID middleware put on the context.
func auditRequestID(r *http.Request) string {
	if id := strings.TrimSpace(r.Header.Get("X-Request-Id")); id != "" {
		return id
	}
	return middleware.GetReqID(r.Context())
}

// auditClientIP is the address the transport middleware resolved for this
// request (middleware.go clientIP): the first usable X-Forwarded-For hop,
// otherwise the peer address without its port.
func auditClientIP(r *http.Request) string { return clientIP(r) }

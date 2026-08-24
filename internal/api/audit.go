package api

// Audit read surface (/iam/v1/audit/events, project.md §5.3).
//
// Reading the audit log is NOT itself audited: an access record for every
// access record recurses without adding evidence, and the read is already
// guarded by `audit.read` (a write permission for the log does not exist,
// §2.11). Every other operation in this package emits an event.

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/internal/iam"
)

// ---- DTOs ----

// AuditEvent is one recorded access event (§5.1: who, when, from where, with
// which access level, over which scope, doing what — never the personal data
// values themselves).
type AuditEvent struct {
	ID          string    `json:"id" example:"evt_1f0c0b6a7d5e4a2b9c8d7e6f5a4b3c2d"`
	ActorID     *string   `json:"actor_id" nullable:"true" doc:"Operator or API key id, or null for system events."`
	ActorType   *string   `json:"actor_type" nullable:"true" doc:"admin | api_key | service_role | user | system."`
	Action      string    `json:"action" example:"PII_FULL_READ" doc:"Recorded action, UPPER_SNAKE_CASE."`
	Resource    *string   `json:"resource" nullable:"true" doc:"Resource or route the action targeted."`
	AccessLevel *string   `json:"access_level" nullable:"true" doc:"masked | full | n/a."`
	RequestID   *string   `json:"request_id" nullable:"true"`
	ResultCount *int      `json:"result_count" nullable:"true" doc:"Number of records the action touched."`
	Reason      *string   `json:"reason" nullable:"true" doc:"Operator-supplied justification (PII reveal 사유), or null."`
	IP          *string   `json:"ip" nullable:"true"`
	UserAgent   *string   `json:"user_agent" nullable:"true"`
	CreatedAt   time.Time `json:"created_at"`
	SubjectIDs  []string  `json:"subject_ids" nullable:"false" doc:"Subject manifest (§5.3). Returned by getAuditEvent; always empty in list responses."`
}

// AuditEventPage is the cursor-paginated list envelope.
type AuditEventPage struct {
	Items      []AuditEvent `json:"items" nullable:"false"`
	NextCursor *string      `json:"next_cursor" nullable:"true" doc:"Opaque cursor for the next page, or null."`
}

func toAuditEvent(in audit.Event) AuditEvent {
	subjects := in.SubjectIDs
	if subjects == nil {
		subjects = []string{}
	}
	return AuditEvent{
		ID: in.ID, ActorID: in.ActorID, ActorType: in.ActorType, Action: in.Action,
		Resource: in.Resource, AccessLevel: in.AccessLevel, RequestID: in.RequestID,
		ResultCount: in.ResultCount, Reason: in.Reason, IP: in.IP,
		UserAgent: in.UserAgent, CreatedAt: in.CreatedAt, SubjectIDs: subjects,
	}
}

// ---- inputs / outputs ----

type listAuditEventsInput struct {
	Limit     int       `query:"limit" default:"20" minimum:"1" maximum:"100" doc:"Page size."`
	Cursor    string    `query:"cursor" doc:"Opaque cursor from a previous response."`
	ActorID   string    `query:"actor_id" doc:"Filter by the actor that performed the action."`
	Action    string    `query:"action" doc:"Filter by action, e.g. PII_FULL_READ."`
	SubjectID string    `query:"subject_id" doc:"Reverse lookup: only events whose subject manifest contains this data subject (§5.3)."`
	From      time.Time `query:"from" required:"false" doc:"Only events at or after this time (RFC 3339). 정기 점검 리포트용 기간 창."`
	To        time.Time `query:"to" required:"false" doc:"Only events before this time (RFC 3339, exclusive)."`
}

type auditEventPageOutput struct {
	Body AuditEventPage
}

type getAuditEventInput struct {
	EventID string `path:"eventId" pattern:"^evt_[0-9a-f]{32}$"`
}

type auditEventOutput struct {
	Body AuditEvent
}

// ---- registration ----

// notAuditedNote is appended to both operation descriptions so the exemption is
// part of the published contract, not folklore.
const notAuditedNote = "\n\nReading the audit log is **not itself audited**: recording an access " +
	"event for every audit read would recurse without adding evidence. The audit log is " +
	"append-only — no write permission for it exists (§5.4)."

func (r *registrar) registerAudit() {
	const perm = iam.PermAuditRead

	listOp := r.op("listAuditEvents", http.MethodGet, "/iam/v1/audit/events",
		"List audit events", perm, "iam", http.StatusOK)
	listOp.Description += "\n\nEvents are returned newest first. `subject_id` answers the " +
		"reverse question \"who accessed subject X\" (§5.3); the subject manifest itself is " +
		"only returned by `getAuditEvent`." + notAuditedNote
	huma.Register(r.api, listOp,
		func(ctx context.Context, in *listAuditEventsInput) (*auditEventPageOutput, error) {
			page, err := r.events.ListEvents(ctx, projectOf(ctx), audit.EventFilter{
				ActorID:   optional(in.ActorID),
				Action:    optional(in.Action),
				SubjectID: optional(in.SubjectID),
				From:      optionalTime(in.From),
				To:        optionalTime(in.To),
			}, listParams(in.Limit, in.Cursor, ""))
			if err != nil {
				return nil, mapAuditError(ctx, err)
			}
			return &auditEventPageOutput{Body: AuditEventPage{
				Items: mapItems(page.Items, toAuditEvent), NextCursor: page.NextCursor,
			}}, nil
		})

	getOp := r.op("getAuditEvent", http.MethodGet, "/iam/v1/audit/events/{eventId}",
		"Get an audit event", perm, "iam", http.StatusOK)
	getOp.Description += "\n\nReturns the event together with its full subject manifest " +
		"(§5.3)." + notAuditedNote
	huma.Register(r.api, getOp,
		func(ctx context.Context, in *getAuditEventInput) (*auditEventOutput, error) {
			ev, err := r.events.GetEvent(ctx, projectOf(ctx), in.EventID)
			if err != nil {
				return nil, mapAuditError(ctx, err)
			}
			return &auditEventOutput{Body: toAuditEvent(*ev)}, nil
		})
}

// optional turns an absent (empty) query parameter into a nil filter.
func optional(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

// optionalTime turns an absent (zero) time parameter into a nil filter.
func optionalTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

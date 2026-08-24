// Package audit implements the default append-only audit sink (project.md §5).
//
// Two tables are written in one transaction: `dilion_audit.events` (one row per
// access event) and `dilion_audit.subjects` (the subject manifest, §5.3) so that
// "who accessed subject X" stays answerable without embedding N user ids in the
// event row. Personal data values are never written here (§5.1).
package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/ports"
)

// Action constants (§5.2). The management plane only ever appends these.
//
// Read actions name the RECORD KIND that was read, not the credential or the
// screen. USER_* is reserved for the account directory itself (the Supabase
// compatible /auth/v1/admin/users surface); subject-scoped records under
// /privacy/v1 have their own actions so that filtering by action stays
// meaningful and §5.2 sensitivity grading survives. Every subject-scoped read
// still records the subject manifest, so reverse lookup ("who accessed user
// X?", §5.3) works regardless of action.
const (
	ActionUserListRead   = "USER_LIST_READ"
	ActionUserDetailRead = "USER_DETAIL_READ"
	ActionUserCreated    = "USER_CREATED"
	ActionUserUpdated    = "USER_UPDATED"
	ActionUserDeleted    = "USER_DELETED"

	ActionPIIMaskedRead = "PII_MASKED_READ"
	ActionPIIFullRead   = "PII_FULL_READ"
	ActionPIIUpdate     = "PII_UPDATE"
	ActionPIIExport     = "PII_EXPORT"

	ActionPrivacyRequestCreated    = "PRIVACY_REQUEST_CREATED"
	ActionPrivacyRequestCanceled   = "PRIVACY_REQUEST_CANCELED"
	ActionPrivacyRequestListRead   = "PRIVACY_REQUEST_LIST_READ"
	ActionPrivacyRequestDetailRead = "PRIVACY_REQUEST_DETAIL_READ"

	ActionConsentChanged = "CONSENT_CHANGED"
	ActionConsentRead    = "CONSENT_READ"
	// CONSENT_SEGMENT_READ is the cross-user consent projection (ids only);
	// CONSENT_AUDIENCE_EXPORT joins it with contact identifiers and is a
	// "매우 민감" export with a mandatory reason (use-cases.md P1).
	ActionConsentSegmentRead    = "CONSENT_SEGMENT_READ"
	ActionConsentAudienceExport = "CONSENT_AUDIENCE_EXPORT"

	// USER_SEARCH is the exact-match lookup by email/phone/profile field. The
	// search value itself is never recorded (§5.1) — only the matched subjects.
	ActionUserSearch = "USER_SEARCH"

	ActionHoldCreated        = "HOLD_CREATED"
	ActionHoldReleased       = "HOLD_RELEASED"
	ActionHoldListRead       = "LEGAL_HOLD_LIST_READ"
	ActionDestinationChanged = "DESTINATION_CHANGED"
	ActionDestinationRead    = "DESTINATION_READ"

	ActionRoleGranted = "ROLE_GRANTED"
	ActionRoleRevoked = "ROLE_REVOKED"
	// Definition changes are permission changes too ("매우 민감", §5.2).
	ActionRoleCreated       = "ROLE_CREATED"
	ActionPermissionCreated = "PERMISSION_CREATED"

	ActionAPIKeyCreated = "API_KEY_CREATED"
	ActionAPIKeyRevoked = "API_KEY_REVOKED"
	// IAM_READ covers reads of the authorization configuration itself
	// (roles, assignments, permissions, holders, api keys).
	ActionIAMRead        = "IAM_READ"
	ActionServiceRoleUse = "SERVICE_ROLE_USED"

	ActionPermissionDenied = "PERMISSION_DENIED"
)

// Access levels recorded on the event row (§5.1 "어떤 권한으로").
const (
	AccessMasked = "masked"
	AccessFull   = "full"
	AccessNA     = "n/a"
)

// DefaultProjectID is used when an event carries no project (wave 1 is single
// project, see PLAN.md §3.5).
const DefaultProjectID = "default"

// PoolFunc resolves the database pool for a request, so that in a
// multi-instance deployment an event is written to the database of the instance
// selected on the context (ports.ContextWithInstance, internal/instances). It
// is structurally identical to instances.PoolFunc; declared locally to keep
// this package's imports narrow.
type PoolFunc func(context.Context) (*pgxpool.Pool, error)

// StaticPool is the single-instance PoolFunc over one fixed pool.
func StaticPool(pool *pgxpool.Pool) PoolFunc {
	return func(context.Context) (*pgxpool.Pool, error) {
		if pool == nil {
			return nil, fmt.Errorf("audit: nil pool")
		}
		return pool, nil
	}
}

func resolvePool(ctx context.Context, f PoolFunc) (*pgxpool.Pool, error) {
	if f == nil {
		return nil, fmt.Errorf("audit: nil pool")
	}
	pool, err := f(ctx)
	if err != nil {
		return nil, err
	}
	if pool == nil {
		return nil, fmt.Errorf("audit: nil pool")
	}
	return pool, nil
}

type sink struct {
	pools PoolFunc
}

// NewSink returns the Postgres-backed audit sink over one fixed pool. The sink
// is append-only: it issues INSERTs and nothing else.
func NewSink(pool *pgxpool.Pool) ports.AuditSink { return &sink{pools: StaticPool(pool)} }

// NewSinkFor returns the audit sink over a per-request pool provider.
func NewSinkFor(pools PoolFunc) ports.AuditSink { return &sink{pools: pools} }

func (s *sink) Append(ctx context.Context, e ports.AuditEvent) error {
	pool, err := resolvePool(ctx, s.pools)
	if err != nil {
		return err
	}
	if e.Action == "" {
		return fmt.Errorf("audit: action is required")
	}
	if e.ProjectID == "" {
		e.ProjectID = DefaultProjectID
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	eventID := httpapi.NewID("evt")

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("audit: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		insert into dilion_audit.events
			(event_id, project_id, actor_id, actor_type, action, resource,
			 access_level, request_id, result_count, reason, ip, user_agent, created_at)
		values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		eventID, e.ProjectID, nullStr(e.ActorID), nullStr(e.ActorType), e.Action,
		nullStr(e.Resource), nullStr(e.AccessLevel), nullStr(e.RequestID),
		e.ResultCount, nullStr(e.Reason), nullStr(e.IP), nullStr(e.UserAgent), e.OccurredAt,
	); err != nil {
		return fmt.Errorf("audit: insert event: %w", err)
	}

	if len(e.SubjectIDs) > 0 {
		seen := make(map[string]struct{}, len(e.SubjectIDs))
		batch := &pgx.Batch{}
		for _, sid := range e.SubjectIDs {
			if sid == "" {
				continue
			}
			if _, dup := seen[sid]; dup {
				continue
			}
			seen[sid] = struct{}{}
			batch.Queue(`insert into dilion_audit.subjects (event_id, subject_id)
			             values ($1,$2) on conflict do nothing`, eventID, sid)
		}
		if batch.Len() > 0 {
			if err := tx.SendBatch(ctx, batch).Close(); err != nil {
				return fmt.Errorf("audit: insert subjects: %w", err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("audit: commit: %w", err)
	}
	return nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// NopSink discards events. Intended for spec generation and tests only — never
// wire it into a deployment, audit logging is a compliance obligation (§5).
type NopSink struct{}

func (NopSink) Append(context.Context, ports.AuditEvent) error { return nil }

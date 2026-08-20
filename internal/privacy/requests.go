package privacy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/dilion-project/dilion/httpapi"
	"github.com/dilion-project/dilion/ports"
)

const requestCols = `id, user_id::text, type, status, policy_id, scheduled_at, requested_at, completed_at`

func scanRequest(row pgx.Row) (*Request, error) {
	var r Request
	err := row.Scan(&r.ID, &r.UserID, &r.Type, &r.Status, &r.PolicyID,
		&r.ScheduledAt, &r.RequestedAt, &r.CompletedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func validRequestType(t RequestType) bool {
	switch t {
	case RequestDeletion, RequestExport, RequestConsentWithdrawal:
		return true
	}
	return false
}

// resolvePolicy implements §2.8 resolution: explicit subject_policies row,
// else the configured default policy.
func (e *Engine) resolvePolicy(ctx context.Context, userID string) (string, *Policy, error) {
	var policyID string
	err := e.pool.QueryRow(ctx,
		`select policy_id from dilion_privacy.subject_policies where user_id = $1::uuid`, userID).
		Scan(&policyID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", nil, fmt.Errorf("privacy: subject policy lookup: %w", err)
	}
	if errors.Is(err, pgx.ErrNoRows) || policyID == "" {
		policyID = e.policies.DefaultPolicy
	}
	p, known := e.policies.Resolve(policyID)
	if !known {
		// Assigned code no longer exists in the policy file. Fall back to the
		// default but keep the audit trail honest.
		e.log.Warn("subject policy code not defined; falling back to default",
			"assigned", policyID, "default", e.policies.DefaultPolicy)
		policyID = e.policies.DefaultPolicy
	}
	return policyID, p, nil
}

// CreateRequest creates a data subject request (§2.9).
func (e *Engine) CreateRequest(ctx context.Context, in CreateRequestInput) (*Request, error) {
	projectID := normProject(in.ProjectID)
	userID, err := validUUID(in.UserID)
	if err != nil {
		return nil, err
	}
	if !validRequestType(in.Type) {
		return nil, fmt.Errorf("%w: unknown request type %q", ErrInvalidInput, in.Type)
	}

	// 1. Idempotency replay (§ api-conventions: same key returns first response).
	if in.IdempotencyKey != "" {
		prev, err := e.requestByIdempotencyKey(ctx, projectID, in.IdempotencyKey)
		if err != nil {
			return nil, err
		}
		if prev != nil {
			// Same key + same input replays the original response; same key with
			// different input is a 409 idempotency conflict.
			if prev.UserID != userID || prev.Type != in.Type {
				return nil, ErrIdempotencyReplay
			}
			return prev, nil
		}
	}

	// 2. Duplicate active DELETION (the partial unique index is the real guard;
	//    this check produces the friendly error on the common path).
	if in.Type == RequestDeletion {
		var exists bool
		if err := e.pool.QueryRow(ctx, `select exists (
			select 1 from dilion_privacy.personal_data_requests
			where user_id = $1::uuid and type = 'DELETION'
			  and status in ('REQUESTED','PROCESSING','MANUAL_REVIEW'))`, userID).Scan(&exists); err != nil {
			return nil, fmt.Errorf("privacy: duplicate request check: %w", err)
		}
		if exists {
			return nil, ErrConflict
		}
	}

	// 3. Resolve + snapshot policy.
	policyID, policy, err := e.resolvePolicy(ctx, userID)
	if err != nil {
		return nil, err
	}
	snapshot, err := policy.Snapshot()
	if err != nil {
		return nil, fmt.Errorf("privacy: policy snapshot: %w", err)
	}

	// 4. Consent / hook gates.
	if in.Type == RequestDeletion {
		payload := map[string]any{
			"project_id": projectID, "user_id": userID, "policy_id": policyID,
			"request_type": string(in.Type), "immediate": in.Immediate,
			"requested_by": in.RequestedBy,
		}
		if err := e.runHook(ctx, ports.BeforeUserDelete, payload); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrPolicyViolation, err)
		}
	}
	if in.Type == RequestConsentWithdrawal {
		// Withdrawing consent required by policy cannot be granted implicitly;
		// the caller must withdraw specific purposes via UpdateConsent.
		if keys := policy.RequiredConsentKeys(); len(keys) > 0 {
			e.log.Info("consent withdrawal request created; required keys stay granted",
				"policy", policyID, "required_keys", strings.Join(keys, ","))
		}
	}

	// 5. Schedule + status.
	now := e.now()
	scheduledAt := now
	if !in.Immediate {
		scheduledAt = now.AddDate(0, 0, policy.GraceDays())
	}
	status := StatusRequested
	var reviewReason *string
	if in.Type == RequestDeletion && policy.ManualReview() {
		status = StatusManualReview
		r := "POLICY"
		reviewReason = &r
	}

	id := httpapi.NewID("pr")
	var idem *string
	if in.IdempotencyKey != "" {
		k := in.IdempotencyKey
		idem = &k
	}
	var requestedBy *string
	if in.RequestedBy != "" {
		rb := in.RequestedBy
		requestedBy = &rb
	}

	const ins = `insert into dilion_privacy.personal_data_requests
		(id, project_id, user_id, type, status, policy_id, policy_snapshot, scheduled_at,
		 requested_at, idempotency_key, requested_by, manual_review_reason)
		values ($1,$2,$3::uuid,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12)
		returning ` + requestCols

	row := e.pool.QueryRow(ctx, ins, id, projectID, userID, in.Type, status, policyID,
		string(snapshot), scheduledAt, now, idem, requestedBy, reviewReason)
	req, err := scanRequest(row)
	if err != nil {
		if isUniqueViolation(err) {
			var pg *pgconn.PgError
			_ = errors.As(err, &pg)
			if pg != nil && strings.Contains(pg.ConstraintName, "idempotency") {
				return nil, ErrIdempotencyReplay
			}
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("privacy: create request: %w", err)
	}

	if in.Type == RequestExport {
		// TODO(wave2): no export pipeline yet — the request is recorded but no
		// worker will fulfil it (PLAN.md §6).
		e.log.Warn("EXPORT request accepted but no export pipeline exists (wave 2)", "request_id", req.ID)
	}
	e.log.Info("privacy request created", "request_id", req.ID, "type", req.Type,
		"status", req.Status, "policy", policyID, "scheduled_at", req.ScheduledAt)
	return req, nil
}

func (e *Engine) requestByIdempotencyKey(ctx context.Context, projectID, key string) (*Request, error) {
	const q = `select ` + requestCols + `
		from dilion_privacy.personal_data_requests
		where project_id = $1 and idempotency_key = $2`
	r, err := scanRequest(e.pool.QueryRow(ctx, q, projectID, key))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("privacy: idempotency lookup: %w", err)
	}
	return r, nil
}

// GetRequest returns a request scoped to the project (cross-tenant reads are
// indistinguishable from "not found" per api-conventions).
func (e *Engine) GetRequest(ctx context.Context, projectID, id string) (*Request, error) {
	const q = `select ` + requestCols + ` from dilion_privacy.personal_data_requests
		where project_id = $1 and id = $2`
	r, err := scanRequest(e.pool.QueryRow(ctx, q, normProject(projectID), id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("privacy: get request: %w", err)
	}
	return r, nil
}

// ListRequests pages requests newest-first, optionally filtered by status.
func (e *Engine) ListRequests(ctx context.Context, projectID string, status *RequestStatus, p httpapi.ListParams) (httpapi.Page[Request], error) {
	p = p.Norm()
	var zero httpapi.Page[Request]
	curTS, curID, err := decodeCursor(p.Cursor)
	if err != nil {
		return zero, err
	}
	const q = `select ` + requestCols + ` from dilion_privacy.personal_data_requests
		where project_id = $1
		  and ($2::text is null or status = $2)
		  and ($3::timestamptz is null or (requested_at, id) < ($3, $4))
		order by requested_at desc, id desc
		limit $5`
	var statusArg *string
	if status != nil {
		s := string(*status)
		statusArg = &s
	}
	var tsArg any
	if !curTS.IsZero() {
		tsArg = curTS
	}
	rows, err := e.pool.Query(ctx, q, normProject(projectID), statusArg, tsArg, curID, p.Limit+1)
	if err != nil {
		return zero, fmt.Errorf("privacy: list requests: %w", err)
	}
	defer rows.Close()
	var items []Request
	for rows.Next() {
		r, err := scanRequest(rows)
		if err != nil {
			return zero, fmt.Errorf("privacy: list requests: %w", err)
		}
		items = append(items, *r)
	}
	if err := rows.Err(); err != nil {
		return zero, fmt.Errorf("privacy: list requests: %w", err)
	}
	return page(items, p.Limit, func(r Request) *string { return encodeCursor(r.RequestedAt, r.ID) }), nil
}

// CancelRequest withdraws a request that is still inside the grace period.
func (e *Engine) CancelRequest(ctx context.Context, projectID, id string) (*Request, error) {
	const q = `update dilion_privacy.personal_data_requests
		set status = 'CANCELED'
		where project_id = $1 and id = $2 and status = 'REQUESTED'
		returning ` + requestCols
	r, err := scanRequest(e.pool.QueryRow(ctx, q, normProject(projectID), id))
	if errors.Is(err, pgx.ErrNoRows) {
		// Distinguish "gone" from "no longer cancelable".
		if _, gerr := e.GetRequest(ctx, projectID, id); gerr != nil {
			return nil, gerr
		}
		return nil, ErrConflict
	}
	if err != nil {
		return nil, fmt.Errorf("privacy: cancel request: %w", err)
	}
	e.log.Info("privacy request canceled", "request_id", r.ID)
	return r, nil
}

// setManualReview parks a request for human handling and records why.
func (e *Engine) setManualReview(ctx context.Context, requestID, reason string) error {
	_, err := e.pool.Exec(ctx, `update dilion_privacy.personal_data_requests
		set status = 'MANUAL_REVIEW', manual_review_reason = $2 where id = $1`, requestID, reason)
	if err != nil {
		return fmt.Errorf("privacy: set manual review: %w", err)
	}
	e.log.Warn("privacy request parked for manual review", "request_id", requestID, "reason", reason)
	return nil
}

package privacy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/dilion-project/dilion/httpapi"
)

const holdCols = `id, user_id::text, domain, reason, coalesce(basis,''), created_at, released_at`

func scanHold(row pgx.Row) (*LegalHold, error) {
	var h LegalHold
	if err := row.Scan(&h.ID, &h.UserID, &h.Domain, &h.Reason, &h.Basis, &h.CreatedAt, &h.ReleasedAt); err != nil {
		return nil, err
	}
	return &h, nil
}

// CreateHold places a legal hold. Holds gate the erasure pipeline, the
// retention scanner and restore-time replay (§2.9 triple gate).
func (e *Engine) CreateHold(ctx context.Context, in CreateHoldInput) (*LegalHold, error) {
	pid := normProject(in.ProjectID)
	uid, err := validUUID(in.UserID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(in.Reason) == "" {
		return nil, fmt.Errorf("%w: reason is required", ErrInvalidInput)
	}
	if in.Domain != nil && *in.Domain != "" && !isRetentionDomain(*in.Domain) {
		return nil, fmt.Errorf("%w: unknown domain %q", ErrInvalidInput, *in.Domain)
	}
	const ins = `insert into dilion_privacy.legal_holds
		(id, project_id, user_id, domain, reason, basis, created_by, created_at)
		values ($1,$2,$3::uuid,$4,$5,nullif($6,''),nullif($7,''),$8) returning ` + holdCols
	h, err := scanHold(e.pool.QueryRow(ctx, ins, httpapi.NewID("hold"), pid, uid, in.Domain,
		in.Reason, in.Basis, in.CreatedBy, e.now()))
	if err != nil {
		return nil, fmt.Errorf("privacy: create hold: %w", err)
	}
	e.log.Warn("legal hold created", "hold_id", h.ID, "user_id", h.UserID, "reason", h.Reason)
	return h, nil
}

// ReleaseHold lifts a hold and resumes requests that the hold had parked
// (§2.9: "해제 시 보류된 요청이 자동으로 재개됩니다").
func (e *Engine) ReleaseHold(ctx context.Context, projectID, id, releasedBy string) (*LegalHold, error) {
	pid := normProject(projectID)
	const upd = `update dilion_privacy.legal_holds
		set released_at = $3, released_by = nullif($4,'')
		where project_id = $1 and id = $2 and released_at is null
		returning ` + holdCols
	h, err := scanHold(e.pool.QueryRow(ctx, upd, pid, id, e.now(), releasedBy))
	if errors.Is(err, pgx.ErrNoRows) {
		if _, gerr := e.getHold(ctx, pid, id); gerr != nil {
			return nil, gerr
		}
		return nil, ErrConflict // already released
	}
	if err != nil {
		return nil, fmt.Errorf("privacy: release hold: %w", err)
	}

	still, err := e.activeHoldFor(ctx, h.UserID, "")
	if err != nil {
		return nil, err
	}
	if !still {
		tag, err := e.pool.Exec(ctx, `update dilion_privacy.personal_data_requests
			set status = 'REQUESTED', manual_review_reason = null
			where user_id = $1::uuid and type = 'DELETION'
			  and status = 'MANUAL_REVIEW' and manual_review_reason = 'LEGAL_HOLD'`, h.UserID)
		if err != nil {
			return nil, fmt.Errorf("privacy: resume held requests: %w", err)
		}
		if n := tag.RowsAffected(); n > 0 {
			e.log.Info("erasure requests resumed after hold release", "user_id", h.UserID, "count", n)
		}
	}
	e.log.Warn("legal hold released", "hold_id", h.ID, "user_id", h.UserID, "released_by", releasedBy)
	return h, nil
}

func (e *Engine) getHold(ctx context.Context, projectID, id string) (*LegalHold, error) {
	const q = `select ` + holdCols + ` from dilion_privacy.legal_holds where project_id = $1 and id = $2`
	h, err := scanHold(e.pool.QueryRow(ctx, q, projectID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("privacy: get hold: %w", err)
	}
	return h, nil
}

func (e *Engine) ListHolds(ctx context.Context, projectID string, f HoldFilter, p httpapi.ListParams) (httpapi.Page[LegalHold], error) {
	p = p.Norm()
	var zero httpapi.Page[LegalHold]
	cur, err := decodeIDCursor(p.Cursor)
	if err != nil {
		return zero, err
	}
	var uid *string
	if f.UserID != nil {
		v, err := validUUID(*f.UserID)
		if err != nil {
			return zero, err
		}
		uid = &v
	}
	const q = `select ` + holdCols + ` from dilion_privacy.legal_holds
		where project_id = $1
		  and ($2::uuid is null or user_id = $2::uuid)
		  and ($3::bool is null or (released_at is null) = $3)
		  and ($4 = '' or id > $4)
		order by id limit $5`
	rows, err := e.pool.Query(ctx, q, normProject(projectID), uid, f.Active, cur, p.Limit+1)
	if err != nil {
		return zero, fmt.Errorf("privacy: list holds: %w", err)
	}
	defer rows.Close()
	var items []LegalHold
	for rows.Next() {
		h, err := scanHold(rows)
		if err != nil {
			return zero, fmt.Errorf("privacy: list holds: %w", err)
		}
		items = append(items, *h)
	}
	if err := rows.Err(); err != nil {
		return zero, fmt.Errorf("privacy: list holds: %w", err)
	}
	return page(items, p.Limit, func(h LegalHold) *string { return encodeIDCursor(h.ID) }), nil
}

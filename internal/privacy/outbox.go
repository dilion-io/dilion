package privacy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dilion-project/dilion/httpapi"
)

const maxOutboxPerTick = 50

// Outbox event types (§2.5, §3.2).
const (
	EventUserDeleted  = "user.deleted"
	EventReconfirmDue = "consent.reconfirm_due"
)

type outboxRow struct {
	ID          string
	EventType   string
	AggregateID string
	Payload     []byte
}

// dispatchOutboxOnce turns committed domain events into privacy work. The
// outbox is written by auth (agent B) inside the account-delete transaction.
func (e *Engine) dispatchOutboxOnce(ctx context.Context) error {
	const q = `select id::text, event_type, aggregate_id, payload
		from dilion_privacy.outbox where published_at is null
		order by created_at limit $1`
	rows, err := e.pool.Query(ctx, q, maxOutboxPerTick)
	if err != nil {
		return fmt.Errorf("privacy: outbox poll: %w", err)
	}
	var batch []outboxRow
	for rows.Next() {
		var r outboxRow
		if err := rows.Scan(&r.ID, &r.EventType, &r.AggregateID, &r.Payload); err != nil {
			rows.Close()
			return fmt.Errorf("privacy: outbox poll: %w", err)
		}
		batch = append(batch, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("privacy: outbox poll: %w", err)
	}

	for _, r := range batch {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var handled bool
		var herr error
		switch r.EventType {
		case EventUserDeleted:
			handled, herr = e.handleUserDeleted(ctx, r)
		case EventReconfirmDue:
			handled, herr = e.handleReconfirmDue(ctx, r)
		default:
			e.log.Warn("unhandled outbox event type", "event_type", r.EventType, "outbox_id", r.ID)
			handled = true
		}
		if herr != nil {
			e.log.Error("outbox dispatch failed", "outbox_id", r.ID, "event_type", r.EventType, "err", herr)
			continue // stays unpublished; retried next tick
		}
		if !handled {
			continue
		}
		if _, err := e.pool.Exec(ctx, `update dilion_privacy.outbox
			set published_at = $2 where id = $1::uuid and published_at is null`, r.ID, e.now()); err != nil {
			return fmt.Errorf("privacy: outbox publish: %w", err)
		}
	}
	return nil
}

type userDeletedPayload struct {
	UserID      string `json:"user_id"`
	ProjectID   string `json:"project_id"`
	RequestedBy string `json:"requested_by"`
}

func (e *Engine) handleUserDeleted(ctx context.Context, r outboxRow) (bool, error) {
	var p userDeletedPayload
	if err := json.Unmarshal(r.Payload, &p); err != nil {
		e.log.Error("malformed user.deleted payload; dropping", "outbox_id", r.ID, "err", err)
		return true, nil
	}
	if p.UserID == "" {
		p.UserID = r.AggregateID
	}
	userID, err := validUUID(p.UserID)
	if err != nil {
		e.log.Error("user.deleted with non-uuid subject; dropping", "outbox_id", r.ID)
		return true, nil
	}

	// Dedup: an account may already have a request (API-initiated, or a replay).
	var exists bool
	if err := e.pool.QueryRow(ctx, `select exists (
		select 1 from dilion_privacy.personal_data_requests
		where user_id = $1::uuid and type = 'DELETION'
		  and status in ('REQUESTED','PROCESSING','MANUAL_REVIEW','DONE'))`, userID).Scan(&exists); err != nil {
		return false, fmt.Errorf("privacy: outbox dedup: %w", err)
	}
	if exists {
		e.log.Info("user.deleted already has a privacy request; marking published",
			"outbox_id", r.ID, "user_id", userID)
		return true, nil
	}

	req, err := e.CreateRequest(ctx, CreateRequestInput{
		ProjectID:      normProject(p.ProjectID),
		UserID:         userID,
		Type:           RequestDeletion,
		Immediate:      false,
		IdempotencyKey: "outbox:" + r.ID,
		RequestedBy:    p.RequestedBy,
	})
	switch {
	case errors.Is(err, ErrConflict), errors.Is(err, ErrIdempotencyReplay):
		return true, nil // lost a race; the request exists
	case err != nil:
		return false, err
	}
	e.log.Info("erasure request created from outbox", "outbox_id", r.ID, "request_id", req.ID)
	return true, nil
}

// handleReconfirmDue fans a reconfirm notice out to webhook destinations,
// reusing the task machinery (signing, retry, DLQ).
func (e *Engine) handleReconfirmDue(ctx context.Context, r outboxRow) (bool, error) {
	var p struct {
		UserID    string `json:"user_id"`
		ProjectID string `json:"project_id"`
	}
	_ = json.Unmarshal(r.Payload, &p)
	if p.UserID == "" {
		p.UserID = r.AggregateID
	}
	userID, err := validUUID(p.UserID)
	if err != nil {
		e.log.Error("consent.reconfirm_due with non-uuid subject; dropping", "outbox_id", r.ID)
		return true, nil
	}

	rows, err := e.pool.Query(ctx, `select id from dilion_privacy.destinations
		where project_id = $1 and enabled and type = $2 order by id`,
		normProject(p.ProjectID), string(DestinationWebhook))
	if err != nil {
		return false, fmt.Errorf("privacy: reconfirm destinations: %w", err)
	}
	var dests []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return false, err
		}
		dests = append(dests, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}

	for _, dst := range dests {
		if _, err := e.pool.Exec(ctx, `insert into dilion_privacy.tasks
			(id, request_id, user_id, destination_id, action, status, created_at, next_attempt_at, payload)
			values ($1,$2,$3::uuid,$4,$5,'pending',$6,$6,$7::jsonb)
			on conflict (request_id, destination_id) do nothing`,
			httpapi.NewID("tsk"), r.ID, userID, dst, TaskActionReconfirm, e.now(), string(r.Payload)); err != nil {
			return false, fmt.Errorf("privacy: reconfirm task: %w", err)
		}
	}
	if len(dests) == 0 {
		e.log.Info("consent.reconfirm_due has no enabled webhook destination",
			"outbox_id", r.ID, "user_id", userID)
	}
	return true, nil
}

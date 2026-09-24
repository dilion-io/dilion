package privacy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/ports"
)

// advisoryLockNS namespaces the per-request advisory lock so several engine
// instances can poll the same database without racing on one request.
const advisoryLockNS = 3345

// maxRequestsPerTick bounds one pipeline pass.
const maxRequestsPerTick = 20

// runCtx is the state shared by the steps of one erasure run.
type runCtx struct {
	RequestID string
	UserID    string
	Policy    *Policy
	Now       time.Time
}

// stepFunc executes a domain step. It returns an evidence note for
// destruction_logs and halt=true when the pipeline must stop without recording
// the step (external tasks still in flight, or parked for manual review).
type stepFunc func(ctx context.Context, rc *runCtx, action ErasureAction) (note string, halt bool, err error)

type erasureStep struct {
	Order   int
	Domain  string
	Default ErasureAction
	Run     stepFunc
}

// steps implements the §2.9 table. Order is significant.
func (e *Engine) steps() []erasureStep {
	return []erasureStep{
		{100, DomainCredential, ActionDelete, e.stepCredential},
		{200, DomainRefreshToken, ActionDelete, e.stepRefreshToken},
		{300, DomainSession, ActionDelete, e.stepSession},
		{400, DomainMFAFactor, ActionDelete, e.stepMFAFactor},
		{500, DomainPasskey, ActionDelete, e.stepPasskey},
		{600, DomainOAuthIdentity, ActionAnonymize, e.stepOAuthIdentity},
		{700, DomainExternalSystem, actionExecute, e.stepExternalSystem},
		{800, DomainAuditLog, ActionAnonymize, e.stepAuditLog},
		{900, DomainSubjectKey, ActionCryptoShred, e.stepSubjectKey},
		{1000, DomainAccount, ActionAnonymize, e.stepAccount},
	}
}

// runPipelineOnce picks up due DELETION requests and advances each of them.
func (e *Engine) runPipelineOnce(ctx context.Context) error {
	const q = `select id from dilion_privacy.personal_data_requests
		where type = 'DELETION' and status in ('REQUESTED','PROCESSING') and scheduled_at <= $1
		order by scheduled_at limit $2`
	rows, err := e.pool.Query(ctx, q, e.now(), maxRequestsPerTick)
	if err != nil {
		return fmt.Errorf("privacy: pipeline poll: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("privacy: pipeline poll: %w", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("privacy: pipeline poll: %w", err)
	}

	for _, id := range ids {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := e.withRequestLock(ctx, id, func(ctx context.Context) error {
			return e.processRequest(ctx, id)
		}); err != nil {
			e.log.Error("erasure request failed", "request_id", id, "err", err)
		}
	}
	return nil
}

func (e *Engine) withRequestLock(ctx context.Context, requestID string, fn func(context.Context) error) error {
	conn, err := e.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("privacy: acquire conn: %w", err)
	}
	defer conn.Release()

	var got bool
	if err := conn.QueryRow(ctx, `select pg_try_advisory_lock($1, hashtext($2))`,
		advisoryLockNS, requestID).Scan(&got); err != nil {
		return fmt.Errorf("privacy: advisory lock: %w", err)
	}
	if !got {
		return nil // another runner owns this request
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(unlockCtx, `select pg_advisory_unlock($1, hashtext($2))`,
			advisoryLockNS, requestID); err != nil {
			e.log.Warn("advisory unlock failed", "request_id", requestID, "err", err)
			// Never return a connection with an uncertain session lock to the pool.
			_ = conn.Conn().Close(unlockCtx)
		}
	}()
	return fn(ctx)
}

// processRequest runs the erasure pipeline for one request. Every step is
// idempotent and the whole function is safe to re-enter after a crash.
func (e *Engine) processRequest(ctx context.Context, requestID string) error {
	const q = `select id, user_id::text, status, policy_snapshot, scheduled_at
		from dilion_privacy.personal_data_requests where id = $1`
	var rc runCtx
	var status RequestStatus
	var snapshot []byte
	var scheduledAt time.Time
	err := e.pool.QueryRow(ctx, q, requestID).
		Scan(&rc.RequestID, &rc.UserID, &status, &snapshot, &scheduledAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("privacy: load request: %w", err)
	}
	rc.Now = e.now()
	// MANUAL_REVIEW / DONE / CANCELED are never advanced by the runner (§2.9).
	if status != StatusRequested && status != StatusProcessing {
		return nil
	}
	if scheduledAt.After(rc.Now) {
		return nil
	}
	if rc.Policy, err = policyFromSnapshot(snapshot); err != nil {
		return err
	}

	// Gate 1 of the triple legal-hold gate (§2.9).
	held, err := e.activeHoldFor(ctx, rc.UserID, "")
	if err != nil {
		return err
	}
	if held {
		if err := e.setManualReview(ctx, rc.RequestID, "LEGAL_HOLD"); err != nil {
			return err
		}
		_ = e.runHook(ctx, ports.BeforeErasureStep, map[string]any{
			"phase": "legal_hold_blocked", "request_id": rc.RequestID,
			"user_id": rc.UserID,
		})
		return nil
	}

	// Before hooks (validating): a rejection parks the request.
	if err := e.runHook(ctx, ports.BeforeErasureStep, map[string]any{
		"phase": "pipeline_start", "request_id": rc.RequestID,
		"user_id": rc.UserID,
	}); err != nil {
		e.log.Warn("erasure blocked by before_erasure_step hook", "request_id", rc.RequestID, "err", err)
		return e.setManualReview(ctx, rc.RequestID, "HOOK_REJECTED")
	}

	if status == StatusRequested {
		tag, err := e.pool.Exec(ctx, `update dilion_privacy.personal_data_requests
			set status = 'PROCESSING' where id = $1 and status = 'REQUESTED'`, rc.RequestID)
		if err != nil {
			return fmt.Errorf("privacy: mark processing: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return nil // cancellation won; no erasure step may execute
		}
	}

	done, err := e.completedDomains(ctx, rc.RequestID)
	if err != nil {
		return err
	}

	for _, st := range e.steps() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if done[st.Domain] {
			continue // re-run dedup via destruction_logs
		}
		action := rc.Policy.ActionFor(st.Domain, st.Default)
		basis := rc.Policy.BasisFor(st.Domain)

		if action == ActionKeep {
			// KEEP still leaves evidence of the decision and its basis.
			if err := e.logDestruction(ctx, rc.RequestID, st.Domain, ActionKeep, basis); err != nil {
				return err
			}
			e.log.Info("erasure step kept by policy", "request_id", rc.RequestID, "domain", st.Domain)
			continue
		}

		if err := e.runHook(ctx, ports.BeforeErasureStep, map[string]any{
			"phase": "step", "request_id": rc.RequestID, "user_id": rc.UserID,
			"domain": st.Domain, "action": string(action),
			"step": st.Order,
		}); err != nil {
			e.log.Warn("erasure step rejected by hook", "request_id", rc.RequestID,
				"domain", st.Domain, "err", err)
			return e.setManualReview(ctx, rc.RequestID, "HOOK_REJECTED")
		}

		note, halt, err := st.Run(ctx, &rc, action)
		if err != nil {
			return fmt.Errorf("privacy: step %d %s: %w", st.Order, st.Domain, err)
		}
		if halt {
			// Still in flight (or parked): keep PROCESSING and retry later.
			return nil
		}
		if basis == "" {
			basis = note
		}
		if err := e.logDestruction(ctx, rc.RequestID, st.Domain, action, basis); err != nil {
			return err
		}
		e.log.Info("erasure step done", "request_id", rc.RequestID, "step", st.Order,
			"domain", st.Domain, "action", action)
	}

	if _, err := e.pool.Exec(ctx, `update dilion_privacy.personal_data_requests
		set status = 'DONE', completed_at = $2, manual_review_reason = null
		where id = $1 and status = 'PROCESSING'`, rc.RequestID, e.now()); err != nil {
		return fmt.Errorf("privacy: mark done: %w", err)
	}
	if err := e.runHook(ctx, ports.AfterErasure, map[string]any{
		"request_id": rc.RequestID, "user_id": rc.UserID,
		"completed_at": e.now(),
	}); err != nil {
		e.log.Warn("after_erasure hook failed", "request_id", rc.RequestID, "err", err)
	}
	e.log.Info("erasure completed", "request_id", rc.RequestID, "user_id", rc.UserID)
	return nil
}

func (e *Engine) completedDomains(ctx context.Context, requestID string) (map[string]bool, error) {
	rows, err := e.pool.Query(ctx,
		`select domain from dilion_privacy.destruction_logs where request_id = $1`, requestID)
	if err != nil {
		return nil, fmt.Errorf("privacy: destruction log read: %w", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, fmt.Errorf("privacy: destruction log read: %w", err)
		}
		out[d] = true
	}
	return out, rows.Err()
}

// logDestruction writes the evidence row; the UNIQUE(request_id, domain) key
// makes re-runs a no-op.
func (e *Engine) logDestruction(ctx context.Context, requestID, domain string, action ErasureAction, basis string) error {
	_, err := e.pool.Exec(ctx, `insert into dilion_privacy.destruction_logs
		(request_id, domain, action, basis, executed_at) values ($1,$2,$3,nullif($4,''),$5)
		on conflict (request_id, domain) do nothing`, requestID, domain, string(action), basis, e.now())
	if err != nil {
		return fmt.Errorf("privacy: destruction log write: %w", err)
	}
	return nil
}

// ---- steps -----------------------------------------------------------------

// skipMissing records the absence of an optional upstream table as evidence
// rather than silently succeeding.
func (e *Engine) skipMissing(table string) (string, bool, error) {
	e.log.Warn("erasure step skipped: table absent", "table", table)
	return "SKIPPED_TABLE_ABSENT:" + table, false, nil
}

// 100 credential — password/OPAQUE record.
func (e *Engine) stepCredential(ctx context.Context, rc *runCtx, _ ErasureAction) (string, bool, error) {
	if !e.tableExists(ctx, "auth.users") {
		return e.skipMissing("auth.users")
	}
	if _, err := e.pool.Exec(ctx,
		`update auth.users set encrypted_password = '' where id = $1::uuid`, rc.UserID); err != nil {
		return "", false, err
	}
	// The OPAQUE record is the password's other form. A missing table is
	// evidence, not success: a wrong name here once left every record behind.
	const opaque = "dilion_auth.opaque_credentials"
	if !e.tableExists(ctx, opaque) {
		return e.skipMissing(opaque)
	}
	tag, err := e.pool.Exec(ctx, `delete from `+opaque+` where user_id = $1::uuid`, rc.UserID)
	if err != nil {
		return "", false, err
	}
	return fmt.Sprintf("opaque_rows=%d", tag.RowsAffected()), false, nil
}

// 200 refresh-token.
func (e *Engine) stepRefreshToken(ctx context.Context, rc *runCtx, _ ErasureAction) (string, bool, error) {
	if !e.tableExists(ctx, "auth.refresh_tokens") {
		return e.skipMissing("auth.refresh_tokens")
	}
	tag, err := e.pool.Exec(ctx, `delete from auth.refresh_tokens where user_id::text = $1`, rc.UserID)
	if err != nil {
		return "", false, err
	}
	return fmt.Sprintf("rows=%d", tag.RowsAffected()), false, nil
}

// 300 session.
func (e *Engine) stepSession(ctx context.Context, rc *runCtx, _ ErasureAction) (string, bool, error) {
	if !e.tableExists(ctx, "auth.sessions") {
		return e.skipMissing("auth.sessions")
	}
	tag, err := e.pool.Exec(ctx, `delete from auth.sessions where user_id::text = $1`, rc.UserID)
	if err != nil {
		return "", false, err
	}
	return fmt.Sprintf("rows=%d", tag.RowsAffected()), false, nil
}

// 400 mfa-factor (challenges cascade from factors upstream).
func (e *Engine) stepMFAFactor(ctx context.Context, rc *runCtx, _ ErasureAction) (string, bool, error) {
	if !e.tableExists(ctx, "auth.mfa_factors") {
		return e.skipMissing("auth.mfa_factors")
	}
	tag, err := e.pool.Exec(ctx, `delete from auth.mfa_factors where user_id::text = $1`, rc.UserID)
	if err != nil {
		return "", false, err
	}
	return fmt.Sprintf("rows=%d", tag.RowsAffected()), false, nil
}

// 500 passkey.
func (e *Engine) stepPasskey(ctx context.Context, rc *runCtx, _ ErasureAction) (string, bool, error) {
	if !e.tableExists(ctx, "auth.webauthn_credentials") {
		return e.skipMissing("auth.webauthn_credentials")
	}
	tag, err := e.pool.Exec(ctx,
		`delete from auth.webauthn_credentials where user_id::text = $1`, rc.UserID)
	if err != nil {
		return "", false, err
	}
	return fmt.Sprintf("rows=%d", tag.RowsAffected()), false, nil
}

// 600 oauth-identity — provider profile removed and the provider's subject
// released; the row is kept for referential sanity.
func (e *Engine) stepOAuthIdentity(ctx context.Context, rc *runCtx, action ErasureAction) (string, bool, error) {
	if !e.tableExists(ctx, "auth.identities") {
		return e.skipMissing("auth.identities")
	}
	if action == ActionDelete {
		tag, err := e.pool.Exec(ctx, `delete from auth.identities where user_id::text = $1`, rc.UserID)
		if err != nil {
			return "", false, err
		}
		return fmt.Sprintf("rows=%d", tag.RowsAffected()), false, nil
	}
	// provider_id is released too, as upstream's soft delete does
	// (auth's obfuscateIdentityProviderID, reproduced in SQL). Left in place, the
	// provider's subject would still point at this account, and signing up again
	// with the same provider account would land in the erased one and write the
	// provider's profile back onto it.
	tag, err := e.pool.Exec(ctx, `update auth.identities
		set identity_data = '{}'::jsonb,
		    provider_id = translate(rtrim(encode(sha256(convert_to(
		        user_id::text || provider || ':' || provider_id, 'UTF8')), 'base64'), '='), '+/', '-_'),
		    updated_at = $2
		where user_id::text = $1`, rc.UserID, e.now())
	if err != nil {
		return "", false, err
	}
	return fmt.Sprintf("rows=%d", tag.RowsAffected()), false, nil
}

// 700 external-system — connector/webhook fan-out (§3.1). The step completes
// only once every task has a receipt.
func (e *Engine) stepExternalSystem(ctx context.Context, rc *runCtx, _ ErasureAction) (string, bool, error) {
	rows, err := e.pool.Query(ctx,
		`select id from dilion_privacy.destinations where enabled order by id`)
	if err != nil {
		return "", false, fmt.Errorf("destination list: %w", err)
	}
	var destIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return "", false, err
		}
		destIDs = append(destIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", false, err
	}

	for _, dst := range destIDs {
		if _, err := e.pool.Exec(ctx, `insert into dilion_privacy.tasks
			(id, request_id, user_id, destination_id, action, status, created_at, next_attempt_at)
			values ($1,$2,$3::uuid,$4,$5,'pending',$6,$6)
			on conflict (request_id, destination_id) do nothing`,
			httpapi.NewID("tsk"), rc.RequestID, rc.UserID, dst, TaskActionDelete, e.now()); err != nil {
			return "", false, fmt.Errorf("task fan-out: %w", err)
		}
	}

	var total, open, dead int
	if err := e.pool.QueryRow(ctx, `select count(*),
			count(*) filter (where status in ('pending','running','failed')),
			count(*) filter (where status = 'dead')
		from dilion_privacy.tasks where request_id = $1`, rc.RequestID).
		Scan(&total, &open, &dead); err != nil {
		return "", false, fmt.Errorf("task roll-up: %w", err)
	}
	if dead > 0 {
		// Dead-lettered delivery is an operator decision, not an auto-skip.
		return "", true, e.setManualReview(ctx, rc.RequestID, "TASK_FAILED")
	}
	if open > 0 {
		e.log.Info("external-system step waiting on tasks",
			"request_id", rc.RequestID, "open", open, "total", total)
		return "", true, nil
	}
	return fmt.Sprintf("tasks=%d", total), false, nil
}

// 800 audit-log — the audit tables belong to agent D.
func (e *Engine) stepAuditLog(ctx context.Context, rc *runCtx, action ErasureAction) (string, bool, error) {
	// TODO(agent D / wave 2): implement subject truncation over dilion_audit.events
	// + dilion_audit.subjects. Truncating the subject manifest must keep the
	// access event row (§5.3). Until those tables exist this step only records
	// the decision so the evidence chain stays complete.
	if e.tableExists(ctx, "dilion_audit.subjects") {
		e.log.Warn("audit-log erasure step is a placeholder; dilion_audit.* not processed",
			"request_id", rc.RequestID, "action", action)
	}
	return "TODO_AUDIT_LOG_STEP_NOT_IMPLEMENTED", false, nil
}

// 900 subject-key — crypto-shred (§2.7): DEFAULT now, CONSENT per retention.
func (e *Engine) stepSubjectKey(ctx context.Context, rc *runCtx, _ ErasureAction) (string, bool, error) {
	if err := e.kms.DestroyDEK(ctx, rc.UserID, ports.KeyScopeDefault); err != nil {
		return "", false, fmt.Errorf("destroy DEFAULT dek: %w", err)
	}
	if e.tableExists(ctx, "dilion_pii.subject_keys") {
		if _, err := e.pool.Exec(ctx, `update dilion_pii.subject_keys
			set shredded_at = coalesce(shredded_at, $2)
			where user_id = $1::uuid and scope = 'DEFAULT'`, rc.UserID, e.now()); err != nil {
			return "", false, err
		}
	}

	var fromErasure *RetentionRule
	var fromCreated *RetentionRule
	for _, r := range rc.Policy.RetentionFor(DomainConsentEvidence) {
		rule := r
		switch rule.From {
		case FromErasure:
			fromErasure = &rule
		case FromCreated:
			fromCreated = &rule
		}
	}
	switch {
	case fromErasure != nil:
		d, err := ParseISODuration(fromErasure.Period)
		if err != nil {
			return "", false, err
		}
		shredAfter := d.AddTo(e.now())
		if _, err := e.pool.Exec(ctx, `update dilion_pii.subject_keys
			set shred_after = $2 where user_id = $1::uuid and scope = 'CONSENT' and shredded_at is null`,
			rc.UserID, shredAfter); err != nil {
			return "", false, err
		}
		return fmt.Sprintf("consent_dek_shred_after=%s", shredAfter.Format(time.RFC3339)), false, nil
	case fromCreated != nil:
		// The retention scanner owns this key; nothing to schedule here.
		return "consent_dek_retained_from_created:" + fromCreated.Period, false, nil
	default:
		if err := e.kms.DestroyDEK(ctx, rc.UserID, ports.KeyScopeConsent); err != nil {
			return "", false, fmt.Errorf("destroy CONSENT dek: %w", err)
		}
		if _, err := e.pool.Exec(ctx, `update dilion_pii.subject_keys
			set shredded_at = coalesce(shredded_at, $2) where user_id = $1::uuid and scope = 'CONSENT'`,
			rc.UserID, e.now()); err != nil {
			return "", false, err
		}
		return "consent_dek_shredded_immediately", false, nil
	}
}

// 1000 account — auth.users truncation, PII vault row removal and tombstone.
func (e *Engine) stepAccount(ctx context.Context, rc *runCtx, _ ErasureAction) (string, bool, error) {
	if e.tableExists(ctx, "auth.users") {
		if _, err := e.pool.Exec(ctx, `update auth.users
			set email = null, phone = null, raw_user_meta_data = '{}'::jsonb,
			    deleted_at = coalesce(deleted_at, $2)
			where id = $1::uuid`, rc.UserID, e.now()); err != nil {
			return "", false, err
		}
	}
	if _, err := e.pool.Exec(ctx,
		`delete from dilion_pii.user_profiles where user_id = $1::uuid`, rc.UserID); err != nil {
		return "", false, err
	}
	// The blind search index (search.go) must not outlive the document — its
	// tokens are keyed hashes of the erased values.
	if _, err := e.pool.Exec(ctx,
		`delete from dilion_pii.profile_search_index where user_id = $1::uuid`, rc.UserID); err != nil {
		return "", false, err
	}
	tombstone := e.tombstoneID(rc.UserID)
	if _, err := e.pool.Exec(ctx, `insert into dilion_privacy.erasure_registry
		(tombstone_id, erased_at, request_id, reason) values ($1,$2,$3,$4)
		on conflict (tombstone_id) do nothing`,
		tombstone, e.now(), rc.RequestID, "DELETION"); err != nil {
		return "", false, err
	}
	return "tombstone=" + tombstone, false, nil
}

// tombstoneID is the keyed hash used by the erasure registry so no raw
// identifier is retained forever (§2.10 "tombstone identifier paradox").
func (e *Engine) tombstoneID(userID string) string {
	m := hmac.New(sha256.New, e.tombstoneKey)
	m.Write([]byte(userID))
	return hex.EncodeToString(m.Sum(nil))
}

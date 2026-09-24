package privacy

import (
	"regexp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/dilion-io/dilion/ports"
)

// Consent ledger actions (§4 — append-only ledger, not current state).
const (
	ConsentGrant           = "GRANT"
	ConsentWithdraw        = "WITHDRAW"
	ConsentReconfirmNotice = "RECONFIRM_NOTICE"
	consentMutationLockNS  = 3347
)

// GetConsents projects the ledger into the current state per purpose and
// computes reconfirm_due from the subject's policy (§2.8 reconfirm).
func (e *Engine) GetConsents(ctx context.Context, userID string) ([]ConsentState, error) {
	uid, err := validUUID(userID)
	if err != nil {
		return nil, err
	}

	const q = `select distinct on (purpose)
			purpose, action, coalesce(policy_version, ''), created_at
		from dilion_privacy.consent_events
		where user_id = $1::uuid and action in ('GRANT','WITHDRAW')
		order by purpose, created_at desc, id desc`
	rows, err := e.pool.Query(ctx, q, uid)
	if err != nil {
		return nil, fmt.Errorf("privacy: get consents: %w", err)
	}
	defer rows.Close()

	type latest struct {
		action  string
		version string
		at      time.Time
	}
	states := map[string]latest{}
	var order []string
	for rows.Next() {
		var purpose, action, version string
		var at time.Time
		if err := rows.Scan(&purpose, &action, &version, &at); err != nil {
			return nil, fmt.Errorf("privacy: get consents: %w", err)
		}
		states[purpose] = latest{action: action, version: version, at: at}
		order = append(order, purpose)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("privacy: get consents: %w", err)
	}

	notices, err := e.lastReconfirmNotices(ctx, uid)
	if err != nil {
		return nil, err
	}
	_, policy, err := e.resolvePolicy(ctx, uid)
	if err != nil {
		return nil, err
	}

	out := make([]ConsentState, 0, len(order))
	for _, purpose := range order {
		st := states[purpose]
		cs := ConsentState{
			Purpose:       purpose,
			Granted:       st.action == ConsentGrant,
			PolicyVersion: st.version,
			UpdatedAt:     st.at,
		}
		if due, ok := reconfirmDue(policy, purpose, cs.Granted, st.at, notices[purpose]); ok {
			cs.ReconfirmDue = &due
		}
		out = append(out, cs)
	}
	return out, nil
}

// reconfirmDue computes the next reconfirmation notice time: base is the later
// of the grant and the last notice. Withdrawn purposes never reconfirm.
func reconfirmDue(p *Policy, purpose string, granted bool, grantedAt time.Time, lastNotice *time.Time) (time.Time, bool) {
	if !granted {
		return time.Time{}, false
	}
	d, ok := p.ReconfirmFor(purpose)
	if !ok {
		return time.Time{}, false
	}
	base := grantedAt
	if lastNotice != nil && lastNotice.After(base) {
		base = *lastNotice
	}
	return d.AddTo(base), true
}

func (e *Engine) lastReconfirmNotices(ctx context.Context, userID string) (map[string]*time.Time, error) {
	const q = `select purpose, max(created_at) from dilion_privacy.consent_events
		where user_id = $1::uuid and action = $2 group by purpose`
	rows, err := e.pool.Query(ctx, q, userID, ConsentReconfirmNotice)
	if err != nil {
		return nil, fmt.Errorf("privacy: reconfirm notices: %w", err)
	}
	defer rows.Close()
	out := map[string]*time.Time{}
	for rows.Next() {
		var purpose string
		var at time.Time
		if err := rows.Scan(&purpose, &at); err != nil {
			return nil, fmt.Errorf("privacy: reconfirm notices: %w", err)
		}
		t := at
		out[purpose] = &t
	}
	return out, rows.Err()
}

// consentPurposeRe bounds a consent purpose key; maxPolicyVersionLen bounds the
// policy version recorded with it; maxPurposesPerSubject bounds how many
// distinct purposes one subject accumulates.
var consentPurposeRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,63}$`)

const (
	maxPolicyVersionLen   = 64
	maxPurposesPerSubject = 200
)

// UpdateConsent appends a GRANT/WITHDRAW event and returns the resulting state.
// Nothing is ever updated in place — the ledger is the record (§4).
func (e *Engine) UpdateConsent(ctx context.Context, userID string, ch ConsentChange) (*ConsentState, error) {
	uid, err := validUUID(userID)
	if err != nil {
		return nil, err
	}
	// The ledger is append-only and outlives the subject, so what goes into
	// it is bounded: purposes are keys like marketing.email, not free text.
	if !consentPurposeRe.MatchString(ch.Purpose) {
		return nil, fmt.Errorf("%w: purpose must be 1-64 of a-z, 0-9, '.', '_', ':' or '-', starting with a letter or digit", ErrInvalidInput)
	}
	if len(ch.PolicyVersion) > maxPolicyVersionLen {
		return nil, fmt.Errorf("%w: policy_version is longer than %d bytes", ErrInvalidInput, maxPolicyVersionLen)
	}
	policyID, policy, err := e.resolvePolicy(ctx, uid)
	if err != nil {
		return nil, err
	}
	if !ch.Granted && policy.RequiresConsent(ch.Purpose) {
		// required-keys is policy data, not code (§2.8).
		return nil, fmt.Errorf("%w: %q is a required consent key", ErrPolicyViolation, ch.Purpose)
	}

	action := ConsentWithdraw
	if ch.Granted {
		action = ConsentGrant
	}
	now := e.now()
	evidence, err := e.sealConsentEvidence(ctx, uid, map[string]any{
		"purpose":        ch.Purpose,
		"action":         action,
		"policy_version": ch.PolicyVersion,
		"source":         ch.Source,
		"recorded_at":    now.Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, err
	}

	var nextDue *time.Time
	if due, ok := reconfirmDue(policy, ch.Purpose, ch.Granted, now, nil); ok {
		nextDue = &due
	}
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("privacy: consent transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	lockKey := fmt.Sprintf("%d:%s%d:%s", len(uid), uid, len(ch.Purpose), ch.Purpose)
	if _, err := tx.Exec(ctx, `select pg_advisory_xact_lock($1, hashtext($2))`,
		consentMutationLockNS, lockKey); err != nil {
		return nil, fmt.Errorf("privacy: consent advisory lock: %w", err)
	}
	var known bool
	var purposes int
	if err := tx.QueryRow(ctx, `select coalesce(bool_or(purpose = $2), false), count(*)
		from dilion_privacy.consent_state where user_id = $1::uuid`, uid, ch.Purpose).Scan(&known, &purposes); err != nil {
		return nil, fmt.Errorf("privacy: consent purposes: %w", err)
	}
	if !known && purposes >= maxPurposesPerSubject {
		return nil, fmt.Errorf("%w: a subject may hold at most %d consent purposes", ErrInvalidInput, maxPurposesPerSubject)
	}
	// Serialise the ledger's ordering as well as the projection, including
	// equal timestamps from fixed/coarse clocks. Evidence recorded_at is the
	// receipt time; created_at is the ordered commit event time.
	var previous *time.Time
	if err := tx.QueryRow(ctx, `select max(created_at) from dilion_privacy.consent_events
		where user_id = $1::uuid and purpose = $2
		  and action in ('GRANT','WITHDRAW')`, uid, ch.Purpose).Scan(&previous); err != nil {
		return nil, err
	}
	if previous != nil && !now.After(*previous) {
		now = previous.Add(time.Microsecond)
	}
	var lastNotice *time.Time
	if err := tx.QueryRow(ctx, `select max(created_at) from dilion_privacy.consent_events
		where user_id = $1::uuid and purpose = $2
		  and action = 'RECONFIRM_NOTICE'`, uid, ch.Purpose).Scan(&lastNotice); err != nil {
		return nil, err
	}
	if due, ok := reconfirmDue(policy, ch.Purpose, ch.Granted, now, lastNotice); ok {
		nextDue = &due
	}
	if err := e.appendConsentEvent(ctx, tx, consentEvent{
		UserID:        uid,
		Purpose:       ch.Purpose,
		Action:        action,
		PolicyVersion: ch.PolicyVersion,
		CreatedAt:     now,
		Source:        ch.Source,
		Evidence:      evidence,
	}); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `insert into dilion_privacy.consent_state
		(user_id, purpose, granted, policy_version, updated_at,
		 next_reconfirm_at, scheduled_policy_id, schedule_revision, schedule_computed)
		values ($1::uuid,$2,$3,$4,$5,$6,$7,$8,true)
		on conflict (user_id, purpose) do update set
		 granted = excluded.granted,
		 policy_version = excluded.policy_version,
		 updated_at = excluded.updated_at,
		 next_reconfirm_at = excluded.next_reconfirm_at,
		 scheduled_policy_id = excluded.scheduled_policy_id,
		 schedule_revision = excluded.schedule_revision,
		 schedule_computed = true`,
		uid, ch.Purpose, ch.Granted, ch.PolicyVersion, now, nextDue, policyID, e.policyRevision); err != nil {
		return nil, fmt.Errorf("privacy: update consent state: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("privacy: consent commit: %w", err)
	}

	if err := e.runHook(ctx, ports.ConsentChanged, map[string]any{
		"user_id": uid, "purpose": ch.Purpose,
		"granted": ch.Granted, "policy_version": ch.PolicyVersion, "source": ch.Source,
	}); err != nil {
		// Observing hook: never rolls back the ledger entry.
		e.log.Warn("consent_changed hook failed", "err", err, "purpose", ch.Purpose)
	}

	st := &ConsentState{
		Purpose:       ch.Purpose,
		Granted:       ch.Granted,
		PolicyVersion: ch.PolicyVersion,
		UpdatedAt:     now,
	}
	st.ReconfirmDue = nextDue
	return st, nil
}

type consentEvent struct {
	UserID        string
	Purpose       string
	Action        string
	PolicyVersion string
	CreatedAt     time.Time
	Source        string
	Region        string
	Evidence      []byte // jsonb
}

func (e *Engine) appendConsentEvent(ctx context.Context, q queryExecer, ev consentEvent) error {
	const ins = `insert into dilion_privacy.consent_events
		(user_id, purpose, action, policy_version, created_at, source, region, evidence)
		values ($1::uuid,$2,$3,nullif($4,''),$5,nullif($6,''),nullif($7,''),$8::jsonb)`
	_, err := q.Exec(ctx, ins, ev.UserID, ev.Purpose, ev.Action, ev.PolicyVersion,
		ev.CreatedAt, ev.Source, ev.Region, string(ev.Evidence))
	if err != nil {
		return fmt.Errorf("privacy: append consent event: %w", err)
	}
	return nil
}

// sealConsentEvidence encrypts consent evidence with the subject's CONSENT-scope
// DEK so it survives account erasure and dies at shred_after (§2.7, §4).
func (e *Engine) sealConsentEvidence(ctx context.Context, userID string, doc map[string]any) ([]byte, error) {
	plain, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("privacy: consent evidence: %w", err)
	}
	ct, err := e.kms.Encrypt(ctx, userID, ports.KeyScopeConsent, plain)
	if err != nil {
		return nil, fmt.Errorf("privacy: seal consent evidence: %w", err)
	}
	return json.Marshal(map[string]any{
		"alg":        "kms-envelope",
		"scope":      string(ports.KeyScopeConsent),
		"ciphertext": base64.StdEncoding.EncodeToString(ct),
	})
}

// ---- reconfirm scanner (§2.8: notice only, never auto-expire) --------------

type reconfirmCandidate struct {
	UserID    string
	Purpose   string
	GrantedAt time.Time
	Version   string
	NoticedAt *time.Time
	PolicyID  string
}

// scanReconfirmDue appends a RECONFIRM_NOTICE ledger entry and an outbox event
// for every granted purpose whose reconfirm period has elapsed.
func (e *Engine) scanReconfirmDue(ctx context.Context) error {
	batch := e.policies.RetentionBatchSize
	if err := e.reconcileConsentSchedules(ctx, batch); err != nil {
		return err
	}
	const q = `select cs.user_id::text, cs.purpose, cs.updated_at, cs.policy_version,
		cs.last_notice_at, cs.scheduled_policy_id
		from dilion_privacy.consent_state cs
		left join dilion_privacy.subject_policies sp on sp.user_id = cs.user_id
		where cs.granted and cs.schedule_computed
		  and cs.schedule_revision = $1
		  and cs.scheduled_policy_id = coalesce(sp.policy_id, $2)
		  and cs.next_reconfirm_at <= $3
		  and not exists (select 1 from dilion_pii.subject_keys sk
		    where sk.user_id = cs.user_id and sk.scope = 'CONSENT' and sk.shredded_at is not null)
		order by cs.next_reconfirm_at, cs.user_id, cs.purpose
		limit $4`
	now := e.now()
	rows, err := e.pool.Query(ctx, q, e.policyRevision,
		e.policies.DefaultPolicy, now, batch)
	if err != nil {
		return fmt.Errorf("privacy: reconfirm scan: %w", err)
	}
	defer rows.Close()
	var candidates []reconfirmCandidate
	for rows.Next() {
		var c reconfirmCandidate
		if err := rows.Scan(&c.UserID, &c.Purpose, &c.GrantedAt, &c.Version, &c.NoticedAt, &c.PolicyID); err != nil {
			return fmt.Errorf("privacy: reconfirm scan: %w", err)
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("privacy: reconfirm scan: %w", err)
	}
	rows.Close()
	for _, c := range candidates {
		_, err := e.emitReconfirmNotice(ctx, c, now)
		if err != nil {
			e.log.Error("reconfirm notice failed", "user_id", c.UserID, "purpose", c.Purpose, "err", err)
			continue
		}
	}
	return nil
}

// reconcileConsentSchedules refreshes a bounded set of new/backfilled/stale
// projection rows. Once refreshed, normal scans use the partial due-date index
// and never walk the append-only ledger.
func (e *Engine) reconcileConsentSchedules(ctx context.Context, batch int) error {
	// Rotate a keyset cursor over at most batch state rows. Filtering all stale
	// revisions with an OR/join before LIMIT would scan the entire table on
	// every idle tick, even though only a bounded number of rows is returned.
	e.scheduleMu.Lock()
	defer e.scheduleMu.Unlock()
	q := `select cs.user_id::text, cs.purpose, cs.updated_at, cs.policy_version,
		cs.last_notice_at, coalesce(sp.policy_id, $1), cs.granted,
		cs.schedule_computed and cs.schedule_revision = $2
		  and cs.scheduled_policy_id = coalesce(sp.policy_id, $1)
		from dilion_privacy.consent_state cs
		left join dilion_privacy.subject_policies sp on sp.user_id = cs.user_id
		where true`
	args := []any{e.policies.DefaultPolicy, e.policyRevision, batch}
	if e.scheduleUser != "" {
		q += ` and (cs.user_id, cs.purpose) > ($4::uuid, $5)`
		args = append(args, e.scheduleUser, e.schedulePurpose)
	}
	q += ` order by cs.user_id, cs.purpose limit $3`
	rows, err := e.pool.Query(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("privacy: consent schedule scan: %w", err)
	}
	type scheduleCandidate struct {
		reconfirmCandidate
		granted bool
		current *bool
	}
	var candidates []scheduleCandidate
	for rows.Next() {
		var c scheduleCandidate
		if err := rows.Scan(&c.UserID, &c.Purpose, &c.GrantedAt, &c.Version, &c.NoticedAt, &c.PolicyID, &c.granted, &c.current); err != nil {
			rows.Close()
			return fmt.Errorf("privacy: consent schedule scan: %w", err)
		}
		candidates = append(candidates, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("privacy: consent schedule scan: %w", err)
	}
	for _, c := range candidates {
		if c.current != nil && *c.current {
			continue
		}
		policy, known := e.policies.Resolve(c.PolicyID)
		if !known {
			policy, _ = e.policies.Resolve(e.policies.DefaultPolicy)
		}
		var nextDue *time.Time
		if due, ok := reconfirmDue(policy, c.Purpose, c.granted, c.GrantedAt, c.NoticedAt); ok {
			nextDue = &due
		}
		if _, err := e.pool.Exec(ctx, `update dilion_privacy.consent_state
			set next_reconfirm_at = $1, scheduled_policy_id = $2,
			    schedule_revision = $3, schedule_computed = true
			where user_id = $4::uuid and purpose = $5
			  and updated_at = $6 and last_notice_at is not distinct from $7`,
			nextDue, c.PolicyID, e.policyRevision, c.UserID,
			c.Purpose, c.GrantedAt, c.NoticedAt); err != nil {
			return fmt.Errorf("privacy: refresh consent schedule: %w", err)
		}
	}
	if len(candidates) < batch {
		e.scheduleUser, e.schedulePurpose = "", ""
	} else {
		last := candidates[len(candidates)-1]
		e.scheduleUser, e.schedulePurpose = last.UserID, last.Purpose
	}
	return nil
}

func (e *Engine) emitReconfirmNotice(ctx context.Context, c reconfirmCandidate, now time.Time) (bool, error) {
	policy, known := e.policies.Resolve(c.PolicyID)
	if !known {
		policy, _ = e.policies.Resolve(e.policies.DefaultPolicy)
	}
	period, ok := policy.ReconfirmFor(c.Purpose)
	if !ok {
		return false, nil
	}

	evidence, err := e.sealConsentEvidence(ctx, c.UserID, map[string]any{
		"purpose":     c.Purpose,
		"action":      ConsentReconfirmNotice,
		"granted_at":  c.GrantedAt.Format(time.RFC3339Nano),
		"noticed_at":  now.Format(time.RFC3339Nano),
		"policy_id":   c.PolicyID,
		"source":      "scanner",
		"recorded_at": now.Format(time.RFC3339Nano),
	})
	if err != nil {
		return false, err
	}
	payload, err := json.Marshal(map[string]any{
		"user_id": c.UserID, "purpose": c.Purpose,
		"policy_id": c.PolicyID, "policy_version": c.Version,
		"granted_at": c.GrantedAt.Format(time.RFC3339),
	})
	if err != nil {
		return false, err
	}

	// Encrypt before reserving a database connection: local KMS uses the same
	// pool. Recheck the exact candidate under a nonblocking row lock.
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("privacy: reconfirm tx: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var claimed bool
	lockKey := fmt.Sprintf("%d:%s%d:%s", len(c.UserID), c.UserID, len(c.Purpose), c.Purpose)
	if err := tx.QueryRow(ctx, `select pg_try_advisory_xact_lock($1, hashtext($2))`,
		consentMutationLockNS, lockKey).Scan(&claimed); err != nil {
		return false, err
	}
	if !claimed {
		return false, nil
	}
	err = tx.QueryRow(ctx, `select true from dilion_privacy.consent_state cs
		where user_id = $1::uuid and purpose = $2
		  and granted and schedule_computed and schedule_revision = $3
		  and updated_at = $4 and policy_version = $5 and scheduled_policy_id = $6
		  and next_reconfirm_at <= $7
		  and scheduled_policy_id = coalesce(
		    (select policy_id from dilion_privacy.subject_policies where user_id = cs.user_id), $8)
		for update skip locked`, c.UserID, c.Purpose, e.policyRevision,
		c.GrantedAt, c.Version, c.PolicyID, now, e.policies.DefaultPolicy).Scan(&claimed)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("privacy: reconfirm recheck: %w", err)
	}
	if err := e.appendConsentEvent(ctx, tx, consentEvent{
		UserID: c.UserID, Purpose: c.Purpose,
		Action: ConsentReconfirmNotice, PolicyVersion: c.Version, CreatedAt: now,
		Source: "scanner", Evidence: evidence,
	}); err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `insert into dilion_privacy.outbox (event_type, aggregate_id, payload, created_at)
		values ('consent.reconfirm_due', $1, $2::jsonb, $3)`, c.UserID, string(payload), now); err != nil {
		return false, fmt.Errorf("privacy: reconfirm outbox: %w", err)
	}
	if _, err := tx.Exec(ctx, `update dilion_privacy.consent_state
		set last_notice_at = $1, next_reconfirm_at = $2, schedule_revision = $3,
		    schedule_computed = true
		where user_id = $4::uuid and purpose = $5`,
		now, period.AddTo(now), e.policyRevision, c.UserID, c.Purpose); err != nil {
		return false, fmt.Errorf("privacy: advance consent schedule: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("privacy: reconfirm commit: %w", err)
	}

	if err := e.runHook(ctx, ports.ConsentReconfirm, map[string]any{
		"user_id": c.UserID, "purpose": c.Purpose,
		"policy_id": c.PolicyID, "granted_at": c.GrantedAt,
	}); err != nil {
		e.log.Warn("consent_reconfirm hook failed", "err", err)
	}
	e.log.Info("consent reconfirm notice emitted", "user_id", c.UserID, "purpose", c.Purpose)
	return true, nil
}

// queryExecer is the shared subset of *pgxpool.Pool and pgx.Tx used here, so
// the same helper can run inside or outside a transaction.
type queryExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

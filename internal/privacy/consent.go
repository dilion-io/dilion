package privacy

import (
	"context"
	"encoding/base64"
	"encoding/json"
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

// UpdateConsent appends a GRANT/WITHDRAW event and returns the resulting state.
// Nothing is ever updated in place — the ledger is the record (§4).
func (e *Engine) UpdateConsent(ctx context.Context, userID string, ch ConsentChange) (*ConsentState, error) {
	uid, err := validUUID(userID)
	if err != nil {
		return nil, err
	}
	if ch.Purpose == "" {
		return nil, fmt.Errorf("%w: purpose is required", ErrInvalidInput)
	}
	_, policy, err := e.resolvePolicy(ctx, uid)
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

	if err := e.appendConsentEvent(ctx, e.pool, consentEvent{
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

	if err := e.runHook(ctx, ports.ConsentChanged, map[string]any{
		"user_id": uid, "purpose": ch.Purpose,
		"granted": ch.Granted, "policy_version": ch.PolicyVersion, "source": ch.Source,
	}); err != nil {
		// Observing hook: never rolls back the ledger entry.
		e.log.Warn("consent_changed hook failed", "err", err, "purpose", ch.Purpose)
	}

	notices, err := e.lastReconfirmNotices(ctx, uid)
	if err != nil {
		return nil, err
	}
	st := &ConsentState{
		Purpose:       ch.Purpose,
		Granted:       ch.Granted,
		PolicyVersion: ch.PolicyVersion,
		UpdatedAt:     now,
	}
	if due, ok := reconfirmDue(policy, ch.Purpose, ch.Granted, now, notices[ch.Purpose]); ok {
		st.ReconfirmDue = &due
	}
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
	const q = `
		with latest as (
			select distinct on (user_id, purpose)
				user_id, purpose, action, created_at, coalesce(policy_version,'') as policy_version
			from dilion_privacy.consent_events
			where action in ('GRANT','WITHDRAW')
			order by user_id, purpose, created_at desc, id desc
		), notice as (
			select user_id, purpose, max(created_at) as noticed_at
			from dilion_privacy.consent_events
			where action = 'RECONFIRM_NOTICE'
			group by user_id, purpose
		)
		select l.user_id::text, l.purpose, l.created_at, l.policy_version, n.noticed_at,
		       coalesce(sp.policy_id, $1)
		from latest l
		left join notice n on n.user_id = l.user_id and n.purpose = l.purpose
		left join dilion_privacy.subject_policies sp on sp.user_id = l.user_id
		where l.action = 'GRANT'
		limit $2`

	// TODO(wave2): this is a full projection scan of the ledger. Replace with a
	// materialised consent-state table + due index when volumes grow.
	rows, err := e.pool.Query(ctx, q, e.policies.DefaultPolicy, e.policies.RetentionBatchSize)
	if err != nil {
		return fmt.Errorf("privacy: reconfirm scan: %w", err)
	}
	var cands []reconfirmCandidate
	for rows.Next() {
		var c reconfirmCandidate
		if err := rows.Scan(&c.UserID, &c.Purpose, &c.GrantedAt, &c.Version, &c.NoticedAt, &c.PolicyID); err != nil {
			rows.Close()
			return fmt.Errorf("privacy: reconfirm scan: %w", err)
		}
		cands = append(cands, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("privacy: reconfirm scan: %w", err)
	}

	now := e.now()
	for _, c := range cands {
		policy, _ := e.policies.Resolve(c.PolicyID)
		due, ok := reconfirmDue(policy, c.Purpose, true, c.GrantedAt, c.NoticedAt)
		if !ok || due.After(now) {
			continue
		}
		if err := e.emitReconfirmNotice(ctx, c, now); err != nil {
			e.log.Error("reconfirm notice failed", "user_id", c.UserID, "purpose", c.Purpose, "err", err)
			continue
		}
	}
	return nil
}

func (e *Engine) emitReconfirmNotice(ctx context.Context, c reconfirmCandidate, now time.Time) error {
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
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"user_id": c.UserID, "purpose": c.Purpose,
		"policy_id": c.PolicyID, "policy_version": c.Version,
		"granted_at": c.GrantedAt.Format(time.RFC3339),
	})
	if err != nil {
		return err
	}

	tx, err := e.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("privacy: reconfirm tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := e.appendConsentEvent(ctx, tx, consentEvent{
		UserID: c.UserID, Purpose: c.Purpose,
		Action: ConsentReconfirmNotice, PolicyVersion: c.Version, CreatedAt: now,
		Source: "scanner", Evidence: evidence,
	}); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `insert into dilion_privacy.outbox (event_type, aggregate_id, payload, created_at)
		values ('consent.reconfirm_due', $1, $2::jsonb, $3)`, c.UserID, string(payload), now); err != nil {
		return fmt.Errorf("privacy: reconfirm outbox: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("privacy: reconfirm commit: %w", err)
	}

	if err := e.runHook(ctx, ports.ConsentReconfirm, map[string]any{
		"user_id": c.UserID, "purpose": c.Purpose,
		"policy_id": c.PolicyID, "granted_at": c.GrantedAt,
	}); err != nil {
		e.log.Warn("consent_reconfirm hook failed", "err", err)
	}
	e.log.Info("consent reconfirm notice emitted", "user_id", c.UserID, "purpose", c.Purpose)
	return nil
}

// queryExecer is the shared subset of *pgxpool.Pool and pgx.Tx used here, so
// the same helper can run inside or outside a transaction.
type queryExecer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

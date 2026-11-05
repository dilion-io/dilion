package privacy

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/dilion-io/dilion/ports"
)

// runRetentionOnce applies the retention section of every policy (§2.8).
// Legal holds are gate 2 of the triple gate: expired rows under hold are
// skipped, never destroyed.
func (e *Engine) runRetentionOnce(ctx context.Context) error {
	batch := e.policies.RetentionBatchSize
	now := e.now()

	// consent-evidence is always `from: erasure` (policy validation): the
	// pipeline snapshotted shred_after when it erased the subject, so this
	// sweep is policy-independent, and a subject that was never erased keeps
	// its evidence.
	if err := e.sweepConsentShredDue(ctx, now, batch); err != nil {
		return err
	}

	ids := make([]string, 0, len(e.policies.Policies))
	for id := range e.policies.Policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		p := e.policies.Policies[id]
		for _, rule := range p.RetentionRules() {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			switch rule.Domain {
			case DomainConsentEvidence:
				// Handled by the shred_after sweep above.
			case DomainAuditLog:
				// The access log is the instance's, not one policy's: it is
				// swept once below, by the longest period any policy keeps it.
			default:
				e.log.Warn("retention gap: no executor for domain",
					"policy", id, "domain", rule.Domain, "period", rule.Period)
			}
		}
	}
	return e.sweepAuditLog(ctx, ids, now, batch)
}

// sweepAuditLog deletes access events older than every policy's audit-log
// retention. Events are shared by the whole instance, so the longest period
// wins, and if any policy sets no audit-log retention the log is kept
// indefinitely — deleting evidence one policy still needs is not an option.
func (e *Engine) sweepAuditLog(ctx context.Context, ids []string, now time.Time, batch int) error {
	// Periods are calendar durations (P3Y), so they are compared by the
	// cutoff each yields: the earliest cutoff is the longest keep.
	cutoff := now
	for _, id := range ids {
		var found bool
		for _, rule := range e.policies.Policies[id].RetentionRules() {
			if rule.Domain != DomainAuditLog {
				continue
			}
			d, err := ParseISODuration(rule.Period)
			if err != nil {
				return err
			}
			found = true
			if c := d.SubFrom(now); c.Before(cutoff) {
				cutoff = c
			}
		}
		if !found {
			return nil
		}
	}
	if !cutoff.Before(now) || !e.tableExists(ctx, "dilion_audit.events") {
		return nil
	}
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("privacy: audit retention: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		with old as (
			select event_id from dilion_audit.events where created_at < $1
			order by created_at limit $2
		), subjects as (
			delete from dilion_audit.subjects where event_id in (select event_id from old)
		)
		delete from dilion_audit.events where event_id in (select event_id from old)`, cutoff, batch); err != nil {
		return fmt.Errorf("privacy: audit retention: %w", err)
	}
	return tx.Commit(ctx)
}

// sweepConsentShredDue crypto-shreds CONSENT-scope DEKs whose snapshotted
// shred_after has arrived (§2.7).
func (e *Engine) sweepConsentShredDue(ctx context.Context, now time.Time, batch int) error {
	const q = `select user_id::text from dilion_pii.subject_keys
		where scope = 'CONSENT' and shredded_at is null
		  and shred_after is not null and shred_after <= $1
		  and not exists (
			select 1 from dilion_privacy.legal_holds h
			where h.user_id = dilion_pii.subject_keys.user_id
			  and h.released_at is null and (h.domain is null or h.domain = $2)
		  )
		order by shred_after, user_id limit $3`
	rows, err := e.pool.Query(ctx, q, now, DomainConsentEvidence, batch)
	if err != nil {
		return fmt.Errorf("privacy: consent shred sweep: %w", err)
	}
	var users []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			rows.Close()
			return fmt.Errorf("privacy: consent shred sweep: %w", err)
		}
		users = append(users, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("privacy: consent shred sweep: %w", err)
	}
	return e.shredConsentKeys(ctx, users, "shred_after")
}

func (e *Engine) shredConsentKeys(ctx context.Context, users []string, reason string) error {
	for _, u := range users {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		held, err := e.activeHoldFor(ctx, u, DomainConsentEvidence)
		if err != nil {
			return err
		}
		if held {
			e.log.Info("retention skipped: legal hold", "user_id", u, "domain", DomainConsentEvidence)
			continue
		}
		if err := e.kms.DestroyDEK(ctx, u, ports.KeyScopeConsent); err != nil {
			e.log.Error("consent DEK shred failed", "user_id", u, "err", err)
			continue
		}
		if _, err := e.pool.Exec(ctx, `update dilion_pii.subject_keys
			set shredded_at = coalesce(shredded_at, $2)
			where user_id = $1::uuid and scope = 'CONSENT'`, u, e.now()); err != nil {
			return fmt.Errorf("privacy: mark consent key shredded: %w", err)
		}
		e.log.Info("consent evidence crypto-shredded", "user_id", u, "reason", reason)
	}
	return nil
}

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

	// consent-evidence / from: erasure — the pipeline snapshotted shred_after,
	// so this sweep is policy-independent.
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
				if rule.From != FromCreated {
					continue // handled by the shred_after sweep
				}
				d, err := ParseISODuration(rule.Period)
				if err != nil {
					return err
				}
				if err := e.sweepConsentFromCreated(ctx, id, d, now, batch); err != nil {
					return err
				}
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

// sweepConsentFromCreated shreds consent evidence whose newest ledger entry is
// older than the policy period. The newest entry is used so that in-retention
// evidence is never destroyed by a subject-scoped key shred.
func (e *Engine) sweepConsentFromCreated(ctx context.Context, policyID string, d Duration, now time.Time, batch int) error {
	cutoff := d.SubFrom(now)
	const q = `select ce.user_id::text
		from dilion_privacy.consent_events ce
		join dilion_pii.subject_keys k
			on k.user_id = ce.user_id and k.scope = 'CONSENT' and k.shredded_at is null
		left join dilion_privacy.subject_policies sp on sp.user_id = ce.user_id
		where coalesce(sp.policy_id, $1) = $2
		  and not exists (
			select 1 from dilion_privacy.legal_holds h
			where h.user_id = ce.user_id and h.released_at is null
			  and (h.domain is null or h.domain = $3)
		  )
		group by ce.user_id
		having max(ce.created_at) <= $4
		order by ce.user_id
		limit $5`
	rows, err := e.pool.Query(ctx, q, e.policies.DefaultPolicy, policyID,
		DomainConsentEvidence, cutoff, batch)
	if err != nil {
		return fmt.Errorf("privacy: consent retention sweep: %w", err)
	}
	var users []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			rows.Close()
			return fmt.Errorf("privacy: consent retention sweep: %w", err)
		}
		users = append(users, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("privacy: consent retention sweep: %w", err)
	}
	return e.shredConsentKeys(ctx, users, "policy:"+policyID)
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

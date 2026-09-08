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
				// TODO(agent D / wave 2): dilion_audit.* is owned by the audit
				// domain; retention over access logs is not implemented yet.
				// Recorded as an explicit compliance gap rather than silently
				// skipped (§2.8 "런타임에 조용히 무시 금지").
				e.log.Warn("retention gap: audit-log rule not executed (dilion_audit.* not owned by privacy)",
					"policy", id, "period", rule.Period, "from", rule.From,
					"action", rule.Action, "basis", rule.Basis)
			default:
				e.log.Warn("retention gap: no executor for domain",
					"policy", id, "domain", rule.Domain, "period", rule.Period)
			}
		}
	}
	return nil
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
		where ce.project_id = $1 and coalesce(sp.policy_id, $2) = $3
		  and not exists (
			select 1 from dilion_privacy.legal_holds h
			where h.user_id = ce.user_id and h.released_at is null
			  and (h.domain is null or h.domain = $4)
		  )
		group by ce.user_id
		having max(ce.created_at) <= $5
		order by ce.user_id
		limit $6`
	rows, err := e.pool.Query(ctx, q, defaultProjectID, e.policies.DefaultPolicy, policyID,
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

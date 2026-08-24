package privacy

// Cross-user consent projections (docs/use-cases.md 제안 P1).
//
// The ledger stays the source of truth (§4): both queries below project the
// latest GRANT/WITHDRAW per (user, purpose) with DISTINCT ON, exactly like the
// per-user GetConsents. If segment reads become hot, materialise the projection
// into a current-state table fed from the ledger — the API contract here would
// not change.

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/dilion-project/dilion/httpapi"
)

// segmentScanBatch is how many projected rows one scan round fetches when a
// Go-side filter (reconfirm_due_before) may discard most of them.
const segmentScanBatch = 500

// segmentScanRounds caps the scan work of one call. When the cap is reached
// before the page fills, the partial page is returned with a cursor so the
// client continues — cursor pagination does not promise full pages.
const segmentScanRounds = 4

// ListConsentStates pages the current consent state across all subjects,
// ordered by (user_id, purpose).
func (e *Engine) ListConsentStates(ctx context.Context, projectID string, f ConsentSegmentFilter, p httpapi.ListParams) (httpapi.Page[SubjectConsent], error) {
	p = p.Norm()
	var zero httpapi.Page[SubjectConsent]
	curUser, curPurpose, err := decodeSegmentCursor(p.Cursor)
	if err != nil {
		return zero, err
	}

	scanLimit := p.Limit + 1
	if f.ReconfirmDueBefore != nil {
		// The reconfirm filter is applied after annotation; over-fetch so a
		// sparse match still fills the page in few rounds.
		scanLimit = segmentScanBatch
	}

	matched := make([]SubjectConsent, 0, p.Limit+1)
	exhausted := false
	var lastUser, lastPurpose string

	for round := 0; round < segmentScanRounds && len(matched) <= p.Limit; round++ {
		batch, err := e.scanConsentSegment(ctx, normProject(projectID), f, curUser, curPurpose, scanLimit)
		if err != nil {
			return zero, err
		}
		if len(batch) < scanLimit {
			exhausted = true
		}
		if len(batch) == 0 {
			break
		}
		last := batch[len(batch)-1]
		curUser, curPurpose = last.UserID, last.Purpose
		lastUser, lastPurpose = last.UserID, last.Purpose

		if err := e.annotateReconfirm(ctx, normProject(projectID), batch); err != nil {
			return zero, err
		}
		for _, sc := range batch {
			if f.ReconfirmDueBefore != nil &&
				(sc.ReconfirmDue == nil || !sc.ReconfirmDue.Before(*f.ReconfirmDueBefore)) {
				continue
			}
			matched = append(matched, sc)
		}
		if exhausted {
			break
		}
	}

	out := httpapi.Page[SubjectConsent]{Items: matched}
	switch {
	case len(matched) > p.Limit:
		out.Items = matched[:p.Limit]
		lastKept := out.Items[len(out.Items)-1]
		out.NextCursor = encodeSegmentCursor(lastKept.UserID, lastKept.Purpose)
	case !exhausted && lastUser != "":
		// Scan budget ran out before the projection did: resume after the last
		// scanned row (not the last matched one) so nothing is skipped.
		out.NextCursor = encodeSegmentCursor(lastUser, lastPurpose)
	}
	if out.Items == nil {
		out.Items = []SubjectConsent{}
	}
	return out, nil
}

// scanConsentSegment fetches one ordered batch of the latest-state projection.
// Granted/purpose filters run in SQL; reconfirm_due is annotated afterwards.
func (e *Engine) scanConsentSegment(ctx context.Context, projectID string, f ConsentSegmentFilter, curUser, curPurpose string, limit int) ([]SubjectConsent, error) {
	const q = `
		with latest as (
			select distinct on (user_id, purpose)
				user_id, purpose, action, coalesce(policy_version, '') as policy_version, created_at
			from dilion_privacy.consent_events
			where project_id = $1 and action in ('GRANT','WITHDRAW')
			  and ($2 = '' or purpose = $2)
			order by user_id, purpose, created_at desc, id desc
		)
		select user_id::text, purpose, action, policy_version, created_at
		from latest
		where ($3::bool is null or (action = 'GRANT') = $3)
		  and ($4 = '' or (user_id::text, purpose) > ($4, $5))
		order by user_id::text, purpose
		limit $6`
	rows, err := e.pool.Query(ctx, q, projectID, f.Purpose, f.Granted, curUser, curPurpose, limit)
	if err != nil {
		return nil, fmt.Errorf("privacy: consent segment scan: %w", err)
	}
	defer rows.Close()
	var out []SubjectConsent
	for rows.Next() {
		var sc SubjectConsent
		var action string
		if err := rows.Scan(&sc.UserID, &sc.Purpose, &action, &sc.PolicyVersion, &sc.UpdatedAt); err != nil {
			return nil, fmt.Errorf("privacy: consent segment scan: %w", err)
		}
		sc.Granted = action == ConsentGrant
		out = append(out, sc)
	}
	return out, rows.Err()
}

// annotateReconfirm fills ReconfirmDue for a batch: subject policies and the
// last RECONFIRM_NOTICE per (user, purpose) are loaded in one query each.
func (e *Engine) annotateReconfirm(ctx context.Context, projectID string, batch []SubjectConsent) error {
	if len(batch) == 0 {
		return nil
	}
	userSet := map[string]struct{}{}
	for _, sc := range batch {
		userSet[sc.UserID] = struct{}{}
	}
	users := make([]string, 0, len(userSet))
	for u := range userSet {
		users = append(users, u)
	}

	policyOf := map[string]string{}
	rows, err := e.pool.Query(ctx, `select user_id::text, policy_id
		from dilion_privacy.subject_policies where user_id = any($1::uuid[])`, users)
	if err != nil {
		return fmt.Errorf("privacy: segment policies: %w", err)
	}
	for rows.Next() {
		var uid, pid string
		if err := rows.Scan(&uid, &pid); err != nil {
			rows.Close()
			return fmt.Errorf("privacy: segment policies: %w", err)
		}
		policyOf[uid] = pid
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("privacy: segment policies: %w", err)
	}

	type key struct{ user, purpose string }
	notices := map[key]*time.Time{}
	rows, err = e.pool.Query(ctx, `select user_id::text, purpose, max(created_at)
		from dilion_privacy.consent_events
		where project_id = $1 and action = $2 and user_id = any($3::uuid[])
		group by user_id, purpose`, projectID, ConsentReconfirmNotice, users)
	if err != nil {
		return fmt.Errorf("privacy: segment notices: %w", err)
	}
	for rows.Next() {
		var uid, purpose string
		var at time.Time
		if err := rows.Scan(&uid, &purpose, &at); err != nil {
			rows.Close()
			return fmt.Errorf("privacy: segment notices: %w", err)
		}
		t := at
		notices[key{uid, purpose}] = &t
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("privacy: segment notices: %w", err)
	}

	for i := range batch {
		sc := &batch[i]
		policyID := policyOf[sc.UserID]
		if policyID == "" {
			policyID = e.policies.DefaultPolicy
		}
		policy, known := e.policies.Resolve(policyID)
		if !known {
			policy, _ = e.policies.Resolve(e.policies.DefaultPolicy)
		}
		if due, ok := reconfirmDue(policy, sc.Purpose, sc.Granted, sc.UpdatedAt,
			notices[key{sc.UserID, sc.Purpose}]); ok {
			d := due
			sc.ReconfirmDue = &d
		}
	}
	return nil
}

// ExportConsentAudience pages the granted segment of one purpose joined with
// auth.users contact identifiers, ordered by user_id. Deleted/erased accounts
// (deleted_at set, or no auth row) are excluded — an audience export must never
// resurrect an erased subject.
func (e *Engine) ExportConsentAudience(ctx context.Context, projectID, purpose string, p httpapi.ListParams) (httpapi.Page[AudienceMember], error) {
	p = p.Norm()
	var zero httpapi.Page[AudienceMember]
	if strings.TrimSpace(purpose) == "" {
		return zero, fmt.Errorf("%w: purpose is required", ErrInvalidInput)
	}
	cur, err := decodeIDCursor(p.Cursor)
	if err != nil {
		return zero, err
	}
	const q = `
		with latest as (
			select distinct on (user_id) user_id, action
			from dilion_privacy.consent_events
			where project_id = $1 and purpose = $2 and action in ('GRANT','WITHDRAW')
			order by user_id, created_at desc, id desc
		)
		select l.user_id::text, coalesce(u.email, ''), coalesce(u.phone, '')
		from latest l
		join auth.users u on u.id = l.user_id and u.deleted_at is null
		where l.action = 'GRANT'
		  and ($3 = '' or l.user_id::text > $3)
		order by l.user_id::text
		limit $4`
	rows, err := e.pool.Query(ctx, q, normProject(projectID), purpose, cur, p.Limit+1)
	if err != nil {
		return zero, fmt.Errorf("privacy: consent audience: %w", err)
	}
	defer rows.Close()
	var items []AudienceMember
	for rows.Next() {
		var m AudienceMember
		if err := rows.Scan(&m.UserID, &m.Email, &m.Phone); err != nil {
			return zero, fmt.Errorf("privacy: consent audience: %w", err)
		}
		items = append(items, m)
	}
	if err := rows.Err(); err != nil {
		return zero, fmt.Errorf("privacy: consent audience: %w", err)
	}
	return page(items, p.Limit, func(m AudienceMember) *string { return encodeIDCursor(m.UserID) }), nil
}

// ---- (user_id, purpose) cursor ---------------------------------------------

func encodeSegmentCursor(userID, purpose string) *string {
	s := base64.RawURLEncoding.EncodeToString([]byte(userID + "|" + purpose))
	return &s
}

func decodeSegmentCursor(c string) (string, string, error) {
	if c == "" {
		return "", "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return "", "", fmt.Errorf("%w: bad cursor", ErrInvalidInput)
	}
	user, purpose, ok := strings.Cut(string(raw), "|")
	if !ok || user == "" {
		return "", "", fmt.Errorf("%w: bad cursor", ErrInvalidInput)
	}
	return user, purpose, nil
}

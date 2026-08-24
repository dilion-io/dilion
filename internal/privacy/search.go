package privacy

// Exact-match user search (docs/use-cases.md 제안 P4).
//
// auth.users identifiers (email, phone) are stored in the clear on the compat
// schema and are matched directly. Vault profile fields are sealed (§2.7), so
// they are matched through a blind index: dilion_pii.profile_search_index keeps
// HMAC(search key, field_key ‖ normalized value) per field, written in the same
// transaction as every profile write and removed with the profile by the
// erasure pipeline. The index supports equality only — nothing about the value
// (not even its length) is recoverable without the instance key.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/dilion-io/dilion/httpapi"
)

// searchKeyLabel derives the blind-index key from the instance's tombstone key.
// A distinct label keeps the derived key domain-separated from the erasure
// registry HMAC (§2.10) even though both come from the same root secret.
const searchKeyLabel = "dilion-pii-search-index-v1"

// SearchUsers looks up subjects by exactly one criterion and pages the matches
// by user_id. Matches carry ids only: reading any value stays a separate,
// audited profile read.
func (e *Engine) SearchUsers(ctx context.Context, projectID string, q UserSearchQuery, p httpapi.ListParams) (httpapi.Page[UserMatch], error) {
	p = p.Norm()
	var zero httpapi.Page[UserMatch]
	cur, err := decodeIDCursor(p.Cursor)
	if err != nil {
		return zero, err
	}

	criteria := 0
	if strings.TrimSpace(q.Email) != "" {
		criteria++
	}
	if strings.TrimSpace(q.Phone) != "" {
		criteria++
	}
	if q.FieldKey != "" || q.FieldValue != "" {
		if !profileKeyRe.MatchString(q.FieldKey) {
			return zero, fmt.Errorf("%w: field key %q must match %s", ErrInvalidInput, q.FieldKey, profileKeyRe)
		}
		if strings.TrimSpace(q.FieldValue) == "" {
			return zero, fmt.Errorf("%w: a field search requires a value", ErrInvalidInput)
		}
		criteria++
	}
	if criteria != 1 {
		return zero, fmt.Errorf("%w: exactly one of email, phone or field+value is required", ErrInvalidInput)
	}

	var (
		sql    string
		arg    string
		source string
		field  string
	)
	switch {
	case strings.TrimSpace(q.Email) != "":
		// Deleted/erased accounts never match: their identifiers are nulled by
		// the erasure pipeline anyway, and a search must not resurrect them.
		sql = `select id::text from auth.users
			where lower(email) = lower($1) and deleted_at is null
			  and ($2 = '' or id::text > $2)
			order by id::text limit $3`
		arg, source = strings.TrimSpace(q.Email), MatchAuthEmail
	case strings.TrimSpace(q.Phone) != "":
		sql = `select id::text from auth.users
			where phone = $1 and deleted_at is null
			  and ($2 = '' or id::text > $2)
			order by id::text limit $3`
		arg, source = normalizePhone(q.Phone), MatchAuthPhone
	default:
		sql = `select user_id::text from dilion_pii.profile_search_index
			where field_key = $4 and value_hmac = $1
			  and ($2 = '' or user_id::text > $2)
			order by user_id::text limit $3`
		arg, source, field = e.searchIndexHMAC(q.FieldKey, q.FieldValue), MatchProfileField, q.FieldKey
	}

	args := []any{arg, cur, p.Limit + 1}
	if field != "" {
		args = append(args, field)
	}
	rows, err := e.pool.Query(ctx, sql, args...)
	if err != nil {
		return zero, fmt.Errorf("privacy: search users: %w", err)
	}
	defer rows.Close()
	var items []UserMatch
	for rows.Next() {
		m := UserMatch{Source: source, FieldKey: field}
		if err := rows.Scan(&m.UserID); err != nil {
			return zero, fmt.Errorf("privacy: search users: %w", err)
		}
		items = append(items, m)
	}
	if err := rows.Err(); err != nil {
		return zero, fmt.Errorf("privacy: search users: %w", err)
	}
	return page(items, p.Limit, func(m UserMatch) *string { return encodeIDCursor(m.UserID) }), nil
}

// ---- blind index maintenance ------------------------------------------------

// searchIndexHMAC computes the equality token for one field value.
func (e *Engine) searchIndexHMAC(fieldKey, value string) string {
	root := hmac.New(sha256.New, e.tombstoneKey)
	root.Write([]byte(searchKeyLabel))
	derived := root.Sum(nil)

	m := hmac.New(sha256.New, derived)
	m.Write([]byte(fieldKey))
	m.Write([]byte{0})
	m.Write([]byte(normalizeSearchValue(value)))
	return hex.EncodeToString(m.Sum(nil))
}

// normalizeSearchValue folds trivial formatting differences so "  A@B.com "
// and "a@b.com" produce the same token. Deliberately conservative: anything
// smarter (unicode folding, phone formats) belongs to the caller.
func normalizeSearchValue(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

// normalizePhone strips the spacing/punctuation people paste so the exact
// match runs over bare digits (+ prefix kept), matching how gotrue stores
// phone numbers.
func normalizePhone(v string) string {
	var b strings.Builder
	for i, r := range strings.TrimSpace(v) {
		if r >= '0' && r <= '9' || (r == '+' && i == 0) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// syncSearchIndex rewrites the subject's index rows to mirror fields. Runs in
// the caller's transaction so the index can never disagree with the sealed
// document it points into.
func (e *Engine) syncSearchIndex(ctx context.Context, q queryExecer, userID string, fields map[string]ProfileField) error {
	if _, err := q.Exec(ctx,
		`delete from dilion_pii.profile_search_index where user_id = $1::uuid`, userID); err != nil {
		return fmt.Errorf("privacy: clear search index: %w", err)
	}
	for key, f := range fields {
		if _, err := q.Exec(ctx, `insert into dilion_pii.profile_search_index
			(user_id, field_key, value_hmac) values ($1::uuid, $2, $3)`,
			userID, key, e.searchIndexHMAC(key, f.Value)); err != nil {
			return fmt.Errorf("privacy: write search index: %w", err)
		}
	}
	return nil
}

package iam

// Actor expansion for the assignment and recertification reports (§2.11).
//
// A role assignment names an ACTOR, which is either an operator (a user UUID)
// or a machine credential (an API key id). Answering "is this grant still
// live?" from the assignment rows alone is impossible: a user may be banned or
// deleted and a key may be revoked, and neither shows up in the ledger. This
// resolves those operational facts in ONE query per actor kind, instead of the
// caller fetching each actor individually.
//
// Deliberately NOT here: email, name, or any other personal data. The
// management plane does not inline personal data into unrelated reports
// (users_search.go states the same rule) — a caller that needs to display a
// subject reads the masked profile surface, which is separately permissioned
// and separately audited.

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ActorDetail is the non-PII operational view of one actor. Which members are
// populated depends on Type; the rest stay nil.
type ActorDetail struct {
	ActorID string
	// Type is ActorTypeUser, ActorTypeAPIKey, or ActorTypeUnknown when the id
	// resolves to neither — a grant to an actor that no longer exists, which is
	// exactly what a recertification review needs to see.
	Type string

	CreatedAt *time.Time

	// User members.
	LastSignInAt *time.Time
	BannedUntil  *time.Time
	DeletedAt    *time.Time

	// API key member.
	RevokedAt *time.Time
}

// ActorTypeUnknown marks an actor id that matches no user and no API key.
const ActorTypeUnknown = "unknown"

// Active reports whether the actor can still exercise the grant at t. An
// unknown actor is never active.
func (d ActorDetail) Active(t time.Time) bool {
	switch d.Type {
	case ActorTypeUser:
		return d.DeletedAt == nil && (d.BannedUntil == nil || !d.BannedUntil.After(t))
	case ActorTypeAPIKey:
		return d.RevokedAt == nil
	default:
		return false
	}
}

// ActorDetails resolves actor ids to their operational view, keyed by actor id.
// Ids that resolve to nothing come back with Type ActorTypeUnknown rather than
// being dropped, so a caller can always pair every id it asked about with an
// answer. Duplicate ids are collapsed. An empty input is not an error.
//
// Two queries total, regardless of how many actors are asked about: one over
// auth.users for the id shaped like a UUID, one over the API key table for the
// rest.
func (s *Service) ActorDetails(ctx context.Context, ids []string) (map[string]ActorDetail, error) {
	out := make(map[string]ActorDetail, len(ids))
	var userIDs, keyIDs []string
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, dup := out[id]; dup {
			continue
		}
		out[id] = ActorDetail{ActorID: id, Type: ActorTypeUnknown}
		if _, err := uuid.Parse(id); err == nil {
			userIDs = append(userIDs, id)
		} else {
			keyIDs = append(keyIDs, id)
		}
	}
	if len(out) == 0 {
		return out, nil
	}
	pool, err := s.db(ctx)
	if err != nil {
		return nil, err
	}

	// Each query is drained and closed before the next one starts, so this
	// holds ONE pooled connection at a time rather than two.
	if len(userIDs) > 0 {
		err := scanActors(ctx, pool, out, `
			select id::text, created_at, last_sign_in_at, banned_until, deleted_at
			from auth.users
			where id = any($1::uuid[])`, userIDs,
			func(rows pgx.Rows, d *ActorDetail) error {
				d.Type = ActorTypeUser
				return rows.Scan(&d.ActorID, &d.CreatedAt, &d.LastSignInAt,
					&d.BannedUntil, &d.DeletedAt)
			})
		if err != nil {
			return nil, fmt.Errorf("iam: actor details (users): %w", err)
		}
	}

	if len(keyIDs) > 0 {
		err := scanActors(ctx, pool, out, `
			select id, created_at, revoked_at
			from dilion_authz.api_keys
			where id = any($1::text[])`, keyIDs,
			func(rows pgx.Rows, d *ActorDetail) error {
				d.Type = ActorTypeAPIKey
				return rows.Scan(&d.ActorID, &d.CreatedAt, &d.RevokedAt)
			})
		if err != nil {
			return nil, fmt.Errorf("iam: actor details (api keys): %w", err)
		}
	}
	return out, nil
}

// scanActors runs one lookup and merges its rows into out, closing the rows
// before it returns so the connection goes back to the pool immediately.
func scanActors(ctx context.Context, pool *pgxpool.Pool, out map[string]ActorDetail,
	query string, ids []string, scan func(pgx.Rows, *ActorDetail) error) error {
	rows, err := pool.Query(ctx, query, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var d ActorDetail
		if err := scan(rows, &d); err != nil {
			return err
		}
		out[d.ActorID] = d
	}
	return rows.Err()
}

// UserActorIDs is the subset of ids that name a data subject, which is what an
// access record's subject manifest may contain (§5.3). Order follows ids and
// duplicates are collapsed.
func UserActorIDs(details map[string]ActorDetail, ids []string) []string {
	seen := make(map[string]struct{}, len(ids))
	out := []string{}
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		if details[id].Type == ActorTypeUser {
			out = append(out, id)
		}
	}
	return out
}

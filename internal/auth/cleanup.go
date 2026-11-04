package auth

// Background cleanup of expired auth rows.
//
// Upstream runs the same deletions opportunistically from an HTTP middleware
// (models.Cleanup, gated by GOTRUE_DB_CLEANUP_ENABLED). Dilion runs them from a
// worker instead: request latency should not depend on how much garbage the
// database happens to hold, and a deployment that is idle still needs its
// expired sessions to disappear (개인정보 보유기간 최소화, project.md §5).

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"strconv"
	"time"
)

// refreshTokenRetention is how long a revoked refresh token is kept after its
// last update. It is deliberately generous: a revoked token is the evidence
// that lets reuse detection recognise a stolen token family.
const refreshTokenRetention = 30 * 24 * time.Hour

// cleanupBatch caps one delete statement so a large backlog is drained over
// several passes instead of locking a table for minutes.
const cleanupBatch = 5000

// RunCleanup runs the cleanup pass periodically until ctx is cancelled. It
// returns immediately when Config.CleanupEnabled is false.
//
// The first pass is delayed by a random fraction of the interval so several
// instances started together do not all sweep at once.
func (a *api) RunCleanup(ctx context.Context) {
	if !a.cfg.CleanupEnabled {
		a.log.InfoContext(ctx, "auth: database cleanup disabled")
		return
	}
	interval := a.cfg.CleanupInterval

	timer := time.NewTimer(time.Duration(rand.Int64N(int64(interval))))
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}

		if n, err := a.cleanupOnce(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			a.log.WarnContext(ctx, "auth: cleanup pass failed", slog.String("error", err.Error()))
		} else if n > 0 {
			a.log.InfoContext(ctx, "auth: cleanup removed expired rows", slog.Int64("rows", n))
		}

		timer.Reset(interval)
	}
}

// cleanupOnce deletes one batch of expired rows and reports how many were
// removed. It is safe to run concurrently with the request path and with other
// instances: every statement is an unconditional DELETE on rows that are already
// unusable.
func (a *api) cleanupOnce(ctx context.Context) (int64, error) {
	pool, err := a.db(ctx)
	if err != nil {
		return 0, err
	}
	now := a.now()
	var total int64

	// 1. Revoked refresh tokens past the retention window.
	tag, err := pool.Exec(ctx, `
		delete from auth.refresh_tokens
		where ctid in (
			select ctid from auth.refresh_tokens
			where revoked is true and updated_at < $1
			limit $2
		)`, now.Add(-refreshTokenRetention), cleanupBatch)
	if err != nil {
		return total, err
	}
	total += tag.RowsAffected()

	// 2. Sessions past their absolute expiry. Their refresh tokens cascade.
	tag, err = pool.Exec(ctx, `
		delete from auth.sessions
		where ctid in (
			select ctid from auth.sessions
			where not_after is not null and not_after < $1
			limit $2
		)`, now, cleanupBatch)
	if err != nil {
		return total, err
	}
	total += tag.RowsAffected()

	// 3. Sessions past the configured timebox / inactivity timeout. Enforcing
	//    the policy on refresh only would leave abandoned sessions behind
	//    forever, and a session row is personal data (IP, user agent).
	if tb := a.cfg.Sessions.Timebox; tb > 0 {
		tag, err = pool.Exec(ctx, `
			delete from auth.sessions
			where ctid in (
				select ctid from auth.sessions where created_at < $1 limit $2
			)`, now.Add(-tb), cleanupBatch)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
	}
	if it := a.cfg.Sessions.InactivityTimeout; it > 0 {
		tag, err = pool.Exec(ctx, `
			delete from auth.sessions
			where ctid in (
				select ctid from auth.sessions
				where coalesce(refreshed_at, created_at) < $1
				limit $2
			)`, now.Add(-it), cleanupBatch)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
	}

	// 4. Tables owned by features that may not have been migrated in yet. Each
	//    delete is guarded with to_regclass so this worker never fails on a
	//    database that predates the feature's migration.
	optional := []struct {
		table string
		sql   string
		arg   any
	}{
		{table: "dilion_auth.opaque_handshakes", sql: `delete from dilion_auth.opaque_handshakes where ctid in (select ctid from dilion_auth.opaque_handshakes where expires_at < $1 limit 5000)`, arg: now},
		{table: "dilion_auth.opaque_session_keys", sql: `delete from dilion_auth.opaque_session_keys where ctid in (select ctid from dilion_auth.opaque_session_keys where expires_at < $1 limit 5000)`, arg: now},
		{table: "dilion_auth.opaque_attempts", sql: `delete from dilion_auth.opaque_attempts where ctid in (select ctid from dilion_auth.opaque_attempts where window_start < $1 limit 5000)`, arg: now.Add(-time.Hour)},
		{table: "dilion_auth.auth_attempts", sql: `delete from dilion_auth.auth_attempts where ctid in (select ctid from dilion_auth.auth_attempts where window_start < $1 limit 5000)`, arg: now.Add(-attemptWindow)},
		{
			// One-time tokens (confirmation, recovery, email change, ...).
			table: "auth.one_time_tokens",
			sql: `delete from auth.one_time_tokens
			      where ctid in (select ctid from auth.one_time_tokens where updated_at < $1 limit ` + strconv.Itoa(cleanupBatch) + `)`,
			arg: now.Add(-a.cfg.Mailer.OTPExpDuration()),
		},
		{
			// PKCE / OAuth flow states.
			table: "auth.flow_state",
			sql: `delete from auth.flow_state
			      where ctid in (select ctid from auth.flow_state where created_at < $1 limit ` + strconv.Itoa(cleanupBatch) + `)`,
			arg: now.Add(-a.cfg.FlowStateExpiry),
		},
		{
			// PKCE verifiers toward external providers (provider_pkce.go). A
			// callback deletes its own; these are the flows nobody finished,
			// and a verifier is useless once its flow state has expired.
			table: "auth.oauth_client_states",
			sql: `delete from auth.oauth_client_states
			      where ctid in (select ctid from auth.oauth_client_states where created_at < $1 limit ` + strconv.Itoa(cleanupBatch) + `)`,
			arg: now.Add(-a.cfg.FlowStateExpiry),
		},
		{
			table: "auth.webauthn_challenges",
			sql: `delete from auth.webauthn_challenges
			      where ctid in (select ctid from auth.webauthn_challenges where expires_at < $1 limit ` + strconv.Itoa(cleanupBatch) + `)`,
			arg: now,
		},
		{
			table: "auth.oauth_authorizations",
			sql: `update auth.oauth_authorizations set status = 'expired'
			      where id in (select id from auth.oauth_authorizations
			                   where status = 'pending' and expires_at < $1 limit ` + strconv.Itoa(cleanupBatch) + `)`,
			arg: now,
		},
	}
	for _, o := range optional {
		var exists bool
		if err := pool.QueryRow(ctx, `select to_regclass($1) is not null`, o.table).Scan(&exists); err != nil {
			return total, err
		}
		if !exists {
			continue
		}
		tag, err = pool.Exec(ctx, o.sql, o.arg)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
	}

	return total, nil
}

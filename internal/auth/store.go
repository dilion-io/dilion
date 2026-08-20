package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// querier is satisfied by *pgxpool.Pool and pgx.Tx, so every query below works
// inside or outside a transaction.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// nilUUID is gotrue's instance_id for non-multi-instance deployments.
const nilUUID = "00000000-0000-0000-0000-000000000000"

// userColumns is the projection used by every user read. uuid columns are cast
// to text so they scan into plain strings.
const userColumns = `
	id::text, aud, role, email, encrypted_password,
	email_confirmed_at, invited_at, phone, phone_confirmed_at,
	confirmation_sent_at, confirmed_at, recovery_sent_at,
	email_change, email_change_sent_at, phone_change, phone_change_sent_at,
	reauthentication_sent_at, last_sign_in_at,
	raw_app_meta_data, raw_user_meta_data,
	created_at, updated_at, banned_until, deleted_at,
	is_anonymous, is_sso_user`

func scanUser(row pgx.Row) (*User, error) {
	var (
		u                                           User
		aud, role, email, phone, emailChg, phoneChg *string
		createdAt, updatedAt                        *time.Time
	)
	err := row.Scan(
		&u.ID, &aud, &role, &email, &u.EncryptedPassword,
		&u.EmailConfirmedAt, &u.InvitedAt, &phone, &u.PhoneConfirmedAt,
		&u.ConfirmationSentAt, &u.ConfirmedAt, &u.RecoverySentAt,
		&emailChg, &u.EmailChangeSentAt, &phoneChg, &u.PhoneChangeSentAt,
		&u.ReauthenticationSentAt, &u.LastSignInAt,
		&u.AppMetaData, &u.UserMetaData,
		&createdAt, &updatedAt, &u.BannedUntil, &u.DeletedAt,
		&u.IsAnonymous, &u.IsSSOUser,
	)
	if err != nil {
		return nil, err
	}
	u.Aud = deref(aud)
	u.Role = deref(role)
	u.Email = deref(email)
	u.Phone = deref(phone)
	u.EmailChange = deref(emailChg)
	u.PhoneChange = deref(phoneChg)
	if createdAt != nil {
		u.CreatedAt = createdAt.UTC()
	}
	if updatedAt != nil {
		u.UpdatedAt = updatedAt.UTC()
	}
	// pgx returns timestamptz in the session time zone; normalize so the wire
	// format is RFC 3339 UTC regardless of where the server runs.
	for _, t := range []**time.Time{
		&u.EmailConfirmedAt, &u.InvitedAt, &u.PhoneConfirmedAt, &u.ConfirmationSentAt,
		&u.ConfirmedAt, &u.RecoverySentAt, &u.EmailChangeSentAt, &u.PhoneChangeSentAt,
		&u.ReauthenticationSentAt, &u.LastSignInAt, &u.BannedUntil, &u.DeletedAt,
	} {
		*t = utc(*t)
	}
	if u.AppMetaData == nil {
		u.AppMetaData = JSONMap{}
	}
	if u.UserMetaData == nil {
		u.UserMetaData = JSONMap{}
	}
	u.Identities = []Identity{}
	return &u, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// utc normalizes a nullable timestamp so responses are RFC 3339 UTC.
func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func ptr[T any](v T) *T { return &v }

// ---- users ----------------------------------------------------------------

func findUserByID(ctx context.Context, q querier, id string) (*User, error) {
	return scanUser(q.QueryRow(ctx,
		`select `+userColumns+` from auth.users where id = $1::uuid`, id))
}

// findUserByEmail mirrors gotrue's FindUserByEmailAndAudience: SSO users are
// excluded (they may legitimately share an email) and soft-deleted users cannot
// match because their email is obfuscated on delete.
func findUserByEmail(ctx context.Context, q querier, email, aud string) (*User, error) {
	return scanUser(q.QueryRow(ctx,
		`select `+userColumns+` from auth.users
		 where instance_id = $1::uuid and lower(email) = $2 and aud = $3 and is_sso_user = false`,
		nilUUID, email, aud))
}

// countUsers / listUsers implement gotrue's page/per_page admin pagination.
func countUsers(ctx context.Context, q querier, aud string) (int64, error) {
	var n int64
	err := q.QueryRow(ctx,
		`select count(*) from auth.users where instance_id = $1::uuid and aud = $2`,
		nilUUID, aud).Scan(&n)
	return n, err
}

func listUsers(ctx context.Context, q querier, aud string, limit, offset int64) ([]*User, error) {
	rows, err := q.Query(ctx,
		`select `+userColumns+` from auth.users
		 where instance_id = $1::uuid and aud = $2
		 order by created_at desc, id desc
		 limit $3 offset $4`,
		nilUUID, aud, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

type newUserParams struct {
	ID                string
	Aud               string
	Role              string
	Email             string // already lowercased; "" means none
	Phone             string
	EncryptedPassword *string
	EmailConfirmedAt  *time.Time
	PhoneConfirmedAt  *time.Time
	AppMetaData       JSONMap
	UserMetaData      JSONMap
	IsAnonymous       bool
	Now               time.Time
}

func insertUser(ctx context.Context, q querier, p newUserParams) (*User, error) {
	return scanUser(q.QueryRow(ctx, `
		insert into auth.users (
			instance_id, id, aud, role, email, phone, encrypted_password,
			email_confirmed_at, phone_confirmed_at,
			raw_app_meta_data, raw_user_meta_data,
			created_at, updated_at,
			is_sso_user, is_anonymous, is_super_admin,
			confirmation_token, recovery_token,
			email_change_token_new, email_change_token_current, email_change,
			phone_change_token, phone_change, reauthentication_token,
			email_change_confirm_status
		) values (
			$1::uuid, $2::uuid, $3, $4, nullif($5, ''), nullif($6, ''), $7,
			$8, $9,
			$10, $11,
			$12, $12,
			false, $13, false,
			'', '',
			'', '', '',
			'', '', '',
			0
		)
		returning `+userColumns,
		nilUUID, p.ID, p.Aud, p.Role, p.Email, p.Phone, p.EncryptedPassword,
		p.EmailConfirmedAt, p.PhoneConfirmedAt,
		p.AppMetaData, p.UserMetaData,
		p.Now, p.IsAnonymous))
}

// updateUserFields applies a dynamic SET list. `updated_at` is always bumped.
//
// The keys of `set` are column names interpolated into the SQL. Every caller
// passes literals defined in this package — never anything derived from request
// input — and the values themselves are always bound as parameters.
func updateUserFields(ctx context.Context, q querier, id string, now time.Time, set map[string]any) (*User, error) {
	if len(set) == 0 {
		return findUserByID(ctx, q, id)
	}
	sql := `update auth.users set updated_at = $1`
	args := []any{now}
	for col, val := range set {
		args = append(args, val)
		sql += fmt.Sprintf(", %s = $%d", col, len(args))
	}
	args = append(args, id)
	sql += fmt.Sprintf(" where id = $%d::uuid returning ", len(args)) + userColumns
	return scanUser(q.QueryRow(ctx, sql, args...))
}

// softDeleteUser reproduces gotrue's models.User.SoftDeleteUser: the record stays
// but every identifying value is replaced by an irreversible digest, which also
// releases the unique constraints on email/phone.
func softDeleteUser(ctx context.Context, q querier, u *User, now time.Time) error {
	_, err := q.Exec(ctx, `
		update auth.users set
			email = $2,
			phone = $3,
			encrypted_password = null,
			email_change = $4,
			phone_change = $5,
			confirmation_token = '',
			recovery_token = '',
			email_change_token_current = '',
			email_change_token_new = '',
			phone_change_token = '',
			raw_user_meta_data = '{}'::jsonb,
			deleted_at = $6,
			updated_at = $6
		where id = $1::uuid`,
		u.ID,
		obfuscateEmail(u.ID, u.Email),
		obfuscatePhone(u.ID, u.Phone),
		obfuscateEmail(u.ID, u.EmailChange),
		obfuscatePhone(u.ID, u.PhoneChange),
		now)
	return err
}

// softDeleteUserIdentities blanks identity_data and obfuscates provider_id so the
// (provider, provider_id) unique constraint is released too.
func softDeleteUserIdentities(ctx context.Context, q querier, userID string, now time.Time) error {
	ids, err := findIdentitiesByUserID(ctx, q, userID)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := q.Exec(ctx, `
			update auth.identities
			set identity_data = '{}'::jsonb, provider_id = $2, updated_at = $3
			where id = $1::uuid`,
			id.ID, obfuscateIdentityProviderID(userID, id.Provider, id.ProviderID), now,
		); err != nil {
			return err
		}
	}
	return nil
}

func hardDeleteUser(ctx context.Context, q querier, id string) error {
	// auth.identities / auth.sessions cascade; refresh_tokens cascade off sessions.
	_, err := q.Exec(ctx, `delete from auth.users where id = $1::uuid`, id)
	return err
}

// ---- identities -----------------------------------------------------------

const identityColumns = `id::text, provider_id, user_id::text, identity_data, provider,
	last_sign_in_at, created_at, updated_at, coalesce(email, '')`

func scanIdentity(row pgx.Row) (Identity, error) {
	var (
		i                    Identity
		createdAt, updatedAt *time.Time
	)
	err := row.Scan(&i.ID, &i.ProviderID, &i.UserID, &i.IdentityData, &i.Provider,
		&i.LastSignInAt, &createdAt, &updatedAt, &i.Email)
	if err != nil {
		return Identity{}, err
	}
	if createdAt != nil {
		i.CreatedAt = createdAt.UTC()
	}
	if updatedAt != nil {
		i.UpdatedAt = updatedAt.UTC()
	}
	i.LastSignInAt = utc(i.LastSignInAt)
	return i, nil
}

func findIdentitiesByUserID(ctx context.Context, q querier, userID string) ([]Identity, error) {
	rows, err := q.Query(ctx,
		`select `+identityColumns+` from auth.identities where user_id = $1::uuid order by created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Identity{}
	for rows.Next() {
		i, err := scanIdentity(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func insertIdentity(ctx context.Context, q querier, userID, provider, providerID string, data JSONMap, now time.Time) error {
	_, err := q.Exec(ctx, `
		insert into auth.identities (provider_id, user_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
		values ($1, $2::uuid, $3, $4, $5, $5, $5)`,
		providerID, userID, data, provider, now)
	return err
}

func updateIdentityData(ctx context.Context, q querier, userID, provider string, data JSONMap, now time.Time) error {
	_, err := q.Exec(ctx,
		`update auth.identities set identity_data = $3, updated_at = $4 where user_id = $1::uuid and provider = $2`,
		userID, provider, data, now)
	return err
}

// ---- sessions -------------------------------------------------------------

func insertSession(ctx context.Context, q querier, id, userID, userAgent string, ip *string, now time.Time) error {
	_, err := q.Exec(ctx, `
		insert into auth.sessions (id, user_id, created_at, updated_at, refreshed_at, aal, user_agent, ip)
		values ($1::uuid, $2::uuid, $3, $3, $4, 'aal1', nullif($5, ''), $6::inet)`,
		id, userID, now, now.UTC(), userAgent, ip)
	return err
}

func findSessionByID(ctx context.Context, q querier, id string) (*session, error) {
	var s session
	var createdAt *time.Time
	err := q.QueryRow(ctx,
		`select id::text, user_id::text, not_after, created_at, refreshed_at
		 from auth.sessions where id = $1::uuid`, id).
		Scan(&s.ID, &s.UserID, &s.NotAfter, &createdAt, &s.RefreshedAt)
	if err != nil {
		return nil, err
	}
	if createdAt != nil {
		s.CreatedAt = createdAt.UTC()
	}
	s.NotAfter = utc(s.NotAfter)
	s.RefreshedAt = utc(s.RefreshedAt)
	return &s, nil
}

func touchSession(ctx context.Context, q querier, id string, now time.Time) error {
	_, err := q.Exec(ctx,
		`update auth.sessions set updated_at = $2, refreshed_at = $3 where id = $1::uuid`,
		id, now, now.UTC())
	return err
}

// deleteSession removes one session; its refresh tokens cascade.
func deleteSession(ctx context.Context, q querier, id string) error {
	_, err := q.Exec(ctx, `delete from auth.sessions where id = $1::uuid`, id)
	return err
}

// deleteUserSessions is gotrue's models.Logout (global scope).
func deleteUserSessions(ctx context.Context, q querier, userID string) error {
	if _, err := q.Exec(ctx, `delete from auth.sessions where user_id = $1::uuid`, userID); err != nil {
		return err
	}
	// Defensive: refresh tokens without a session_id do not cascade.
	_, err := q.Exec(ctx,
		`update auth.refresh_tokens set revoked = true, updated_at = now()
		 where user_id = $1 and revoked is distinct from true`, userID)
	return err
}

// deleteOtherUserSessions is gotrue's models.LogoutAllExceptMe.
func deleteOtherUserSessions(ctx context.Context, q querier, userID, keepSessionID string) error {
	_, err := q.Exec(ctx,
		`delete from auth.sessions where user_id = $1::uuid and id <> $2::uuid`, userID, keepSessionID)
	return err
}

// ---- refresh tokens -------------------------------------------------------

const refreshTokenColumns = `id, token, user_id, coalesce(parent, ''), session_id::text,
	coalesce(revoked, false), created_at, updated_at`

func scanRefreshToken(row pgx.Row) (*refreshToken, error) {
	var (
		rt                   refreshToken
		createdAt, updatedAt *time.Time
	)
	err := row.Scan(&rt.ID, &rt.Token, &rt.UserID, &rt.Parent, &rt.SessionID,
		&rt.Revoked, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	if createdAt != nil {
		rt.CreatedAt = *createdAt
	}
	if updatedAt != nil {
		rt.UpdatedAt = *updatedAt
	}
	return &rt, nil
}

// findRefreshTokenForUpdate locks the row so concurrent refreshes of the same
// token serialize; reuse detection depends on that.
func findRefreshTokenForUpdate(ctx context.Context, q querier, token string) (*refreshToken, error) {
	return scanRefreshToken(q.QueryRow(ctx,
		`select `+refreshTokenColumns+` from auth.refresh_tokens where token = $1 for update`, token))
}

func insertRefreshToken(ctx context.Context, q querier, token, userID, parent, sessionID string, now time.Time) error {
	_, err := q.Exec(ctx, `
		insert into auth.refresh_tokens (instance_id, token, user_id, parent, session_id, revoked, created_at, updated_at)
		values ($1::uuid, $2, $3, $4, $5::uuid, false, $6, $6)`,
		nilUUID, token, userID, parent, sessionID, now)
	return err
}

// findActiveRefreshTokenForSession returns the session's currently usable
// refresh token — the newest row that has not been revoked. It is upstream's
// models.Session.FindCurrentlyActiveRefreshToken and answers a reuse that falls
// inside Security.RefreshTokenReuseInterval.
func findActiveRefreshTokenForSession(ctx context.Context, q querier, sessionID string) (*refreshToken, error) {
	return scanRefreshToken(q.QueryRow(ctx,
		`select `+refreshTokenColumns+` from auth.refresh_tokens
		 where session_id = $1::uuid and revoked is distinct from true
		 order by created_at desc, id desc
		 limit 1`, sessionID))
}

func revokeRefreshToken(ctx context.Context, q querier, id int64, now time.Time) error {
	_, err := q.Exec(ctx,
		`update auth.refresh_tokens set revoked = true, updated_at = $2 where id = $1`, id, now)
	return err
}

// revokeTokenFamily is gotrue's models.RevokeTokenFamily: on reuse detection the
// whole session's token chain dies, not just the presented token.
func revokeTokenFamily(ctx context.Context, q querier, rt *refreshToken, now time.Time) error {
	if rt.SessionID != nil {
		_, err := q.Exec(ctx,
			`update auth.refresh_tokens set revoked = true, updated_at = $2
			 where session_id = $1::uuid and revoked is distinct from true`, *rt.SessionID, now)
		return err
	}
	// No session: walk the parent chain from this token downwards.
	_, err := q.Exec(ctx, `
		with recursive family as (
			select id, token from auth.refresh_tokens where id = $1
			union
			select rt.id, rt.token from auth.refresh_tokens rt join family f on rt.parent = f.token
		)
		update auth.refresh_tokens set revoked = true, updated_at = $2
		where id in (select id from family)`, rt.ID, now)
	return err
}

func revokeUserRefreshTokens(ctx context.Context, q querier, userID string, now time.Time) error {
	_, err := q.Exec(ctx,
		`update auth.refresh_tokens set revoked = true, updated_at = $2
		 where user_id = $1 and revoked is distinct from true`, userID, now)
	return err
}

// ---- outbox (project.md §2.5 / PLAN.md §3.2) -------------------------------

// insertUserDeletedOutbox writes the transactional-outbox row consumed by the
// privacy engine (agent C, migration 02xx). It MUST run in the same transaction
// as the account deletion.
func insertUserDeletedOutbox(ctx context.Context, q querier, userID, requestedBy string) error {
	_, err := q.Exec(ctx, `
		insert into dilion_privacy.outbox (event_type, aggregate_id, payload)
		values ('user.deleted', $1, jsonb_build_object(
			'user_id', $1::text,
			'requested_by', $2::text
		))`, userID, requestedBy)
	return err
}

// ---- helpers --------------------------------------------------------------

func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

// isUniqueViolation reports a Postgres 23505, optionally narrowed to one
// constraint/index name.
func isUniqueViolation(err error, constraints ...string) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		return false
	}
	if len(constraints) == 0 {
		return true
	}
	for _, c := range constraints {
		if pgErr.ConstraintName == c {
			return true
		}
	}
	return false
}

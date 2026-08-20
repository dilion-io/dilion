package auth

// One-time tokens: the storage layer behind every email flow (signup
// confirmation, magic link, recovery, invite, email change, reauthentication).
//
// # Upstream parity
//
// This file reproduces github.com/supabase/auth/internal/models/one_time_token.go
// and the token primitives of internal/crypto:
//
//   - the token a user sees is an OTP: `Mailer.OTPLength` decimal digits,
//     zero-padded, drawn from crypto/rand (crypto.GenerateOtp);
//   - what is STORED is never the OTP but the hash
//     `sha224_hex(emailOrPhone + otp)` (crypto.GenerateTokenHash). The hash is
//     also what the emailed link carries as its `token` / `token_hash`
//     parameter, so a link click and a typed OTP converge on the same value;
//   - a PKCE flow prefixes the stored hash with "pkce_" (api/pkce.go
//     addFlowPrefixToToken) so /verify can tell the two flows apart from the
//     token alone.
//
// # Dual write
//
// Upstream master still dual-writes: the hash goes BOTH into the legacy
// auth.users column (confirmation_token, recovery_token,
// email_change_token_current/new, reauthentication_token) AND into
// auth.one_time_tokens. Dilion does the same, deliberately:
//
//   - POST /verify with {email, token} resolves the user by email and compares
//     against the legacy column (upstream verifyUserAndToken), so the columns
//     are not vestigial;
//   - POST/GET /verify with a token_hash resolves through one_time_tokens,
//     whose hash index makes the lookup a single equality probe.
//
// # Schema notes (migrations/0110_auth_one_time_tokens.sql)
//
//   - UNIQUE (user_id, token_type): at most ONE live token per type per user.
//     Issuing is therefore an UPSERT on that key, which is also how upstream
//     behaves (CreateOneTimeToken deletes then inserts).
//   - created_at / updated_at are `timestamp WITHOUT time zone` — the only
//     auth.* table where that is true. Every value written here is a UTC
//     instant and every value read back is re-stamped as UTC (see utcNaive),
//     so a server running in a non-UTC zone cannot skew OTP expiry.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
)

// One-time token types. The strings are the labels of the
// auth.one_time_token_type enum and of upstream's OneTimeTokenType.String().
const (
	tokenTypeConfirmation       = "confirmation_token"
	tokenTypeReauthentication   = "reauthentication_token"
	tokenTypeRecovery           = "recovery_token"
	tokenTypeEmailChangeNew     = "email_change_token_new"
	tokenTypeEmailChangeCurrent = "email_change_token_current"
	tokenTypePhoneChange        = "phone_change_token"
)

// pkcePrefix marks a stored token hash as belonging to a PKCE flow
// (upstream api.PKCEPrefix).
const pkcePrefix = "pkce_"

// oneTimeToken is one auth.one_time_tokens row.
type oneTimeToken struct {
	ID        string
	UserID    string
	TokenType string
	TokenHash string
	RelatesTo string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ---- token primitives ------------------------------------------------------

// generateOTP returns a uniformly random decimal string of exactly `digits`
// characters, zero padded on the left. It is upstream's crypto.GenerateOtp.
func generateOTP(digits int) (string, error) {
	if digits < 6 || digits > 10 {
		digits = DefaultOTPLength
	}
	upper := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	n, err := rand.Int(rand.Reader, upper)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*s", digits, n.String()), nil
}

// generateTokenHash is upstream's crypto.GenerateTokenHash: the lowercase hex
// SHA-224 of the recipient (email or phone) concatenated with the OTP.
//
// The recipient is part of the pre-image on purpose: it binds a token to the
// address it was mailed to, so a token harvested for one address cannot be
// replayed against another.
func generateTokenHash(emailOrPhone, otp string) string {
	return fmt.Sprintf("%x", sha256.Sum224([]byte(emailOrPhone+otp)))
}

// addFlowPrefix stamps a token hash with the flow it belongs to. Only the PKCE
// flow carries a prefix; the implicit flow stores the bare hash.
func addFlowPrefix(hash string, pkce bool) string {
	if pkce {
		return pkcePrefix + hash
	}
	return hash
}

// isPKCEToken reports whether a token value came out of a PKCE flow.
func isPKCEToken(token string) bool { return strings.HasPrefix(token, pkcePrefix) }

// utcNaive normalizes a `timestamp without time zone` value read from Postgres:
// pgx hands it back with a zero offset but no location, and every writer in this
// package stores UTC, so re-stamping it as UTC is lossless and makes arithmetic
// against a.now() correct.
func utcNaive(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
}

// ---- storage ---------------------------------------------------------------

// issueOneTimeToken writes (or replaces) the user's live token of this type.
//
// It is an UPSERT on the UNIQUE (user_id, token_type) index, which is exactly
// upstream's "clear then create" with one statement instead of two: requesting a
// second magic link invalidates the first, and there is never more than one live
// token of a kind per user.
func issueOneTimeToken(ctx context.Context, q querier, userID, relatesTo, tokenHash, tokenType string, now time.Time) error {
	_, err := q.Exec(ctx, `
		insert into auth.one_time_tokens (id, user_id, token_type, token_hash, relates_to, created_at, updated_at)
		values ($1::uuid, $2::uuid, $3::auth.one_time_token_type, $4, lower($5), $6, $6)
		on conflict (user_id, token_type) do update set
			token_hash = excluded.token_hash,
			relates_to = excluded.relates_to,
			updated_at = excluded.updated_at`,
		uuid.NewString(), userID, tokenType, tokenHash, relatesTo, now.UTC())
	return err
}

const oneTimeTokenColumns = `id::text, user_id::text, token_type::text, token_hash, relates_to, created_at, updated_at`

// findOneTimeToken looks a token up by its hash, restricted to the given types.
//
// The lookup is a strict equality probe on token_hash, which is what the HASH
// index on that column supports (a hash index answers `=` and nothing else).
// Upstream accepts at most two types per lookup; this signature accepts any
// number because the SQL costs the same.
func findOneTimeToken(ctx context.Context, q querier, tokenHash string, tokenTypes ...string) (*oneTimeToken, error) {
	var t oneTimeToken
	err := q.QueryRow(ctx, `
		select `+oneTimeTokenColumns+`
		from auth.one_time_tokens
		where token_hash = $1 and token_type::text = any($2::text[])
		limit 1`, tokenHash, tokenTypes).
		Scan(&t.ID, &t.UserID, &t.TokenType, &t.TokenHash, &t.RelatesTo, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	t.CreatedAt = utcNaive(t.CreatedAt)
	t.UpdatedAt = utcNaive(t.UpdatedAt)
	return &t, nil
}

// findOneTimeTokenAnyFlow resolves a token hash that may or may not carry the
// PKCE prefix. GET /verify hands over the value verbatim from the email link
// (prefixed for PKCE); POST /verify with {email, token} computes the bare hash.
// Trying both keeps one code path for the two.
func findOneTimeTokenAnyFlow(ctx context.Context, q querier, tokenHash string, tokenTypes ...string) (*oneTimeToken, error) {
	t, err := findOneTimeToken(ctx, q, tokenHash, tokenTypes...)
	if err == nil || !isNoRows(err) {
		return t, err
	}
	if isPKCEToken(tokenHash) {
		return nil, err
	}
	return findOneTimeToken(ctx, q, pkcePrefix+tokenHash, tokenTypes...)
}

// clearOneTimeToken drops one live token of a user.
func clearOneTimeToken(ctx context.Context, q querier, userID, tokenType string) error {
	_, err := q.Exec(ctx,
		`delete from auth.one_time_tokens where user_id = $1::uuid and token_type::text = $2`, userID, tokenType)
	return err
}

// clearAllOneTimeTokens drops every live token of a user. Upstream calls this
// whenever a token is successfully consumed (models.User.Confirm / Recover /
// ConfirmEmailChange / ConfirmReauthentication): confirming an address retires
// every pending link on the account, not just the one that was clicked.
func clearAllOneTimeTokens(ctx context.Context, q querier, userID string) error {
	_, err := q.Exec(ctx, `delete from auth.one_time_tokens where user_id = $1::uuid`, userID)
	return err
}

// ---- legacy auth.users token columns --------------------------------------

// userTokenColumns is the projection of the legacy token columns that
// verifyUserAndToken (POST /verify with {email, token}) compares against, plus
// the email-change confirmation counter. They are NOT part of store.go's
// userColumns because they must never reach a response body.
type userTokens struct {
	ConfirmationToken        string
	RecoveryToken            string
	EmailChangeTokenCurrent  string
	EmailChangeTokenNew      string
	ReauthenticationToken    string
	EmailChangeConfirmStatus int
}

func findUserTokens(ctx context.Context, q querier, userID string) (*userTokens, error) {
	var t userTokens
	err := q.QueryRow(ctx, `
		select coalesce(confirmation_token, ''), coalesce(recovery_token, ''),
		       coalesce(email_change_token_current, ''), coalesce(email_change_token_new, ''),
		       coalesce(reauthentication_token, ''), coalesce(email_change_confirm_status, 0)
		from auth.users where id = $1::uuid`, userID).
		Scan(&t.ConfirmationToken, &t.RecoveryToken, &t.EmailChangeTokenCurrent,
			&t.EmailChangeTokenNew, &t.ReauthenticationToken, &t.EmailChangeConfirmStatus)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ---- OTP validity ----------------------------------------------------------

// isOTPExpired reports whether a token sent at sentAt has outlived Mailer.OTPExp.
func (a *api) isOTPExpired(sentAt *time.Time) bool {
	if sentAt == nil {
		return true
	}
	return a.now().After(sentAt.Add(a.cfg.Mailer.OTPExpDuration()))
}

// isOTPValid is upstream's isOtpValid: the presented hash must equal the stored
// one — tolerating the "pkce_" prefix on the stored side — and must still be
// inside the expiry window.
func (a *api) isOTPValid(actual, expected string, sentAt *time.Time) bool {
	if expected == "" || sentAt == nil {
		return false
	}
	if a.isOTPExpired(sentAt) {
		return false
	}
	return actual == expected || pkcePrefix+actual == expected
}

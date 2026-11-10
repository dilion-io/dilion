package auth

// MFA recovery codes (upstream internal/api/recovery_codes.go,
// internal/crypto/recovery_codes.go, internal/models/recovery_code.go):
//
//	GET    /factors/recovery-codes             status     -> {id, type, total, remaining}
//	POST   /factors/recovery-codes             generate   -> {id, type, friendly_name, total, codes}
//	POST   /factors/recovery-codes/verify      verify     -> a NEW aal2 session envelope
//	POST   /factors/recovery-codes/regenerate  regenerate -> {id, type, friendly_name, total, codes}
//	DELETE /factors/recovery-codes             delete     -> {id}
//
// A user's codes are one `recovery_code` factor, created verified, plus one
// auth.mfa_recovery_code_sets row holding the failure counter and lockout, and
// one auth.mfa_recovery_codes row per code (migration 0122). Only argon2id
// hashes are stored; the plaintexts are returned once, by generate and
// regenerate.
//
// Recovery codes are a fallback second factor: generating them needs another
// verified factor. This follows upstream v2.197.0, which does NOT yet guard
// the other direction — DELETE /factors/{id} may remove that other factor, or
// the recovery_code factor itself, while codes exist. Upstream added those
// guards after v2.197.0 (supabase/auth 4b5069b, 79ad7b2).
//
// Failed verifications are counted on the set, under its row lock, and lock
// verification for MFA.RecoveryCodes.LockoutDuration after MaxVerifyAttempts in
// a row. That is upstream's own mechanism, so these attempts do not also go
// through attempts.go's per-account counter.
//
// Self-service factor changes are not written to the audit store, the same as
// every other /factors route (audit.go records administrative access), so
// upstream's recovery_codes_* audit actions have no Dilion events behind them.

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/argon2"
)

// DefaultRecoveryCodeFriendlyName names the factor when generate is given no
// friendly_name (upstream models.DefaultRecoveryCodeFriendlyName).
const DefaultRecoveryCodeFriendlyName = "Recovery codes"

// ---- request / response shapes ---------------------------------------------

// RecoveryCodesGenerateParams is the optional POST /factors/recovery-codes body.
type RecoveryCodesGenerateParams struct {
	FriendlyName string `json:"friendly_name"`
}

// RecoveryCodesVerifyParams is the POST /factors/recovery-codes/verify body.
type RecoveryCodesVerifyParams struct {
	Code string `json:"code"`
}

// RecoveryCodesResponse is upstream's RecoveryCodesResponse, shared by status
// (Remaining set, Codes empty) and generate/regenerate (Codes set, Remaining
// nil). ID is the factor's id, not the set's, like every other factor route.
type RecoveryCodesResponse struct {
	ID           string   `json:"id"`
	Type         string   `json:"type"`
	FriendlyName string   `json:"friendly_name,omitempty"`
	Total        int      `json:"total"`
	Remaining    *int     `json:"remaining,omitempty"`
	Codes        []string `json:"codes,omitempty"`
}

// ---- crypto ----------------------------------------------------------------

// recoveryCodeAlphabet is RFC 4648 base32, lowercased: no 0/O or 1/I/L to
// confuse. 32 symbols, so a random byte masked to 5 bits picks one uniformly.
const recoveryCodeAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// argon2id parameters for new hashes (upstream's). Verification reads them
// from the stored PHC string, so they can change without breaking old codes.
const (
	recoveryCodeArgon2Memory      uint32 = 19456 // KiB
	recoveryCodeArgon2Iterations  uint32 = 2
	recoveryCodeArgon2Parallelism uint8  = 1
	recoveryCodeArgon2SaltLength         = 16
	recoveryCodeArgon2KeyLength   uint32 = 32
)

var errRecoveryCodeMismatch = errors.New("auth: recovery code hash and code mismatch")

// recoveryCodeHashRE is the strict PHC subset accepted for stored hashes:
// argon2id, version 19, no keyid/data, unpadded standard base64.
var recoveryCodeHashRE = regexp.MustCompile(`^\$argon2id\$v=19\$m=([0-9]+),t=([0-9]+),p=([0-9]+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$`)

// generateRecoveryCode returns a random code of length characters in
// canonical (lowercase, unseparated) form.
func generateRecoveryCode(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i, b := range buf {
		buf[i] = recoveryCodeAlphabet[b&31]
	}
	return string(buf), nil
}

// normalizeRecoveryCode is upstream's NormalizeRecoveryCode: whitespace and
// "-" separators removed, lowercased, so "K4M9-X7QP" and "k4m9x7qp" match.
func normalizeRecoveryCode(input string) string {
	return strings.ToLower(strings.Map(func(r rune) rune {
		if r == '-' || unicode.IsSpace(r) {
			return -1
		}
		return r
	}, input))
}

// hashRecoveryCode hashes a canonical code with argon2id and a random salt
// into a PHC string: $argon2id$v=19$m=19456,t=2,p=1$<salt>$<digest>.
func hashRecoveryCode(code string) (string, error) {
	salt := make([]byte, recoveryCodeArgon2SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	digest := argon2.IDKey([]byte(code), salt, recoveryCodeArgon2Iterations,
		recoveryCodeArgon2Memory, recoveryCodeArgon2Parallelism, recoveryCodeArgon2KeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, recoveryCodeArgon2Memory, recoveryCodeArgon2Iterations, recoveryCodeArgon2Parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(digest)), nil
}

// compareRecoveryCodeHash returns nil when code matches the stored hash and
// errRecoveryCodeMismatch when it does not. Any other error is a malformed
// hash; the parameter bounds are upstream's, so a stored row cannot make a
// verification allocate unbounded memory or time.
func compareRecoveryCodeHash(hash, code string) error {
	m := recoveryCodeHashRE.FindStringSubmatch(hash)
	if m == nil {
		return errors.New("auth: incorrect recovery code hash format")
	}
	memory, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil || memory > 1024*1024 {
		return fmt.Errorf("auth: recovery code hash has unusable m parameter %q", m[1])
	}
	iterations, err := strconv.ParseUint(m[2], 10, 32)
	if err != nil || iterations == 0 || iterations > 20 {
		return fmt.Errorf("auth: recovery code hash has unusable t parameter %q", m[2])
	}
	threads, err := strconv.ParseUint(m[3], 10, 8)
	if err != nil || threads == 0 || threads > 16 {
		return fmt.Errorf("auth: recovery code hash has unusable p parameter %q", m[3])
	}
	if memory < 8*threads { // RFC 9106: at least 8 KiB per lane
		return fmt.Errorf("auth: recovery code hash has m parameter %d below the minimum", memory)
	}
	salt, err := base64.RawStdEncoding.DecodeString(m[4])
	if err != nil || len(salt) < 8 {
		return errors.New("auth: recovery code hash has an unusable salt")
	}
	want, err := base64.RawStdEncoding.DecodeString(m[5])
	if err != nil || len(want) < 16 {
		return errors.New("auth: recovery code hash has an unusable digest")
	}
	got := argon2.IDKey([]byte(code), salt, uint32(iterations), uint32(memory), uint8(threads), uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return errRecoveryCodeMismatch
	}
	return nil
}

// generateRecoveryCodes returns Count distinct canonical codes and their
// hashes.
func (a *api) generateRecoveryCodes() ([]string, []string, error) {
	rc := a.cfg.MFA.RecoveryCodes
	seen := make(map[string]bool, rc.Count)
	codes := make([]string, 0, rc.Count)
	for len(codes) < rc.Count {
		code, err := generateRecoveryCode(rc.CodeLength)
		if err != nil {
			return nil, nil, internalServerError("Error generating recovery codes").withInternal(err)
		}
		if seen[code] {
			continue
		}
		seen[code] = true
		codes = append(codes, code)
	}
	hashes := make([]string, 0, len(codes))
	for _, code := range codes {
		h, err := hashRecoveryCode(code)
		if err != nil {
			return nil, nil, internalServerError("Error generating recovery codes").withInternal(err)
		}
		hashes = append(hashes, h)
	}
	return codes, hashes, nil
}

// ---- storage ---------------------------------------------------------------

// recoveryCodeSet is one auth.mfa_recovery_code_sets row.
type recoveryCodeSet struct {
	ID                      string
	UserID                  string
	FactorID                string
	FailedVerificationCount int
	VerificationLockedUntil *time.Time
}

func (s *recoveryCodeSet) isLocked(now time.Time) bool {
	return s.VerificationLockedUntil != nil && now.Before(*s.VerificationLockedUntil)
}

// recoveryCodeEntry is one unconsumed auth.mfa_recovery_codes row.
type recoveryCodeEntry struct {
	ID       string
	CodeHash string
}

const recoveryCodeSetColumns = `id::text, user_id::text, mfa_factor_id::text,
	failed_verification_count, verification_locked_until`

func scanRecoveryCodeSet(row pgx.Row) (*recoveryCodeSet, error) {
	s := &recoveryCodeSet{}
	if err := row.Scan(&s.ID, &s.UserID, &s.FactorID, &s.FailedVerificationCount, &s.VerificationLockedUntil); err != nil {
		return nil, err
	}
	return s, nil
}

// findRecoveryCodeSet returns the user's set; pgx.ErrNoRows when none.
func findRecoveryCodeSet(ctx context.Context, q querier, userID string) (*recoveryCodeSet, error) {
	return scanRecoveryCodeSet(q.QueryRow(ctx,
		`select `+recoveryCodeSetColumns+` from auth.mfa_recovery_code_sets where user_id = $1::uuid`, userID))
}

// lockRecoveryCodeSet is findRecoveryCodeSet with a blocking row lock, so
// concurrent verifications, regenerations and unenrolls serialise on the set.
func lockRecoveryCodeSet(ctx context.Context, tx pgx.Tx, userID string) (*recoveryCodeSet, error) {
	return scanRecoveryCodeSet(tx.QueryRow(ctx,
		`select `+recoveryCodeSetColumns+` from auth.mfa_recovery_code_sets where user_id = $1::uuid for update`, userID))
}

func insertRecoveryCodeSet(ctx context.Context, tx pgx.Tx, userID, factorID string, hashes []string, now time.Time) error {
	setID := uuid.NewString()
	if _, err := tx.Exec(ctx, `
		insert into auth.mfa_recovery_code_sets (id, user_id, mfa_factor_id, created_at, updated_at)
		values ($1::uuid, $2::uuid, $3::uuid, $4, $4)`, setID, userID, factorID, now); err != nil {
		return err
	}
	return insertRecoveryCodes(ctx, tx, setID, hashes, now)
}

func insertRecoveryCodes(ctx context.Context, tx pgx.Tx, setID string, hashes []string, now time.Time) error {
	ids := make([]string, len(hashes))
	for i := range hashes {
		ids[i] = uuid.NewString()
	}
	_, err := tx.Exec(ctx, `
		insert into auth.mfa_recovery_codes (id, mfa_recovery_code_set_id, code_hash, created_at)
		select id, $2::uuid, hash, $4
		from unnest($1::uuid[], $3::text[]) as c(id, hash)`, ids, setID, hashes, now)
	return err
}

// replaceRecoveryCodes swaps the set's codes for a new batch and clears its
// lockout. The caller holds the set's row lock.
func replaceRecoveryCodes(ctx context.Context, tx pgx.Tx, setID string, hashes []string, now time.Time) error {
	if _, err := tx.Exec(ctx, `delete from auth.mfa_recovery_codes where mfa_recovery_code_set_id = $1::uuid`, setID); err != nil {
		return err
	}
	if err := insertRecoveryCodes(ctx, tx, setID, hashes, now); err != nil {
		return err
	}
	return setRecoveryCodeLockout(ctx, tx, setID, 0, nil, now)
}

func setRecoveryCodeLockout(ctx context.Context, tx pgx.Tx, setID string, failures int, lockedUntil *time.Time, now time.Time) error {
	_, err := tx.Exec(ctx, `
		update auth.mfa_recovery_code_sets
		set failed_verification_count = $2, verification_locked_until = $3, updated_at = $4
		where id = $1::uuid`, setID, failures, lockedUntil, now)
	return err
}

// findUnusedRecoveryCodes returns the set's unconsumed codes in a fixed order.
func findUnusedRecoveryCodes(ctx context.Context, q querier, setID string) ([]recoveryCodeEntry, error) {
	rows, err := q.Query(ctx, `
		select id::text, code_hash from auth.mfa_recovery_codes
		where mfa_recovery_code_set_id = $1::uuid and consumed_at is null
		order by created_at asc, id asc`, setID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []recoveryCodeEntry
	for rows.Next() {
		var e recoveryCodeEntry
		if err := rows.Scan(&e.ID, &e.CodeHash); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func countRecoveryCodes(ctx context.Context, q querier, setID string) (total, remaining int, err error) {
	err = q.QueryRow(ctx, `
		select count(*), count(*) filter (where consumed_at is null)
		from auth.mfa_recovery_codes where mfa_recovery_code_set_id = $1::uuid`, setID).Scan(&total, &remaining)
	return total, remaining, err
}

// consumeRecoveryCode marks a code used. It reports false when a concurrent
// request consumed it first (or regenerate deleted it).
func consumeRecoveryCode(ctx context.Context, tx pgx.Tx, id string, now time.Time) (bool, error) {
	tag, err := tx.Exec(ctx,
		`update auth.mfa_recovery_codes set consumed_at = $2 where id = $1::uuid and consumed_at is null`, id, now)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// ---- factor rules ----------------------------------------------------------

// hasOtherVerifiedFactor is v2.197.0's check in RecoveryCodesGenerate: a
// verified factor other than recovery codes, whatever its type's enable flags.
func hasOtherVerifiedFactor(factors []*Factor) bool {
	for _, f := range factors {
		if f.IsVerified() && !f.IsRecoveryCodeFactor() {
			return true
		}
	}
	return false
}

// requireAAL2 refuses a session below aal2 with upstream's 403.
func (a *api) requireAAL2(ctx context.Context, q querier, mc *mfaContext, action string) error {
	aal, err := a.sessionAAL(ctx, q, mc.sessionID)
	if err != nil {
		return err
	}
	if aal != AAL2 {
		return forbiddenError(ErrorCodeInsufficientAAL, "AAL2 required to %s recovery codes", action)
	}
	return nil
}

func recoveryCodesNotEnrolledError() *HTTPError {
	return notFoundError(ErrorCodeMFAFactorNotFound, "The user has not enrolled recovery codes")
}

func recoveryCodeVerificationFailedError() *HTTPError {
	return unprocessableEntityError(ErrorCodeMFAVerificationFailed, "Invalid recovery code entered")
}

func recoveryCodeLockedError() *HTTPError {
	return httpError(http.StatusTooManyRequests, ErrorCodeMFARecoveryCodesLocked,
		"Too many failed verification attempts, try again later")
}

// ---- handlers --------------------------------------------------------------

// recoveryCodesStatus is upstream's RecoveryCodesStatus: counts only, never
// code values or lockout state. It works whatever the enable flags say.
func (a *api) recoveryCodesStatus(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	mc, err := a.mfaContextOf(r)
	if err != nil {
		return err
	}
	pool, err := a.db(ctx)
	if err != nil {
		return err
	}
	set, err := findRecoveryCodeSet(ctx, pool, mc.user.ID)
	if err != nil {
		if isNoRows(err) {
			return recoveryCodesNotEnrolledError()
		}
		return internalServerError("Database error finding recovery code set").withInternal(err)
	}
	total, remaining, err := countRecoveryCodes(ctx, pool, set.ID)
	if err != nil {
		return internalServerError("Database error counting recovery codes").withInternal(err)
	}
	return sendJSON(w, http.StatusOK, &RecoveryCodesResponse{
		ID:        set.FactorID,
		Type:      FactorTypeRecoveryCode,
		Total:     total,
		Remaining: &remaining,
	})
}

// recoveryCodesGenerate is upstream's RecoveryCodesGenerate: creates the
// verified recovery_code factor and its set, and returns the codes once.
func (a *api) recoveryCodesGenerate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	mc, err := a.mfaContextOf(r)
	if err != nil {
		return err
	}
	if !a.cfg.MFA.RecoveryCodes.EnrollEnabled {
		return unprocessableEntityError(ErrorCodeMFARecoveryCodesEnrollDisabled, "MFA enroll is disabled for recovery codes")
	}
	params := &RecoveryCodesGenerateParams{}
	if err := decodeBody(r, params); err != nil { // the body is optional
		return err
	}
	pool, err := a.db(ctx)
	if err != nil {
		return err
	}
	if err := a.requireAAL2(ctx, pool, mc, "generate"); err != nil {
		return err
	}
	if _, err := findRecoveryCodeSet(ctx, pool, mc.user.ID); err == nil {
		return unprocessableEntityError(ErrorCodeMFAVerifiedFactorExists,
			"Recovery codes are already enrolled for this user, use regenerate to rotate them")
	} else if !isNoRows(err) {
		return internalServerError("Database error finding recovery code set").withInternal(err)
	}

	name := trimName(params.FriendlyName)
	if name == "" {
		name = DefaultRecoveryCodeFriendlyName
	}
	if err := a.validateFactors(ctx, pool, mc, name); err != nil {
		return err
	}
	factors, err := findFactorsByUserID(ctx, pool, mc.user.ID)
	if err != nil {
		return internalServerError("Database error loading factors").withInternal(err)
	}
	if !hasOtherVerifiedFactor(factors) {
		return unprocessableEntityError(ErrorCodeMFARecoveryCodesSoleFactor,
			"At least one other verified factor is required to generate recovery codes")
	}

	// Hashing (argon2id, ~20 MiB each) happens before the transaction opens.
	codes, hashes, err := a.generateRecoveryCodes()
	if err != nil {
		return err
	}
	factor := &Factor{
		ID:           uuid.NewString(),
		UserID:       mc.user.ID,
		FriendlyName: name,
		FactorType:   FactorTypeRecoveryCode,
		Status:       FactorStateVerified,
	}
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		now := a.now()
		if err := insertFactor(ctx, tx, factor, now); err != nil {
			if isUniqueViolation(err, "mfa_factors_user_friendly_name_unique") {
				return unprocessableEntityError(ErrorCodeMFAFactorNameConflict,
					"A factor with the friendly name %q for this user already exists", name)
			}
			return internalServerError("Database error creating factor").withInternal(err)
		}
		// user_id is unique on the set table: a concurrent generate loses here.
		if err := insertRecoveryCodeSet(ctx, tx, mc.user.ID, factor.ID, hashes, now); err != nil {
			if isUniqueViolation(err, "mfa_recovery_code_sets_user_id_key") {
				return unprocessableEntityError(ErrorCodeMFAVerifiedFactorExists,
					"Recovery codes are already enrolled for this user, use regenerate to rotate them")
			}
			return internalServerError("Database error creating recovery codes").withInternal(err)
		}
		return nil
	}); err != nil {
		return err
	}

	a.notify(ctx, mc.user.Email, "A new MFA factor was added to your account",
		fmt.Sprintf("A %s factor was enrolled on your account.", FactorTypeRecoveryCode))

	return sendJSON(w, http.StatusOK, &RecoveryCodesResponse{
		ID:           factor.ID,
		Type:         FactorTypeRecoveryCode,
		FriendlyName: factor.FriendlyName,
		Total:        len(codes),
		Codes:        codes,
	})
}

// recoveryCodesRegenerate is upstream's RecoveryCodesRegenerate: replaces the
// codes and clears any lockout, atomically.
func (a *api) recoveryCodesRegenerate(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	mc, err := a.mfaContextOf(r)
	if err != nil {
		return err
	}
	if !a.cfg.MFA.RecoveryCodes.EnrollEnabled {
		return unprocessableEntityError(ErrorCodeMFARecoveryCodesEnrollDisabled, "MFA enroll is disabled for recovery codes")
	}
	pool, err := a.db(ctx)
	if err != nil {
		return err
	}
	if err := a.requireAAL2(ctx, pool, mc, "regenerate"); err != nil {
		return err
	}
	set, err := findRecoveryCodeSet(ctx, pool, mc.user.ID)
	if err != nil {
		if isNoRows(err) {
			return recoveryCodesNotEnrolledError()
		}
		return internalServerError("Database error finding recovery code set").withInternal(err)
	}
	factor, err := findFactorByID(ctx, pool, set.FactorID)
	if err != nil {
		if isNoRows(err) {
			return recoveryCodesNotEnrolledError()
		}
		return internalServerError("Database error finding recovery code factor").withInternal(err)
	}

	codes, hashes, err := a.generateRecoveryCodes()
	if err != nil {
		return err
	}
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		locked, err := lockRecoveryCodeSet(ctx, tx, mc.user.ID)
		if err != nil {
			if isNoRows(err) {
				return recoveryCodesNotEnrolledError()
			}
			return internalServerError("Database error locking recovery code set").withInternal(err)
		}
		if locked.ID != set.ID {
			// Deleted and generated again in between: not the set we read.
			return recoveryCodesNotEnrolledError()
		}
		if err := replaceRecoveryCodes(ctx, tx, set.ID, hashes, a.now()); err != nil {
			return internalServerError("Database error replacing recovery codes").withInternal(err)
		}
		return nil
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, &RecoveryCodesResponse{
		ID:           factor.ID,
		Type:         FactorTypeRecoveryCode,
		FriendlyName: factor.FriendlyName,
		Total:        len(codes),
		Codes:        codes,
	})
}

// recoveryCodesVerify is upstream's RecoveryCodesVerify: redeems one code and
// upgrades the session to aal2. A wrong code, a used code and "no codes
// enrolled" all answer the same 422, so the endpoint does not reveal which.
func (a *api) recoveryCodesVerify(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	mc, err := a.mfaContextOf(r)
	if err != nil {
		return err
	}
	if !a.cfg.MFA.RecoveryCodes.VerifyEnabled {
		return unprocessableEntityError(ErrorCodeMFARecoveryCodesVerifyDisabled, "MFA verification is disabled for recovery codes")
	}
	params := &RecoveryCodesVerifyParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	code := normalizeRecoveryCode(params.Code)
	if code == "" {
		return badRequestError(ErrorCodeValidationFailed, "Code needs to be non-empty")
	}
	pool, err := a.db(ctx)
	if err != nil {
		return err
	}
	set, err := findRecoveryCodeSet(ctx, pool, mc.user.ID)
	if err != nil {
		if isNoRows(err) {
			return recoveryCodeVerificationFailedError()
		}
		return internalServerError("Database error finding recovery code set").withInternal(err)
	}
	if set.isLocked(a.now()) {
		return recoveryCodeLockedError()
	}
	factor, err := findFactorByID(ctx, pool, set.FactorID)
	if err != nil {
		if isNoRows(err) {
			return recoveryCodeVerificationFailedError()
		}
		return internalServerError("Database error finding recovery code factor").withInternal(err)
	}
	entries, err := findUnusedRecoveryCodes(ctx, pool, set.ID)
	if err != nil {
		return internalServerError("Database error finding recovery codes").withInternal(err)
	}

	// Compare against every unused code, without stopping at the first match,
	// so the time taken does not say how far down the list the code was.
	var matched *recoveryCodeEntry
	for i := range entries {
		switch cerr := compareRecoveryCodeHash(entries[i].CodeHash, code); {
		case cerr == nil:
			if matched == nil {
				matched = &entries[i]
			}
		case !errors.Is(cerr, errRecoveryCodeMismatch):
			// A malformed stored hash is a non-match.
			a.log.WarnContext(ctx, "auth: invalid recovery code hash in database",
				slog.String("recovery_code_id", entries[i].ID), slog.String("error", cerr.Error()))
		}
	}

	// Upstream runs the hook with the local outcome, valid or not, and signs
	// the user out everywhere when it rejects. A hook that fails to run is an
	// error, not a rejection.
	if _, herr := a.runMFAVerificationHook(ctx, mc.user.ID, factor.ID, factor.FactorType, matched != nil); herr != nil {
		var he *HTTPError
		if errors.As(herr, &he) && he.ErrorCode == ErrorCodeMFAVerificationRejected {
			if lerr := a.inTx(ctx, func(tx pgx.Tx) error { return deleteUserSessions(ctx, tx, mc.user.ID) }); lerr != nil {
				return lerr
			}
		}
		return herr
	}

	var resp *AccessTokenResponse
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		now := a.now()
		locked, err := lockRecoveryCodeSet(ctx, tx, mc.user.ID)
		if err != nil {
			if isNoRows(err) {
				return recoveryCodeVerificationFailedError()
			}
			return internalServerError("Database error locking recovery code set").withInternal(err)
		}
		if locked.isLocked(now) {
			return recoveryCodeLockedError()
		}
		failures := locked.FailedVerificationCount
		if locked.VerificationLockedUntil != nil {
			failures = 0 // the lock has expired: start counting afresh
		}

		consumed := false
		if matched != nil && locked.ID == set.ID {
			if consumed, err = consumeRecoveryCode(ctx, tx, matched.ID, now); err != nil {
				return internalServerError("Database error consuming recovery code").withInternal(err)
			}
		}
		if !consumed {
			// A code a concurrent request consumed first counts as a failure,
			// exactly like a wrong one. The count must commit although the
			// request fails.
			failures++
			var lockedUntil *time.Time
			if failures >= a.cfg.MFA.RecoveryCodes.MaxVerifyAttempts {
				until := now.Add(a.cfg.MFA.RecoveryCodes.LockoutDuration)
				lockedUntil = &until
			}
			if err := setRecoveryCodeLockout(ctx, tx, locked.ID, failures, lockedUntil, now); err != nil {
				return internalServerError("Database error recording failed verification").withInternal(err)
			}
			return commitAndFail(recoveryCodeVerificationFailedError())
		}
		if err := setRecoveryCodeLockout(ctx, tx, locked.ID, 0, nil, now); err != nil {
			return internalServerError("Database error resetting recovery code lockout").withInternal(err)
		}

		resp, err = a.upgradeSessionToAAL2(ctx, tx, mc, factor, now)
		return err
	}); err != nil {
		return err
	}
	return sendJSON(w, http.StatusOK, resp)
}

// recoveryCodesDelete is upstream's RecoveryCodesDelete: removes the factor
// (the set and codes cascade) and downgrades the sessions it raised to aal2.
// It works whatever the enable flags say.
func (a *api) recoveryCodesDelete(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	mc, err := a.mfaContextOf(r)
	if err != nil {
		return err
	}
	pool, err := a.db(ctx)
	if err != nil {
		return err
	}
	if err := a.requireAAL2(ctx, pool, mc, "delete"); err != nil {
		return err
	}
	set, err := findRecoveryCodeSet(ctx, pool, mc.user.ID)
	if err != nil {
		if isNoRows(err) {
			return recoveryCodesNotEnrolledError()
		}
		return internalServerError("Database error finding recovery code set").withInternal(err)
	}
	factor, err := findFactorByID(ctx, pool, set.FactorID)
	if err != nil {
		if isNoRows(err) {
			return recoveryCodesNotEnrolledError()
		}
		return internalServerError("Database error finding recovery code factor").withInternal(err)
	}
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		return a.downgradeAndDeleteFactor(ctx, tx, factor)
	}); err != nil {
		return err
	}

	a.notify(ctx, mc.user.Email, "An MFA factor was removed from your account",
		fmt.Sprintf("The %s factor %q was removed from your account.", factor.FactorType, factor.FriendlyName))

	return sendJSON(w, http.StatusOK, &UnenrollFactorResponse{ID: factor.ID})
}

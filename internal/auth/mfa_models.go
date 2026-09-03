package auth

// MFA (multi-factor authentication) model, storage and AAL/AMR computation.
//
// Reproduces github.com/supabase/auth/internal/models/{factor.go,challenge.go,
// amr.go} and the AAL/AMR half of internal/models/sessions.go, on top of
// migration 0112_auth_mfa.sql.
//
// # AAL / AMR in one paragraph
//
// Every session-creating flow writes ONE row into auth.mfa_amr_claims naming
// the authentication method it used ("password", "otp", "oauth", ...). A
// successful MFA verification adds a SECOND row for the factor's method
// ("totp", "mfa/phone", "mfa/webauthn"). The JWT's `aal` claim is aal2 exactly
// when the session carries at least one of those factor methods, and the `amr`
// claim is the whole list, most recently updated first. Nothing else feeds the
// claims — auth.sessions.aal is maintained for parity with upstream (and for
// SQL-side policies) but is never the source of truth for a token.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---- constants -------------------------------------------------------------

// Factor types, matching the auth.factor_type enum (upstream models.TOTP etc.).
const (
	FactorTypeTOTP     = "totp"
	FactorTypePhone    = "phone"
	FactorTypeWebAuthn = "webauthn"
)

// Factor states, matching the auth.factor_status enum
// (upstream models.FactorState.String()).
const (
	FactorStateUnverified = "unverified"
	FactorStateVerified   = "verified"
)

// Authenticator assurance levels (upstream models.AuthenticatorAssuranceLevel).
const (
	AAL1 = "aal1"
	AAL2 = "aal2"
	AAL3 = "aal3"
)

// AMR authentication methods. These strings are the wire contract: they are
// stored verbatim in auth.mfa_amr_claims.authentication_method and echoed in
// the JWT `amr` claim, and they are copied from upstream
// models.AuthenticationMethod.String().
const (
	AMRMethodOAuth        = "oauth"
	AMRMethodPassword     = "password"
	AMRMethodOTP          = "otp"
	AMRMethodTOTP         = "totp"
	AMRMethodMFAPhone     = "mfa/phone"
	AMRMethodMFAWebAuthn  = "mfa/webauthn"
	AMRMethodRecovery     = "recovery"
	AMRMethodInvite       = "invite"
	AMRMethodMagicLink    = "magiclink"
	AMRMethodEmailSignup  = "email/signup"
	AMRMethodEmailChange  = "email_change"
	AMRMethodTokenRefresh = "token_refresh"
	AMRMethodAnonymous    = "anonymous"
	AMRMethodSSOSAML      = "sso/saml"
)

// MFA error codes, copied verbatim from upstream
// internal/api/apierrors/errorcode.go. They live here (not in errors.go) so the
// MFA feature owns its own vocabulary.
const (
	ErrorCodeTooManyEnrolledMFAFactors = "too_many_enrolled_mfa_factors"
	ErrorCodeMFAFactorNameConflict     = "mfa_factor_name_conflict"
	ErrorCodeMFAFactorNotFound         = "mfa_factor_not_found"
	ErrorCodeMFAIPAddressMismatch      = "mfa_ip_address_mismatch"
	ErrorCodeMFAChallengeExpired       = "mfa_challenge_expired"
	ErrorCodeMFAVerificationFailed     = "mfa_verification_failed"
	ErrorCodeMFAVerificationRejected   = "mfa_verification_rejected"
	ErrorCodeInsufficientAAL           = "insufficient_aal"
	ErrorCodeMFAVerifiedFactorExists   = "mfa_verified_factor_exists"

	ErrorCodeMFATOTPEnrollDisabled     = "mfa_totp_enroll_not_enabled"
	ErrorCodeMFATOTPVerifyDisabled     = "mfa_totp_verify_not_enabled"
	ErrorCodeMFAPhoneEnrollDisabled    = "mfa_phone_enroll_not_enabled"
	ErrorCodeMFAPhoneVerifyDisabled    = "mfa_phone_verify_not_enabled"
	ErrorCodeMFAWebAuthnEnrollDisabled = "mfa_webauthn_enroll_not_enabled"
	ErrorCodeMFAWebAuthnVerifyDisabled = "mfa_webauthn_verify_not_enabled"
)

// Durations upstream reads from GOTRUE_MFA_*; Config.MFA carries only the TOTP
// enable flags and MaxEnrolledFactors (conf.go is owned by another feature), so
// the remaining knobs are pinned to upstream's DEFAULTS here.
const (
	// mfaChallengeExpiryDuration is GOTRUE_MFA_CHALLENGE_EXPIRY_DURATION
	// (upstream default 300 seconds).
	mfaChallengeExpiryDuration = 300 * time.Second
	// mfaFactorExpiryDuration is GOTRUE_MFA_FACTOR_EXPIRY_DURATION (upstream
	// default 300 seconds): how long an unverified, never-challenged factor
	// survives before an enroll request garbage-collects it.
	mfaFactorExpiryDuration = 300 * time.Second
	// mfaMaxVerifiedFactors is GOTRUE_MFA_MAX_VERIFIED_FACTORS (upstream
	// default 10).
	mfaMaxVerifiedFactors = 10
)

// totpPeriod / totpSkew / totpDigits are upstream's ValidateOpts for TOTP.
const (
	totpPeriod = 30
	totpSkew   = 1
)

// ---- models ----------------------------------------------------------------

// Factor is the auth.mfa_factors row as gotrue serialises it. FIELD ORDER and
// json tags follow upstream models.Factor; the columns Dilion does not
// implement (WebAuthn credential blobs) are simply absent.
type Factor struct {
	ID               string     `json:"id"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	Status           string     `json:"status"`
	FriendlyName     string     `json:"friendly_name,omitempty"`
	FactorType       string     `json:"factor_type"`
	Phone            string     `json:"phone"`
	LastChallengedAt *time.Time `json:"last_challenged_at"`

	// WebAuthnAAGUID is auth.mfa_factors.web_authn_aaguid: the model identifier
	// the authenticator reported when the webauthn factor was registered
	// (upstream models.Factor.WebAuthnAAGUID, written by SaveWebAuthnCredential
	// — see updateFactorWebAuthnCredential). Upstream types it *uuid.UUID with
	// `omitempty`, which for a pointer means "absent when nil"; a *string
	// serialises identically. Always nil on a totp/phone factor, and on a
	// webauthn factor whose authenticator declined to identify its model (the
	// all-zero AAGUID is stored as NULL — see formatUUIDBytes).
	WebAuthnAAGUID *string `json:"web_authn_aaguid,omitempty"`

	// LastWebAuthnChallengeData is auth.mfa_factors.last_webauthn_challenge_data
	// (upstream models.Factor.LastWebAuthnChallengeData, migration
	// 20250925093508_add_last_webauthn_challenge_data). Upstream writes it on
	// EVERY webauthn verify — registration and assertion alike — and, having no
	// `json:"-"`, returns it from every endpoint that serialises a factor. See
	// updateFactorLastWebAuthnChallenge.
	LastWebAuthnChallengeData *LastWebAuthnChallengeData `json:"last_webauthn_challenge_data,omitempty"`

	// DB-only. The TOTP secret NEVER leaves the server after enrolment.
	UserID string `json:"-"`
	Secret string `json:"-"`
}

// LastWebAuthnChallengeData is the jsonb document stored on
// auth.mfa_factors.last_webauthn_challenge_data, copied field-for-field from
// upstream models.LastWebAuthnChallengeData:
//
//	Challenge          Challenge       `json:"challenge"`
//	Type               string          `json:"type"`
//	CredentialResponse json.RawMessage `json:"credential_response"`
//
// It is a forensic record of the last WebAuthn ceremony the factor completed —
// upstream's column comment calls it "the latest WebAuthn challenge data
// including attestation/assertion for customer verification". Nothing in the
// request path ever reads it back; it exists to be served.
type LastWebAuthnChallengeData struct {
	// Challenge is the challenge row as it stood when the ceremony was
	// validated, BEFORE it was consumed.
	Challenge MFAChallengeRecord `json:"challenge"`
	// Type is the ceremony: "create" (registration) or "request" (assertion).
	Type string `json:"type"`
	// CredentialResponse is the PARSED authenticator response, exactly as
	// upstream stores it: go-webauthn's ParsedCredentialCreationData /
	// ParsedCredentialAssertionData marshalled to JSON — not the raw body the
	// client posted.
	CredentialResponse json.RawMessage `json:"credential_response"`
}

// MFAChallengeRecord is the JSON projection of an auth.mfa_challenges row,
// mirroring upstream models.Challenge's json tags (note `challenge_id`, not
// `id`). It exists only as the `challenge` member of LastWebAuthnChallengeData.
//
// Upstream's Challenge additionally carries `factor` and `otp_code`, both
// `omitempty`: `factor` is nil unless the row was eager-loaded (it is not on
// this path) and `otp_code` is empty on a webauthn challenge, so both are
// absent from upstream's stored document too. Omitting the fields here yields
// byte-identical JSON.
type MFAChallengeRecord struct {
	ID                  string          `json:"challenge_id"`
	FactorID            string          `json:"factor_id"`
	CreatedAt           time.Time       `json:"created_at"`
	VerifiedAt          *time.Time      `json:"verified_at,omitempty"`
	IPAddress           string          `json:"ip_address"`
	WebAuthnSessionData json.RawMessage `json:"web_authn_session_data,omitempty"`
}

// record projects an in-flight challenge into the stored shape.
func (c *mfaChallenge) record(sessionData []byte) MFAChallengeRecord {
	return MFAChallengeRecord{
		ID:                  c.ID,
		FactorID:            c.FactorID,
		CreatedAt:           c.CreatedAt,
		VerifiedAt:          c.VerifiedAt,
		IPAddress:           c.IPAddress,
		WebAuthnSessionData: json.RawMessage(sessionData),
	}
}

// IsVerified / IsUnverified mirror upstream's helpers.
func (f *Factor) IsVerified() bool   { return f.Status == FactorStateVerified }
func (f *Factor) IsUnverified() bool { return f.Status == FactorStateUnverified }

// amrMethod is upstream's amrMethodForFactorType: the authentication_method a
// successful verification of this factor writes into auth.mfa_amr_claims.
func (f *Factor) amrMethod() (string, error) {
	switch f.FactorType {
	case FactorTypeTOTP:
		return AMRMethodTOTP, nil
	case FactorTypePhone:
		return AMRMethodMFAPhone, nil
	case FactorTypeWebAuthn:
		return AMRMethodMFAWebAuthn, nil
	}
	return "", fmt.Errorf("auth: no AMR authentication method mapped for factor type %q", f.FactorType)
}

// mfaChallenge is the auth.mfa_challenges row.
type mfaChallenge struct {
	ID         string
	FactorID   string
	CreatedAt  time.Time
	VerifiedAt *time.Time
	IPAddress  string
}

// hasExpired mirrors upstream Challenge.HasExpired.
func (c *mfaChallenge) hasExpired(now time.Time, d time.Duration) bool {
	return now.After(c.expiryTime(d))
}

func (c *mfaChallenge) expiryTime(d time.Duration) time.Time { return c.CreatedAt.Add(d) }

// amrClaim is the auth.mfa_amr_claims row.
type amrClaim struct {
	SessionID string
	Method    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// isAAL2Claim is upstream AMRClaim.IsAAL2Claim: only the MFA factor methods
// raise a session to aal2 — never the sign-in method that created it.
func (c amrClaim) isAAL2Claim() bool {
	switch c.Method {
	case AMRMethodTOTP, AMRMethodMFAPhone, AMRMethodMFAWebAuthn:
		return true
	}
	return false
}

// ---- AAL / AMR computation -------------------------------------------------

// computeAAL is upstream models.Session.CalculateAALAndAMR over an already
// loaded, updated_at-descending claim list. It returns the `aal` claim and the
// `amr` claim as the []any of {method, timestamp} maps the JWT carries.
//
// Deviation: upstream additionally decorates an `sso/saml` entry with the
// provider taken from the user's single SSO identity. Dilion has no SSO
// sign-in yet, so no entry can carry that method; the hook is left out rather
// than written dead.
func computeAAL(claims []amrClaim) (string, []any) {
	aal := AAL1
	amr := make([]any, 0, len(claims))
	for _, c := range claims {
		if c.isAAL2Claim() {
			aal = AAL2
		}
		amr = append(amr, map[string]any{
			"method":    c.Method,
			"timestamp": c.UpdatedAt.Unix(),
		})
	}
	return aal, amr
}

// sessionAAL reports the authenticator assurance level of one session, derived
// from its AMR claims — the same source the JWT is built from.
func (a *api) sessionAAL(ctx context.Context, q querier, sessionID string) (string, error) {
	if sessionID == "" {
		return AAL1, nil
	}
	claims, err := findAMRClaims(ctx, q, sessionID)
	if err != nil {
		return "", internalServerError("Database error loading AMR claims").withInternal(err)
	}
	aal, _ := computeAAL(claims)
	return aal, nil
}

// ---- storage: amr claims ---------------------------------------------------

// findAMRClaims returns a session's AMR claims, most recently updated first —
// the order upstream sorts the `amr` array into.
func findAMRClaims(ctx context.Context, q querier, sessionID string) ([]amrClaim, error) {
	rows, err := q.Query(ctx, `
		select session_id::text, authentication_method, created_at, updated_at
		  from auth.mfa_amr_claims
		 where session_id = $1::uuid
		 order by updated_at desc, authentication_method asc`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []amrClaim
	for rows.Next() {
		var c amrClaim
		if err := rows.Scan(&c.SessionID, &c.Method, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		c.CreatedAt = c.CreatedAt.UTC()
		c.UpdatedAt = c.UpdatedAt.UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}

// addAMRClaimToSession is upstream models.AddClaimToSession: upsert on the
// (session_id, authentication_method) unique constraint, refreshing updated_at
// so the claim moves to the head of the `amr` array.
func addAMRClaimToSession(ctx context.Context, q querier, sessionID, method string, now time.Time) error {
	if sessionID == "" || method == "" {
		return nil
	}
	_, err := q.Exec(ctx, `
		insert into auth.mfa_amr_claims (id, session_id, created_at, updated_at, authentication_method)
		values (gen_random_uuid(), $1::uuid, $2, $2, $3)
		on conflict on constraint mfa_amr_claims_session_id_authentication_method_pkey
		do update set updated_at = $2`, sessionID, now, method)
	return err
}

// deleteAMRClaimForFactorSessions drops the factor's AMR claim from every
// session that was upgraded by it (upstream Factor.DowngradeSessionsToAAL1).
func deleteAMRClaimForFactorSessions(ctx context.Context, q querier, userID, factorID, method string) error {
	_, err := q.Exec(ctx, `
		delete from auth.mfa_amr_claims
		 where authentication_method = $3
		   and session_id in (select id from auth.sessions where user_id = $1::uuid and factor_id = $2::uuid)`,
		userID, factorID, method)
	return err
}

// ---- storage: sessions (AAL columns) ---------------------------------------

// updateSessionAALAndFactor is upstream Session.UpdateAALAndAssociatedFactor.
func updateSessionAALAndFactor(ctx context.Context, q querier, sessionID, aal string, factorID *string) error {
	_, err := q.Exec(ctx,
		`update auth.sessions set aal = $2::auth.aal_level, factor_id = $3::uuid where id = $1::uuid`,
		sessionID, aal, factorID)
	return err
}

// clearFactorAssociatedSessions is upstream updateFactorAssociatedSessions:
// every session that was tied to the factor falls back to aal1 and loses the
// association.
func clearFactorAssociatedSessions(ctx context.Context, q querier, userID, factorID string) error {
	_, err := q.Exec(ctx, `
		update auth.sessions set aal = $3::auth.aal_level, factor_id = null
		 where user_id = $1::uuid and factor_id = $2::uuid`, userID, factorID, AAL1)
	return err
}

// invalidateSessionsWithAALLessThan is upstream
// models.InvalidateSessionsWithAALLessThan: after an MFA upgrade every other
// session of the user that never reached that level is destroyed.
//
// Deviation: upstream compares the aal ENUM with `<`, which relies on the enum
// ordering; auth.aal_level is declared in the same order here, so the operator
// behaves identically.
func invalidateSessionsWithAALLessThan(ctx context.Context, q querier, userID, level string) error {
	_, err := q.Exec(ctx,
		`delete from auth.sessions where user_id = $1::uuid and aal < $2::auth.aal_level`, userID, level)
	return err
}

// ---- storage: factors ------------------------------------------------------

const factorColumns = `
	id::text, user_id::text, coalesce(friendly_name, ''), factor_type::text, status::text,
	created_at, updated_at, coalesce(secret, ''), coalesce(phone, ''), last_challenged_at,
	web_authn_aaguid::text, last_webauthn_challenge_data`

func scanFactor(row pgx.Row) (*Factor, error) {
	var f Factor
	var lastChallengeData []byte
	if err := row.Scan(&f.ID, &f.UserID, &f.FriendlyName, &f.FactorType, &f.Status,
		&f.CreatedAt, &f.UpdatedAt, &f.Secret, &f.Phone, &f.LastChallengedAt,
		&f.WebAuthnAAGUID, &lastChallengeData); err != nil {
		return nil, err
	}
	f.CreatedAt = f.CreatedAt.UTC()
	f.UpdatedAt = f.UpdatedAt.UTC()
	f.LastChallengedAt = utc(f.LastChallengedAt)
	// A malformed document is treated as absent rather than as a 500: the column
	// is a forensic record, never an input to a decision, so it must not be able
	// to break a factor read. Upstream's Scan would error; nothing upstream can
	// write a non-conforming document either.
	if len(lastChallengeData) > 0 {
		var d LastWebAuthnChallengeData
		if err := json.Unmarshal(lastChallengeData, &d); err == nil {
			f.LastWebAuthnChallengeData = &d
		}
	}
	return &f, nil
}

func findFactorByID(ctx context.Context, q querier, id string) (*Factor, error) {
	return scanFactor(q.QueryRow(ctx,
		`select `+factorColumns+` from auth.mfa_factors where id = $1::uuid`, id))
}

// findFactorsByUserID is upstream's `db.Load(user, "Factors")`, ordered the way
// the (user_id, created_at) index serves it.
func findFactorsByUserID(ctx context.Context, q querier, userID string) ([]*Factor, error) {
	rows, err := q.Query(ctx,
		`select `+factorColumns+` from auth.mfa_factors where user_id = $1::uuid order by created_at asc`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*Factor{}
	for rows.Next() {
		f, err := scanFactor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func insertFactor(ctx context.Context, q querier, f *Factor, now time.Time) error {
	_, err := q.Exec(ctx, `
		insert into auth.mfa_factors (id, user_id, friendly_name, factor_type, status, created_at, updated_at, secret, phone)
		values ($1::uuid, $2::uuid, nullif($3, ''), $4::auth.factor_type, $5::auth.factor_status, $6, $6, nullif($7, ''), nullif($8, ''))`,
		f.ID, f.UserID, f.FriendlyName, f.FactorType, f.Status, now, f.Secret, f.Phone)
	if err == nil {
		f.CreatedAt, f.UpdatedAt = now, now
	}
	return err
}

// updateFactorWebAuthnCredential persists the go-webauthn credential blob and
// its AAGUID onto a webauthn MFA factor — upstream Factor.SaveWebAuthnCredential.
// The credential lives on auth.mfa_factors.web_authn_credential (jsonb), NOT in
// auth.webauthn_credentials: the MFA webauthn FACTOR and the first-class PASSKEY
// are two separate surfaces (see the split documented in passkey_models.go).
func updateFactorWebAuthnCredential(ctx context.Context, q querier, id string, credential []byte, aaguid *string, now time.Time) error {
	_, err := q.Exec(ctx, `
		update auth.mfa_factors
		   set web_authn_credential = $2::jsonb, web_authn_aaguid = $3::uuid, updated_at = $4
		 where id = $1::uuid`, id, credential, aaguid, now)
	return err
}

// updateFactorLastWebAuthnChallenge persists the forensic record of the WebAuthn
// ceremony that just completed — upstream Factor.UpdateLastWebAuthnChallenge,
// which writes it on EVERY verify (registration and assertion alike), not only
// on the one that promotes the factor.
func updateFactorLastWebAuthnChallenge(ctx context.Context, q querier, id string, data *LastWebAuthnChallengeData, now time.Time) error {
	blob, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `
		update auth.mfa_factors
		   set last_webauthn_challenge_data = $2::jsonb, updated_at = $3
		 where id = $1::uuid`, id, blob, now)
	return err
}

// findFactorWebAuthnCredential reads back the stored credential blob (nil when
// the factor has none, e.g. an unverified webauthn factor mid-enrolment).
func findFactorWebAuthnCredential(ctx context.Context, q querier, id string) ([]byte, error) {
	var blob []byte
	err := q.QueryRow(ctx,
		`select web_authn_credential from auth.mfa_factors where id = $1::uuid`, id).Scan(&blob)
	return blob, err
}

func updateFactorStatus(ctx context.Context, q querier, id, status string, now time.Time) error {
	_, err := q.Exec(ctx,
		`update auth.mfa_factors set status = $2::auth.factor_status, updated_at = $3 where id = $1::uuid`,
		id, status, now)
	return err
}

func updateFactorFriendlyName(ctx context.Context, q querier, id, name string, now time.Time) error {
	_, err := q.Exec(ctx,
		`update auth.mfa_factors set friendly_name = nullif($2, ''), updated_at = $3 where id = $1::uuid`,
		id, name, now)
	return err
}

// updateFactorPhone re-assigns a phone factor's number (upstream
// Factor.UpdatePhone). The (user_id, phone) unique index enforces uniqueness.
func updateFactorPhone(ctx context.Context, q querier, id, phone string, now time.Time) error {
	_, err := q.Exec(ctx,
		`update auth.mfa_factors set phone = nullif($2, ''), updated_at = $3 where id = $1::uuid`,
		id, phone, now)
	return err
}

func deleteFactor(ctx context.Context, q querier, id string) error {
	_, err := q.Exec(ctx, `delete from auth.mfa_factors where id = $1::uuid`, id)
	return err
}

// deleteUnverifiedFactors is upstream models.DeleteUnverifiedFactors, run after
// a successful verification so the leftovers of abandoned enrolments go away.
func deleteUnverifiedFactors(ctx context.Context, q querier, userID, factorType string) error {
	_, err := q.Exec(ctx,
		`delete from auth.mfa_factors where user_id = $1::uuid and status = 'unverified' and factor_type = $2::auth.factor_type`,
		userID, factorType)
	return err
}

// deleteExpiredFactors is upstream models.DeleteExpiredFactors: unverified
// factors that were never challenged and are older than the factor expiry are
// garbage-collected on the next enrolment.
func deleteExpiredFactors(ctx context.Context, q querier, now time.Time, d time.Duration) error {
	_, err := q.Exec(ctx, `
		delete from auth.mfa_factors f
		 where f.status <> 'verified'
		   and not exists (select 1 from auth.mfa_challenges c where c.factor_id = f.id)
		   and f.created_at + $2::interval < $1`, now, fmt.Sprintf("%d seconds", int64(d/time.Second)))
	return err
}

// touchFactorLastChallengedAt sets mfa_factors.last_challenged_at.
//
// PITFALL: migration 0112 carries upstream's oddity
// `mfa_factors_last_challenged_at_key unique (last_challenged_at)` — a GLOBAL
// unique constraint across every factor of every user. Two challenges that land
// on the same microsecond (trivially reproducible with an injected, frozen test
// clock) collide with a 23505. Upstream survives on wall-clock jitter alone; we
// nudge the timestamp forward by a microsecond and retry instead.
func touchFactorLastChallengedAt(ctx context.Context, tx pgx.Tx, id string, now time.Time) (time.Time, error) {
	var err error
	for i := 0; i < 8; i++ {
		ts := now.Add(time.Duration(i) * time.Microsecond)

		// Each attempt runs in its own SAVEPOINT: a 23505 poisons the enclosing
		// transaction, so the retry would otherwise fail with "current
		// transaction is aborted" instead of succeeding on the next
		// microsecond. pgx.Tx.Begin on an open transaction is exactly that.
		sp, berr := tx.Begin(ctx)
		if berr != nil {
			return time.Time{}, berr
		}
		if _, err = sp.Exec(ctx,
			`update auth.mfa_factors set last_challenged_at = $2 where id = $1::uuid`, id, ts); err == nil {
			if err = sp.Commit(ctx); err == nil {
				return ts, nil
			}
		}
		_ = sp.Rollback(ctx)
		if !isUniqueViolation(err, "mfa_factors_last_challenged_at_key") {
			return time.Time{}, err
		}
	}
	return time.Time{}, err
}

// ---- storage: challenges ---------------------------------------------------

func insertChallenge(ctx context.Context, q querier, c *mfaChallenge, now time.Time) error {
	_, err := q.Exec(ctx, `
		insert into auth.mfa_challenges (id, factor_id, created_at, ip_address)
		values ($1::uuid, $2::uuid, $3, $4::inet)`, c.ID, c.FactorID, now, c.IPAddress)
	if err == nil {
		c.CreatedAt = now
	}
	return err
}

// insertPhoneChallenge is insertChallenge for a phone factor: it additionally
// stores the OTP token hash in auth.mfa_challenges.otp_code (upstream
// Factor.CreatePhoneChallenge). The stored value is generateTokenHash(phone,
// otp) — the same sha224(phone+otp) construction the email/SMS lifecycle uses —
// so the plaintext OTP never touches the database.
func insertPhoneChallenge(ctx context.Context, q querier, c *mfaChallenge, otpHash string, now time.Time) error {
	_, err := q.Exec(ctx, `
		insert into auth.mfa_challenges (id, factor_id, created_at, ip_address, otp_code)
		values ($1::uuid, $2::uuid, $3, $4::inet, $5)`, c.ID, c.FactorID, now, c.IPAddress, otpHash)
	if err == nil {
		c.CreatedAt = now
	}
	return err
}

// insertWebAuthnChallenge is insertChallenge for a webauthn factor: it stores
// the go-webauthn SessionData JSON in auth.mfa_challenges.web_authn_session_data
// (upstream WebAuthnSessionData.ToChallenge + WriteChallengeToDatabase).
func insertWebAuthnChallenge(ctx context.Context, q querier, c *mfaChallenge, sessionData []byte, now time.Time) error {
	_, err := q.Exec(ctx, `
		insert into auth.mfa_challenges (id, factor_id, created_at, ip_address, web_authn_session_data)
		values ($1::uuid, $2::uuid, $3, $4::inet, $5::jsonb)`, c.ID, c.FactorID, now, c.IPAddress, sessionData)
	if err == nil {
		c.CreatedAt = now
	}
	return err
}

// findChallengeOTP reads the otp_code hash stored on a phone challenge.
func findChallengeOTP(ctx context.Context, q querier, challengeID string) (string, error) {
	var otp string
	err := q.QueryRow(ctx,
		`select coalesce(otp_code, '') from auth.mfa_challenges where id = $1::uuid`, challengeID).Scan(&otp)
	return otp, err
}

// findChallengeWebAuthnSessionData reads the go-webauthn SessionData stored on a
// webauthn challenge.
func findChallengeWebAuthnSessionData(ctx context.Context, q querier, challengeID string) ([]byte, error) {
	var data []byte
	err := q.QueryRow(ctx,
		`select web_authn_session_data from auth.mfa_challenges where id = $1::uuid`, challengeID).Scan(&data)
	return data, err
}

// findChallengeByID is upstream Factor.FindChallengeByID: a challenge is only
// ever addressable through the factor that owns it.
func findChallengeByID(ctx context.Context, q querier, factorID, challengeID string) (*mfaChallenge, error) {
	var c mfaChallenge
	err := q.QueryRow(ctx, `
		select id::text, factor_id::text, created_at, verified_at, host(ip_address)
		  from auth.mfa_challenges where id = $1::uuid and factor_id = $2::uuid`,
		challengeID, factorID).Scan(&c.ID, &c.FactorID, &c.CreatedAt, &c.VerifiedAt, &c.IPAddress)
	if err != nil {
		return nil, err
	}
	c.CreatedAt = c.CreatedAt.UTC()
	c.VerifiedAt = utc(c.VerifiedAt)
	return &c, nil
}

func verifyChallenge(ctx context.Context, q querier, id string, now time.Time) error {
	_, err := q.Exec(ctx, `update auth.mfa_challenges set verified_at = $2 where id = $1::uuid`, id, now)
	return err
}

func deleteChallenge(ctx context.Context, q querier, id string) error {
	_, err := q.Exec(ctx, `delete from auth.mfa_challenges where id = $1::uuid`, id)
	return err
}

// ---- user object -----------------------------------------------------------

// loadFactors fills User.Factors, which is what upstream's `db.Load(user,
// "Factors")` does before a user object is serialised.
//
// INTEGRATION TODO: GET /user and PUT /user (user.go) and the /admin/users
// reads (admin.go) are owned by other features and are NOT wired to this yet,
// so their user objects still omit `factors`. One line — `_ =
// a.loadFactors(ctx, pool, u)` before the sendJSON — closes the gap in each.
func (a *api) loadFactors(ctx context.Context, q querier, u *User) error {
	if u == nil {
		return nil
	}
	factors, err := findFactorsByUserID(ctx, q, u.ID)
	if err != nil {
		return err
	}
	u.Factors = make([]any, 0, len(factors))
	for _, f := range factors {
		u.Factors = append(u.Factors, f)
	}
	if len(u.Factors) == 0 {
		// `factors` is omitempty upstream: a user with no factors has no key.
		u.Factors = nil
	}
	return nil
}

// mfaClientIP is the value stored in auth.mfa_challenges.ip_address and
// compared against on verify.
//
// Deviation: the column is `inet NOT NULL` with no default, while upstream's
// utilities.GetIPAddress may legitimately return a non-address (unix sockets,
// synthetic requests). Rather than fail the request we fall back to the
// unspecified address, and — crucially — the verify-side comparison runs
// through this same function, so the "challenge and verify IP mismatch" check
// stays self-consistent.
func mfaClientIP(r *http.Request) string {
	if ip := clientIPInet(r); ip != nil {
		return *ip
	}
	return "0.0.0.0"
}

// trimName normalises a friendly name the way the partial unique index
// `mfa_factors_user_friendly_name_unique ... where trim(friendly_name) <> ”`
// expects.
func trimName(s string) string { return strings.TrimSpace(s) }

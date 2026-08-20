package auth

// Passkey (WebAuthn) model, storage and error vocabulary.
//
// Reproduces github.com/supabase/auth/internal/models/{webauthn_credential.go,
// webauthn_challenge.go} on top of migration 0115_auth_webauthn.sql, plus the
// passkey/WebAuthn half of internal/api/apierrors/errorcode.go.
//
// # Passkeys vs. the MFA WebAuthn factor
//
// These are two different things and they live in two different tables. A
// PASSKEY is a first-class sign-in method: the credential rows are in
// auth.webauthn_credentials and a successful assertion creates a session whose
// first AMR claim is "passkey" (an aal1 method — see AMRMethodPasskey). The MFA
// WebAuthn FACTOR is a second factor on top of an existing session; its
// credential blob lives on auth.mfa_factors and its AMR method is
// "mfa/webauthn" (aal2). Upstream has the same split — the TODO(fm) in its
// passkey_webauthn.go is about consolidating them one day; until then the two
// surfaces deliberately do not see each other's credentials.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
)

// ---- error codes -----------------------------------------------------------

// Passkey and WebAuthn error codes, copied verbatim from upstream
// internal/api/apierrors/errorcode.go. They live here (not in errors.go) so the
// passkey feature owns its own vocabulary, the way mfa_models.go owns the MFA
// codes.
const (
	// ErrorCodePasskeyDisabled is every /passkeys route while
	// Config.Passkeys.Enabled is false. Upstream answers 404 (not 422) — see
	// requirePasskeyEnabled.
	ErrorCodePasskeyDisabled = "passkey_disabled"
	// ErrorCodeTooManyPasskeys is a registration that would exceed
	// maxPasskeysPerUser (422).
	ErrorCodeTooManyPasskeys = "too_many_passkeys"

	// WebAuthn protocol-level codes. Upstream shares them between passkeys and
	// the MFA WebAuthn factor.

	// ErrorCodeWebAuthnCredentialNotFound is a credential the server does not
	// know (or does not know for this user).
	ErrorCodeWebAuthnCredentialNotFound = "webauthn_credential_not_found"
	// ErrorCodeWebAuthnChallengeNotFound is a challenge_id that never existed,
	// was already consumed, or belongs to a different ceremony/user.
	ErrorCodeWebAuthnChallengeNotFound = "webauthn_challenge_not_found"
	// ErrorCodeWebAuthnChallengeExpired is a challenge past its expires_at.
	ErrorCodeWebAuthnChallengeExpired = "webauthn_challenge_expired"
	// ErrorCodeWebAuthnVerificationFailed is a malformed or cryptographically
	// invalid attestation/assertion — wrong origin, wrong RP ID, bad signature.
	ErrorCodeWebAuthnVerificationFailed = "webauthn_verification_failed"
	// ErrorCodeWebAuthnCredentialExists is a credential_id that is already
	// registered (the unique index on webauthn_credentials.credential_id).
	ErrorCodeWebAuthnCredentialExists = "webauthn_credential_exists"
)

// AMRMethodPasskey is the authentication_method a passkey sign-in writes into
// auth.mfa_amr_claims, and therefore the entry that shows up in the JWT `amr`
// array. It is upstream models.PasskeyLogin.String() == "passkey".
//
// It is deliberately NOT an aal2 method (see amrClaim.isAAL2Claim in
// mfa_models.go): a passkey is a sign-in method here, not a second factor, so a
// passkey session starts at aal1 exactly like a password session and is raised
// to aal2 only by verifying an MFA factor against it. That is upstream's
// behaviour too — PasskeyLogin is absent from AMRClaim.IsAAL2Claim.
const AMRMethodPasskey = "passkey"

// Challenge types, matching the
// webauthn_challenges_challenge_type_check constraint of migration 0115 and
// upstream models.WebAuthnChallengeType*.
const (
	// webAuthnChallengeTypeSignup is accepted by the CHECK constraint but has
	// NO handler — upstream master has no passkey-signup ceremony either (its
	// routes are registration/* and authentication/* only, and nothing outside
	// internal/models references the constant). The constant is declared so the
	// enum is complete and so a future signup flow does not have to guess the
	// spelling.
	webAuthnChallengeTypeSignup = "signup"
	// webAuthnChallengeTypeRegistration is "add a passkey to the session's
	// account": the row always carries a user_id.
	webAuthnChallengeTypeRegistration = "registration"
	// webAuthnChallengeTypeAuthentication is the discoverable ("usernameless")
	// login ceremony: the row's user_id is NULL because the user is only known
	// once the authenticator returns a user handle.
	webAuthnChallengeTypeAuthentication = "authentication"
)

var _ = webAuthnChallengeTypeSignup // declared for completeness; see above.

// Knobs upstream reads from GOTRUE_WEBAUTHN_* / GOTRUE_PASSKEY_*.
// Config.Passkeys (conf.go, owned by another feature) carries only
// {Enabled, RPID, RPOrigins}, so the remaining upstream knobs are pinned to
// upstream's DEFAULTS here. Promoting them to Config later is a pure addition.
const (
	// passkeyChallengeExpiry is GOTRUE_WEBAUTHN_CHALLENGE_EXPIRY_DURATION
	// (upstream default 5m): how long an issued options challenge stays usable.
	passkeyChallengeExpiry = 5 * time.Minute
	// maxPasskeysPerUser is GOTRUE_PASSKEY_MAX_PASSKEYS_PER_USER (upstream
	// default 10).
	maxPasskeysPerUser = 10
	// passkeyFriendlyNameMaxLength is upstream's PATCH /passkeys/{id} limit.
	passkeyFriendlyNameMaxLength = 120
	// passkeyDefaultFriendlyName is upstream utilities.PasskeyFriendlyName's
	// fallback for an authenticator whose AAGUID is unknown.
	passkeyDefaultFriendlyName = "Passkey"
)

// ---- models ----------------------------------------------------------------

// passkeyCredential is one auth.webauthn_credentials row (upstream
// models.WebAuthnCredential). It is DB-internal: the wire shape clients see is
// PasskeyListItem / PasskeyMetadataResponse, which deliberately expose neither
// the credential id nor the public key.
type passkeyCredential struct {
	ID              string
	UserID          string
	CredentialID    []byte
	PublicKey       []byte
	AttestationType string
	// AAGUID is the authenticator model identifier, or nil when the
	// authenticator reported none (the all-zero AAGUID is stored as NULL).
	AAGUID         *string
	SignCount      uint32
	Transports     []protocol.AuthenticatorTransport
	BackupEligible bool
	BackedUp       bool
	FriendlyName   string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	LastUsedAt     *time.Time
}

// toWebAuthnCredential converts the row back into the library's type, which is
// what verification needs (upstream WebAuthnCredential.ToWebAuthnCredential).
func (c *passkeyCredential) toWebAuthnCredential() webauthn.Credential {
	cred := webauthn.Credential{
		ID:              c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       c.Transports,
		Flags: webauthn.CredentialFlags{
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackedUp,
		},
		Authenticator: webauthn.Authenticator{
			SignCount: c.SignCount,
		},
	}
	if c.AAGUID != nil {
		if raw, err := uuidBytes(*c.AAGUID); err == nil {
			cred.Authenticator.AAGUID = raw
		}
	}
	return cred
}

// passkeyChallenge is one auth.webauthn_challenges row (upstream
// models.WebAuthnChallenge).
type passkeyChallenge struct {
	ID            string
	UserID        *string
	ChallengeType string
	SessionData   webauthn.SessionData
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// isExpired mirrors upstream WebAuthnChallenge.IsExpired. `now` is the API
// clock (ports.Clock), so a test can step past the expiry without sleeping.
func (c *passkeyChallenge) isExpired(now time.Time) bool { return now.After(c.ExpiresAt) }

// ---- webauthn.User adapter -------------------------------------------------

// webAuthnUser adapts a Dilion *User plus its PASSKEY credentials to the
// webauthn.User interface (upstream's webAuthnUser in passkey_webauthn.go).
//
// The adapter exists for the same reason it exists upstream: *User cannot
// implement WebAuthnCredentials() itself without picking a side in the
// passkey/MFA-factor split described at the top of this file.
type webAuthnUser struct {
	user        *User
	credentials []webauthn.Credential
}

func newWebAuthnUser(u *User, creds []*passkeyCredential) *webAuthnUser {
	out := make([]webauthn.Credential, len(creds))
	for i, c := range creds {
		out[i] = c.toWebAuthnCredential()
	}
	return &webAuthnUser{user: u, credentials: out}
}

// WebAuthnID is the user handle stored in the credential: upstream uses the
// user's UUID in its canonical STRING form (36 ASCII bytes), not its 16 raw
// bytes. Copied exactly — the handle round-trips through the authenticator and
// is what discoverable login resolves the account from.
func (u *webAuthnUser) WebAuthnID() []byte { return []byte(u.user.ID) }

func (u *webAuthnUser) WebAuthnName() string {
	if u.user.Email != "" {
		return u.user.Email
	}
	return u.user.Phone
}

func (u *webAuthnUser) WebAuthnDisplayName() string {
	if u.user.UserMetaData != nil {
		if name, ok := u.user.UserMetaData["name"].(string); ok && name != "" {
			return name
		}
	}
	return u.WebAuthnName()
}

func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// ---- friendly names --------------------------------------------------------

// wellKnownAAGUIDs maps an authenticator model id to a human-readable name.
//
// DEVIATION: upstream embeds the FULL passkeydeveloper/passkey-authenticator-aaguids
// table (~24 KB of JSON, refreshed by `go generate`). Dilion carries only the
// handful of AAGUIDs that cover the platform authenticators and password
// managers a Korean/global consumer deployment actually meets, and falls back
// to "Passkey" for everything else — exactly what upstream does for an AAGUID
// missing from its table. The name is cosmetic and user-editable through
// PATCH /passkeys/{passkey_id}, so the vendored blob is not worth its
// maintenance cost. Entries below are copied verbatim from upstream's table.
var wellKnownAAGUIDs = map[string]string{
	"fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "Apple Passwords",
	"dd4ec289-e01d-41c9-bb89-70fa845d4bf2": "iCloud Keychain (Managed)",
	"adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome on Mac",
	"771b48fd-d3d4-4f74-9232-fc157ab0507a": "Edge on Mac",
	"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
	"08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
	"9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
	"6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
	"53414d53-554e-4700-0000-000000000000": "Samsung Pass",
	"bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
	"d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",
	"531126d6-e717-415c-9320-3d9aa6981239": "Dashlane",
	"b84e4048-15dc-4dd0-8640-f4f60813c8af": "NordPass",
	"0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6": "Keeper",
	"50726f74-6f6e-5061-7373-50726f746f6e": "Proton Pass",
}

// passkeyFriendlyName is upstream utilities.PasskeyFriendlyName: a
// human-readable authenticator name derived from the raw AAGUID bytes, falling
// back to "Passkey".
func passkeyFriendlyName(aaguid []byte) string {
	if s := formatUUIDBytes(aaguid); s != "" {
		if name, ok := wellKnownAAGUIDs[s]; ok {
			return name
		}
	}
	return passkeyDefaultFriendlyName
}

// ---- uuid <-> bytes --------------------------------------------------------

// formatUUIDBytes renders 16 raw bytes as a canonical lowercase UUID. It
// returns "" for a wrong length or for the all-zero AAGUID, which the spec uses
// to mean "this authenticator declines to identify its model".
func formatUUIDBytes(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	zero := true
	for _, x := range b {
		if x != 0 {
			zero = false
			break
		}
	}
	if zero {
		return ""
	}
	const hex = "0123456789abcdef"
	out := make([]byte, 0, 36)
	for i, x := range b {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out = append(out, '-')
		}
		out = append(out, hex[x>>4], hex[x&0x0f])
	}
	return string(out)
}

// uuidBytes is formatUUIDBytes' inverse: the 16 raw bytes of a canonical UUID.
func uuidBytes(s string) ([]byte, error) {
	clean := strings.ReplaceAll(s, "-", "")
	out := make([]byte, 0, 16)
	var err error
	for i := 0; i+1 < len(clean); i += 2 {
		var hi, lo int
		if hi, err = hexDigit(clean[i]); err != nil {
			return nil, err
		}
		if lo, err = hexDigit(clean[i+1]); err != nil {
			return nil, err
		}
		out = append(out, byte(hi<<4|lo))
	}
	if len(out) != 16 {
		return nil, errNotAUUID
	}
	return out, nil
}

var errNotAUUID = errors.New("auth: not a canonical uuid")

func hexDigit(c byte) (int, error) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), nil
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, nil
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, nil
	}
	return 0, errNotAUUID
}

// ---- storage: credentials --------------------------------------------------

// passkeyColumns is the projection of every credential read. uuid columns are
// cast to text so they scan into plain strings, matching store.go's convention.
const passkeyColumns = `
	id::text, user_id::text, credential_id, public_key, attestation_type,
	aaguid::text, sign_count, transports, backup_eligible, backed_up,
	friendly_name, created_at, updated_at, last_used_at`

func scanPasskey(row pgx.Row) (*passkeyCredential, error) {
	var (
		c          passkeyCredential
		signCount  int64
		transports []byte
	)
	if err := row.Scan(&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey, &c.AttestationType,
		&c.AAGUID, &signCount, &transports, &c.BackupEligible, &c.BackedUp,
		&c.FriendlyName, &c.CreatedAt, &c.UpdatedAt, &c.LastUsedAt); err != nil {
		return nil, err
	}
	// sign_count is `bigint` (upstream's column type) but the WebAuthn counter
	// is a uint32; a value outside that range can only come from a hand-edited
	// row, and clamping is safer than wrapping.
	if signCount < 0 {
		signCount = 0
	} else if signCount > 0xFFFFFFFF {
		signCount = 0xFFFFFFFF
	}
	c.SignCount = uint32(signCount)
	if len(transports) > 0 {
		_ = json.Unmarshal(transports, &c.Transports)
	}
	c.CreatedAt = c.CreatedAt.UTC()
	c.UpdatedAt = c.UpdatedAt.UTC()
	c.LastUsedAt = utc(c.LastUsedAt)
	return &c, nil
}

// findPasskeysByUserID is upstream FindWebAuthnCredentialsByUserID.
func findPasskeysByUserID(ctx context.Context, q querier, userID string) ([]*passkeyCredential, error) {
	rows, err := q.Query(ctx,
		`select `+passkeyColumns+` from auth.webauthn_credentials
		 where user_id = $1::uuid order by created_at asc, id asc`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*passkeyCredential{}
	for rows.Next() {
		c, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// findPasskeyByIDAndUserID is upstream FindWebAuthnCredentialByIDAndUserID: a
// passkey is only ever addressable through the user that owns it.
func findPasskeyByIDAndUserID(ctx context.Context, q querier, id, userID string) (*passkeyCredential, error) {
	return scanPasskey(q.QueryRow(ctx,
		`select `+passkeyColumns+` from auth.webauthn_credentials
		 where id = $1::uuid and user_id = $2::uuid`, id, userID))
}

// findPasskeyByCredentialID is upstream FindWebAuthnCredentialByCredentialID.
func findPasskeyByCredentialID(ctx context.Context, q querier, credentialID []byte) (*passkeyCredential, error) {
	return scanPasskey(q.QueryRow(ctx,
		`select `+passkeyColumns+` from auth.webauthn_credentials where credential_id = $1`, credentialID))
}

func countPasskeys(ctx context.Context, q querier, userID string) (int, error) {
	var n int
	err := q.QueryRow(ctx,
		`select count(*) from auth.webauthn_credentials where user_id = $1::uuid`, userID).Scan(&n)
	return n, err
}

// insertPasskey stores a freshly created credential.
//
// The uniqueness of credential_id is a unique INDEX upstream, not a named table
// constraint, so `on conflict (credential_id)` (the index's inference clause) is
// the only spelling that works — `on constraint ...` has nothing to name. DO
// NOTHING plus RETURNING turns the collision into pgx.ErrNoRows, which the
// handler maps to upstream's webauthn_credential_exists; that is race-free
// where a pre-flight SELECT would not be.
func insertPasskey(ctx context.Context, q querier, c *passkeyCredential, now time.Time) error {
	transports, err := json.Marshal(c.Transports)
	if err != nil {
		return err
	}
	if c.Transports == nil {
		transports = []byte(`[]`)
	}
	row := q.QueryRow(ctx, `
		insert into auth.webauthn_credentials (
			id, user_id, credential_id, public_key, attestation_type, aaguid,
			sign_count, transports, backup_eligible, backed_up, friendly_name,
			created_at, updated_at
		) values (
			$1::uuid, $2::uuid, $3, $4, $5, $6::uuid,
			$7, $8, $9, $10, $11,
			$12, $12
		)
		on conflict (credential_id) do nothing
		returning `+passkeyColumns,
		c.ID, c.UserID, c.CredentialID, c.PublicKey, c.AttestationType, c.AAGUID,
		int64(c.SignCount), transports, c.BackupEligible, c.BackedUp, c.FriendlyName,
		now)
	stored, err := scanPasskey(row)
	if err != nil {
		return err
	}
	*c = *stored
	return nil
}

// updatePasskeyFriendlyName is upstream WebAuthnCredential.UpdateFriendlyName.
func updatePasskeyFriendlyName(ctx context.Context, q querier, id, name string, now time.Time) error {
	_, err := q.Exec(ctx,
		`update auth.webauthn_credentials set friendly_name = $2, updated_at = $3 where id = $1::uuid`,
		id, name, now)
	return err
}

// updatePasskeyLastUsed is upstream
// WebAuthnCredential.UpdateLastUsedWithSignCount: one statement bumping both the
// replay counter and the "seen at" marker after a successful assertion.
func updatePasskeyLastUsed(ctx context.Context, q querier, id string, signCount uint32, now time.Time) error {
	_, err := q.Exec(ctx, `
		update auth.webauthn_credentials
		   set sign_count = $2, last_used_at = $3, updated_at = $3
		 where id = $1::uuid`, id, int64(signCount), now)
	return err
}

func deletePasskey(ctx context.Context, q querier, id string) error {
	_, err := q.Exec(ctx, `delete from auth.webauthn_credentials where id = $1::uuid`, id)
	return err
}

// ---- storage: challenges ---------------------------------------------------

const passkeyChallengeColumns = `id::text, user_id::text, challenge_type, session_data, created_at, expires_at`

func scanPasskeyChallenge(row pgx.Row) (*passkeyChallenge, error) {
	var (
		c    passkeyChallenge
		data []byte
	)
	if err := row.Scan(&c.ID, &c.UserID, &c.ChallengeType, &data, &c.CreatedAt, &c.ExpiresAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &c.SessionData); err != nil {
		return nil, err
	}
	c.CreatedAt = c.CreatedAt.UTC()
	c.ExpiresAt = c.ExpiresAt.UTC()
	return &c, nil
}

// insertPasskeyChallenge is upstream models.NewWebAuthnChallenge + db.Create.
// userID is nil for the discoverable authentication ceremony, which is exactly
// why migration 0115 leaves webauthn_challenges.user_id nullable.
func insertPasskeyChallenge(ctx context.Context, q querier, c *passkeyChallenge, now time.Time) error {
	data, err := json.Marshal(c.SessionData)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `
		insert into auth.webauthn_challenges (id, user_id, challenge_type, session_data, created_at, expires_at)
		values ($1::uuid, $2::uuid, $3, $4, $5, $6)`,
		c.ID, c.UserID, c.ChallengeType, data, now, c.ExpiresAt)
	if err == nil {
		c.CreatedAt = now
	}
	return err
}

// consumePasskeyChallenge is upstream ConsumeWebAuthnChallengeByID: DELETE ...
// RETURNING, so a challenge is single-use by construction and two concurrent
// verifies cannot both win. The type and the owner are part of the predicate,
// so a registration challenge can never be replayed into the authentication
// ceremony (or into another user's).
//
// userID == nil selects the `user_id IS NULL` rows — the discoverable
// authentication ceremony — and NOT "any user".
func consumePasskeyChallenge(ctx context.Context, q querier, id, challengeType string, userID *string) (*passkeyChallenge, error) {
	if userID != nil {
		return scanPasskeyChallenge(q.QueryRow(ctx, `
			delete from auth.webauthn_challenges
			 where id = $1::uuid and challenge_type = $2 and user_id = $3::uuid
			 returning `+passkeyChallengeColumns, id, challengeType, *userID))
	}
	return scanPasskeyChallenge(q.QueryRow(ctx, `
		delete from auth.webauthn_challenges
		 where id = $1::uuid and challenge_type = $2 and user_id is null
		 returning `+passkeyChallengeColumns, id, challengeType))
}

// deleteExpiredPasskeyChallenges drops challenges past their expires_at.
//
// DEVIATION / GAP COVER: upstream's models.Cleanup includes
// `delete from webauthn_challenges where expires_at < now()`, but Dilion's
// cleanup worker (cleanup.go, owned by another change) does not yet list the
// table — see the note in passkeys.go. Until it does, the options endpoints
// call this best-effort so an abandoned ceremony is not kept forever
// (개인정보 보유기간 최소화, project.md §5). The batch is small and the statement
// touches only rows that are already unusable, so it is safe to run
// concurrently with anything.
func deleteExpiredPasskeyChallenges(ctx context.Context, q querier, now time.Time, limit int) error {
	_, err := q.Exec(ctx, `
		delete from auth.webauthn_challenges
		 where ctid in (select ctid from auth.webauthn_challenges where expires_at < $1 limit $2)`,
		now, limit)
	return err
}

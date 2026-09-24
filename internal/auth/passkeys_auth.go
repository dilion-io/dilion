package auth

// The passkey LOGIN ceremony — POST /passkeys/authentication/{options,verify}.
//
// Reproduces github.com/supabase/auth/internal/api/passkey_authentication.go.
//
// This is the discoverable-credential ("usernameless") flow: the client asks for
// options without naming a user, the authenticator picks a credential it holds
// for this relying party, and the assertion carries a USER HANDLE that the
// server resolves back to an account. That is why the challenge row's user_id is
// NULL (migration 0115 makes the column nullable for exactly this reason) and
// why the options carry an empty allowCredentials list.

import (
	"encoding/json"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PasskeyAuthenticationOptionsResponse is the POST
// /passkeys/authentication/options body (upstream
// api.PasskeyAuthenticationOptionsResponse). `options` is handed straight to
// navigator.credentials.get().
type PasskeyAuthenticationOptionsResponse struct {
	ChallengeID string                                      `json:"challenge_id"`
	Options     *protocol.PublicKeyCredentialRequestOptions `json:"options"`
	ExpiresAt   int64                                       `json:"expires_at"`
}

// PasskeyAuthenticationVerifyParams is the POST /passkeys/authentication/verify
// body.
type PasskeyAuthenticationVerifyParams struct {
	ChallengeID string          `json:"challenge_id"`
	Credential  json.RawMessage `json:"credential"`
}

// ---- POST /passkeys/authentication/options ---------------------------------

// passkeyAuthenticationOptions implements upstream PasskeyAuthenticationOptions.
// It is UNAUTHENTICATED by design — it is the front door of the sign-in flow —
// and therefore captcha-gated and rate limited (see the route table in
// passkeys.go).
func (a *api) passkeyAuthenticationOptions(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	if err := a.verifyCaptcha(r); err != nil {
		return err
	}

	pool, err := a.db(ctx)
	if err != nil {
		return err
	}

	rp, err := a.passkeyWebAuthn()
	if err != nil {
		return err
	}
	// BeginDiscoverableLogin: no user binding, empty allowCredentials.
	options, sessionData, berr := rp.BeginDiscoverableLogin()
	if berr != nil {
		return internalServerError("Failed to generate WebAuthn authentication options").withInternal(berr)
	}

	now := a.now()
	challenge := &passkeyChallenge{
		ID: uuid.NewString(),
		// No user_id: the account is unknown until the assertion comes back.
		UserID:        nil,
		ChallengeType: webAuthnChallengeTypeAuthentication,
		SessionData:   *sessionData,
		ExpiresAt:     now.Add(passkeyChallengeExpiry),
	}
	if err := insertPasskeyChallenge(ctx, pool, challenge, now); err != nil {
		return internalServerError("Database error storing challenge").withInternal(err)
	}
	a.purgeExpiredPasskeyChallenges(ctx, pool, now)

	return sendJSON(w, http.StatusOK, &PasskeyAuthenticationOptionsResponse{
		ChallengeID: challenge.ID,
		Options:     &options.Response,
		ExpiresAt:   challenge.ExpiresAt.Unix(),
	})
}

// ---- POST /passkeys/authentication/verify ----------------------------------

// passkeyAuthenticationVerify implements upstream PasskeyAuthenticationVerify:
// consume the challenge, validate the assertion, resolve the account from the
// user handle, and mint a session.
func (a *api) passkeyAuthenticationVerify(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	params := &PasskeyAuthenticationVerifyParams{}
	if derr := decodeBody(r, params); derr != nil {
		return derr
	}
	challengeID, verr := validatePasskeyVerifyParams(params.ChallengeID, params.Credential)
	if verr != nil {
		return verr
	}

	pool, err := a.db(ctx)
	if err != nil {
		return err
	}

	// nil userID selects the `user_id IS NULL` rows: a REGISTRATION challenge —
	// which always names a user — can never be replayed into this ceremony.
	challenge, cerr := consumePasskeyChallenge(ctx, pool, challengeID, webAuthnChallengeTypeAuthentication, nil)
	if cerr != nil {
		if isNoRows(cerr) {
			return badRequestError(ErrorCodeWebAuthnChallengeNotFound, "Challenge not found or already used")
		}
		return internalServerError("Database error consuming challenge").withInternal(cerr)
	}
	if challenge.isExpired(a.now()) {
		return badRequestError(ErrorCodeWebAuthnChallengeExpired, "Challenge has expired")
	}

	var car protocol.CredentialAssertionResponse
	if err := json.Unmarshal(params.Credential, &car); err != nil {
		return badRequestError(ErrorCodeWebAuthnVerificationFailed, "Invalid credential response").withInternal(err)
	}
	parsed, perr := car.Parse()
	if perr != nil {
		return badRequestError(ErrorCodeWebAuthnVerificationFailed, "Invalid credential response").withInternal(perr)
	}

	rp, err := a.passkeyWebAuthn()
	if err != nil {
		return err
	}

	// The handler resolves the assertion's user handle into the account and its
	// credentials. Anything it returns as an error surfaces below as a generic
	// verification failure — deliberately: this endpoint must not become an
	// oracle for which accounts or credentials exist.
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		userID := string(userHandle)
		if _, err := uuid.Parse(userID); err != nil {
			return nil, err
		}
		u, err := findUserByID(ctx, pool, userID)
		if err != nil {
			return nil, err
		}
		if u.DeletedAt != nil {
			// A soft-deleted account keeps its passkeys; it is still gone.
			return nil, pgx.ErrNoRows
		}
		creds, err := findPasskeysByUserID(ctx, pool, u.ID)
		if err != nil {
			return nil, err
		}
		if len(creds) == 0 {
			return nil, pgx.ErrNoRows
		}
		return newWebAuthnUser(u, creds), nil
	}

	// ValidatePasskeyLogin performs the whole §7.2 assertion check: the
	// challenge, the origin against RPOrigins, the RP ID hash against RPID, the
	// signature against the stored public key, the user-handle/credential
	// binding, and the backup-flag consistency rules.
	//
	// SIGN COUNT: step 17 is inside this call. A counter that did NOT advance
	// (a replayed or cloned authenticator) sets credential.Authenticator
	// .CloneWarning and leaves SignCount at the STORED value; it does not fail
	// the ceremony. Upstream then persists credential.Authenticator.SignCount
	// unconditionally, so a regression simply leaves the stored counter
	// untouched. Matched exactly — deviating would break every authenticator
	// that reports a constant 0 counter (which is most passkey providers).
	webauthnUser, credential, lerr := rp.ValidatePasskeyLogin(handler, challenge.SessionData, parsed)
	if lerr != nil {
		return badRequestError(ErrorCodeWebAuthnVerificationFailed, "Credential verification failed").withInternal(lerr)
	}

	userID := string(webauthnUser.WebAuthnID())
	if _, err := uuid.Parse(userID); err != nil {
		return badRequestError(ErrorCodeValidationFailed, "Invalid user handle in assertion")
	}
	u, uerr := a.loadUserWithIdentities(ctx, pool, userID)
	if uerr != nil {
		if isNoRows(uerr) {
			return badRequestError(ErrorCodeWebAuthnVerificationFailed, "Credential verification failed")
		}
		return internalServerError("Database error loading user").withInternal(uerr)
	}

	// Same account-state gate upstream applies after a successful assertion.
	if u.Email != "" && u.EmailConfirmedAt == nil {
		return forbiddenError(ErrorCodeEmailNotConfirmed, "Email not confirmed")
	}
	if u.Phone != "" && u.PhoneConfirmedAt == nil {
		return forbiddenError(ErrorCodePhoneNotConfirmed, "Phone not confirmed")
	}
	if u.IsBanned(a.now()) {
		return forbiddenError(ErrorCodeUserBanned, "User is banned")
	}

	stored, serr := findPasskeyByCredentialID(ctx, pool, credential.ID)
	if serr != nil {
		if isNoRows(serr) {
			// The credential validated against a public key we no longer have a
			// row for — only reachable if it was deleted mid-ceremony.
			return badRequestError(ErrorCodeWebAuthnCredentialNotFound, "Passkey not found")
		}
		return internalServerError("Database error loading passkey").withInternal(serr)
	}

	now := a.now()
	var token *AccessTokenResponse
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		if uerr := updatePasskeyLastUsed(ctx, tx, stored.ID, credential.Authenticator.SignCount, now); uerr != nil {
			return internalServerError("Database error updating passkey").withInternal(uerr)
		}
		var gerr error
		// AMRMethodPasskey ("passkey") is upstream models.PasskeyLogin: an
		// aal1 sign-in method, so the session starts at aal1 like any other.
		token, gerr = a.grantSession(ctx, tx, u, r, AMRMethodPasskey)
		return gerr
	}); err != nil {
		return err
	}

	// NOTE: no hook is fired here. ports.HookPoint has no login/sign-in point
	// (signup, delete, erasure, consent, claims only), and ports/ is owned
	// outside this package — adding one is a separate change.
	return sendJSON(w, http.StatusOK, token)
}

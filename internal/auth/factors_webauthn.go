package auth

// The WebAuthn MFA factor: WebAuthn used as a SECOND factor on top of an
// existing session, distinct from the first-class Passkey sign-in method
// (passkeys.go). Upstream internal/api/mfa.go enrollWebAuthnFactor /
// challengeWebAuthnFactor / verifyWebAuthnFactor.
//
//	POST /factors {factor_type:"webauthn", friendly_name}
//	    -> gated by Config.MFA.WebAuthn.EnrollEnabled; creates an UNVERIFIED
//	       factor with no credential yet (enrolment is finished by the first
//	       challenge+verify round).
//	POST /factors/{id}/challenge
//	    -> gated by Config.MFA.WebAuthn.VerifyEnabled; for an UNVERIFIED factor it
//	       runs BeginRegistration (webauthn.type "create"), for a VERIFIED factor
//	       BeginLogin (webauthn.type "request"). The go-webauthn SessionData is
//	       stored on auth.mfa_challenges.web_authn_session_data.
//	POST /factors/{id}/verify {challenge_id, webauthn:{credential}}
//	    -> UNVERIFIED: CreateCredential, persist the credential onto
//	       auth.mfa_factors.web_authn_credential and promote the factor; VERIFIED:
//	       ValidateLogin over the stored credential. Either way the session is
//	       raised to aal2, AMR method "mfa/webauthn".
//
// # Storage decision (matches upstream)
//
// The credential blob lives on auth.mfa_factors.web_authn_credential (jsonb) +
// web_authn_aaguid, NOT in auth.webauthn_credentials. The webauthn_credentials
// table is the PASSKEY surface; the MFA webauthn FACTOR is a different thing on
// a different table with a different AMR method ("mfa/webauthn" vs "passkey").
// The split is documented at the top of passkey_models.go and is upstream's own
// (its TODO(fm) is about someday consolidating the two).
//
// # Relying-party configuration
//
// The RP (RP ID, origins) is the SAME as the passkey surface: this reuses
// a.passkeyWebAuthn() rather than building a second webauthn.WebAuthn, so RP ID
// and origins resolve from Config.Passkeys.RP* (or are derived from SiteURL —
// see passkeyWebAuthnConfig). This does NOT require Config.Passkeys.Enabled: the
// passkey feature gate guards the /passkeys routes, not the RP config helper.

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// webauthn factor challenge ceremony types (upstream WebAuthnChallengeData.Type).
const (
	webAuthnFactorTypeCreate  = "create"  // BeginRegistration, unverified factor
	webAuthnFactorTypeRequest = "request" // BeginLogin, verified factor
)

// ---- webauthn.User adapter -------------------------------------------------

// mfaWebAuthnUser adapts a *User plus the MFA factor's OWN credential(s) to the
// webauthn.User interface. It is the MFA twin of passkey_models.go's
// webAuthnUser; the two are separate types because they draw their credentials
// from different tables (auth.mfa_factors vs auth.webauthn_credentials) and must
// not see each other's.
//
// WebAuthnID is the user's UUID string, identical to the passkey adapter, so a
// user handle minted here round-trips through the authenticator the same way.
type mfaWebAuthnUser struct {
	user  *User
	creds []webauthn.Credential
}

func (u *mfaWebAuthnUser) WebAuthnID() []byte { return []byte(u.user.ID) }

func (u *mfaWebAuthnUser) WebAuthnName() string {
	if u.user.Email != "" {
		return u.user.Email
	}
	return u.user.Phone
}

func (u *mfaWebAuthnUser) WebAuthnDisplayName() string {
	if u.user.UserMetaData != nil {
		if name, ok := u.user.UserMetaData["name"].(string); ok && name != "" {
			return name
		}
	}
	return u.WebAuthnName()
}

func (u *mfaWebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// ---- enroll ----------------------------------------------------------------

// enrollWebAuthnFactor implements POST /factors for factor_type "webauthn".
// Upstream creates the factor with no credential; the ceremony that produces the
// credential is the first challenge+verify pair.
func (a *api) enrollWebAuthnFactor(w http.ResponseWriter, r *http.Request, mc *mfaContext, params *EnrollFactorParams) error {
	ctx := r.Context()
	pool, derr := a.db(ctx)
	if derr != nil {
		return derr
	}
	name := trimName(params.FriendlyName)
	if err := a.validateFactors(ctx, pool, mc, name); err != nil {
		return err
	}

	factor := &Factor{
		ID:           uuid.NewString(),
		UserID:       mc.user.ID,
		FriendlyName: name,
		FactorType:   FactorTypeWebAuthn,
		Status:       FactorStateUnverified,
	}

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		if err := insertFactor(ctx, tx, factor, a.now()); err != nil {
			if isUniqueViolation(err, "mfa_factors_user_friendly_name_unique") {
				return unprocessableEntityError(ErrorCodeMFAFactorNameConflict,
					"A factor with the friendly name %q for this user already exists", name)
			}
			return internalServerError("Database error creating factor").withInternal(err)
		}
		return nil
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, &EnrollFactorResponse{
		ID:           factor.ID,
		Type:         FactorTypeWebAuthn,
		FriendlyName: factor.FriendlyName,
	})
}

// ---- challenge -------------------------------------------------------------

// challengeWebAuthnFactor implements POST /factors/{id}/challenge for a webauthn
// factor: BeginRegistration for an unverified factor, BeginLogin for a verified
// one, persisting the ceremony's SessionData on the challenge.
func (a *api) challengeWebAuthnFactor(w http.ResponseWriter, r *http.Request, factor *Factor) error {
	ctx := r.Context()
	u := userFrom(ctx)
	if u == nil {
		return internalServerError("A valid session and a registered user are required to challenge a factor")
	}
	pool, derr := a.db(ctx)
	if derr != nil {
		return derr
	}
	rp, rerr := a.passkeyWebAuthn()
	if rerr != nil {
		return rerr
	}

	var (
		sessionData   *webauthn.SessionData
		options       any
		challengeType string
	)

	if factor.IsUnverified() {
		// Registration ceremony. Exclude every credential the user already holds
		// on a webauthn factor so an authenticator refuses to enrol twice.
		exclude, xerr := a.mfaWebAuthnExclusions(ctx, pool, factor.UserID)
		if xerr != nil {
			return xerr
		}
		creation, sd, berr := rp.BeginRegistration(&mfaWebAuthnUser{user: u}, webauthn.WithExclusions(exclude))
		if berr != nil {
			return internalServerError("Failed to generate WebAuthn registration options").withInternal(berr)
		}
		sessionData, options, challengeType = sd, creation.Response, webAuthnFactorTypeCreate
	} else {
		cred, cerr := a.loadFactorCredential(ctx, pool, factor)
		if cerr != nil {
			return cerr
		}
		assertion, sd, berr := rp.BeginLogin(&mfaWebAuthnUser{user: u, creds: []webauthn.Credential{cred}})
		if berr != nil {
			return internalServerError("Failed to generate WebAuthn login options").withInternal(berr)
		}
		sessionData, options, challengeType = sd, assertion.Response, webAuthnFactorTypeRequest
	}

	data, merr := json.Marshal(sessionData)
	if merr != nil {
		return internalServerError("Error encoding WebAuthn session").withInternal(merr)
	}

	challenge := &mfaChallenge{
		ID:        uuid.NewString(),
		FactorID:  factor.ID,
		IPAddress: mfaClientIP(r),
	}
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		now := a.now()
		if err := insertWebAuthnChallenge(ctx, tx, challenge, data, now); err != nil {
			return internalServerError("Database error creating challenge").withInternal(err)
		}
		if _, err := touchFactorLastChallengedAt(ctx, tx, factor.ID, now); err != nil {
			return internalServerError("Database error updating factor").withInternal(err)
		}
		return nil
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, &ChallengeFactorResponse{
		ID:        challenge.ID,
		Type:      factor.FactorType,
		ExpiresAt: challenge.expiryTime(mfaChallengeExpiryDuration).Unix(),
		WebAuthn: &WebAuthnChallengeData{
			Type:              challengeType,
			CredentialOptions: options,
		},
	})
}

// ---- verify ----------------------------------------------------------------

// verifyWebAuthnFactor implements POST /factors/{id}/verify for a webauthn
// factor. An unverified factor finishes registration (CreateCredential) and the
// credential is persisted atomically with the session upgrade; a verified factor
// validates a login assertion (ValidateLogin).
func (a *api) verifyWebAuthnFactor(w http.ResponseWriter, r *http.Request, mc *mfaContext, factor *Factor, params *VerifyFactorParams) error {
	ctx := r.Context()
	pool, derr := a.db(ctx)
	if derr != nil {
		return derr
	}
	if params.WebAuthn == nil || len(params.WebAuthn.Credential) == 0 {
		return badRequestError(ErrorCodeValidationFailed, "webauthn credential is required")
	}

	challenge, cerr := a.validateChallenge(ctx, r, pool, factor, params.ChallengeID, mfaChallengeExpiryDuration)
	if cerr != nil {
		return cerr
	}
	rawSession, serr := findChallengeWebAuthnSessionData(ctx, pool, challenge.ID)
	if serr != nil {
		return internalServerError("Database error loading challenge").withInternal(serr)
	}
	if len(rawSession) == 0 {
		return unprocessableEntityError(ErrorCodeMFAFactorNotFound,
			"MFA factor with the provided challenge ID not found")
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(rawSession, &session); err != nil {
		return internalServerError("Error decoding WebAuthn session").withInternal(err)
	}

	rp, rerr := a.passkeyWebAuthn()
	if rerr != nil {
		return rerr
	}

	var credential *webauthn.Credential
	if factor.IsUnverified() {
		// Finish registration: CreateCredential runs the whole §7.1 attestation
		// check (challenge, origin against RPOrigins, RP ID hash against RPID).
		var ccr protocol.CredentialCreationResponse
		if err := json.Unmarshal(params.WebAuthn.Credential, &ccr); err != nil {
			return badRequestError(ErrorCodeWebAuthnVerificationFailed, "Invalid credential response").withInternal(err)
		}
		parsed, perr := ccr.Parse()
		if perr != nil {
			return badRequestError(ErrorCodeWebAuthnVerificationFailed, "Invalid credential response").withInternal(perr)
		}
		cred, verr := rp.CreateCredential(&mfaWebAuthnUser{user: mc.user}, session, parsed)
		if verr != nil {
			return badRequestError(ErrorCodeWebAuthnVerificationFailed, "Credential verification failed").withInternal(verr)
		}
		credential = cred
	} else {
		// Finish login: ValidateLogin runs the whole §7.2 assertion check over the
		// factor's stored credential.
		stored, lerr := a.loadFactorCredential(ctx, pool, factor)
		if lerr != nil {
			return lerr
		}
		var car protocol.CredentialAssertionResponse
		if err := json.Unmarshal(params.WebAuthn.Credential, &car); err != nil {
			return badRequestError(ErrorCodeWebAuthnVerificationFailed, "Invalid credential response").withInternal(err)
		}
		parsed, perr := car.Parse()
		if perr != nil {
			return badRequestError(ErrorCodeWebAuthnVerificationFailed, "Invalid credential response").withInternal(perr)
		}
		cred, verr := rp.ValidateLogin(&mfaWebAuthnUser{user: mc.user, creds: []webauthn.Credential{stored}}, session, parsed)
		if verr != nil {
			return badRequestError(ErrorCodeWebAuthnVerificationFailed, "Credential verification failed").withInternal(verr)
		}
		credential = cred
	}

	blob, merr := json.Marshal(credential)
	if merr != nil {
		return internalServerError("Error encoding WebAuthn credential").withInternal(merr)
	}
	var aaguid *string
	if s := formatUUIDBytes(credential.Authenticator.AAGUID); s != "" {
		aaguid = &s
	}

	// The credential (and its advanced sign count) is written in the SAME
	// transaction that upgrades the session, so enrolment and the aal2 promotion
	// commit together.
	store := func(ctx context.Context, tx pgx.Tx, now time.Time) error {
		if err := updateFactorWebAuthnCredential(ctx, tx, factor.ID, blob, aaguid, now); err != nil {
			return internalServerError("Database error saving WebAuthn credential").withInternal(err)
		}
		return nil
	}
	return a.finalizeFactorVerification(w, r, mc, factor, challenge, store)
}

// ---- credential helpers ----------------------------------------------------

// loadFactorCredential reads a webauthn factor's stored credential back into the
// library type. A verified factor always has one; a missing blob is treated as a
// verification failure rather than a 500 (only reachable if the row was tampered
// with).
func (a *api) loadFactorCredential(ctx context.Context, q querier, factor *Factor) (webauthn.Credential, error) {
	blob, err := findFactorWebAuthnCredential(ctx, q, factor.ID)
	if err != nil {
		return webauthn.Credential{}, internalServerError("Database error loading WebAuthn credential").withInternal(err)
	}
	if len(blob) == 0 {
		return webauthn.Credential{}, badRequestError(ErrorCodeWebAuthnCredentialNotFound,
			"WebAuthn credential not found for this factor")
	}
	var cred webauthn.Credential
	if err := json.Unmarshal(blob, &cred); err != nil {
		return webauthn.Credential{}, internalServerError("Error decoding WebAuthn credential").withInternal(err)
	}
	return cred, nil
}

// mfaWebAuthnExclusions is the excludeCredentials list for a registration
// ceremony: every credential the user already holds on any webauthn factor.
func (a *api) mfaWebAuthnExclusions(ctx context.Context, q querier, userID string) ([]protocol.CredentialDescriptor, error) {
	factors, err := findFactorsByUserID(ctx, q, userID)
	if err != nil {
		return nil, internalServerError("Database error loading factors").withInternal(err)
	}
	out := []protocol.CredentialDescriptor{}
	for _, f := range factors {
		if f.FactorType != FactorTypeWebAuthn || !f.IsVerified() {
			continue
		}
		cred, cerr := a.loadFactorCredential(ctx, q, f)
		if cerr != nil {
			// A verified factor with no credential is a data anomaly, not a reason
			// to fail an unrelated enrolment; skip it.
			continue
		}
		out = append(out, protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: cred.ID,
		})
	}
	return out, nil
}

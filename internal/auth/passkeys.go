package auth

// Passkeys — WebAuthn as a first-class sign-in method.
//
// Reproduces github.com/supabase/auth/internal/api/{passkey_webauthn.go,
// passkey_registration.go} and the /passkeys route table of its api.go
// (L314-333). The manage half is passkeys_manage.go, the login half is
// passkeys_auth.go, the admin half is passkeys_admin.go, and the model/storage
// layer is passkey_models.go.
//
// # Route table (mounted under /auth/v1)
//
//	POST   /passkeys/authentication/options   -- anonymous; discoverable login
//	POST   /passkeys/authentication/verify    -- anonymous; issues a session
//	POST   /passkeys/registration/options     -- authenticated, non-anonymous
//	POST   /passkeys/registration/verify      -- authenticated, non-anonymous
//	GET    /passkeys                          -- authenticated
//	PATCH  /passkeys/{passkey_id}             -- authenticated
//	DELETE /passkeys/{passkey_id}             -- authenticated
//	GET    /admin/users/{user_id}/passkeys                 -- admin
//	DELETE /admin/users/{user_id}/passkeys/{passkey_id}    -- admin
//
// # Configuration mapping
//
// Config.Passkeys (conf.go) carries {Enabled, RPID, RPOrigins}; upstream's
// WebAuthnConfiguration additionally has RPDisplayName and
// ChallengeExpiryDuration, and its PasskeyConfiguration has MaxPasskeysPerUser.
// Those three are pinned to upstream's defaults as package constants
// (passkey_models.go) and RPDisplayName is derived — see passkeyWebAuthnConfig.
//
// # Known gap: expired challenge rows
//
// Upstream's models.Cleanup deletes `webauthn_challenges where expires_at <
// now()`. Dilion's cleanup worker (cleanup.go) does NOT list the table — its
// `optional` set covers auth.one_time_tokens and auth.flow_state only. cleanup.go
// is owned by another change, so instead of editing it this feature purges
// expired challenges opportunistically from its own options endpoints
// (deleteExpiredPasskeyChallenges). The durable fix is one more entry in
// cleanup.go's `optional` slice:
//
//	{
//	    table: "auth.webauthn_challenges",
//	    sql:   `delete from auth.webauthn_challenges
//	            where ctid in (select ctid from auth.webauthn_challenges where expires_at < $1 limit 5000)`,
//	    arg:   now,
//	}

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func init() {
	registerFeature("passkeys", func(a *api, r chi.Router) {
		r.Route("/passkeys", func(r chi.Router) {
			r.Use(a.requirePasskeyEnabled)

			// The login ceremony is unauthenticated, so it carries the
			// per-IP passkey limiter and (like every other unauthenticated
			// credential surface) the captcha check.
			//
			// DEVIATION: upstream rate-limits only .../options and leaves
			// .../verify unlimited. Dilion limits BOTH: verify is where a
			// signature is checked and a session is minted, which is exactly
			// the endpoint an attacker would hammer. Both draw on the same
			// LimiterPasskey bucket (GOTRUE_RATE_LIMIT_PASSKEY), so a
			// legitimate client — which calls the pair once — is unaffected.
			r.With(a.limit(LimiterPasskey)).Post("/authentication/options", a.handle(a.passkeyAuthenticationOptions))
			r.With(a.limit(LimiterPasskey)).Post("/authentication/verify", a.handle(a.passkeyAuthenticationVerify))

			r.Group(func(r chi.Router) {
				r.Use(a.requireAuthentication)
				r.Post("/registration/options", a.handle(a.passkeyRegistrationOptions))
				r.Post("/registration/verify", a.handle(a.passkeyRegistrationVerify))

				r.Get("/", a.handle(a.passkeyList))
				r.Patch("/{passkey_id}", a.handle(a.passkeyUpdate))
				r.Delete("/{passkey_id}", a.handle(a.passkeyDelete))
			})
		})
	})
}

// ---- gates -----------------------------------------------------------------

// requirePasskeyEnabled is upstream's middleware of the same name: with the
// feature off every /passkeys route answers 404 passkey_disabled — NOT 422.
// Upstream chose 404 so a deployment without passkeys is indistinguishable from
// one that predates the feature; matched exactly.
func (a *api) requirePasskeyEnabled(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.cfg.Passkeys.Enabled {
			a.writeError(r, w, notFoundError(ErrorCodePasskeyDisabled, "Passkeys are disabled"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireNotAnonymousUser is upstream's requireNotAnonymous, inlined: Dilion has
// no such middleware, and the check needs the loaded user anyway.
func requireNotAnonymousUser(u *User) error {
	if u != nil && u.IsAnonymous {
		return forbiddenError(ErrorCodeNoAuthorization, "Anonymous user not allowed to perform these actions")
	}
	return nil
}

// requirePasskeyManagementAAL is upstream's function of the same name: adding or
// removing a passkey needs an AAL2 session WHEN the user has a verified MFA
// factor. A user with no verified factor can never reach aal2, so requiring it
// would lock them out of their own credentials — hence the conditional.
//
// The check fails CLOSED: a request without a session_id claim (a service-role
// token, a hand-made JWT) reads as aal1 and is rejected once MFA is on.
func (a *api) requirePasskeyManagementAAL(ctx context.Context, q querier, u *User) error {
	factors, err := findFactorsByUserID(ctx, q, u.ID)
	if err != nil {
		return internalServerError("Database error loading factors").withInternal(err)
	}
	hasMFA := false
	for _, f := range factors {
		if f.IsVerified() {
			hasMFA = true
			break
		}
	}
	if !hasMFA {
		return nil
	}
	aal, err := a.sessionAAL(ctx, q, sessionIDFrom(claimsFrom(ctx)))
	if err != nil {
		return err
	}
	if aal != AAL2 {
		return forbiddenError(ErrorCodeInsufficientAAL,
			"AAL2 session is required to manage passkeys when MFA is enabled")
	}
	return nil
}

// ---- WebAuthn relying-party configuration ----------------------------------

// passkeyWebAuthnConfig maps Config.Passkeys onto a webauthn.Config.
//
//	RPID      <- Passkeys.RPID      (GOTRUE_WEBAUTHN_RP_ID)
//	RPOrigins <- Passkeys.RPOrigins (GOTRUE_WEBAUTHN_RP_ORIGINS)
//
// DEVIATION (documented fallback): upstream REQUIRES both to be set and refuses
// to boot otherwise (conf.WebAuthnConfiguration.Validate). Dilion derives them
// from SiteURL when they are empty, so the zero-config developer path
// (SITE_URL=http://localhost:5173 + PASSKEY_ENABLED=true) works without two more
// environment variables:
//
//	RPID      = hostname of SiteURL          e.g. "localhost"
//	RPOrigins = [scheme://host[:port]]       e.g. ["http://localhost:5173"]
//
// The derivation is only ever a DEFAULT: an explicit RPID/RPOrigins always wins,
// and a production deployment behind a different front-end origin must set them
// (an RP ID is security-relevant — it is the scope a credential is bound to).
//
// RPDisplayName has no Dilion knob (upstream: GOTRUE_WEBAUTHN_RP_DISPLAY_NAME).
// It is purely cosmetic — the authenticator shows it in its consent UI — so it
// falls back to the RP ID.
//
// AttestationPreference and AuthenticatorSelection are copied verbatim from
// upstream: no attestation is requested (nothing here would verify a cert
// chain), a RESIDENT key is required (without it the credential is not
// discoverable and the usernameless login ceremony cannot work), and user
// verification is "preferred".
func (a *api) passkeyWebAuthnConfig() *webauthn.Config {
	rpID := strings.TrimSpace(a.cfg.Passkeys.RPID)
	origins := a.cfg.Passkeys.RPOrigins

	if rpID == "" || len(origins) == 0 {
		if site, err := url.Parse(a.cfg.SiteURL); err == nil && site.Host != "" {
			if rpID == "" {
				rpID = site.Hostname()
			}
			if len(origins) == 0 {
				origins = []string{site.Scheme + "://" + site.Host}
			}
		}
	}

	return &webauthn.Config{
		RPDisplayName:         rpID,
		RPID:                  rpID,
		RPOrigins:             origins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			// Required to support discoverable ("usernameless") credentials.
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationPreferred,
		},
	}
}

// passkeyWebAuthn builds the relying party (upstream getPasskeyWebAuthn). A
// mis-configured RP is a 500, not a 4xx: the client did nothing wrong.
func (a *api) passkeyWebAuthn() (*webauthn.WebAuthn, error) {
	w, err := webauthn.New(a.passkeyWebAuthnConfig())
	if err != nil {
		return nil, internalServerError("Failed to initialize WebAuthn").withInternal(err)
	}
	return w, nil
}

// ---- wire types ------------------------------------------------------------

// PasskeyRegistrationOptionsResponse is the POST /passkeys/registration/options
// body (upstream api.PasskeyRegistrationOptionsResponse). `options` is the raw
// PublicKeyCredentialCreationOptions the browser hands to
// navigator.credentials.create().
type PasskeyRegistrationOptionsResponse struct {
	ChallengeID string                                       `json:"challenge_id"`
	Options     *protocol.PublicKeyCredentialCreationOptions `json:"options"`
	ExpiresAt   int64                                        `json:"expires_at"`
}

// PasskeyRegistrationVerifyParams is the POST /passkeys/registration/verify body.
type PasskeyRegistrationVerifyParams struct {
	ChallengeID string          `json:"challenge_id"`
	Credential  json.RawMessage `json:"credential"`
}

// PasskeyMetadataResponse is the body of a successful passkey creation.
type PasskeyMetadataResponse struct {
	ID           string    `json:"id"`
	FriendlyName string    `json:"friendly_name,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// ---- POST /passkeys/registration/options -----------------------------------

// passkeyRegistrationOptions implements upstream PasskeyRegistrationOptions:
// begin a registration ceremony for the signed-in user and persist its
// challenge.
func (a *api) passkeyRegistrationOptions(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	u := userFrom(ctx)

	if err := requireNotAnonymousUser(u); err != nil {
		return err
	}
	if u.IsSSOUser {
		return unprocessableEntityError(ErrorCodeValidationFailed, "SSO users cannot register passkeys")
	}

	pool, err := a.db(ctx)
	if err != nil {
		return err
	}
	if err := a.requirePasskeyManagementAAL(ctx, pool, u); err != nil {
		return err
	}

	existing, derr := findPasskeysByUserID(ctx, pool, u.ID)
	if derr != nil {
		return internalServerError("Database error loading passkeys").withInternal(derr)
	}
	if len(existing) >= maxPasskeysPerUser {
		return unprocessableEntityError(ErrorCodeTooManyPasskeys, "Maximum number of passkeys reached")
	}

	// Credentials the user already has are excluded, so an authenticator that
	// holds one refuses to create a second (upstream WithExclusions).
	exclude := make([]protocol.CredentialDescriptor, len(existing))
	for i, c := range existing {
		exclude[i] = protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: c.CredentialID,
		}
	}

	rp, err := a.passkeyWebAuthn()
	if err != nil {
		return err
	}
	options, sessionData, berr := rp.BeginRegistration(newWebAuthnUser(u, existing), webauthn.WithExclusions(exclude))
	if berr != nil {
		return internalServerError("Failed to generate WebAuthn registration options").withInternal(berr)
	}

	now := a.now()
	challenge := &passkeyChallenge{
		ID:            uuid.NewString(),
		UserID:        &u.ID,
		ChallengeType: webAuthnChallengeTypeRegistration,
		SessionData:   *sessionData,
		ExpiresAt:     now.Add(passkeyChallengeExpiry),
	}
	if err := insertPasskeyChallenge(ctx, pool, challenge, now); err != nil {
		return internalServerError("Database error storing challenge").withInternal(err)
	}
	a.purgeExpiredPasskeyChallenges(ctx, pool, now)

	return sendJSON(w, http.StatusOK, &PasskeyRegistrationOptionsResponse{
		ChallengeID: challenge.ID,
		Options:     &options.Response,
		ExpiresAt:   challenge.ExpiresAt.Unix(),
	})
}

// ---- POST /passkeys/registration/verify ------------------------------------

// passkeyRegistrationVerify implements upstream PasskeyRegistrationVerify:
// consume the challenge, verify the attestation, store the credential.
func (a *api) passkeyRegistrationVerify(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	u := userFrom(ctx)

	if err := requireNotAnonymousUser(u); err != nil {
		return err
	}
	if u.IsSSOUser {
		return unprocessableEntityError(ErrorCodeValidationFailed, "SSO users cannot register passkeys")
	}

	pool, err := a.db(ctx)
	if err != nil {
		return err
	}
	if err := a.requirePasskeyManagementAAL(ctx, pool, u); err != nil {
		return err
	}

	params := &PasskeyRegistrationVerifyParams{}
	if derr := decodeBody(r, params); derr != nil {
		return derr
	}
	challengeID, verr := validatePasskeyVerifyParams(params.ChallengeID, params.Credential)
	if verr != nil {
		return verr
	}

	// The challenge is consumed atomically (DELETE ... RETURNING), so it is
	// single-use even under concurrent verifies, and it is scoped to this user
	// AND to the registration ceremony.
	challenge, cerr := consumePasskeyChallenge(ctx, pool, challengeID, webAuthnChallengeTypeRegistration, &u.ID)
	if cerr != nil {
		if isNoRows(cerr) {
			return badRequestError(ErrorCodeWebAuthnChallengeNotFound, "Challenge not found or already used")
		}
		return internalServerError("Database error consuming challenge").withInternal(cerr)
	}
	if challenge.isExpired(a.now()) {
		return badRequestError(ErrorCodeWebAuthnChallengeExpired, "Challenge has expired")
	}

	var ccr protocol.CredentialCreationResponse
	if err := json.Unmarshal(params.Credential, &ccr); err != nil {
		return badRequestError(ErrorCodeWebAuthnVerificationFailed, "Invalid credential response").withInternal(err)
	}
	parsed, perr := ccr.Parse()
	if perr != nil {
		return badRequestError(ErrorCodeWebAuthnVerificationFailed, "Invalid credential response").withInternal(perr)
	}

	rp, err := a.passkeyWebAuthn()
	if err != nil {
		return err
	}

	existing, derr := findPasskeysByUserID(ctx, pool, u.ID)
	if derr != nil {
		return internalServerError("Database error loading passkeys").withInternal(derr)
	}

	// CreateCredential performs the whole §7.1 attestation check: the challenge
	// must match, the origin must be one of RPOrigins, the RP ID hash must match
	// RPID, and the attestation statement must verify.
	credential, cverr := rp.CreateCredential(newWebAuthnUser(u, existing), challenge.SessionData, parsed)
	if cverr != nil {
		return badRequestError(ErrorCodeWebAuthnVerificationFailed, "Credential verification failed").withInternal(cverr)
	}

	now := a.now()
	stored := &passkeyCredential{
		ID:              uuid.NewString(),
		UserID:          u.ID,
		CredentialID:    credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		SignCount:       credential.Authenticator.SignCount,
		Transports:      credential.Transport,
		BackupEligible:  credential.Flags.BackupEligible,
		BackedUp:        credential.Flags.BackupState,
		FriendlyName:    passkeyFriendlyName(credential.Authenticator.AAGUID),
	}
	if s := formatUUIDBytes(credential.Authenticator.AAGUID); s != "" {
		stored.AAGUID = &s
	}

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		// Re-count inside the transaction: two parallel registrations must not
		// both squeeze past the limit (upstream re-checks here too).
		count, cerr := countPasskeys(ctx, tx, u.ID)
		if cerr != nil {
			return internalServerError("Database error counting passkeys").withInternal(cerr)
		}
		if count >= maxPasskeysPerUser {
			return unprocessableEntityError(ErrorCodeTooManyPasskeys, "Maximum number of passkeys reached")
		}
		if ierr := insertPasskey(ctx, tx, stored, now); ierr != nil {
			if isNoRows(ierr) {
				// `on conflict (credential_id) do nothing` returned no row.
				return unprocessableEntityError(ErrorCodeWebAuthnCredentialExists,
					"This credential is already registered")
			}
			return internalServerError("Database error creating passkey").withInternal(ierr)
		}
		return nil
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, &PasskeyMetadataResponse{
		ID:           stored.ID,
		FriendlyName: stored.FriendlyName,
		CreatedAt:    stored.CreatedAt,
	})
}

// ---- shared helpers --------------------------------------------------------

// validatePasskeyVerifyParams is the parameter validation both verify endpoints
// share, with upstream's exact codes and messages.
func validatePasskeyVerifyParams(challengeID string, credential json.RawMessage) (string, error) {
	if challengeID == "" {
		return "", badRequestError(ErrorCodeValidationFailed, "challenge_id is required")
	}
	if credential == nil {
		return "", badRequestError(ErrorCodeValidationFailed, "credential is required")
	}
	if _, err := uuid.Parse(challengeID); err != nil {
		return "", badRequestError(ErrorCodeValidationFailed, "challenge_id must be a valid UUID")
	}
	return challengeID, nil
}

// purgeExpiredPasskeyChallenges is the best-effort stand-in for the cleanup
// worker entry this feature is missing (see the file header). It is fire and
// forget: a failure is logged at DEBUG and never touches the response, because
// housekeeping must not be able to fail a login.
func (a *api) purgeExpiredPasskeyChallenges(ctx context.Context, q querier, now time.Time) {
	const batch = 100
	if err := deleteExpiredPasskeyChallenges(ctx, q, now, batch); err != nil {
		a.log.DebugContext(ctx, "auth: purging expired webauthn challenges failed",
			"error", err.Error())
	}
}

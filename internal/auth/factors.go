package auth

// The /auth/v1/factors surface: TOTP enrolment, challenge, verification and
// unenrolment (upstream internal/api/mfa.go).
//
//	POST   /factors                        enroll     -> factor + secret + otpauth URI + QR
//	POST   /factors/{factor_id}/challenge  challenge  -> challenge id + expiry
//	POST   /factors/{factor_id}/verify     verify     -> a NEW aal2 session envelope
//	DELETE /factors/{factor_id}            unenroll   -> {id}
//
// Only the TOTP factor type is implemented. `phone` and `webauthn` are answered
// with upstream's "…_enroll_not_enabled" / "…_verify_not_enabled" 422, which is
// byte-identical to what upstream returns for a deployment that leaves
// GOTRUE_MFA_PHONE_* / GOTRUE_MFA_WEBAUTHN_* at their defaults (both off).

import (
	"context"
	"encoding/json"
	"errors"
	"image/color"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/boombuler/barcode/qr"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"fmt"
)

func init() {
	registerFeature("factors", func(a *api, r chi.Router) {
		r.Group(func(r chi.Router) {
			r.Use(a.requireAuthentication)
			r.Route("/factors", func(r chi.Router) {
				r.Post("/", a.handle(a.enrollFactor))
				r.Route("/{factor_id}", func(r chi.Router) {
					// Upstream guards verify/challenge with their own
					// limiters (GOTRUE_RATE_LIMIT_FACTOR_*); Config has no
					// such knob, so both ride the /verify limiter, which is
					// the closest existing budget for a code-guessing surface.
					r.With(a.limit(LimiterVerify)).Post("/verify", a.handle(a.verifyFactor))
					r.With(a.limit(LimiterVerify)).Post("/challenge", a.handle(a.challengeFactor))
					r.Delete("/", a.handle(a.unenrollFactor))
				})
			})
		})
	})
}

// ---- request / response shapes (upstream api/mfa.go) -----------------------

// EnrollFactorParams is the POST /factors body.
type EnrollFactorParams struct {
	FriendlyName string `json:"friendly_name"`
	FactorType   string `json:"factor_type"`
	Issuer       string `json:"issuer"`
	Phone        string `json:"phone"`
}

// TOTPObject is the `totp` member of an enrolment response.
type TOTPObject struct {
	QRCode string `json:"qr_code,omitempty"`
	Secret string `json:"secret,omitempty"`
	URI    string `json:"uri,omitempty"`
}

// EnrollFactorResponse is the POST /factors body.
type EnrollFactorResponse struct {
	ID           string      `json:"id"`
	Type         string      `json:"type"`
	FriendlyName string      `json:"friendly_name"`
	TOTP         *TOTPObject `json:"totp,omitempty"`
	Phone        string      `json:"phone,omitempty"`
}

// ChallengeFactorParams is the POST /factors/{id}/challenge body.
type ChallengeFactorParams struct {
	Channel string `json:"channel"`
}

// ChallengeFactorResponse is the POST /factors/{id}/challenge body.
type ChallengeFactorResponse struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	// WebAuthn carries the go-webauthn credential options for a webauthn factor
	// challenge (upstream ChallengeFactorResponse.WebAuthn). It is absent for
	// TOTP and phone.
	WebAuthn *WebAuthnChallengeData `json:"webauthn,omitempty"`
}

// WebAuthnChallengeData is the `webauthn` member of a webauthn factor challenge
// (upstream api.WebAuthnChallengeData). Type is "create" for an unverified
// factor (BeginRegistration) and "request" for a verified one (BeginLogin);
// CredentialOptions is the raw PublicKeyCredential(Creation|Request)Options the
// browser hands to navigator.credentials.
type WebAuthnChallengeData struct {
	Type              string `json:"type"`
	CredentialOptions any    `json:"credential_options"`
}

// VerifyFactorParams is the POST /factors/{id}/verify body.
type VerifyFactorParams struct {
	ChallengeID string `json:"challenge_id"`
	Code        string `json:"code"`
	// WebAuthn carries the authenticator's response for a webauthn factor verify
	// (upstream VerifyFactorParams.WebAuthn). `credential` is the raw
	// CredentialCreationResponse ("create") or CredentialAssertionResponse
	// ("request"); the ceremony is inferred from the factor's status, so the
	// client-supplied type is advisory.
	WebAuthn *WebAuthnVerifyData `json:"webauthn"`
}

// WebAuthnVerifyData is the `webauthn` member of a webauthn factor verify.
type WebAuthnVerifyData struct {
	Type       string          `json:"type"`
	Credential json.RawMessage `json:"credential"`
}

// UnenrollFactorResponse is the DELETE /factors/{id} body.
type UnenrollFactorResponse struct {
	ID string `json:"id"`
}

// ---- shared plumbing -------------------------------------------------------

// mfaContext is what every /factors handler needs: the authenticated user and
// the session the Bearer token names. Upstream gets both from middleware; here
// the session id comes from the `session_id` claim.
type mfaContext struct {
	user      *User
	sessionID string
}

func (a *api) mfaContextOf(r *http.Request) (*mfaContext, error) {
	u := userFrom(r.Context())
	sid := sessionIDFrom(claimsFrom(r.Context()))
	if u == nil || sid == "" {
		// Upstream: "A valid session and a registered user are required…".
		return nil, internalServerError(
			"A valid session and a registered user are required to enroll a factor")
	}
	// Upstream mounts /factors behind requireNotAnonymous: an anonymous
	// account has nothing to protect with a second factor, and enrolling one
	// would pin a throwaway session to aal2.
	if err := requireNotAnonymousUser(u); err != nil {
		return nil, err
	}
	return &mfaContext{user: u, sessionID: sid}, nil
}

// loadOwnedFactor is upstream's loadFactor middleware + User.FindOwnedFactorByID:
// a factor that does not exist, or belongs to somebody else, is a 404 with the
// SAME body — the endpoint must not confirm that another user's factor exists.
func (a *api) loadOwnedFactor(ctx context.Context, q querier, u *User, factorID string) (*Factor, error) {
	if _, err := uuid.Parse(factorID); err != nil {
		return nil, notFoundError(ErrorCodeMFAFactorNotFound, "Factor not found")
	}
	f, err := findFactorByID(ctx, q, factorID)
	if err != nil {
		if isNoRows(err) {
			return nil, notFoundError(ErrorCodeMFAFactorNotFound, "Factor not found")
		}
		return nil, internalServerError("Database error loading factor").withInternal(err)
	}
	if f.UserID != u.ID {
		return nil, notFoundError(ErrorCodeMFAFactorNotFound, "Factor not found")
	}
	return f, nil
}

// ---- enroll ----------------------------------------------------------------

func (a *api) enrollFactor(w http.ResponseWriter, r *http.Request) error {
	mc, err := a.mfaContextOf(r)
	if err != nil {
		return err
	}

	params := &EnrollFactorParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}

	switch params.FactorType {
	case FactorTypeTOTP:
		if !a.cfg.MFA.TOTP.EnrollEnabled {
			return unprocessableEntityError(ErrorCodeMFATOTPEnrollDisabled, "MFA enroll is disabled for TOTP")
		}
		return a.enrollTOTPFactor(w, r, mc, params)
	case FactorTypePhone:
		if !a.cfg.MFA.Phone.EnrollEnabled {
			return unprocessableEntityError(ErrorCodeMFAPhoneEnrollDisabled, "MFA enroll is disabled for Phone")
		}
		return a.enrollPhoneFactor(w, r, mc, params)
	case FactorTypeWebAuthn:
		if !a.cfg.MFA.WebAuthn.EnrollEnabled {
			return unprocessableEntityError(ErrorCodeMFAWebAuthnEnrollDisabled, "MFA enroll is disabled for WebAuthn")
		}
		return a.enrollWebAuthnFactor(w, r, mc, params)
	default:
		return badRequestError(ErrorCodeValidationFailed, "factor_type needs to be totp, phone, or webauthn")
	}
}

// validateFactors is upstream api.validateFactors: expiry sweep, name-conflict,
// factor budgets and the "aal2 required to add a factor to an already-protected
// account" rule.
func (a *api) validateFactors(ctx context.Context, q querier, mc *mfaContext, newName string) error {
	now := a.now()
	if err := deleteExpiredFactors(ctx, q, now, mfaFactorExpiryDuration); err != nil {
		return internalServerError("Database error deleting expired factors").withInternal(err)
	}
	factors, err := findFactorsByUserID(ctx, q, mc.user.ID)
	if err != nil {
		return internalServerError("Database error loading factors").withInternal(err)
	}

	verified := 0
	for _, f := range factors {
		if f.FriendlyName == newName {
			return unprocessableEntityError(ErrorCodeMFAFactorNameConflict,
				"A factor with the friendly name %q for this user already exists", newName)
		}
		if f.IsVerified() {
			verified++
		}
	}

	max := a.cfg.MFA.MaxEnrolledFactors
	if max > 0 && len(factors) >= max {
		return unprocessableEntityError(ErrorCodeTooManyEnrolledMFAFactors,
			"Maximum number of verified factors reached, unenroll to continue")
	}
	if verified >= mfaMaxVerifiedFactors {
		return unprocessableEntityError(ErrorCodeTooManyEnrolledMFAFactors,
			"Maximum number of verified factors reached, unenroll to continue")
	}

	if verified > 0 {
		aal, err := a.sessionAAL(ctx, q, mc.sessionID)
		if err != nil {
			return err
		}
		if aal != AAL2 {
			return forbiddenError(ErrorCodeInsufficientAAL, "AAL2 required to enroll a new factor")
		}
	}
	return nil
}

func (a *api) enrollTOTPFactor(w http.ResponseWriter, r *http.Request, mc *mfaContext, params *EnrollFactorParams) error {
	ctx := r.Context()

	issuer := params.Issuer
	if issuer == "" {
		u, err := url.ParseRequestURI(a.site(ctx).SiteURL)
		if err != nil {
			return internalServerError("site url is improperly formatted")
		}
		issuer = u.Host
	}

	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	name := trimName(params.FriendlyName)
	if err := a.validateFactors(ctx, pool, mc, name); err != nil {
		return err
	}

	key, err := totp.Generate(totp.GenerateOpts{Issuer: issuer, AccountName: mc.user.Email})
	if err != nil {
		return internalServerError("Error generating TOTP secret").withInternal(err)
	}
	qrCode, err := totpQRCodeSVG(key.String())
	if err != nil {
		return internalServerError("%s", qrCodeGenerationErrorMessage).withInternal(err)
	}

	factor := &Factor{
		ID:           uuid.NewString(),
		UserID:       mc.user.ID,
		FriendlyName: name,
		FactorType:   FactorTypeTOTP,
		Status:       FactorStateUnverified,
		Secret:       key.Secret(),
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
		Type:         FactorTypeTOTP,
		FriendlyName: factor.FriendlyName,
		TOTP: &TOTPObject{
			QRCode: qrCode,
			Secret: key.Secret(),
			URI:    key.URL(),
		},
	})
}

// ---- challenge -------------------------------------------------------------

func (a *api) challengeFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	mc, err := a.mfaContextOf(r)
	if err != nil {
		return err
	}
	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	factor, ferr := a.loadOwnedFactor(ctx, pool, mc.user, chi.URLParam(r, "factor_id"))
	if ferr != nil {
		return ferr
	}

	// The body is read (and validated) even though TOTP ignores `channel`,
	// so a malformed body is still a 400 as upstream.
	params := &ChallengeFactorParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}

	switch factor.FactorType {
	case FactorTypeTOTP:
		if !a.cfg.MFA.TOTP.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFATOTPVerifyDisabled, "MFA verification is disabled for TOTP")
		}
		return a.challengeTOTPFactor(w, r, factor)
	case FactorTypePhone:
		if !a.cfg.MFA.Phone.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFAPhoneVerifyDisabled, "MFA verification is disabled for Phone")
		}
		return a.challengePhoneFactor(w, r, factor, params)
	case FactorTypeWebAuthn:
		if !a.cfg.MFA.WebAuthn.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFAWebAuthnVerifyDisabled, "MFA verification is disabled for WebAuthn")
		}
		return a.challengeWebAuthnFactor(w, r, factor)
	default:
		return badRequestError(ErrorCodeValidationFailed, "factor_type needs to be totp, phone, or webauthn")
	}
}

// challengeTOTPFactor stores a bare challenge for a TOTP factor: the code the
// user enters is verified against the shared secret at verify time, so nothing
// factor-specific is persisted on the challenge.
func (a *api) challengeTOTPFactor(w http.ResponseWriter, r *http.Request, factor *Factor) error {
	ctx := r.Context()
	challenge := &mfaChallenge{
		ID:        uuid.NewString(),
		FactorID:  factor.ID,
		IPAddress: mfaClientIP(r),
	}

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		now := a.now()
		if err := insertChallenge(ctx, tx, challenge, now); err != nil {
			return internalServerError("Database error creating challenge").withInternal(err)
		}
		// Upstream's WriteChallengeToDatabase also stamps the factor.
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
	})
}

// validateChallenge is upstream api.validateChallenge. `expiry` is the factor's
// challenge lifetime: mfaChallengeExpiryDuration for TOTP/webauthn, and
// Config.MFA.PhoneOTPExp for the phone factor (upstream reads the OTP expiry
// from the factor's own config).
func (a *api) validateChallenge(ctx context.Context, r *http.Request, q querier, factor *Factor, challengeID string, expiry time.Duration) (*mfaChallenge, error) {
	if _, err := uuid.Parse(challengeID); err != nil {
		return nil, unprocessableEntityError(ErrorCodeMFAFactorNotFound,
			"MFA factor with the provided challenge ID not found")
	}
	c, err := findChallengeByID(ctx, q, factor.ID, challengeID)
	if err != nil {
		if isNoRows(err) {
			return nil, unprocessableEntityError(ErrorCodeMFAFactorNotFound,
				"MFA factor with the provided challenge ID not found")
		}
		return nil, internalServerError("Database error finding Challenge").withInternal(err)
	}
	if c.VerifiedAt != nil || c.IPAddress != mfaClientIP(r) {
		return nil, unprocessableEntityError(ErrorCodeMFAIPAddressMismatch,
			"Challenge and verify IP addresses mismatch.")
	}
	if c.hasExpired(a.now(), expiry) {
		if err := deleteChallenge(ctx, q, c.ID); err != nil {
			return nil, internalServerError("Database error deleting challenge").withInternal(err)
		}
		return nil, unprocessableEntityError(ErrorCodeMFAChallengeExpired,
			"MFA challenge %v has expired, verify against another challenge or create a new challenge.", c.ID)
	}
	return c, nil
}

// ---- verify ----------------------------------------------------------------

func (a *api) verifyFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	mc, err := a.mfaContextOf(r)
	if err != nil {
		return err
	}
	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	factor, ferr := a.loadOwnedFactor(ctx, pool, mc.user, chi.URLParam(r, "factor_id"))
	if ferr != nil {
		return ferr
	}

	params := &VerifyFactorParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}

	switch factor.FactorType {
	case FactorTypeTOTP:
		if !a.cfg.MFA.TOTP.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFATOTPVerifyDisabled, "MFA verification is disabled for TOTP")
		}
		return a.verifyTOTPFactor(w, r, mc, factor, params)
	case FactorTypePhone:
		if !a.cfg.MFA.Phone.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFAPhoneVerifyDisabled, "MFA verification is disabled for Phone")
		}
		return a.verifyPhoneFactor(w, r, mc, factor, params)
	case FactorTypeWebAuthn:
		if !a.cfg.MFA.WebAuthn.VerifyEnabled {
			return unprocessableEntityError(ErrorCodeMFAWebAuthnVerifyDisabled, "MFA verification is disabled for WebAuthn")
		}
		return a.verifyWebAuthnFactor(w, r, mc, factor, params)
	default:
		return badRequestError(ErrorCodeValidationFailed, "factor_type needs to be totp, phone, or webauthn")
	}
}

// verifyTOTPFactor validates a code against the factor's shared secret and, on
// success, upgrades the session to aal2.
func (a *api) verifyTOTPFactor(w http.ResponseWriter, r *http.Request, mc *mfaContext, factor *Factor, params *VerifyFactorParams) error {
	ctx := r.Context()
	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	if params.Code == "" {
		return badRequestError(ErrorCodeValidationFailed, "Code needs to be non-empty")
	}
	challenge, cerr := a.validateChallenge(ctx, r, pool, factor, params.ChallengeID, mfaChallengeExpiryDuration)
	if cerr != nil {
		return cerr
	}

	// Upstream's ValidateOpts, verbatim: 30s step, ±1 step of skew, 6 digits,
	// SHA-1. The clock is the injected one so a stubbed clock verifies too.
	valid, verr := totp.ValidateCustom(params.Code, factor.Secret, a.now(), totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:      totpSkew,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if !valid {
		return unprocessableEntityError(ErrorCodeMFAVerificationFailed, "Invalid TOTP code entered").
			withInternal(verr)
	}
	return a.finalizeFactorVerification(w, r, mc, factor, challenge, nil)
}

// finalizeFactorVerification is the session-upgrade half every factor type
// shares once its own credential check has passed (upstream
// updateMFASessionAndClaims / GrantRefreshTokenSwap). It runs the
// mfa_verification_attempt hook, marks the challenge consumed, promotes the
// factor to verified on first use, writes the factor's AMR claim, raises the
// session to aal2, rotates the refresh token so the aal1 token can never be
// replayed, drops every other sub-aal2 session and garbage collects the user's
// leftover unverified factors of this type.
//
// `store`, when non-nil, runs inside the same transaction right after the
// challenge is consumed — the webauthn factor uses it to persist the credential
// it just verified, so enrolment is atomic with the session upgrade.
func (a *api) finalizeFactorVerification(w http.ResponseWriter, r *http.Request, mc *mfaContext, factor *Factor, challenge *mfaChallenge, store func(ctx context.Context, tx pgx.Tx, now time.Time) error) error {
	ctx := r.Context()

	// The mfa_verification_attempt hook may veto an otherwise-valid credential
	// (upstream runs it immediately before the session upgrade). It is only
	// reached here on a locally-valid attempt, so `valid` is true; a reject
	// surfaces as a 403 mfa_verification_rejected carrying the hook's message.
	if ok, herr := a.runMFAVerificationHook(ctx, mc.user.ID, factor.ID, factor.FactorType, true); herr != nil {
		return herr
	} else if !ok {
		return forbiddenError(ErrorCodeMFAVerificationRejected, "%s", DefaultMFAHookRejectionMessage)
	}

	var resp *AccessTokenResponse
	newlyVerified := false

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		now := a.now()

		if err := verifyChallenge(ctx, tx, challenge.ID, now); err != nil {
			return internalServerError("Database error verifying challenge").withInternal(err)
		}
		if store != nil {
			if err := store(ctx, tx, now); err != nil {
				return err
			}
		}
		if !factor.IsVerified() {
			if err := updateFactorStatus(ctx, tx, factor.ID, FactorStateVerified, now); err != nil {
				return internalServerError("Database error updating factor").withInternal(err)
			}
			factor.Status = FactorStateVerified
			newlyVerified = true
		}

		method, merr := factor.amrMethod()
		if merr != nil {
			return internalServerError("Error resolving AMR method").withInternal(merr)
		}
		if err := addAMRClaimToSession(ctx, tx, mc.sessionID, method, now); err != nil {
			return internalServerError("Database error adding AMR claim").withInternal(err)
		}

		// The session is now aal2 and belongs to this factor.
		if err := updateSessionAALAndFactor(ctx, tx, mc.sessionID, AAL2, &factor.ID); err != nil {
			return internalServerError("Failed to update session").withInternal(err)
		}

		// A brand new refresh token is issued so the AAL1 token the client is
		// holding can never be replayed into an AAL2 session (upstream
		// updateMFASessionAndClaims / GrantRefreshTokenSwap).
		current, err := findActiveRefreshTokenForSession(ctx, tx, mc.sessionID)
		if err != nil && !isNoRows(err) {
			return internalServerError("Error loading refresh token").withInternal(err)
		}
		next, err := newRefreshToken()
		if err != nil {
			return internalServerError("Error generating refresh token").withInternal(err)
		}
		parent := ""
		if current != nil {
			parent = current.Token
			if err := revokeRefreshToken(ctx, tx, current.ID, now); err != nil {
				return internalServerError("Error revoking refresh token").withInternal(err)
			}
		}
		if err := insertRefreshToken(ctx, tx, next, mc.user.ID, parent, mc.sessionID, now); err != nil {
			return internalServerError("Error creating refresh token").withInternal(err)
		}

		// Every OTHER session that never reached aal2 dies here.
		if err := invalidateSessionsWithAALLessThan(ctx, tx, mc.user.ID, AAL2); err != nil {
			return internalServerError("Failed to update sessions").withInternal(err)
		}
		if err := deleteUnverifiedFactors(ctx, tx, mc.user.ID, factor.FactorType); err != nil {
			return internalServerError("Error removing unverified factors").withInternal(err)
		}

		user, uerr := a.loadUserWithIdentities(ctx, tx, mc.user.ID)
		if uerr != nil {
			return internalServerError("Database error loading user").withInternal(uerr)
		}
		if lerr := a.loadFactors(ctx, tx, user); lerr != nil {
			return internalServerError("Database error loading factors").withInternal(lerr)
		}

		// "" derives the authentication method from the session, which is the
		// factor verified moments ago: its AMR claim was written above and is
		// now the session's newest.
		resp, err = a.buildSessionResponse(ctx, tx, user, mc.sessionID, next, "")
		return err
	}); err != nil {
		return err
	}

	if newlyVerified {
		a.notify(ctx, mc.user.Email, "A new MFA factor was added to your account",
			fmt.Sprintf("A %s factor was enrolled on your account.", factor.FactorType))
	}

	return sendJSON(w, http.StatusOK, resp)
}

// ---- unenroll --------------------------------------------------------------

func (a *api) unenrollFactor(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	mc, err := a.mfaContextOf(r)
	if err != nil {
		return err
	}
	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	factor, ferr := a.loadOwnedFactor(ctx, pool, mc.user, chi.URLParam(r, "factor_id"))
	if ferr != nil {
		return ferr
	}

	if factor.IsVerified() {
		aal, aerr := a.sessionAAL(ctx, pool, mc.sessionID)
		if aerr != nil {
			return aerr
		}
		if aal != AAL2 {
			return unprocessableEntityError(ErrorCodeInsufficientAAL, "AAL2 required to unenroll verified factor")
		}
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

// downgradeAndDeleteFactor removes a factor and applies upstream's
// Factor.DowngradeSessionsToAAL1 to every session it had upgraded.
//
// UPSTREAM BEHAVIOUR, made explicit: the sessions are NOT destroyed and their
// currently-issued (aal2) access tokens keep working until they expire. The
// downgrade takes effect on the next refresh — the AMR claim is gone, so
// computeAAL answers aal1 and the new JWT carries aal1 with `totp` dropped
// from `amr`.
func (a *api) downgradeAndDeleteFactor(ctx context.Context, tx querier, factor *Factor) error {
	method, merr := factor.amrMethod()
	if merr != nil {
		return internalServerError("Error resolving AMR method").withInternal(merr)
	}
	if err := deleteAMRClaimForFactorSessions(ctx, tx, factor.UserID, factor.ID, method); err != nil {
		return internalServerError("Database error downgrading sessions").withInternal(err)
	}
	if err := clearFactorAssociatedSessions(ctx, tx, factor.UserID, factor.ID); err != nil {
		return internalServerError("Database error downgrading sessions").withInternal(err)
	}
	// auth.sessions.factor_id has NO foreign key upstream (a session outlives a
	// deleted factor), so the order of these two statements is a choice, not a
	// constraint: the claims are cleared first so no window exists in which a
	// refresh could still mint aal2 from a factor that is on its way out.
	if err := deleteFactor(ctx, tx, factor.ID); err != nil {
		return internalServerError("Database error deleting factor").withInternal(err)
	}
	return nil
}

// ---- QR code ---------------------------------------------------------------

const qrCodeGenerationErrorMessage = "Error generating QR Code"

// qrBlockSize is upstream's DefaultQRSize.
const qrBlockSize = 3

// totpQRCodeSVG renders the otpauth:// URI as an SVG QR code.
//
// Upstream builds this with github.com/aaronarduino/goqrsvg over
// github.com/ajstarks/svgo and returns the RAW SVG document (not a data: URI —
// see the css-tricks link in upstream's source). Neither of those two modules
// is in go.mod and adding dependencies is out of scope for this change, so the
// twenty lines of SVG they emit are reproduced here byte-for-byte over
// github.com/boombuler/barcode/qr, which IS already required (transitively, by
// pquerna/otp). The response field is therefore identical to upstream's.
func totpQRCodeSVG(uri string) (string, error) {
	code, err := qr.Encode(uri, qr.H, qr.Auto)
	if err != nil {
		return "", err
	}
	width := code.Bounds().Max.X
	if width <= 0 {
		return "", errors.New("auth: empty QR code")
	}
	size := width*qrBlockSize + qrBlockSize*8

	var b strings.Builder
	fmt.Fprintf(&b, "<?xml version=\"1.0\"?>\n<!-- Generated by SVGo -->\n<svg width=\"%d\" height=\"%d\"", size, size)
	b.WriteString("\n     xmlns=\"http://www.w3.org/2000/svg\"\n     xmlns:xlink=\"http://www.w3.org/1999/xlink\">\n")

	// goqrsvg's "quiet zone": four blocks of margin on the top and left.
	currY := qrBlockSize * 4
	for x := 0; x < width; x++ {
		currX := qrBlockSize * 4
		for y := 0; y < width; y++ {
			switch code.At(x, y) {
			case color.Black:
				writeQRRect(&b, currX, currY, "black")
			case color.White:
				writeQRRect(&b, currX, currY, "white")
			}
			currX += qrBlockSize
		}
		currY += qrBlockSize
	}
	b.WriteString("</svg>\n")
	return b.String(), nil
}

func writeQRRect(b *strings.Builder, x, y int, fill string) {
	fmt.Fprintf(b, "<rect x=\"%d\" y=\"%d\" width=\"%d\" height=\"%d\" style=\"fill:%s;stroke:none\" />\n",
		x, y, qrBlockSize, qrBlockSize, fill)
}

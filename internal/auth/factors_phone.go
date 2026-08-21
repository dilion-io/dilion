package auth

// The phone (SMS) MFA factor: a second factor whose challenge delivers a
// one-time code over SMS and whose verify checks that code
// (upstream internal/api/mfa.go enrollPhoneFactor / challengePhoneFactor /
// verifyPhoneFactor).
//
//	POST /factors {factor_type:"phone", phone, friendly_name}
//	    -> gated by Config.MFA.Phone.EnrollEnabled; normalizes the number to
//	       E.164, stores it on auth.mfa_factors.phone.
//	POST /factors/{id}/challenge
//	    -> gated by Config.MFA.Phone.VerifyEnabled; mints an OTP
//	       (Config.MFA.PhoneOTPLength), stores its hash in
//	       auth.mfa_challenges.otp_code, delivers it through the SMS provider and
//	       stamps last_challenged_at.
//	POST /factors/{id}/verify {challenge_id, code}
//	    -> validates the OTP and upgrades the session to aal2, AMR method
//	       "mfa/phone" (see Factor.amrMethod / computeAAL).
//
// # Reuse of the SMS lifecycle
//
// The provider selection (smsProviderFor), template rendering (renderSMS) and
// number normalization (validatePhone / formatPhoneNumber) are smsflow.go's,
// called here rather than duplicated. smsflow.go itself is READ-ONLY for this
// change; its sendPhoneConfirmation is deliberately NOT reused because that path
// writes the OTP into the legacy auth.users columns and one_time_tokens (it is
// the phone SIGN-UP / phone-change lifecycle). An MFA phone challenge stores its
// OTP on the challenge row instead, exactly as upstream's CreatePhoneChallenge
// does, so the two lifecycles never collide over a user's confirmation_token.
//
// # Throttle
//
// Upstream throttles the challenge with Config.MFA.Phone.MaxFrequency. That knob
// is absent from Dilion's frozen MFA config (conf.go), so the challenge reuses
// the SMS-lifecycle throttle Config.SMS.MaxFrequency via checkSMSFrequency,
// measured against the factor's last_challenged_at. The 429 body is upstream's
// verbatim over_sms_send_rate_limit.

import (
	"crypto/subtle"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// enrollPhoneFactor implements POST /factors for factor_type "phone".
func (a *api) enrollPhoneFactor(w http.ResponseWriter, r *http.Request, mc *mfaContext, params *EnrollFactorParams) error {
	ctx := r.Context()

	phone, perr := validatePhone(params.Phone)
	if perr != nil {
		return perr
	}

	pool, derr := a.db(ctx)
	if derr != nil {
		return derr
	}
	name := trimName(params.FriendlyName)

	// Upstream: a phone factor is unique per (user, number). A VERIFIED factor on
	// that number is a hard error; an UNVERIFIED leftover from an abandoned
	// enrolment is deleted so the user can start over.
	existing, ferr := findFactorsByUserID(ctx, pool, mc.user.ID)
	if ferr != nil {
		return internalServerError("Database error loading factors").withInternal(ferr)
	}
	for _, f := range existing {
		if f.FactorType == FactorTypePhone && f.Phone == phone {
			if f.IsVerified() {
				return unprocessableEntityError(ErrorCodeMFAVerifiedFactorExists,
					"A verified phone factor already exists for this number, unenroll to continue")
			}
			if err := a.inTx(ctx, func(tx pgx.Tx) error { return deleteFactor(ctx, tx, f.ID) }); err != nil {
				return internalServerError("Database error deleting factor").withInternal(err)
			}
		}
	}

	if err := a.validateFactors(ctx, pool, mc, name); err != nil {
		return err
	}

	factor := &Factor{
		ID:           uuid.NewString(),
		UserID:       mc.user.ID,
		FriendlyName: name,
		FactorType:   FactorTypePhone,
		Status:       FactorStateUnverified,
		Phone:        phone,
	}

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		if err := insertFactor(ctx, tx, factor, a.now()); err != nil {
			if isUniqueViolation(err, "mfa_factors_user_friendly_name_unique") {
				return unprocessableEntityError(ErrorCodeMFAFactorNameConflict,
					"A factor with the friendly name %q for this user already exists", name)
			}
			if isUniqueViolation(err, "unique_phone_factor_per_user") {
				return unprocessableEntityError(ErrorCodeMFAVerifiedFactorExists,
					"A phone factor already exists for this number, unenroll to continue")
			}
			return internalServerError("Database error creating factor").withInternal(err)
		}
		return nil
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, &EnrollFactorResponse{
		ID:           factor.ID,
		Type:         FactorTypePhone,
		FriendlyName: factor.FriendlyName,
		Phone:        factor.Phone,
	})
}

// challengePhoneFactor implements POST /factors/{id}/challenge for a phone
// factor: it mints and delivers an SMS OTP and persists its hash on the
// challenge.
func (a *api) challengePhoneFactor(w http.ResponseWriter, r *http.Request, factor *Factor, params *ChallengeFactorParams) error {
	ctx := r.Context()

	channel := defaultChannel(params.Channel)
	if !a.isValidMessageChannel(channel) {
		return badRequestError(ErrorCodeValidationFailed, "%s", invalidChannelError)
	}

	// Per-user throttle against the factor's own last_challenged_at.
	if err := a.checkSMSFrequency(factor.LastChallengedAt); err != nil {
		return err
	}
	// Per-IP SMS budget, applied just before an OTP is minted (as smsflow does).
	if err := a.limitCheck(LimiterSMS, r); err != nil {
		return err
	}

	otp, oerr := generateOTP(a.cfg.MFA.PhoneOTPLength)
	if oerr != nil {
		return internalServerError("Error generating one-time token").withInternal(oerr)
	}
	otpHash := generateTokenHash(factor.Phone, otp)

	challenge := &mfaChallenge{
		ID:        uuid.NewString(),
		FactorID:  factor.ID,
		IPAddress: mfaClientIP(r),
	}

	// Persist-then-deliver inside one transaction, smsflow's ordering: a delivery
	// failure rolls the challenge back, so a delivered code never lacks a stored
	// hash and a stored hash never lacks a delivered code.
	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		now := a.now()
		if err := insertPhoneChallenge(ctx, tx, challenge, otpHash, now); err != nil {
			return internalServerError("Database error creating challenge").withInternal(err)
		}
		if _, err := touchFactorLastChallengedAt(ctx, tx, factor.ID, now); err != nil {
			return internalServerError("Database error updating factor").withInternal(err)
		}
		if _, derr := a.deliverSMS(ctx, factor.Phone, otp, "mfa", channel); derr != nil {
			return derr
		}
		return nil
	}); err != nil {
		return err
	}

	return sendJSON(w, http.StatusOK, &ChallengeFactorResponse{
		ID:        challenge.ID,
		Type:      factor.FactorType,
		ExpiresAt: challenge.expiryTime(a.cfg.MFA.PhoneOTPExp).Unix(),
	})
}

// verifyPhoneFactor implements POST /factors/{id}/verify for a phone factor.
func (a *api) verifyPhoneFactor(w http.ResponseWriter, r *http.Request, mc *mfaContext, factor *Factor, params *VerifyFactorParams) error {
	ctx := r.Context()
	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	if params.Code == "" {
		return badRequestError(ErrorCodeValidationFailed, "Code needs to be non-empty")
	}

	challenge, cerr := a.validateChallenge(ctx, r, pool, factor, params.ChallengeID, a.cfg.MFA.PhoneOTPExp)
	if cerr != nil {
		return cerr
	}

	stored, herr := findChallengeOTP(ctx, pool, challenge.ID)
	if herr != nil {
		return internalServerError("Database error loading challenge").withInternal(herr)
	}
	// Constant-time comparison of the token hashes: the OTP is bound to the
	// factor's number, so a code minted for one factor cannot be replayed to
	// another (generateTokenHash mixes the phone into the pre-image).
	got := generateTokenHash(factor.Phone, params.Code)
	if stored == "" || subtle.ConstantTimeCompare([]byte(got), []byte(stored)) != 1 {
		return unprocessableEntityError(ErrorCodeMFAVerificationFailed, "Invalid MFA phone code entered")
	}

	return a.finalizeFactorVerification(w, r, mc, factor, challenge, nil)
}

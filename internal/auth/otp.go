package auth

// POST /otp and POST /magiclink — passwordless sign-in by email.
//
// Reproduces github.com/supabase/auth/internal/api/otp.go and magic_link.go.
//
//	POST /otp       {email, create_user?, data?, code_challenge?, code_challenge_method?}
//	POST /magiclink {email, data?, code_challenge?, code_challenge_method?}   (legacy alias)
//
// Both answer `{}` with 200 whatever happens, so neither can be used to find out
// which addresses have accounts. The mail carries BOTH a link and the OTP
// itself, so a client may either open the link (-> GET /verify) or post the code
// back (-> POST /verify {type:"magiclink"|"email", email, token}).
//
// POST /otp also carries the SMS half of the endpoint (upstream's SmsOtp):
//
//	POST /otp {phone, create_user?, data?, channel?}
//	-> 200 {"message_id": "..."}   (or {} — see smsOTP)
//
// The SMS carries the OTP alone; there is no link, so the code comes back as
// POST /verify {type:"sms", phone, token}.

import (
	"context"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dilion-io/dilion/ports"
)

func init() {
	registerFeature("otp", func(a *api, r chi.Router) {
		r.With(a.limit(LimiterOTP)).Post("/otp", a.handle(a.otp))
		r.With(a.limit(LimiterMagicLink)).Post("/magiclink", a.handle(a.magicLink))
	})
}

// OtpParams is the POST /otp body (upstream api.OtpParams).
type OtpParams struct {
	Email      string         `json:"email"`
	Phone      string         `json:"phone"`
	CreateUser bool           `json:"create_user"`
	Data       map[string]any `json:"data"`
	Channel    string         `json:"channel"`

	CodeChallengeMethod string `json:"code_challenge_method"`
	CodeChallenge       string `json:"code_challenge"`

	// RedirectTo is not an upstream body field (upstream reads redirect_to from
	// the query string / Referer); it is accepted here as well because several
	// client libraries send it in the body.
	RedirectTo string `json:"redirect_to"`
}

// MagicLinkParams is the POST /magiclink body (upstream api.MagicLinkParams).
type MagicLinkParams struct {
	Email               string         `json:"email"`
	Data                map[string]any `json:"data"`
	CodeChallengeMethod string         `json:"code_challenge_method"`
	CodeChallenge       string         `json:"code_challenge"`
	RedirectTo          string         `json:"redirect_to"`
}

// otp implements POST /otp: upstream's Otp, which is a router between the email
// (magic link / email OTP) and the phone (SMS OTP) paths.
func (a *api) otp(w http.ResponseWriter, r *http.Request) error {
	// CAPTCHA first (captcha.go): /otp both sends mail and, with create_user
	// on, creates accounts.
	if cerr := a.verifyCaptcha(r); cerr != nil {
		return cerr
	}

	// Upstream defaults create_user to TRUE before decoding, so an absent field
	// means "sign this address up".
	params := &OtpParams{CreateUser: true}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	params.Email = strings.ToLower(strings.TrimSpace(params.Email))
	params.Phone = strings.TrimSpace(params.Phone)

	if params.Email != "" && params.Phone != "" {
		return badRequestError(ErrorCodeValidationFailed, "Only an email address or phone number should be provided")
	}
	if params.Email != "" && params.Channel != "" {
		return badRequestError(ErrorCodeValidationFailed, "Channel should only be specified with Phone OTP")
	}
	if err := validatePKCEParams(params.CodeChallengeMethod, params.CodeChallenge); err != nil {
		return err
	}
	if params.Phone != "" {
		return a.smsOTP(w, r, params)
	}
	if params.Email == "" {
		return badRequestError(ErrorCodeValidationFailed, "One of email or phone must be set")
	}
	if _, err := mail.ParseAddress(params.Email); err != nil {
		return badRequestError(ErrorCodeValidationFailed, "Unable to validate email address: invalid format")
	}

	// create_user=false only sends to addresses that already have an account.
	if !params.CreateUser {
		pool, perr := a.db(r.Context())
		if perr != nil {
			return perr
		}
		_, ferr := findUserByEmail(r.Context(), pool, params.Email, requestAud(r))
		if ferr != nil {
			if isNoRows(ferr) {
				return unprocessableEntityError(ErrorCodeOTPDisabled, "Signups not allowed for otp")
			}
			return internalServerError("Database error finding user").withInternal(ferr)
		}
	}

	return a.sendMagicLinkTo(w, r, &MagicLinkParams{
		Email:               params.Email,
		Data:                params.Data,
		CodeChallengeMethod: params.CodeChallengeMethod,
		CodeChallenge:       params.CodeChallenge,
		RedirectTo:          params.RedirectTo,
	})
}

// magicLink implements POST /magiclink, the legacy alias supabase-js still uses.
func (a *api) magicLink(w http.ResponseWriter, r *http.Request) error {
	// CAPTCHA first (captcha.go).
	if cerr := a.verifyCaptcha(r); cerr != nil {
		return cerr
	}

	params := &MagicLinkParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}
	params.Email = strings.ToLower(strings.TrimSpace(params.Email))
	if params.Email == "" {
		return unprocessableEntityError(ErrorCodeValidationFailed, "Password recovery requires an email")
	}
	if _, err := mail.ParseAddress(params.Email); err != nil {
		return badRequestError(ErrorCodeValidationFailed, "Unable to validate email address: invalid format")
	}
	if err := validatePKCEParams(params.CodeChallengeMethod, params.CodeChallenge); err != nil {
		return err
	}
	return a.sendMagicLinkTo(w, r, params)
}

// sendMagicLinkTo is upstream's MagicLink handler.
//
// A magic link for an address with NO account (or with an unconfirmed one) is a
// signup: upstream creates the account with a random password and then, when
// Mailer.Autoconfirm is on, mails the magic link; when confirmation is required
// it mails the CONFIRMATION instead, because that link already logs the user in.
func (a *api) sendMagicLinkTo(w http.ResponseWriter, r *http.Request, params *MagicLinkParams) error {
	ctx := r.Context()

	if !a.cfg.External[ProviderEmail].Enabled {
		return unprocessableEntityError(ErrorCodeEmailProviderDisabled, "Email logins are disabled")
	}
	if params.Data == nil {
		params.Data = map[string]any{}
	}
	pkce := isPKCERequest(params.CodeChallenge)
	aud := requestAud(r)
	redirectTo := params.RedirectTo
	if redirectTo == "" {
		redirectTo = redirectToOf(r)
	}

	pool, perr := a.db(ctx)
	if perr != nil {
		return perr
	}
	existing, err := findUserByEmail(ctx, pool, params.Email, aud)
	if err != nil && !isNoRows(err) {
		return internalServerError("Database error finding user").withInternal(err)
	}
	isNewUser := existing == nil || existing.EmailConfirmedAt == nil

	// Creating an account needs the validating BeforeSignup hook and a password
	// hash, both of which must happen outside the transaction.
	var hashed string
	if isNewUser && existing == nil {
		if a.cfg.DisableSignup {
			return unprocessableEntityError(ErrorCodeSignupDisabled, "Signups not allowed for this instance")
		}
		h, data, herr := a.prepareEmailUser(ctx, params.Email, params.Data)
		if herr != nil {
			return herr
		}
		hashed, params.Data = h, data
	}

	now := a.now()
	created := false
	var user *User

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		user = existing
		if user == nil {
			var cerr error
			user, cerr = a.insertEmailUser(ctx, tx, params.Email, aud, hashed, params.Data, a.cfg.Mailer.Autoconfirm, now)
			if cerr != nil {
				return cerr
			}
			created = true
		}

		authMethod := authMethodMagicLink
		if isNewUser && !a.cfg.Mailer.Autoconfirm {
			authMethod = authMethodEmailSignup
		}
		if pkce {
			if _, ferr := createFlowState(ctx, tx, authMethod, authMethod,
				params.CodeChallengeMethod, params.CodeChallenge, user.ID, now); ferr != nil {
				return internalServerError("Error creating flow state").withInternal(ferr)
			}
		}

		if isNewUser && !a.cfg.Mailer.Autoconfirm {
			// The confirmation mail IS the magic link for a fresh account.
			_, serr := a.sendConfirmation(ctx, tx, r, user, redirectTo, pkce)
			return serr
		}
		_, serr := a.sendMagicLink(ctx, tx, r, user, redirectTo, pkce)
		return serr
	}); err != nil {
		return err
	}

	if created {
		a.observeHook(ctx, ports.AfterSignup, map[string]any{
			"user_id":    user.ID,
			"email":      user.Email,
			"provider":   ProviderEmail,
			"project_id": DefaultProjectID,
		})
	}

	// Upstream always answers with an empty object, whether or not anything was
	// sent: the endpoint must not reveal which addresses exist.
	return sendJSON(w, http.StatusOK, map[string]string{})
}

// ---- SMS OTP ---------------------------------------------------------------

// smsOTP is upstream's SmsOtp: passwordless sign-in (and sign-up) by phone.
//
// An OTP for a number with NO account — or with an unconfirmed one — is a
// SIGNUP. Upstream implements that by re-entering its own /signup handler with
// a rewritten body and a fake ResponseWriter; Dilion does the same work
// directly, which is the only structural difference between the two.
//
// The response shape is upstream's, including the quirk that a signup answers
// with a bare `{}` while an OTP to an established account answers with the
// provider's `{"message_id": ...}`:
//
//	established account                     -> {"message_id": "..."}
//	new/unconfirmed + SMS.Autoconfirm off   -> {}
//	new/unconfirmed + SMS.Autoconfirm on    -> the number is confirmed on the
//	                                           spot and the OTP still goes out,
//	                                           so -> {"message_id": "..."}
//
// `create_user: false` restricts the endpoint to numbers that already have an
// account; anything else answers 422 otp_disabled.
func (a *api) smsOTP(w http.ResponseWriter, r *http.Request, params *OtpParams) error {
	ctx := r.Context()

	if !a.phoneProviderEnabled() {
		return badRequestError(ErrorCodePhoneProviderDisabled, "Unsupported phone provider")
	}
	params.Channel = defaultChannel(params.Channel)
	if !a.isValidMessageChannel(params.Channel) {
		return badRequestError(ErrorCodeValidationFailed, "%s", invalidChannelError)
	}
	phone, perr := validatePhone(params.Phone)
	if perr != nil {
		return perr
	}
	params.Phone = phone
	if params.Data == nil {
		params.Data = map[string]any{}
	}

	aud := requestAud(r)
	pool, dberr := a.db(ctx)
	if dberr != nil {
		return dberr
	}
	existing, ferr := findUserByPhone(ctx, pool, phone, aud)
	if ferr != nil && !isNoRows(ferr) {
		return internalServerError("Database error finding user").withInternal(ferr)
	}

	if !params.CreateUser && existing == nil {
		return unprocessableEntityError(ErrorCodeOTPDisabled, "Signups not allowed for otp")
	}

	// "New" covers a number that has never signed up AND one whose signup was
	// never finished — neither has proven ownership, so both are re-signed-up.
	isNewUser := existing == nil || existing.PhoneConfirmedAt == nil

	// Account creation needs the validating BeforeSignup hook and a password
	// hash, both of which must happen outside the transaction.
	var hashed string
	if existing == nil {
		if a.cfg.DisableSignup {
			return unprocessableEntityError(ErrorCodeSignupDisabled, "Signups not allowed for this instance")
		}
		h, data, herr := a.preparePhoneUser(ctx, phone, params.Data)
		if herr != nil {
			return herr
		}
		hashed, params.Data = h, data
	}

	now := a.now()
	created := false
	messageID := ""
	var user *User

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		user = existing
		if user == nil {
			var cerr error
			user, cerr = a.insertPhoneUser(ctx, tx, phone, aud, hashed, params.Data, a.cfg.SMS.Autoconfirm, now)
			if cerr != nil {
				return cerr
			}
			created = true
		} else if isNewUser && a.cfg.SMS.Autoconfirm {
			// An abandoned signup, now that autoconfirm is on: upstream's
			// Signup confirms it before the OTP goes out.
			confirmed, cerr := a.confirmPhone(ctx, tx, user)
			if cerr != nil {
				return cerr
			}
			user = confirmed
		}

		mID, serr := a.sendPhoneConfirmation(ctx, tx, r, user, phone, phoneConfirmationOTP, params.Channel)
		if serr != nil {
			return serr
		}
		messageID = mID
		return nil
	}); err != nil {
		return err
	}

	if created {
		a.observeHook(ctx, ports.AfterSignup, map[string]any{
			"user_id":    user.ID,
			"email":      "",
			"phone":      user.Phone,
			"provider":   ProviderPhone,
			"project_id": DefaultProjectID,
		})
	}

	if isNewUser && !a.cfg.SMS.Autoconfirm {
		// Upstream answers a signup with an empty object and withholds the
		// provider message id.
		return sendJSON(w, http.StatusOK, map[string]any{})
	}
	return sendJSON(w, http.StatusOK, smsResponse(messageID))
}

// ---- shared account creation ----------------------------------------------

// prepareEmailUser runs the validating BeforeSignup hook and hashes a random
// password. It MUST be called outside a transaction: password hashing is
// deliberately slow and a hook may call out over the network.
//
// The password is random and never disclosed — an account created by a magic
// link, an invite or a generated link has no password the user knows, which is
// exactly upstream's behaviour (they later set one through PUT /user).
func (a *api) prepareEmailUser(ctx context.Context, email string, data map[string]any) (string, map[string]any, error) {
	if data == nil {
		data = map[string]any{}
	}
	payload, err := a.runHook(ctx, ports.BeforeSignup, map[string]any{
		"provider":      ProviderEmail,
		"email":         email,
		"phone":         "",
		"user_metadata": data,
		"project_id":    DefaultProjectID,
	})
	if err != nil {
		return "", nil, unprocessableEntityError(ErrorCodeSignupDisabled, "Signup rejected: %v", err)
	}
	if v, ok := payload["user_metadata"].(map[string]any); ok && v != nil {
		data = v
	}

	random, err := newRefreshToken()
	if err != nil {
		return "", nil, internalServerError("Error generating password").withInternal(err)
	}
	hashed, err := HashPassword(random)
	if err != nil {
		return "", nil, internalServerError("Error hashing password").withInternal(err)
	}
	return hashed, data, nil
}

// insertEmailUser creates the user row plus its email identity inside the
// caller's transaction. `confirmed` mirrors Mailer.Autoconfirm.
func (a *api) insertEmailUser(ctx context.Context, tx querier, email, aud, hashedPassword string,
	data map[string]any, confirmed bool, now time.Time) (*User, error) {

	var confirmedAt *time.Time
	if confirmed {
		confirmedAt = &now
	}
	var password *string
	if hashedPassword != "" {
		password = &hashedPassword
	}

	user, err := insertUser(ctx, tx, newUserParams{
		ID:                uuid.NewString(),
		Aud:               aud,
		Role:              RoleAuthenticated,
		Email:             email,
		EncryptedPassword: password,
		EmailConfirmedAt:  confirmedAt,
		AppMetaData:       JSONMap{"provider": ProviderEmail, "providers": []any{ProviderEmail}},
		UserMetaData:      JSONMap(data),
		Now:               now,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return nil, unprocessableEntityError(ErrorCodeUserAlreadyExists, "User already registered")
		}
		return nil, internalServerError("Database error saving new user").withInternal(err)
	}

	identityData := JSONMap{
		"sub":            user.ID,
		"email":          email,
		"email_verified": confirmed,
		"phone_verified": false,
	}
	if err := insertIdentity(ctx, tx, user.ID, ProviderEmail, user.ID, identityData, now); err != nil {
		return nil, internalServerError("Error creating identity").withInternal(err)
	}
	ids, err := findIdentitiesByUserID(ctx, tx, user.ID)
	if err != nil {
		return nil, internalServerError("Error loading identities").withInternal(err)
	}
	user.Identities = ids
	return user, nil
}

package auth

import (
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/dilion-io/dilion/ports"
)

// ProviderEmail is the identity provider used for email/password accounts.
const ProviderEmail = "email"

// ProviderAnonymous is the app_metadata provider of an anonymous user
// (upstream api.AnonymousProvider).
const ProviderAnonymous = "anonymous"

// SignupParams is the POST /signup body (wave-1 subset of upstream's).
type SignupParams struct {
	Email    string         `json:"email"`
	Phone    string         `json:"phone"`
	Password string         `json:"password"`
	Data     map[string]any `json:"data"`
	Channel  string         `json:"channel"` // "sms" (default) or "whatsapp"

	// CodeChallenge / CodeChallengeMethod turn the signup into a PKCE flow
	// (pkce.go): a flow_state row is created alongside the user and the mailed
	// confirmation token is prefixed "pkce_", so following the link redirects
	// to `?code=<auth_code>` instead of dropping tokens in the URL fragment.
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// signup implements POST /signup.
//
// The response is one of the two shapes openapi.yaml declares for the 200 body
// (oneOf[AccessTokenResponseSchema, UserSchema]), chosen exactly as upstream
// chooses it:
//
//	Mailer.Autoconfirm = true   -> the account is usable at once, answer with a
//	                               full session (AccessTokenResponse)
//	Mailer.Autoconfirm = false  -> email_confirmed_at stays NULL, a confirmation
//	                               mail goes out, answer with the bare user
//	                               object and NO session; the account becomes
//	                               usable through /verify
//
// A repeated signup is answered without revealing whether the address is taken:
// upstream returns 422 user_already_exists only when the account is already
// CONFIRMED and autoconfirm is on; with confirmation pending it re-sends the
// mail (or, for an already-registered confirmed address, returns a fabricated
// user object — sanitizedSignupUser below).
func (a *api) signup(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	// CAPTCHA first: it is the guard that keeps this endpoint from being used
	// to mint accounts in bulk, so it runs before anything is parsed or looked
	// up (captcha.go; upstream runs it as middleware in front of the route).
	if cerr := a.verifyCaptcha(r); cerr != nil {
		return cerr
	}

	params := &SignupParams{}
	if err := decodeBody(r, params); err != nil {
		return err
	}

	params.Email = strings.ToLower(strings.TrimSpace(params.Email))
	params.Phone = strings.TrimSpace(params.Phone)

	// Neither identifier: this is an anonymous sign-in (upstream routes it the
	// same way, inside the /signup handler).
	if params.Email == "" && params.Phone == "" {
		if !a.cfg.AnonymousUsersEnabled {
			return unprocessableEntityError(ErrorCodeAnonymousProviderDisabled, "Anonymous sign-ins are disabled")
		}
		if lerr := a.limitCheck(LimiterAnonymous, r); lerr != nil {
			return lerr
		}
		return a.signupAnonymously(w, r, params)
	}

	if lerr := a.limitCheck(LimiterSignup, r); lerr != nil {
		return lerr
	}
	if a.cfg.DisableSignup {
		return unprocessableEntityError(ErrorCodeSignupDisabled, "Signups not allowed for this instance")
	}
	if params.Email != "" && params.Phone != "" {
		return badRequestError(ErrorCodeValidationFailed,
			"Only an email address or phone number should be provided on signup.")
	}
	if params.Phone != "" {
		return a.signupWithPhone(w, r, params)
	}
	if _, err := mail.ParseAddress(params.Email); err != nil {
		return badRequestError(ErrorCodeValidationFailed, "Unable to validate email address: invalid format")
	}
	if params.Password == "" {
		return badRequestError(ErrorCodeValidationFailed, "Signup requires a valid password")
	}
	if herr := a.checkPasswordStrength(ctx, params.Password); herr != nil {
		return herr
	}
	if params.Data == nil {
		params.Data = map[string]any{}
	}

	aud := requestAud(r)

	// BeforeSignup is a validating hook: it may reject the signup, and may
	// rewrite the email / user_metadata that get persisted.
	hookPayload, err := a.runHook(ctx, ports.BeforeSignup, map[string]any{
		"provider":      ProviderEmail,
		"email":         params.Email,
		"phone":         "",
		"user_metadata": params.Data,
	})
	if err != nil {
		return unprocessableEntityError(ErrorCodeSignupDisabled, "Signup rejected: %v", err)
	}
	if v, ok := hookPayload["email"].(string); ok && v != "" {
		params.Email = strings.ToLower(strings.TrimSpace(v))
	}
	if v, ok := hookPayload["user_metadata"].(map[string]any); ok && v != nil {
		params.Data = v
	}

	hashed, err := HashPassword(params.Password)
	if err != nil {
		return internalServerError("Error hashing password").withInternal(err)
	}

	// A code_challenge turns this into a PKCE signup (pkce.go).
	if perr := validatePKCEParams(params.CodeChallengeMethod, params.CodeChallenge); perr != nil {
		return perr
	}
	pkce := isPKCERequest(params.CodeChallenge)

	now := a.now()
	var (
		user      *User
		session   *AccessTokenResponse
		created   bool
		sanitized *User
	)

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		existing, ferr := findUserByEmail(ctx, tx, params.Email, aud)
		if ferr != nil && !isNoRows(ferr) {
			return internalServerError("Database error finding user").withInternal(ferr)
		}

		switch {
		case existing != nil && existing.EmailConfirmedAt != nil:
			// Already a real account. With autoconfirm on there is nothing to
			// hide (the address is provably in use, because it was usable the
			// moment it signed up); with confirmation required, upstream hands
			// back a FABRICATED user so a signup form cannot be used to
			// enumerate registered addresses.
			if a.cfg.Mailer.Autoconfirm {
				return unprocessableEntityError(ErrorCodeUserAlreadyExists, "User already registered")
			}
			sanitized = sanitizedSignupUser(params, aud, now)
			return nil

		case existing != nil:
			// Signup repeated while confirmation is still pending: upstream
			// does NOT touch the existing row (the caller has not proven they
			// own the address) and just re-sends the confirmation.
			user = existing

		default:
			var cerr error
			confirmedAt := &now
			if !a.cfg.Mailer.Autoconfirm {
				confirmedAt = nil
			}
			user, cerr = insertUser(ctx, tx, newUserParams{
				ID:                uuid.NewString(),
				Aud:               aud,
				Role:              RoleAuthenticated,
				Email:             params.Email,
				EncryptedPassword: ptr(hashed),
				EmailConfirmedAt:  confirmedAt,
				AppMetaData:       JSONMap{"provider": ProviderEmail, "providers": []any{ProviderEmail}},
				UserMetaData:      JSONMap(params.Data),
				Now:               now,
			})
			if cerr != nil {
				if isUniqueViolation(cerr) {
					return unprocessableEntityError(ErrorCodeUserAlreadyExists, "User already registered")
				}
				return internalServerError("Database error saving new user").withInternal(cerr)
			}
			created = true

			identityData := JSONMap{
				"sub":            user.ID,
				"email":          params.Email,
				"email_verified": a.cfg.Mailer.Autoconfirm,
				"phone_verified": false,
			}
			if ierr := insertIdentity(ctx, tx, user.ID, ProviderEmail, user.ID, identityData, now); ierr != nil {
				return internalServerError("Error creating identity").withInternal(ierr)
			}
		}

		ids, ierr := findIdentitiesByUserID(ctx, tx, user.ID)
		if ierr != nil {
			return internalServerError("Error loading identities").withInternal(ierr)
		}
		user.Identities = ids

		if a.cfg.Mailer.Autoconfirm {
			session, err = a.grantSession(ctx, tx, user, r, "password")
			return err
		}

		// Confirmation required: no session is issued. The account exists but
		// email_confirmed_at is NULL until /verify is followed.
		if pkce {
			if _, ferr := createFlowState(ctx, tx, ProviderEmail, authMethodEmailSignup,
				params.CodeChallengeMethod, params.CodeChallenge, user.ID, now); ferr != nil {
				return internalServerError("Error creating flow state").withInternal(ferr)
			}
		}
		if _, serr := a.sendConfirmation(ctx, tx, r, user, redirectToOf(r), pkce); serr != nil {
			return serr
		}
		refreshed, rerr := a.loadUserWithIdentities(ctx, tx, user.ID)
		if rerr != nil {
			return internalServerError("Error refetching user").withInternal(rerr)
		}
		user = refreshed
		return nil
	}); err != nil {
		return err
	}

	if sanitized != nil {
		return sendJSON(w, http.StatusOK, sanitized)
	}

	if created {
		a.observeHook(ctx, ports.AfterSignup, map[string]any{
			"user_id":  user.ID,
			"email":    user.Email,
			"provider": ProviderEmail,
		})
	}

	if session != nil {
		return sendJSON(w, http.StatusOK, session)
	}
	return sendJSON(w, http.StatusOK, user)
}

// signupWithPhone implements the phone half of POST /signup — upstream's Signup
// with params.Provider == PhoneProvider.
//
// The response is chosen exactly as the email path chooses it, with SMS.Autoconfirm
// standing in for Mailer.Autoconfirm:
//
//	SMS.Autoconfirm = true   -> phone_confirmed_at is stamped at once and the
//	                            answer is a full session (AccessTokenResponse)
//	SMS.Autoconfirm = false  -> phone_confirmed_at stays NULL, an OTP is texted,
//	                            and the answer is the bare user object with NO
//	                            session; the account becomes usable through
//	                            POST /verify {type:"sms", phone, token}
//
// A repeat signup for an already CONFIRMED number is answered the same way the
// email path answers one: 422 user_already_exists when autoconfirm is on (the
// number is provably in use either way), a FABRICATED user object otherwise, so
// the endpoint cannot be used to enumerate registered numbers.
//
// # Deviations from upstream
//
//   - A PASSWORD IS REQUIRED. Upstream accepts a phone signup with an empty
//     password and stores a hash of "", which then satisfies
//     grant_type=password with an empty password. Dilion requires one, matching
//     its email path. Passwordless phone sign-in is POST /otp, which mints a
//     random password internally.
//
//   - IDENTITY DATA. See phoneIdentityData (smsflow.go).
func (a *api) signupWithPhone(w http.ResponseWriter, r *http.Request, params *SignupParams) error {
	ctx := r.Context()

	if !a.phoneProviderEnabled() {
		return badRequestError(ErrorCodePhoneProviderDisabled, "Phone signups are disabled")
	}
	// Upstream refuses PKCE here: a phone signup already returns the session in
	// the body, so there would be nothing for a code exchange to hand over.
	if params.CodeChallenge != "" {
		return badRequestError(ErrorCodeValidationFailed, "PKCE not supported for phone signups")
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

	if params.Password == "" {
		return badRequestError(ErrorCodeValidationFailed, "Signup requires a valid password")
	}
	if herr := a.checkPasswordStrength(ctx, params.Password); herr != nil {
		return herr
	}
	if params.Data == nil {
		params.Data = map[string]any{}
	}

	aud := requestAud(r)

	// BeforeSignup is validating: it may reject the signup and may rewrite the
	// phone / user_metadata that get persisted.
	hookPayload, err := a.runHook(ctx, ports.BeforeSignup, map[string]any{
		"provider":      ProviderPhone,
		"email":         "",
		"phone":         phone,
		"user_metadata": params.Data,
	})
	if err != nil {
		return unprocessableEntityError(ErrorCodeSignupDisabled, "Signup rejected: %v", err)
	}
	if v, ok := hookPayload["phone"].(string); ok && v != "" {
		normalized, verr := validatePhone(v)
		if verr != nil {
			return verr
		}
		phone, params.Phone = normalized, normalized
	}
	if v, ok := hookPayload["user_metadata"].(map[string]any); ok && v != nil {
		params.Data = v
	}

	hashed, err := HashPassword(params.Password)
	if err != nil {
		return internalServerError("Error hashing password").withInternal(err)
	}

	now := a.now()
	var (
		user      *User
		session   *AccessTokenResponse
		created   bool
		sanitized *User
	)

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		existing, ferr := findUserByPhone(ctx, tx, phone, aud)
		if ferr != nil && !isNoRows(ferr) {
			return internalServerError("Database error finding user").withInternal(ferr)
		}

		switch {
		case existing != nil && existing.PhoneConfirmedAt != nil:
			if a.cfg.SMS.Autoconfirm {
				return unprocessableEntityError(ErrorCodeUserAlreadyExists, "User already registered")
			}
			sanitized = sanitizedPhoneSignupUser(params, aud, now)
			return nil

		case existing != nil:
			// Signup repeated while confirmation is still pending: upstream
			// leaves the row untouched (the caller has not proven the number is
			// theirs) and just re-sends the OTP.
			user = existing

		default:
			var cerr error
			user, cerr = a.insertPhoneUser(ctx, tx, phone, aud, hashed, params.Data, a.cfg.SMS.Autoconfirm, now)
			if cerr != nil {
				return cerr
			}
			created = true
		}

		ids, ierr := findIdentitiesByUserID(ctx, tx, user.ID)
		if ierr != nil {
			return internalServerError("Error loading identities").withInternal(ierr)
		}
		user.Identities = ids

		if a.cfg.SMS.Autoconfirm {
			// A pre-existing unconfirmed row (a signup that was abandoned while
			// autoconfirm was off) is confirmed now, upstream's ConfirmPhone.
			if user.PhoneConfirmedAt == nil {
				confirmed, cerr := a.confirmPhone(ctx, tx, user)
				if cerr != nil {
					return cerr
				}
				user = confirmed
			}
			var gerr error
			session, gerr = a.grantSession(ctx, tx, user, r, "password")
			return gerr
		}

		if _, serr := a.sendPhoneConfirmation(ctx, tx, r, user, phone, phoneConfirmationOTP, params.Channel); serr != nil {
			return serr
		}
		refreshed, rerr := a.loadUserWithIdentities(ctx, tx, user.ID)
		if rerr != nil {
			return internalServerError("Error refetching user").withInternal(rerr)
		}
		user = refreshed
		return nil
	}); err != nil {
		return err
	}

	if sanitized != nil {
		return sendJSON(w, http.StatusOK, sanitized)
	}
	if created {
		a.observeHook(ctx, ports.AfterSignup, map[string]any{
			"user_id":  user.ID,
			"email":    "",
			"phone":    user.Phone,
			"provider": ProviderPhone,
		})
	}
	if session != nil {
		return sendJSON(w, http.StatusOK, session)
	}
	return sendJSON(w, http.StatusOK, user)
}

// sanitizedPhoneSignupUser is sanitizedSignupUser for the phone provider: a
// FABRICATED user object returned when a confirmation-required signup targets a
// number that is already registered (upstream sanitizeUser, PhoneProvider case
// — note that it keeps the phone and blanks the email).
func sanitizedPhoneSignupUser(params *SignupParams, aud string, now time.Time) *User {
	return &User{
		ID:                 uuid.NewString(),
		Aud:                aud,
		Phone:              params.Phone,
		ConfirmationSentAt: &now,
		AppMetaData:        JSONMap{"provider": ProviderPhone, "providers": []any{ProviderPhone}},
		UserMetaData:       JSONMap(params.Data),
		Identities:         []Identity{},
		CreatedAt:          now,
		UpdatedAt:          now,
	}
}

// redirectToOf reads the redirect_to a mail-sending request asked for. Upstream
// accepts it in the body and in the query string; the value is validated against
// the allow-list later (Config.RedirectURLOrSiteURL).
func redirectToOf(r *http.Request) string {
	return r.URL.Query().Get("redirect_to")
}

// sanitizedSignupUser is upstream's sanitizeUser: a plausible but FABRICATED
// user object returned when a confirmation-required signup targets an address
// that is already registered. It carries a fresh random id, the submitted
// metadata, no identities and no timestamps that would betray the real account.
func sanitizedSignupUser(params *SignupParams, aud string, now time.Time) *User {
	return &User{
		ID:                 uuid.NewString(),
		Aud:                aud,
		Email:              params.Email,
		ConfirmationSentAt: &now,
		AppMetaData:        JSONMap{"provider": ProviderEmail, "providers": []any{ProviderEmail}},
		UserMetaData:       JSONMap(params.Data),
		Identities:         []Identity{},
		CreatedAt:          now,
		UpdatedAt:          now,
	}
}

// signupAnonymously implements POST /signup with neither an email nor a phone
// number: upstream's SignupAnonymously. It creates a user row with
// is_anonymous = true, no identity and no password, and hands back a full
// session — the access token carries `is_anonymous: true` (issueAccessToken), so
// RLS policies can tell anonymous users apart from real ones.
//
// The account can later be "upgraded" by adding an email/phone through
// PUT /user, which is when is_anonymous drops to false.
func (a *api) signupAnonymously(w http.ResponseWriter, r *http.Request, params *SignupParams) error {
	ctx := r.Context()

	if a.cfg.DisableSignup {
		return unprocessableEntityError(ErrorCodeSignupDisabled, "Signups not allowed for this instance")
	}
	if params.Data == nil {
		params.Data = map[string]any{}
	}

	aud := requestAud(r)

	// BeforeSignup may still reject an anonymous sign-in (abuse controls) and
	// may rewrite user_metadata.
	hookPayload, err := a.runHook(ctx, ports.BeforeSignup, map[string]any{
		"provider":      ProviderAnonymous,
		"email":         "",
		"phone":         "",
		"user_metadata": params.Data,
	})
	if err != nil {
		return unprocessableEntityError(ErrorCodeSignupDisabled, "Signup rejected: %v", err)
	}
	if v, ok := hookPayload["user_metadata"].(map[string]any); ok && v != nil {
		params.Data = v
	}

	now := a.now()
	var (
		user    *User
		session *AccessTokenResponse
	)

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		var cerr error
		user, cerr = insertUser(ctx, tx, newUserParams{
			ID:           uuid.NewString(),
			Aud:          aud,
			Role:         RoleAuthenticated,
			AppMetaData:  JSONMap{"provider": ProviderAnonymous, "providers": []any{ProviderAnonymous}},
			UserMetaData: JSONMap(params.Data),
			IsAnonymous:  true,
			Now:          now,
		})
		if cerr != nil {
			return internalServerError("Database error creating anonymous user").withInternal(cerr)
		}
		user.Identities = []Identity{}

		var gerr error
		session, gerr = a.grantSession(ctx, tx, user, r, "anonymous")
		return gerr
	}); err != nil {
		return err
	}

	a.observeHook(ctx, ports.AfterSignup, map[string]any{
		"user_id":  user.ID,
		"email":    "",
		"provider": ProviderAnonymous,
	})

	return sendJSON(w, http.StatusOK, session)
}

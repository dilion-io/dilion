package auth

// GET/POST /verify — redeeming an email link or a typed OTP.
//
// Reproduces github.com/supabase/auth/internal/api/verify.go.
//
// # The two shapes of a redemption
//
//	POST /verify {"type":"...", "email":"a@b.c", "token":"123456"}   typed OTP
//	POST /verify {"type":"...", "token_hash":"<hash>"}               hashed token
//	GET  /verify?token=<hash>&type=<t>&redirect_to=<r>               clicked link
//
// POST answers with a session (the gotrue AccessTokenResponse). GET always
// REDIRECTS, because a link is opened by a browser:
//
//	implicit flow -> 303 <redirect_to>#access_token=...&refresh_token=...&type=...
//	PKCE flow     -> 303 <redirect_to>?code=<auth_code>
//	failure       -> 303 <redirect_to>#error=...&error_code=...&error_description=...
//	                 (PKCE additionally repeats error_code/error_description in the
//	                  query string, upstream prepErrorRedirectURL)
//
// redirect_to is ALWAYS run through Config.IsRedirectAllowed and falls back to
// SiteURL — an open redirect here would hand an attacker the tokens in the
// fragment.

import (
	"context"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

func init() {
	registerFeature("verify", func(a *api, r chi.Router) {
		r.With(a.limit(LimiterVerify)).Get("/verify", a.handle(a.verify))
		r.With(a.limit(LimiterVerify)).Post("/verify", a.handle(a.verify))
	})
}

// email_change_confirm_status values (upstream zeroConfirmation /
// singleConfirmation).
const (
	zeroConfirmation   = 0
	singleConfirmation = 1
)

// singleConfirmationAccepted is upstream's message for the first half of a
// secure email change.
const singleConfirmationAccepted = "Confirmation link accepted. Please proceed to confirm link sent to the other email"

// oauthErrorForStatus is upstream's oauthErrorMap: the OAuth2 `error` value that
// accompanies an error redirect.
var oauthErrorForStatus = map[int]string{
	http.StatusBadRequest:          "invalid_request",
	http.StatusUnauthorized:        "unauthorized_client",
	http.StatusForbidden:           "access_denied",
	http.StatusInternalServerError: "server_error",
	http.StatusServiceUnavailable:  "temporarily_unavailable",
}

// VerifyParams is the /verify request (upstream api.VerifyParams).
type VerifyParams struct {
	Type       string `json:"type"`
	Token      string `json:"token"`
	TokenHash  string `json:"token_hash"`
	Email      string `json:"email"`
	Phone      string `json:"phone"`
	RedirectTo string `json:"redirect_to"`
}

// validate is upstream's VerifyParams.Validate.
func (p *VerifyParams) validate(r *http.Request) error {
	if p.Type == "" {
		return badRequestError(ErrorCodeValidationFailed, "Verify requires a verification type")
	}
	switch r.Method {
	case http.MethodGet:
		if p.Token == "" {
			return badRequestError(ErrorCodeValidationFailed, "Verify requires a token or a token hash")
		}
		// Upstream still accepts `token` on GET and treats it as the hash; the
		// deprecation is upstream's to make, not Dilion's.
		p.TokenHash = p.Token
	case http.MethodPost:
		if (p.Token == "" && p.TokenHash == "") || (p.Token != "" && p.TokenHash != "") {
			return badRequestError(ErrorCodeValidationFailed, "Verify requires either a token or a token hash")
		}
		if p.Token != "" {
			switch {
			case p.Phone != "" && p.Email == "":
				// An SMS carries no link, so {phone, token} is the ONLY way a
				// phone OTP comes back. The hash is built over the NORMALIZED
				// number, which is also what was stored.
				normalized, err := validatePhone(p.Phone)
				if err != nil {
					return err
				}
				p.Phone = normalized
				p.TokenHash = generateTokenHash(p.Phone, p.Token)
			case p.Phone == "" && p.Email != "":
				p.Email = strings.ToLower(strings.TrimSpace(p.Email))
				if _, err := mail.ParseAddress(p.Email); err != nil {
					return unprocessableEntityError(ErrorCodeValidationFailed, "Invalid email format")
				}
				p.TokenHash = generateTokenHash(p.Email, p.Token)
			default:
				return badRequestError(ErrorCodeValidationFailed,
					"Only an email address or phone number should be provided on verify")
			}
		} else if p.Email != "" || p.Phone != "" || p.RedirectTo != "" {
			return badRequestError(ErrorCodeValidationFailed, "Only the token_hash and type should be provided")
		}
	}
	return nil
}

// usesTokenHash is upstream's isUsingTokenHash.
func (p *VerifyParams) usesTokenHash() bool {
	return p.TokenHash != "" && p.Token == "" && p.Phone == "" && p.Email == ""
}

// verify dispatches GET and POST /verify.
func (a *api) verify(w http.ResponseWriter, r *http.Request) error {
	params := &VerifyParams{}
	switch r.Method {
	case http.MethodGet:
		params.Token = r.FormValue("token")
		params.Type = r.FormValue("type")
		params.RedirectTo = a.referrerFor(r, r.FormValue("redirect_to"))
		if err := params.validate(r); err != nil {
			return err
		}
		return a.verifyGet(w, r, params)
	default:
		// Captcha gates POST /verify (upstream); GET link-follows are exempt.
		if err := a.verifyCaptcha(r); err != nil {
			return err
		}
		if err := decodeBody(r, params); err != nil {
			return err
		}
		if err := params.validate(r); err != nil {
			return err
		}
		return a.verifyPost(w, r, params)
	}
}

// ---- GET -------------------------------------------------------------------

func (a *api) verifyGet(w http.ResponseWriter, r *http.Request, params *VerifyParams) error {
	ctx := r.Context()

	pkce := isPKCEToken(params.Token)
	authMethod := ""
	if pkce {
		m, err := authMethodForVerifyType(params.Type)
		if err != nil {
			return a.redirectError(w, r, err, params.RedirectTo, pkce)
		}
		authMethod = m
	}

	var (
		session  *AccessTokenResponse
		authCode string
		halfDone bool
	)

	err := a.inTx(ctx, func(tx pgx.Tx) error {
		user, terr := a.verifyTokenHash(ctx, tx, params)
		if terr != nil {
			return terr
		}

		user, terr = a.applyVerification(ctx, tx, r, params, user)
		if terr != nil {
			return terr
		}
		if user == nil {
			// Secure email change: only one of the two links has been
			// followed so far.
			halfDone = true
			return nil
		}

		if pkce {
			code, cerr := a.issueAuthCode(ctx, tx, user.ID, authMethod)
			if cerr != nil {
				return cerr
			}
			authCode = code
			return nil
		}

		var serr error
		session, serr = a.grantSession(ctx, tx, user, r, "otp")
		return serr
	})
	if err != nil {
		return a.redirectError(w, r, err, params.RedirectTo, pkce)
	}

	if halfDone {
		rurl, perr := prepMessageRedirectURL(singleConfirmationAccepted, params.RedirectTo, pkce)
		if perr != nil {
			return internalServerError("Error building redirect URL").withInternal(perr)
		}
		http.Redirect(w, r, rurl, http.StatusSeeOther)
		return nil
	}

	rurl := params.RedirectTo
	if pkce {
		built, perr := prepPKCERedirectURL(rurl, authCode)
		if perr != nil {
			return internalServerError("Error building redirect URL").withInternal(perr)
		}
		rurl = built
	} else if session != nil {
		q := url.Values{}
		q.Set("type", params.Type)
		rurl = session.asRedirectURL(rurl, q)
	}
	http.Redirect(w, r, rurl, http.StatusSeeOther)
	return nil
}

// ---- POST ------------------------------------------------------------------

func (a *api) verifyPost(w http.ResponseWriter, r *http.Request, params *VerifyParams) error {
	ctx := r.Context()
	aud := requestAud(r)

	var (
		session  *AccessTokenResponse
		halfDone bool
	)

	if err := a.inTx(ctx, func(tx pgx.Tx) error {
		var (
			user *User
			terr error
		)
		if params.usesTokenHash() {
			user, terr = a.verifyTokenHash(ctx, tx, params)
		} else {
			// A typed OTP is six digits: counted per address (attempts.go).
			terr = a.throttled(ctx, attemptOTP, aud+":"+params.Email+params.Phone, func() error {
				var verr error
				user, verr = a.verifyUserAndToken(ctx, tx, params, aud)
				return verr
			})
		}
		if terr != nil {
			return terr
		}

		user, terr = a.applyVerification(ctx, tx, r, params, user)
		if terr != nil {
			return terr
		}
		if user == nil {
			halfDone = true
			return nil
		}

		var serr error
		session, serr = a.grantSession(ctx, tx, user, r, "otp")
		return serr
	}); err != nil {
		return err
	}

	if halfDone {
		return sendJSON(w, http.StatusOK, map[string]string{
			"msg":  singleConfirmationAccepted,
			"code": strconv.Itoa(http.StatusOK),
		})
	}
	return sendJSON(w, http.StatusOK, session)
}

// applyVerification runs the per-type effect of a successful token redemption.
// A nil user with a nil error means "first half of a secure email change".
func (a *api) applyVerification(ctx context.Context, tx pgx.Tx, r *http.Request, params *VerifyParams, user *User) (*User, error) {
	switch params.Type {
	case mailSignup, mailInvite:
		return a.signupVerify(ctx, tx, user)
	case mailRecovery, mailMagicLink:
		return a.recoverVerify(ctx, tx, user)
	case mailEmailChange:
		return a.emailChangeVerify(ctx, tx, r, params, user)
	case smsVerification, phoneChangeVerification:
		return a.smsVerify(ctx, tx, r, params, user)
	default:
		return nil, badRequestError(ErrorCodeValidationFailed, "Unsupported verification type")
	}
}

// ---- token resolution ------------------------------------------------------

// verifyTokenHash is upstream's verifyTokenHash: resolve the user through
// auth.one_time_tokens, then check the expiry of the *_sent_at that guards this
// token type.
//
// A missing token and an expired one deliberately produce the SAME answer
// (403 otp_expired, "Email link is invalid or has expired") so /verify is not an
// oracle for which links exist.
func (a *api) verifyTokenHash(ctx context.Context, q querier, params *VerifyParams) (*User, error) {
	var types []string
	switch params.Type {
	case mailEmailOTP:
		types = []string{tokenTypeConfirmation, tokenTypeRecovery}
	case mailSignup, mailInvite:
		types = []string{tokenTypeConfirmation}
	case mailRecovery, mailMagicLink:
		types = []string{tokenTypeRecovery}
	case mailEmailChange:
		types = []string{tokenTypeEmailChangeCurrent, tokenTypeEmailChangeNew}
	case smsVerification:
		// A phone signup confirmation shares confirmation_token with the email
		// one; that is upstream's column layout (smsflow.go).
		types = []string{tokenTypeConfirmation}
	case phoneChangeVerification:
		types = []string{tokenTypePhoneChange}
	default:
		return nil, badRequestError(ErrorCodeValidationFailed, "Invalid email verification type")
	}

	ott, err := findOneTimeTokenAnyFlow(ctx, q, params.TokenHash, types...)
	if err != nil {
		if isNoRows(err) {
			return nil, forbiddenError(ErrorCodeOTPExpired, "Email link is invalid or has expired")
		}
		return nil, internalServerError("Database error finding user from email link").withInternal(err)
	}
	// The stored hash is authoritative from here on: it carries the flow prefix
	// even when the caller presented the bare hash.
	params.TokenHash = ott.TokenHash

	user, err := a.loadUserWithIdentities(ctx, q, ott.UserID)
	if err != nil {
		if isNoRows(err) {
			return nil, forbiddenError(ErrorCodeOTPExpired, "Email link is invalid or has expired")
		}
		return nil, internalServerError("Database error finding user from email link").withInternal(err)
	}
	if user.IsBanned(a.now()) {
		return nil, forbiddenError(ErrorCodeUserBanned, "User is banned")
	}

	// The `email` type does not say which of the two tokens matched; upstream
	// narrows it here and rewrites params.Type accordingly.
	if params.Type == mailEmailOTP {
		if ott.TokenType == tokenTypeRecovery {
			params.Type = mailMagicLink
		} else {
			params.Type = mailSignup
		}
	}

	// Phone tokens live for SMS.OTPExp (60s by default), not the mailer's hour.
	if params.Type == smsVerification || params.Type == phoneChangeVerification {
		if a.isSMSOTPExpired(phoneSentAt(user, params.Type)) {
			return nil, forbiddenError(ErrorCodeOTPExpired, "Token has expired or is invalid")
		}
		return user, nil
	}
	if a.isOTPExpired(mailSentAt(user, params.Type)) {
		return nil, forbiddenError(ErrorCodeOTPExpired, "Email link is invalid or has expired")
	}
	return user, nil
}

// phoneSentAt is mailSentAt's twin: when the OTP guarding a phone action type
// was last texted.
func phoneSentAt(u *User, verifyType string) *time.Time {
	switch verifyType {
	case smsVerification:
		return u.ConfirmationSentAt
	case phoneChangeVerification:
		return u.PhoneChangeSentAt
	}
	return nil
}

// verifyUserAndToken is upstream's verifyUserAndToken: the {email, token} form,
// where the user is resolved by ADDRESS and the token compared against the
// legacy auth.users column (which tolerates the "pkce_" prefix).
func (a *api) verifyUserAndToken(ctx context.Context, q querier, params *VerifyParams, aud string) (*User, error) {
	var (
		user *User
		err  error
	)
	switch params.Type {
	case mailEmailChange:
		user, err = a.findUserForEmailChange(ctx, q, params.TokenHash, aud)
	case smsVerification:
		user, err = findUserByPhone(ctx, q, params.Phone, aud)
	case phoneChangeVerification:
		// A pending change is identified by the number it is TO, which is not
		// yet the account's phone.
		user, err = findUserByPhoneChange(ctx, q, params.Phone, aud)
	default:
		user, err = findUserByEmail(ctx, q, params.Email, aud)
	}
	if err != nil {
		if isNoRows(err) {
			return nil, forbiddenError(ErrorCodeOTPExpired, "Token has expired or is invalid")
		}
		return nil, internalServerError("Database error finding user").withInternal(err)
	}
	if user.DeletedAt != nil {
		return nil, forbiddenError(ErrorCodeOTPExpired, "Token has expired or is invalid")
	}
	if user.IsBanned(a.now()) {
		return nil, forbiddenError(ErrorCodeUserBanned, "User is banned")
	}

	tokens, err := findUserTokens(ctx, q, user.ID)
	if err != nil {
		return nil, internalServerError("Database error finding user").withInternal(err)
	}

	valid := false
	switch params.Type {
	case mailEmailOTP:
		if a.isOTPValid(params.TokenHash, tokens.ConfirmationToken, user.ConfirmationSentAt) {
			valid, params.Type = true, mailSignup
		} else if a.isOTPValid(params.TokenHash, tokens.RecoveryToken, user.RecoverySentAt) {
			valid, params.Type = true, mailMagicLink
		}
	case mailSignup, mailInvite:
		valid = a.isOTPValid(params.TokenHash, tokens.ConfirmationToken, user.ConfirmationSentAt)
	case mailRecovery, mailMagicLink:
		valid = a.isOTPValid(params.TokenHash, tokens.RecoveryToken, user.RecoverySentAt)
	case mailEmailChange:
		valid = a.isOTPValid(params.TokenHash, tokens.EmailChangeTokenCurrent, user.EmailChangeSentAt) ||
			a.isOTPValid(params.TokenHash, tokens.EmailChangeTokenNew, user.EmailChangeSentAt)
	case smsVerification, phoneChangeVerification:
		ptokens, perr := findPhoneTokens(ctx, q, user.ID)
		if perr != nil {
			return nil, internalServerError("Database error finding user").withInternal(perr)
		}
		if params.Type == smsVerification {
			valid = a.isSMSOTPValid(params.TokenHash, ptokens.ConfirmationToken, user.ConfirmationSentAt)
		} else {
			valid = a.isSMSOTPValid(params.TokenHash, ptokens.PhoneChangeToken, user.PhoneChangeSentAt)
		}
	default:
		return nil, badRequestError(ErrorCodeValidationFailed, "Unsupported verification type")
	}
	if !valid {
		return nil, forbiddenError(ErrorCodeOTPExpired, "Token has expired or is invalid")
	}
	// Downstream (emailChangeVerify) compares against the STORED value, which
	// carries the flow prefix; normalize now that the token is known good.
	if params.Type == mailEmailChange {
		switch {
		case pkcePrefix+params.TokenHash == tokens.EmailChangeTokenCurrent,
			pkcePrefix+params.TokenHash == tokens.EmailChangeTokenNew:
			params.TokenHash = pkcePrefix + params.TokenHash
		}
	}
	return user, nil
}

// findUserForEmailChange is upstream's models.FindUserForEmailChange: an email
// change token identifies its user on its own, from either side of the change.
func (a *api) findUserForEmailChange(ctx context.Context, q querier, tokenHash, aud string) (*User, error) {
	types := []string{tokenTypeEmailChangeNew}
	if a.cfg.Mailer.SecureEmailChangeEnabled {
		types = append(types, tokenTypeEmailChangeCurrent)
	}
	ott, err := findOneTimeTokenAnyFlow(ctx, q, tokenHash, types...)
	if err != nil {
		return nil, err
	}
	user, err := a.loadUserWithIdentities(ctx, q, ott.UserID)
	if err != nil {
		return nil, err
	}
	if user.Aud != aud {
		return nil, pgx.ErrNoRows
	}
	return user, nil
}

// ---- per-type effects ------------------------------------------------------

// signupVerify is upstream's signupVerify: confirm the address, mark the email
// identity verified, and retire every pending one-time token on the account.
//
// A user who was INVITED has no password yet; upstream sets a random one so the
// account cannot be taken over by whoever guesses the (empty) password, and
// expects the application to walk the user through PUT /user. Dilion does the
// same.
func (a *api) signupVerify(ctx context.Context, tx pgx.Tx, user *User) (*User, error) {
	now := a.now()
	set := map[string]any{
		"confirmation_token": "",
		"email_confirmed_at": now,
	}

	if user.EncryptedPassword == nil || *user.EncryptedPassword == "" {
		if user.InvitedAt != nil {
			random, err := newRefreshToken() // 32 bytes of crypto/rand, base64
			if err != nil {
				return nil, internalServerError("Error generating password").withInternal(err)
			}
			hashed, err := HashPassword(random)
			if err != nil {
				return nil, internalServerError("Error hashing password").withInternal(err)
			}
			set["encrypted_password"] = hashed
		}
	}

	meta := JSONMap{}
	for k, v := range user.UserMetaData {
		meta[k] = v
	}
	meta["email_verified"] = true
	set["raw_user_meta_data"] = meta

	updated, err := updateUserFields(ctx, tx, user.ID, now, set)
	if err != nil {
		return nil, internalServerError("Error confirming user").withInternal(err)
	}
	if err := clearAllOneTimeTokens(ctx, tx, user.ID); err != nil {
		return nil, internalServerError("Error confirming user").withInternal(err)
	}
	if err := a.markEmailIdentityVerified(ctx, tx, updated, now); err != nil {
		return nil, err
	}
	return a.reloadUser(ctx, tx, updated)
}

// recoverVerify is upstream's recoverVerify: burn the recovery token and, when
// the address was not confirmed yet (a magic link to a half-finished signup),
// confirm it.
func (a *api) recoverVerify(ctx context.Context, tx pgx.Tx, user *User) (*User, error) {
	now := a.now()
	set := map[string]any{"recovery_token": ""}

	if user.EmailConfirmedAt == nil {
		set["email_confirmed_at"] = now
		set["confirmation_token"] = ""
		meta := JSONMap{}
		for k, v := range user.UserMetaData {
			meta[k] = v
		}
		meta["email_verified"] = true
		set["raw_user_meta_data"] = meta
	}

	updated, err := updateUserFields(ctx, tx, user.ID, now, set)
	if err != nil {
		return nil, internalServerError("Database error updating user").withInternal(err)
	}
	if err := clearAllOneTimeTokens(ctx, tx, user.ID); err != nil {
		return nil, internalServerError("Database error updating user").withInternal(err)
	}
	if user.EmailConfirmedAt == nil {
		if err := a.markEmailIdentityVerified(ctx, tx, updated, now); err != nil {
			return nil, err
		}
	}
	return a.reloadUser(ctx, tx, updated)
}

// emailChangeVerify is upstream's emailChangeVerify.
//
// With Mailer.SecureEmailChangeEnabled and a user who already has an address,
// the FIRST link only bumps email_change_confirm_status to 1 and burns the half
// that was used; it returns (nil, nil), which the caller renders as the
// "please confirm the other link" answer. The SECOND link falls through to the
// apply branch below.
func (a *api) emailChangeVerify(ctx context.Context, tx pgx.Tx, r *http.Request, params *VerifyParams, user *User) (*User, error) {
	tokens, err := findUserTokens(ctx, tx, user.ID)
	if err != nil {
		return nil, internalServerError("Database error updating user").withInternal(err)
	}

	if !a.cfg.Mailer.Autoconfirm && a.cfg.Mailer.SecureEmailChangeEnabled &&
		tokens.EmailChangeConfirmStatus == zeroConfirmation && user.Email != "" {

		set := map[string]any{"email_change_confirm_status": singleConfirmation}
		switch {
		case tokens.EmailChangeTokenCurrent != "" && params.TokenHash == tokens.EmailChangeTokenCurrent:
			set["email_change_token_current"] = ""
			if err := clearOneTimeToken(ctx, tx, user.ID, tokenTypeEmailChangeCurrent); err != nil {
				return nil, internalServerError("Database error updating user").withInternal(err)
			}
		case tokens.EmailChangeTokenNew != "" && params.TokenHash == tokens.EmailChangeTokenNew:
			set["email_change_token_new"] = ""
			if err := clearOneTimeToken(ctx, tx, user.ID, tokenTypeEmailChangeNew); err != nil {
				return nil, internalServerError("Database error updating user").withInternal(err)
			}
		}
		if _, err := updateUserFields(ctx, tx, user.ID, a.now(), set); err != nil {
			return nil, internalServerError("Database error updating user").withInternal(err)
		}
		return nil, nil
	}

	// Apply the change.
	oldEmail := user.Email
	newEmail := user.EmailChange
	if newEmail == "" {
		return nil, badRequestError(ErrorCodeValidationFailed, "No email change is pending for this user")
	}

	now := a.now()
	set := map[string]any{
		"email":                       newEmail,
		"email_change":                "",
		"email_change_token_current":  "",
		"email_change_token_new":      "",
		"email_change_confirm_status": zeroConfirmation,
		"email_confirmed_at":          now,
		"confirmation_token":          "",
	}
	if user.IsAnonymous {
		set["is_anonymous"] = false
	}
	meta := JSONMap{}
	for k, v := range user.UserMetaData {
		meta[k] = v
	}
	meta["email_verified"] = true
	set["raw_user_meta_data"] = meta

	updated, err := updateUserFields(ctx, tx, user.ID, now, set)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, unprocessableEntityError(ErrorCodeEmailExists,
				"A user with this email address has already been registered")
		}
		return nil, internalServerError("Error confirm email").withInternal(err)
	}
	if err := clearAllOneTimeTokens(ctx, tx, user.ID); err != nil {
		return nil, internalServerError("Error confirm email").withInternal(err)
	}
	if err := a.markEmailIdentityVerified(ctx, tx, updated, now); err != nil {
		return nil, err
	}

	updated, err = a.reloadUser(ctx, tx, updated)
	if err != nil {
		return nil, err
	}

	// Upstream notifies the OLD address after the change lands. Delivery is
	// best effort: the change has already been committed to.
	if oldEmail != "" && oldEmail != newEmail {
		a.notify(r.Context(), oldEmail, "Your email address was changed",
			"The email address on your account was changed from "+oldEmail+" to "+newEmail+".")
	}
	return updated, nil
}

// smsVerify is upstream's smsVerify: the per-type effect of redeeming a phone
// OTP.
//
//	type "sms"           the number on the account is CONFIRMED
//	type "phone_change"  the number parked in phone_change REPLACES it
//
// Both retire every pending one-time token on the account and drop
// is_anonymous, exactly as their email counterparts do.
func (a *api) smsVerify(ctx context.Context, tx pgx.Tx, r *http.Request, params *VerifyParams, user *User) (*User, error) {
	if params.Type == smsVerification {
		return a.confirmPhone(ctx, tx, user)
	}

	// phone_change: the pending number is authoritative, not params.Phone —
	// they are equal for the {phone, token} form and only phone_change is
	// available for the {token_hash} one.
	newPhone := user.PhoneChange
	if newPhone == "" {
		return nil, badRequestError(ErrorCodeValidationFailed, "No phone change is pending for this user")
	}
	oldPhone := user.Phone

	now := a.now()
	set := map[string]any{
		"phone":              newPhone,
		"phone_change":       "",
		"phone_change_token": "",
		"phone_confirmed_at": now,
	}
	if user.IsAnonymous {
		set["is_anonymous"] = false
	}
	set["raw_user_meta_data"] = withPhoneVerified(user.UserMetaData)

	updated, err := updateUserFields(ctx, tx, user.ID, now, set)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, unprocessableEntityError(ErrorCodePhoneExists, "%s", duplicatePhoneMsg)
		}
		return nil, internalServerError("Error confirming user").withInternal(err)
	}
	if err := clearAllOneTimeTokens(ctx, tx, user.ID); err != nil {
		return nil, internalServerError("Error confirming user").withInternal(err)
	}
	if err := a.markPhoneIdentityVerified(ctx, tx, updated, now); err != nil {
		return nil, err
	}

	updated, err = a.reloadUser(ctx, tx, updated)
	if err != nil {
		return nil, err
	}

	// Upstream notifies the account's EMAIL after a phone change lands
	// (sendPhoneChangedNotification). Delivery is best effort: the change has
	// already been committed to.
	if updated.Email != "" && oldPhone != "" && oldPhone != newPhone {
		a.notify(r.Context(), updated.Email, "Your phone number was changed",
			"The phone number on your account was changed to +"+newPhone+".")
	}
	return updated, nil
}

// confirmPhone is upstream's models.User.ConfirmPhone: stamp phone_confirmed_at,
// burn the confirmation token, and retire every pending one-time token.
//
// It is shared by POST /verify {type:"sms"} and by the SMS.Autoconfirm branches
// of /signup and /otp, which is why it lives here rather than inline.
//
// DEVIATION: upstream's ConfirmPhone touches only confirmation_token and
// phone_confirmed_at. Dilion additionally sets user_metadata.phone_verified and
// flips the phone IDENTITY to phone_verified: true — the same two things
// signupVerify does for email, and what supabase-js and RLS policies read.
func (a *api) confirmPhone(ctx context.Context, tx querier, user *User) (*User, error) {
	now := a.now()
	set := map[string]any{
		"confirmation_token": "",
		"phone_confirmed_at": now,
		"raw_user_meta_data": withPhoneVerified(user.UserMetaData),
	}
	if user.IsAnonymous {
		set["is_anonymous"] = false
	}

	updated, err := updateUserFields(ctx, tx, user.ID, now, set)
	if err != nil {
		return nil, internalServerError("Error confirming user").withInternal(err)
	}
	if err := clearAllOneTimeTokens(ctx, tx, user.ID); err != nil {
		return nil, internalServerError("Error confirming user").withInternal(err)
	}
	if err := a.markPhoneIdentityVerified(ctx, tx, updated, now); err != nil {
		return nil, err
	}
	return a.reloadUser(ctx, tx, updated)
}

// withPhoneVerified copies user_metadata and stamps phone_verified.
func withPhoneVerified(meta JSONMap) JSONMap {
	out := JSONMap{}
	for k, v := range meta {
		out[k] = v
	}
	out["phone_verified"] = true
	return out
}

// ---- shared helpers --------------------------------------------------------

// markEmailIdentityVerified keeps the email identity's identity_data in step
// with auth.users; RLS policies and supabase-js read the identity, not the user
// row. When the user has no email identity yet (an invited or anonymous account)
// one is created, matching upstream's behaviour on email change.
func (a *api) markEmailIdentityVerified(ctx context.Context, q querier, user *User, now time.Time) error {
	if user.Email == "" {
		return nil
	}
	data := JSONMap{
		"sub":            user.ID,
		"email":          user.Email,
		"email_verified": true,
		"phone_verified": false,
	}
	ids, err := findIdentitiesByUserID(ctx, q, user.ID)
	if err != nil {
		return internalServerError("Error loading identities").withInternal(err)
	}
	for _, id := range ids {
		if id.Provider == ProviderEmail {
			if err := updateIdentityData(ctx, q, user.ID, ProviderEmail, data, now); err != nil {
				return internalServerError("Error updating identity").withInternal(err)
			}
			return nil
		}
	}
	if err := insertIdentity(ctx, q, user.ID, ProviderEmail, user.ID, data, now); err != nil {
		return internalServerError("Error creating identity").withInternal(err)
	}
	return nil
}

// reloadUser re-reads the user with its identities so generated columns
// (confirmed_at) and the identity list in the response are current — upstream's
// tx.Reload + tx.Load(user, "Identities").
func (a *api) reloadUser(ctx context.Context, q querier, user *User) (*User, error) {
	fresh, err := a.loadUserWithIdentities(ctx, q, user.ID)
	if err != nil {
		return nil, internalServerError("Error refetching user").withInternal(err)
	}
	return fresh, nil
}

// ---- redirect construction -------------------------------------------------

// asRedirectURL is upstream's AccessTokenResponse.AsRedirectURL: the implicit
// flow hands the session back in the URL FRAGMENT, which is never sent to a
// server and therefore never lands in an access log.
func (t *AccessTokenResponse) asRedirectURL(redirectURL string, extra url.Values) string {
	extra.Set("access_token", t.Token)
	extra.Set("token_type", t.TokenType)
	extra.Set("expires_in", strconv.Itoa(t.ExpiresIn))
	extra.Set("expires_at", strconv.FormatInt(t.ExpiresAt, 10))
	extra.Set("refresh_token", t.RefreshToken)
	// Upstream's marker so a client can tell a Supabase Auth redirect apart.
	extra.Set("sb", "")
	return redirectURL + "#" + extra.Encode()
}

// prepPKCERedirectURL is upstream's prepPKCERedirectURL.
func prepPKCERedirectURL(rurl, code string) (string, error) {
	u, err := url.Parse(rurl)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("code", code)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// prepMessageRedirectURL is upstream's prepRedirectURL.
func prepMessageRedirectURL(message, rurl string, pkce bool) (string, error) {
	u, err := url.Parse(rurl)
	if err != nil {
		return "", err
	}
	q := u.Query()
	hq := url.Values{}
	hq.Set("message", message)
	if pkce {
		q.Set("message", message)
	}
	u.RawQuery = q.Encode()
	hq.Set("sb", "")
	u.Fragment = hq.Encode()
	return u.String(), nil
}

// redirectError renders a failed GET /verify as upstream's error redirect: the
// details go into the fragment always, and into the query string as well for
// PKCE (where the client reads them server-side).
func (a *api) redirectError(w http.ResponseWriter, r *http.Request, err error, rurl string, pkce bool) error {
	he, ok := err.(*HTTPError)
	if !ok {
		return err
	}
	a.log.WarnContext(r.Context(), "auth: verify failed",
		"error_code", he.ErrorCode, "status", he.HTTPStatus, "error", he.Error())

	u, perr := url.Parse(rurl)
	if perr != nil {
		return he
	}
	q := u.Query()
	hq := url.Values{}
	if oauthErr, found := oauthErrorForStatus[he.HTTPStatus]; found {
		hq.Set("error", oauthErr)
		q.Set("error", oauthErr)
	}
	hq.Set("error_code", he.ErrorCode)
	hq.Set("error_description", he.Message)
	q.Set("error_code", he.ErrorCode)
	q.Set("error_description", he.Message)
	if pkce {
		u.RawQuery = q.Encode()
	}
	hq.Set("sb", "")
	u.Fragment = hq.Encode()

	http.Redirect(w, r, u.String(), http.StatusSeeOther)
	return nil
}

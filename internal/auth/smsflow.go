package auth

// Transactional SMS for the /auth/v1 phone lifecycle.
//
// This is Dilion's equivalent of upstream's internal/api/phone.go +
// internal/api/sms_provider: it validates and normalizes phone numbers, mints
// the OTP, persists its hash (legacy auth.users column AND
// auth.one_time_tokens, see ott.go), renders GOTRUE_SMS_TEMPLATE and hands the
// message to a provider.
//
// It is the phone twin of mailflow.go and deliberately mirrors that file's
// shape, so the two lifecycles can be read side by side.
//
// # Where an SMS OTP is stored
//
// Upstream master DUAL-WRITES, exactly as it does for email
// (api/phone.go sendPhoneConfirmation):
//
//	otp type            legacy auth.users column     one_time_tokens type
//	------------------  ---------------------------  --------------------------
//	confirmation        confirmation_token           confirmation_token
//	                    confirmation_sent_at
//	phone_change        phone_change_token           phone_change_token
//	                    phone_change_sent_at
//	                    (+ phone_change = new phone)
//	reauthentication    reauthentication_token       reauthentication_token
//	                    reauthentication_sent_at
//
// Note that a phone SIGNUP confirmation shares confirmation_token /
// confirmation_sent_at with the email signup confirmation — that is upstream's
// layout, not a Dilion simplification, and it is why an account cannot have an
// email confirmation and an SMS OTP pending at the same time.
//
// The stored value is `sha224_hex(phone + otp)` (ott.go generateTokenHash), the
// same construction email uses, so POST /verify {phone, token, type} and
// POST /verify {token_hash} converge on one lookup. SMS tokens are NEVER
// PKCE-prefixed: upstream rejects code_challenge on phone signups because a
// phone signup already returns the session in the body.
//
// # Deviations from upstream, and why
//
//   - PROVIDERS. Upstream ships five SMS providers plus a send_sms hook.
//     Dilion has a PORT (ports.SMSSender) and one built-in provider (Twilio,
//     sms_twilio.go). An injected sender always wins; "twilio" is selected from
//     Config.SMS.Provider when nothing is injected. Other provider names are
//     still reported by GET /settings (upstream parity) but have no transport,
//     and a send through them fails with upstream's 500.
//
//   - SEND ORDER. Upstream sends the SMS and then writes the token, rolling
//     nothing back if the write fails. Dilion persists first and delivers
//     second, exactly as mailflow.go does: the persistence lives in the
//     caller's transaction, so a delivery failure aborts that transaction and
//     nothing is left behind either way — but the reverse order can leave a
//     delivered code with no stored hash.
//
//   - TEST OTPs. Upstream's GOTRUE_SMS_TEST_OTP / _VALID_UNTIL (a static map of
//     phone -> code that bypasses the provider) is NOT implemented. Inject a
//     ports.SMSSender instead, which is strictly more capable and does not put
//     a permanent backdoor into the configuration surface.

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"

	"github.com/dilion-io/dilion/ports"
)

// ProviderPhone is the identity provider used for phone/SMS accounts
// (upstream api.PhoneProvider).
const ProviderPhone = "phone"

// Phone OTP types. The first three are upstream's phone.go constants; the last
// two are the `type` values POST /verify and POST /resend accept
// (upstream verify.go smsVerification / phoneChangeVerification).
const (
	phoneConfirmationOTP     = "confirmation"
	phoneReauthenticationOTP = "reauthentication"
	smsVerification          = "sms"
	phoneChangeVerification  = "phone_change"
)

// Message channels (upstream sms_provider.SMSProvider / WhatsappProvider).
const (
	channelSMS      = "sms"
	channelWhatsApp = "whatsapp"
)

// Error codes upstream declares in apierrors/errorcode.go. They live here
// rather than in errors.go because errors.go is shared and this wave owns the
// phone surface.
const (
	// ErrorCodeOverSMSSendRateLimit is the 429 of the SMS-sending endpoints
	// (the per-USER SMS.MaxFrequency throttle; the per-IP LimiterSMS bucket
	// answers with over_request_rate_limit).
	ErrorCodeOverSMSSendRateLimit = "over_sms_send_rate_limit"
	// ErrorCodeSMSSendFailed is upstream's 422 when the SMS provider rejects
	// the message.
	ErrorCodeSMSSendFailed = "sms_send_failed"
)

// Upstream's verbatim messages (api/errors.go).
const (
	duplicatePhoneMsg   = "A user with this phone number has already been registered"
	invalidChannelError = "Invalid channel, supported values are 'sms' or 'whatsapp'. 'whatsapp' is only supported if Twilio or Twilio Verify is used as the provider."
	invalidPhoneFormat  = "Invalid phone number format (E.164 required)"
)

// ---- number validation -----------------------------------------------------

// e164Format is upstream's e164Format: the digits of an E.164 number with the
// leading "+" already stripped — a non-zero country code followed by 1..14 more
// digits.
var e164Format = regexp.MustCompile(`^[1-9][0-9]{1,14}$`)

// formatPhoneNumber is upstream's formatPhoneNumber: drop a leading "+" and
// every space. It is deliberately NOT a full normalizer — upstream stores the
// bare digits, and auth.users.phone therefore never carries a "+".
func formatPhoneNumber(phone string) string {
	return strings.ReplaceAll(strings.TrimPrefix(strings.TrimSpace(phone), "+"), " ", "")
}

// validateE164Format is upstream's validateE164Format.
func validateE164Format(phone string) bool { return e164Format.MatchString(phone) }

// validatePhone is upstream's validatePhone: normalize, then insist on E.164.
func validatePhone(phone string) (string, error) {
	phone = formatPhoneNumber(phone)
	if !validateE164Format(phone) {
		return "", badRequestError(ErrorCodeValidationFailed, "%s", invalidPhoneFormat)
	}
	return phone, nil
}

// phoneProviderEnabled reports whether GOTRUE_EXTERNAL_PHONE_ENABLED is on.
func (a *api) phoneProviderEnabled() bool { return a.cfg.External[ProviderPhone].Enabled }

// isValidMessageChannel is upstream's sms_provider.IsValidMessageChannel.
// "whatsapp" is only offered by Twilio; an INJECTED sender is trusted with any
// supported channel, mirroring upstream's treatment of the send_sms hook (the
// channel is the embedder's business once delivery is theirs).
func (a *api) isValidMessageChannel(channel string) bool {
	switch channel {
	case channelSMS:
		return true
	case channelWhatsApp:
		return a.cfg.SMS.Sender != nil || a.cfg.SMS.Provider == "twilio"
	default:
		return false
	}
}

// defaultChannel applies upstream's backwards-compatible default: a phone
// request with no channel means SMS.
func defaultChannel(channel string) string {
	if strings.TrimSpace(channel) == "" {
		return channelSMS
	}
	return channel
}

// ---- provider selection ----------------------------------------------------

// smsProvider is the internal transport contract. It is wider than
// ports.SMSSender because upstream's providers take a channel and the raw OTP
// (WhatsApp content templates substitute the code themselves) and report a
// provider-side message id.
type smsProvider interface {
	SendMessage(ctx context.Context, phone, message, channel, otp string) (string, error)
}

// portSender adapts an injected ports.SMSSender to smsProvider. The channel and
// the raw OTP are dropped — a port that only knows Send(to, body) cannot use
// them — and the recipient is handed over in "+E.164" form, which is what every
// carrier API expects and what upstream sends to Twilio.
type portSender struct{ s ports.SMSSender }

func (p portSender) SendMessage(ctx context.Context, phone, message, _, _ string) (string, error) {
	return "", p.s.Send(ctx, "+"+phone, message)
}

// smsProviderFor resolves the transport for this mount.
//
// Precedence — an INJECTED sender always wins, so an embedder that supplies one
// never accidentally talks to Twilio because SMS_PROVIDER happens to be set:
//
//  1. Config.SMS.Sender      (ports.SMSSender)
//  2. Config.SMS.Provider == "twilio"  -> the built-in Twilio REST sender
//  3. nothing                -> upstream's 500 "Unable to get SMS provider"
func (a *api) smsProviderFor() (smsProvider, error) {
	if a.cfg.SMS.Sender != nil {
		return portSender{s: a.cfg.SMS.Sender}, nil
	}
	if a.cfg.SMS.Provider == "twilio" {
		return newTwilioSender(a.cfg.SMS.Twilio)
	}
	return nil, fmt.Errorf("sms provider %q could not be found", a.cfg.SMS.Provider)
}

// renderSMS is upstream's generateSMSFromTemplate.
func (a *api) renderSMS(otp string) (string, error) {
	t, err := template.New("sms").Parse(a.cfg.SMS.SMSTemplateOrDefault())
	if err != nil {
		return "", err
	}
	var body bytes.Buffer
	if err := t.Execute(&body, struct{ Code string }{Code: otp}); err != nil {
		return "", err
	}
	return body.String(), nil
}

// ---- send frequency --------------------------------------------------------

// checkSMSFrequency is upstream's per-user SMS throttle: at most one message of
// a given kind per SMS.MaxFrequency.
//
// Unlike checkMailFrequency (which reads auth.one_time_tokens.updated_at) this
// measures against the legacy auth.users *_sent_at column, because that is what
// upstream's sendPhoneConfirmation compares and because the caller already has
// the value in memory. The 429 body is upstream's verbatim — clients display the
// seconds-remaining message:
//
//	{"code":429,"error_code":"over_sms_send_rate_limit",
//	 "msg":"For security purposes, you can only request this after 42 seconds."}
func (a *api) checkSMSFrequency(sentAt *time.Time) error {
	freq := a.cfg.SMS.MaxFrequency
	if freq <= 0 || sentAt == nil {
		return nil
	}
	now := a.now()
	if !now.Before(sentAt.Add(freq)) {
		return nil
	}
	left := int64(sentAt.Add(freq).Sub(now) / time.Second)
	return httpError(http.StatusTooManyRequests, ErrorCodeOverSMSSendRateLimit,
		"For security purposes, you can only request this after %d seconds.", left)
}

// ---- OTP validity ----------------------------------------------------------

// isSMSOTPExpired measures a phone token against SMS.OTPExp (60s by default),
// NOT the mailer's much longer window.
func (a *api) isSMSOTPExpired(sentAt *time.Time) bool {
	if sentAt == nil {
		return true
	}
	return a.now().After(sentAt.Add(a.cfg.SMS.OTPExpDuration()))
}

// isSMSOTPValid is isOTPValid with the SMS expiry.
func (a *api) isSMSOTPValid(actual, expected string, sentAt *time.Time) bool {
	if expected == "" || sentAt == nil {
		return false
	}
	if a.isSMSOTPExpired(sentAt) {
		return false
	}
	return actual == expected || pkcePrefix+actual == expected
}

// ---- the send --------------------------------------------------------------

// sendPhoneConfirmation is upstream's sendPhoneConfirmation: mint an OTP,
// persist its hash for `otpType`, and deliver the rendered message.
//
// It returns the provider-side message id, which the endpoints surface as
// `message_id` (upstream SmsOtpResponse / ResendResponse).
//
// Must run inside the caller's transaction.
func (a *api) sendPhoneConfirmation(ctx context.Context, tx querier, r *http.Request, u *User, phone, otpType, channel string) (string, error) {
	var (
		sentAt      *time.Time
		tokenColumn string
		sentColumn  string
		tokenType   string
		relatesTo   = phone
		extra       = map[string]any{}
	)

	switch otpType {
	case phoneConfirmationOTP:
		sentAt, tokenColumn, sentColumn, tokenType =
			u.ConfirmationSentAt, "confirmation_token", "confirmation_sent_at", tokenTypeConfirmation
	case phoneChangeVerification:
		sentAt, tokenColumn, sentColumn, tokenType =
			u.PhoneChangeSentAt, "phone_change_token", "phone_change_sent_at", tokenTypePhoneChange
		// The pending number is parked on the user by the SAME statement that
		// stores the token, so the two can never disagree.
		extra["phone_change"] = phone
	case phoneReauthenticationOTP:
		sentAt, tokenColumn, sentColumn, tokenType =
			u.ReauthenticationSentAt, "reauthentication_token", "reauthentication_sent_at", tokenTypeReauthentication
	default:
		return "", internalServerError("invalid otp type")
	}

	if err := a.checkSMSFrequency(sentAt); err != nil {
		return "", err
	}
	// The per-IP SMS bucket (GOTRUE_RATE_LIMIT_SMS_SENT) is applied here, just
	// before an OTP is minted, exactly where upstream applies limiterOpts.Phone.
	if err := a.limitCheck(LimiterSMS, r); err != nil {
		return "", err
	}

	otp, err := generateOTP(a.cfg.SMS.OTPLength)
	if err != nil {
		return "", internalServerError("Error generating one-time token").withInternal(err)
	}
	hash := generateTokenHash(phone, otp)
	now := a.now()

	set := map[string]any{tokenColumn: hash, sentColumn: now}
	for k, v := range extra {
		set[k] = v
	}
	if _, err := updateUserFields(ctx, tx, u.ID, now, set); err != nil {
		if isUniqueViolation(err) {
			return "", unprocessableEntityError(ErrorCodePhoneExists, "%s", duplicatePhoneMsg)
		}
		return "", internalServerError("Database error updating user for phone").withInternal(err)
	}
	if err := issueOneTimeToken(ctx, tx, u.ID, relatesTo, hash, tokenType, now); err != nil {
		return "", internalServerError("error creating one time token").withInternal(err)
	}

	// Keep the in-memory user consistent with what was just written — /verify
	// and the throttle read these.
	switch otpType {
	case phoneConfirmationOTP:
		u.ConfirmationSentAt = &now
	case phoneChangeVerification:
		u.PhoneChange = phone
		u.PhoneChangeSentAt = &now
	case phoneReauthenticationOTP:
		u.ReauthenticationSentAt = &now
	}

	return a.deliverSMS(ctx, phone, otp, otpType, defaultChannel(channel))
}

// deliverSMS renders the template and hands the message to the provider.
//
// A missing provider is a hard 500 (upstream: "Unable to get SMS provider") —
// unlike mailflow.go's nil-mailer no-op, because an OTP nobody can receive
// would silently create an account that can never sign in.
func (a *api) deliverSMS(ctx context.Context, phone, otp, otpType, channel string) (string, error) {
	provider, err := a.smsProviderFor()
	if err != nil {
		return "", internalServerError("Unable to get SMS provider").withInternal(err)
	}
	message, err := a.renderSMS(otp)
	if err != nil {
		return "", internalServerError("error generating sms template").withInternal(err)
	}
	messageID, err := provider.SendMessage(ctx, phone, message, channel, otp)
	if err != nil {
		return messageID, unprocessableEntityError(ErrorCodeSMSSendFailed,
			"Error sending %s OTP to provider: %v", otpType, err)
	}
	a.log.InfoContext(ctx, "auth: sms otp sent",
		"otp_type", otpType, "channel", channel, "message_id", messageID)
	return messageID, nil
}

// smsResponse is the body of the SMS-sending endpoints (upstream
// SmsOtpResponse and resend's map): `message_id` only when the provider
// reported one, so an injected ports.SMSSender answers with a bare `{}` exactly
// as upstream does when no id comes back.
func smsResponse(messageID string) map[string]any {
	out := map[string]any{}
	if messageID != "" {
		out["message_id"] = messageID
	}
	return out
}

// ---- storage ---------------------------------------------------------------

// findUserByPhone is upstream's models.FindUserByPhoneAndAudience. Like the
// email lookup it excludes SSO users; soft-deleted users cannot match because
// their phone is obfuscated on delete (store.go softDeleteUser).
func findUserByPhone(ctx context.Context, q querier, phone, aud string) (*User, error) {
	return scanUser(q.QueryRow(ctx,
		`select `+userColumns+` from auth.users
		 where instance_id = $1::uuid and phone = $2 and aud = $3 and is_sso_user = false`,
		nilUUID, phone, aud))
}

// findUserByPhoneChange is upstream's models.FindUserByPhoneChangeAndAudience:
// a phone-change OTP identifies its user by the number the change is TO, which
// is not yet the user's phone.
func findUserByPhoneChange(ctx context.Context, q querier, phone, aud string) (*User, error) {
	return scanUser(q.QueryRow(ctx,
		`select `+userColumns+` from auth.users
		 where instance_id = $1::uuid and phone_change = $2 and aud = $3 and is_sso_user = false`,
		nilUUID, phone, aud))
}

// phoneTokens is the projection of the legacy token columns a phone
// verification compares against. ott.go's userTokens covers the EMAIL columns
// only; phone_change_token has no email counterpart.
type phoneTokens struct {
	ConfirmationToken     string
	PhoneChangeToken      string
	ReauthenticationToken string
}

func findPhoneTokens(ctx context.Context, q querier, userID string) (*phoneTokens, error) {
	var t phoneTokens
	err := q.QueryRow(ctx, `
		select coalesce(confirmation_token, ''), coalesce(phone_change_token, ''),
		       coalesce(reauthentication_token, '')
		from auth.users where id = $1::uuid`, userID).
		Scan(&t.ConfirmationToken, &t.PhoneChangeToken, &t.ReauthenticationToken)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// isDuplicatePhone is upstream's models.IsDuplicatedPhone, scoped to accounts
// OTHER than the caller's.
func isDuplicatePhone(ctx context.Context, q querier, phone, aud, exceptUserID string) (bool, error) {
	var n int64
	err := q.QueryRow(ctx, `
		select count(*) from auth.users
		where instance_id = $1::uuid and phone = $2 and aud = $3
		  and is_sso_user = false and id <> $4::uuid`,
		nilUUID, phone, aud, exceptUserID).Scan(&n)
	return n > 0, err
}

// ---- identities ------------------------------------------------------------

// phoneIdentityData is the identity_data of a phone identity.
//
// DEVIATION: upstream's SIGNUP path builds a phone identity from
// provider.Claims{Subject, Email} and never records the number, while its
// phone-CHANGE path writes {phone, phone_verified}. Dilion writes the same
// shape from both, matching the phone-change path and the email identity's
// {sub, email, email_verified} — supabase-js and RLS policies read the
// identity, not auth.users.
func phoneIdentityData(userID, phone string, verified bool) JSONMap {
	return JSONMap{
		"sub":            userID,
		"phone":          phone,
		"phone_verified": verified,
	}
}

// markPhoneIdentityVerified is markEmailIdentityVerified's twin: it keeps the
// phone identity in step with auth.users, creating it when the account has none
// (upstream createNewIdentity inside smsVerify).
func (a *api) markPhoneIdentityVerified(ctx context.Context, q querier, u *User, now time.Time) error {
	if u.Phone == "" {
		return nil
	}
	data := phoneIdentityData(u.ID, u.Phone, true)
	ids, err := findIdentitiesByUserID(ctx, q, u.ID)
	if err != nil {
		return internalServerError("Error loading identities").withInternal(err)
	}
	for _, id := range ids {
		if id.Provider == ProviderPhone {
			if err := updateIdentityData(ctx, q, u.ID, ProviderPhone, data, now); err != nil {
				return internalServerError("Error updating identity").withInternal(err)
			}
			return nil
		}
	}
	if err := insertIdentity(ctx, q, u.ID, ProviderPhone, u.ID, data, now); err != nil {
		return internalServerError("Error creating identity").withInternal(err)
	}
	return nil
}

// ---- account creation ------------------------------------------------------

// insertPhoneUser creates the user row plus its phone identity inside the
// caller's transaction. `confirmed` mirrors SMS.Autoconfirm.
func (a *api) insertPhoneUser(ctx context.Context, tx querier, phone, aud, hashedPassword string,
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
		Phone:             phone,
		EncryptedPassword: password,
		PhoneConfirmedAt:  confirmedAt,
		AppMetaData:       JSONMap{"provider": ProviderPhone, "providers": []any{ProviderPhone}},
		UserMetaData:      JSONMap(data),
		Now:               now,
	})
	if err != nil {
		if isUniqueViolation(err) {
			return nil, unprocessableEntityError(ErrorCodeUserAlreadyExists, "User already registered")
		}
		return nil, internalServerError("Database error saving new user").withInternal(err)
	}

	if err := insertIdentity(ctx, tx, user.ID, ProviderPhone, user.ID,
		phoneIdentityData(user.ID, phone, confirmed), now); err != nil {
		return nil, internalServerError("Error creating identity").withInternal(err)
	}
	ids, err := findIdentitiesByUserID(ctx, tx, user.ID)
	if err != nil {
		return nil, internalServerError("Error loading identities").withInternal(err)
	}
	user.Identities = ids
	return user, nil
}

// preparePhoneUser is prepareEmailUser's twin: the validating BeforeSignup hook
// plus a hashed random password. It MUST run outside a transaction — hashing is
// deliberately slow and a hook may call out over the network.
func (a *api) preparePhoneUser(ctx context.Context, phone string, data map[string]any) (string, map[string]any, error) {
	if data == nil {
		data = map[string]any{}
	}
	payload, err := a.runHook(ctx, ports.BeforeSignup, map[string]any{
		"provider":      ProviderPhone,
		"email":         "",
		"phone":         phone,
		"user_metadata": data,
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

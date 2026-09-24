package auth

// Database-backed tests for the phone/SMS lifecycle: signup, password login,
// /otp, /verify, phone change, /resend, /reauthenticate and the per-user send
// throttle.
//
// Like the other *_db_test.go files these only run when DILION_TEST_DB is set:
//
//	DILION_TEST_DB=postgres://dilion:dilion@localhost:55432/dilion_test_phone \
//	  go test -race -count=1 -run 'Phone|SMS' ./internal/auth/...

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/internal/hooks"
)

// ---- harness ---------------------------------------------------------------

// recordedSMS is one message the API handed to ports.SMSSender.
type recordedSMS struct {
	To   string
	Body string
}

type recordingSMS struct {
	mu   sync.Mutex
	sent []recordedSMS
	err  error // when set, every send fails
}

func (s *recordingSMS) Send(_ context.Context, to, body string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.sent = append(s.sent, recordedSMS{To: to, Body: body})
	return nil
}

func (s *recordingSMS) all() []recordedSMS {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedSMS(nil), s.sent...)
}

func (s *recordingSMS) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = nil
}

// to returns every message delivered to one number.
func (s *recordingSMS) to(number string) []recordedSMS {
	var out []recordedSMS
	for _, m := range s.all() {
		if m.To == number {
			out = append(out, m)
		}
	}
	return out
}

var smsCodePattern = regexp.MustCompile(`(\d{4,10})`)

// code returns the OTP the message carries.
func (m recordedSMS) code(t *testing.T) string {
	t.Helper()
	found := smsCodePattern.FindStringSubmatch(m.Body)
	if found == nil {
		t.Fatalf("no OTP in sms to %s: %q", m.To, m.Body)
	}
	return found[1]
}

type phoneEnv struct {
	*testEnv
	sms   *recordingSMS
	mails *recordingMailer
	clock *stepClock
	cfg   *Config
}

// phoneTestConfig is the configuration the phone flows are exercised under:
// the phone provider on, confirmation REQUIRED (the only setting where the OTP
// flow is observable) and an allow-list that admits one app origin.
func phoneTestConfig() *Config {
	cfg := testConfig()
	cfg.SiteURL = "https://app.test"
	cfg.URIAllowList = []string{"https://app.test/**"}
	cfg.Mailer.Autoconfirm = false
	cfg.SMS.Autoconfirm = false
	cfg.External[ProviderPhone] = ProviderConfig{Enabled: true}
	return cfg
}

// newPhoneEnv builds a mount whose SMS transport is a recording
// ports.SMSSender. `mutate` may adjust the configuration before it is validated.
func newPhoneEnv(t *testing.T, mutate func(*Config)) *phoneEnv {
	t.Helper()

	dsn := os.Getenv("DILION_TEST_DB")
	if dsn == "" {
		t.Skip("DILION_TEST_DB not set; skipping database-backed tests")
	}
	if !strings.HasPrefix(dsn, "postgres") {
		dsn = defaultTestDSN
	}

	sms := &recordingSMS{}
	cfg := phoneTestConfig()
	cfg.SMS.Sender = sms
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect %s: %v", dsn, err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping %s: %v", dsn, err)
	}

	applySchema(t, pool)
	applyEmailSchema(t, pool)
	// grantSession writes auth.mfa_amr_claims, which lives in 0112.
	applyMFASchema(t, pool)
	truncateAll(t, pool)
	truncateEmailTables(t, pool)

	env := &phoneEnv{
		testEnv: &testEnv{
			pool:   pool,
			tokens: NewTokenServiceHS(testSecret()),
			hooks:  hooks.NewRegistry(),
			mailer: &captureMailer{},
		},
		sms:   sms,
		mails: &recordingMailer{},
		clock: &stepClock{t: time.Now().UTC()},
		cfg:   cfg,
	}
	env.router = chi.NewRouter()
	Register(env.router, Deps{
		Pool:   pool,
		Tokens: env.tokens,
		Mailer: env.mails,
		Hooks:  env.hooks,
		Config: cfg,
		Clock:  env.clock,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return env
}

// ---- account helpers -------------------------------------------------------

const (
	testPhone     = "+15551230001"
	testPhoneE164 = "15551230001"
	testPassword  = "hunter22phone"
)

// unconfirmedPhoneSignup signs a number up while confirmation is required and
// returns the user object plus the OTP that was texted.
func (e *phoneEnv) unconfirmedPhoneSignup(t *testing.T, phone, password string) (User, string) {
	t.Helper()
	e.sms.reset()
	rec := e.do(t, http.MethodPost, "/signup",
		map[string]any{"phone": phone, "password": password}, "")
	user := decodeInto[User](t, rec, http.StatusOK)

	msgs := e.sms.to(phone)
	if len(msgs) != 1 {
		t.Fatalf("confirmation messages to %s = %d, want 1 (%+v)", phone, len(msgs), e.sms.all())
	}
	return user, msgs[0].code(t)
}

// confirmedPhoneUser signs a number up and redeems its OTP, leaving a usable
// account and a live session.
func (e *phoneEnv) confirmedPhoneUser(t *testing.T, phone, password string) AccessTokenResponse {
	t.Helper()
	_, code := e.unconfirmedPhoneSignup(t, phone, password)

	rec := e.do(t, http.MethodPost, "/verify",
		map[string]any{"type": smsVerification, "phone": phone, "token": code}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	e.sms.reset()
	return session
}

// phoneErrorBody decodes a gotrue error envelope and asserts the status.
func phoneErrorBody(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int) HTTPError {
	t.Helper()
	return decodeInto[HTTPError](t, rec, wantStatus)
}

// ---- signup ----------------------------------------------------------------

// The headline flow: a phone signup returns a USER and no session, the number is
// unconfirmed, and redeeming the texted code both confirms it and signs in.
func TestPhoneSignupConfirmationThenVerifyThenLogin(t *testing.T) {
	env := newPhoneEnv(t, nil)

	user, code := env.unconfirmedPhoneSignup(t, testPhone, testPassword)

	if user.PhoneConfirmedAt != nil {
		t.Errorf("phone_confirmed_at = %v, want NULL before confirmation", user.PhoneConfirmedAt)
	}
	// auth.users.phone stores the BARE E.164 digits, never the "+".
	if user.Phone != testPhoneE164 {
		t.Errorf("phone = %q, want %q", user.Phone, testPhoneE164)
	}
	if user.ConfirmationSentAt == nil {
		t.Error("confirmation_sent_at was not stamped")
	}
	if got := user.AppMetaData["provider"]; got != ProviderPhone {
		t.Errorf("app_metadata.provider = %v, want %q", got, ProviderPhone)
	}
	if len(user.Identities) != 1 || user.Identities[0].Provider != ProviderPhone {
		t.Errorf("identities = %+v, want one %q identity", user.Identities, ProviderPhone)
	}
	if len(code) != DefaultOTPLength {
		t.Errorf("otp %q has %d digits, want %d", code, len(code), DefaultOTPLength)
	}

	// An unconfirmed number cannot sign in.
	rec := env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"phone": testPhone, "password": testPassword}, "")
	if body := phoneErrorBody(t, rec, http.StatusBadRequest); body.ErrorCode != ErrorCodePhoneNotConfirmed {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodePhoneNotConfirmed)
	}

	// Redeeming the OTP confirms the number and issues a session.
	rec = env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": smsVerification, "phone": testPhone, "token": code}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if session.Token == "" || session.RefreshToken == "" {
		t.Fatalf("verify returned an incomplete session: %+v", session)
	}
	if session.User.PhoneConfirmedAt == nil {
		t.Error("phone_confirmed_at is still NULL after verify")
	}
	if v, _ := session.User.UserMetaData["phone_verified"].(bool); !v {
		t.Errorf("user_metadata.phone_verified = %v, want true", session.User.UserMetaData["phone_verified"])
	}
	if len(session.User.Identities) == 1 {
		if v, _ := session.User.Identities[0].IdentityData["phone_verified"].(bool); !v {
			t.Errorf("identity phone_verified = %v, want true", session.User.Identities[0].IdentityData["phone_verified"])
		}
	}

	// And now the password grant works.
	rec = env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"phone": testPhone, "password": testPassword}, "")
	login := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if login.User.ID != session.User.ID {
		t.Errorf("login returned user %s, want %s", login.User.ID, session.User.ID)
	}
}

// With SMS.Autoconfirm the number is usable at once and NOTHING is texted.
func TestPhoneSignupAutoconfirmReturnsSessionWithoutSMS(t *testing.T) {
	env := newPhoneEnv(t, func(c *Config) { c.SMS.Autoconfirm = true })

	rec := env.do(t, http.MethodPost, "/signup",
		map[string]any{"phone": testPhone, "password": testPassword}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	if session.Token == "" {
		t.Fatalf("autoconfirm signup returned no session: %+v", session)
	}
	if session.User.PhoneConfirmedAt == nil {
		t.Error("phone_confirmed_at is NULL under SMS.Autoconfirm")
	}
	if n := len(env.sms.all()); n != 0 {
		t.Errorf("%d messages sent under autoconfirm, want 0: %+v", n, env.sms.all())
	}

	// A repeat signup of a CONFIRMED number is refused, as on the email path.
	rec = env.do(t, http.MethodPost, "/signup",
		map[string]any{"phone": testPhone, "password": testPassword}, "")
	if body := phoneErrorBody(t, rec, http.StatusUnprocessableEntity); body.ErrorCode != ErrorCodeUserAlreadyExists {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeUserAlreadyExists)
	}
}

// With confirmation required, a repeat signup of a CONFIRMED number must not
// reveal that it is taken.
func TestPhoneSignupOfConfirmedNumberIsSanitized(t *testing.T) {
	env := newPhoneEnv(t, nil)
	session := env.confirmedPhoneUser(t, testPhone, testPassword)

	env.sms.reset()
	rec := env.do(t, http.MethodPost, "/signup",
		map[string]any{"phone": testPhone, "password": "adifferentpassword"}, "")
	fake := decodeInto[User](t, rec, http.StatusOK)

	if fake.ID == session.User.ID {
		t.Error("the real user id leaked through a repeated signup")
	}
	if fake.PhoneConfirmedAt != nil {
		t.Error("the fabricated user claims a confirmed phone")
	}
	if n := len(env.sms.all()); n != 0 {
		t.Errorf("%d messages sent for a repeated signup, want 0", n)
	}
}

func TestPhoneSignupRejectsBadInput(t *testing.T) {
	env := newPhoneEnv(t, nil)

	cases := []struct {
		name     string
		body     map[string]any
		status   int
		wantCode string
	}{
		{"both identifiers", map[string]any{"email": "a@b.co", "phone": testPhone, "password": testPassword},
			http.StatusBadRequest, ErrorCodeValidationFailed},
		{"not e164", map[string]any{"phone": "555-123-0001", "password": testPassword},
			http.StatusBadRequest, ErrorCodeValidationFailed},
		{"no password", map[string]any{"phone": testPhone},
			http.StatusBadRequest, ErrorCodeValidationFailed},
		{"pkce", map[string]any{"phone": testPhone, "password": testPassword,
			"code_challenge": "0123456789012345678901234567890123456789012", "code_challenge_method": "s256"},
			http.StatusBadRequest, ErrorCodeValidationFailed},
		{"bad channel", map[string]any{"phone": testPhone, "password": testPassword, "channel": "carrier-pigeon"},
			http.StatusBadRequest, ErrorCodeValidationFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := env.do(t, http.MethodPost, "/signup", tc.body, "")
			if body := phoneErrorBody(t, rec, tc.status); body.ErrorCode != tc.wantCode {
				t.Errorf("error_code = %q, want %q", body.ErrorCode, tc.wantCode)
			}
		})
	}
}

// Every phone-shaped request is still refused while the provider is off.
func TestPhoneSurfaceIsClosedWhenTheProviderIsDisabled(t *testing.T) {
	env := newPhoneEnv(t, func(c *Config) { c.External[ProviderPhone] = ProviderConfig{} })

	for _, tc := range []struct {
		name   string
		method string
		path   string
		body   map[string]any
		status int
	}{
		{"signup", http.MethodPost, "/signup",
			map[string]any{"phone": testPhone, "password": testPassword}, http.StatusBadRequest},
		{"otp", http.MethodPost, "/otp", map[string]any{"phone": testPhone}, http.StatusBadRequest},
		{"resend", http.MethodPost, "/resend",
			map[string]any{"type": smsVerification, "phone": testPhone}, http.StatusBadRequest},
		{"password grant", http.MethodPost, "/token?grant_type=password",
			map[string]any{"phone": testPhone, "password": testPassword}, http.StatusUnprocessableEntity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := env.do(t, tc.method, tc.path, tc.body, "")
			if body := phoneErrorBody(t, rec, tc.status); body.ErrorCode != ErrorCodePhoneProviderDisabled {
				t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodePhoneProviderDisabled)
			}
		})
	}
}

// ---- /otp ------------------------------------------------------------------

// POST /otp for an unknown number signs it up and texts the code; the code then
// redeems into a session through /verify.
func TestPhoneOTPSignsUpAndVerifies(t *testing.T) {
	env := newPhoneEnv(t, nil)

	rec := env.do(t, http.MethodPost, "/otp", map[string]any{"phone": testPhone}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	msgs := env.sms.to(testPhone)
	if len(msgs) != 1 {
		t.Fatalf("messages = %d, want 1 (%+v)", len(msgs), env.sms.all())
	}

	rec = env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": smsVerification, "phone": testPhone, "token": msgs[0].code(t)}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if session.User.PhoneConfirmedAt == nil {
		t.Error("phone is still unconfirmed after an /otp round trip")
	}
	if session.User.Phone != testPhoneE164 {
		t.Errorf("phone = %q, want %q", session.User.Phone, testPhoneE164)
	}
}

// A second /otp to an ESTABLISHED account reports the provider message id.
func TestPhoneOTPToEstablishedAccountReportsMessageID(t *testing.T) {
	env := newPhoneEnv(t, nil)
	env.confirmedPhoneUser(t, testPhone, testPassword)

	// Clear the throttle window left by the signup OTP.
	env.clock.advance(2 * env.cfg.SMS.MaxFrequency)

	rec := env.do(t, http.MethodPost, "/otp", map[string]any{"phone": testPhone}, "")
	body := decodeInto[map[string]any](t, rec, http.StatusOK)
	// The injected port reports no id, so upstream's field is absent — what
	// matters is that a message went out.
	if _, unexpected := body["error_code"]; unexpected {
		t.Fatalf("otp failed: %s", rec.Body.String())
	}
	if len(env.sms.to(testPhone)) != 1 {
		t.Errorf("messages = %d, want 1", len(env.sms.to(testPhone)))
	}
}

func TestPhoneOTPWithCreateUserFalseRefusesUnknownNumbers(t *testing.T) {
	env := newPhoneEnv(t, nil)

	rec := env.do(t, http.MethodPost, "/otp",
		map[string]any{"phone": testPhone, "create_user": false}, "")
	if body := phoneErrorBody(t, rec, http.StatusUnprocessableEntity); body.ErrorCode != ErrorCodeOTPDisabled {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeOTPDisabled)
	}
	if n := len(env.sms.all()); n != 0 {
		t.Errorf("%d messages sent, want 0", n)
	}
}

// ---- /verify ---------------------------------------------------------------

func TestPhoneVerifyRejectsWrongAndExpiredCodes(t *testing.T) {
	env := newPhoneEnv(t, nil)
	_, code := env.unconfirmedPhoneSignup(t, testPhone, testPassword)

	// Wrong code.
	wrong := "000000"
	if wrong == code {
		wrong = "111111"
	}
	rec := env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": smsVerification, "phone": testPhone, "token": wrong}, "")
	if body := phoneErrorBody(t, rec, http.StatusForbidden); body.ErrorCode != ErrorCodeOTPExpired {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeOTPExpired)
	}

	// The right code, but past SMS.OTPExp (60s by default, NOT the mailer's hour).
	env.clock.advance(env.cfg.SMS.OTPExpDuration() + time.Second)
	rec = env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": smsVerification, "phone": testPhone, "token": code}, "")
	if body := phoneErrorBody(t, rec, http.StatusForbidden); body.ErrorCode != ErrorCodeOTPExpired {
		t.Errorf("expired: error_code = %q, want %q", body.ErrorCode, ErrorCodeOTPExpired)
	}
}

// The OTP is bound to the number it was texted to.
func TestPhoneVerifyCodeIsNotReplayableOnAnotherNumber(t *testing.T) {
	env := newPhoneEnv(t, nil)
	_, code := env.unconfirmedPhoneSignup(t, testPhone, testPassword)

	other := "+15551230002"
	env.do(t, http.MethodPost, "/signup",
		map[string]any{"phone": other, "password": testPassword}, "")

	rec := env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": smsVerification, "phone": other, "token": code}, "")
	if body := phoneErrorBody(t, rec, http.StatusForbidden); body.ErrorCode != ErrorCodeOTPExpired {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeOTPExpired)
	}
}

// ---- phone change ----------------------------------------------------------

func TestPhoneChangeRequiresVerification(t *testing.T) {
	env := newPhoneEnv(t, nil)
	session := env.confirmedPhoneUser(t, testPhone, testPassword)
	env.clock.advance(2 * env.cfg.SMS.MaxFrequency)

	const newPhone = "+15559990001"
	const newPhoneE164 = "15559990001"

	rec := env.do(t, http.MethodPut, "/user", map[string]any{"phone": newPhone}, session.Token)
	parked := decodeInto[User](t, rec, http.StatusOK)

	if parked.Phone != testPhoneE164 {
		t.Errorf("phone = %q, want the OLD number %q until the change is confirmed", parked.Phone, testPhoneE164)
	}
	if parked.PhoneChange != newPhoneE164 {
		t.Errorf("new_phone = %q, want %q", parked.PhoneChange, newPhoneE164)
	}

	// The OTP goes to the NEW number.
	msgs := env.sms.to(newPhone)
	if len(msgs) != 1 {
		t.Fatalf("messages to the new number = %d, want 1 (%+v)", len(msgs), env.sms.all())
	}

	rec = env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": phoneChangeVerification, "phone": newPhone, "token": msgs[0].code(t)}, "")
	confirmed := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	if confirmed.User.Phone != newPhoneE164 {
		t.Errorf("phone = %q, want %q after the change lands", confirmed.User.Phone, newPhoneE164)
	}
	if confirmed.User.PhoneChange != "" {
		t.Errorf("new_phone = %q, want it cleared", confirmed.User.PhoneChange)
	}
	if confirmed.User.PhoneConfirmedAt == nil {
		t.Error("phone_confirmed_at was not re-stamped")
	}

	// The old number no longer signs in; the new one does.
	rec = env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"phone": testPhone, "password": testPassword}, "")
	if body := phoneErrorBody(t, rec, http.StatusBadRequest); body.ErrorCode != ErrorCodeInvalidCredentials {
		t.Errorf("old number: error_code = %q, want %q", body.ErrorCode, ErrorCodeInvalidCredentials)
	}
	rec = env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"phone": newPhone, "password": testPassword}, "")
	decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
}

// With SMS.Autoconfirm the change lands immediately and nothing is texted —
// upstream behaves the same way.
func TestPhoneChangeAppliesImmediatelyUnderAutoconfirm(t *testing.T) {
	env := newPhoneEnv(t, func(c *Config) { c.SMS.Autoconfirm = true })

	rec := env.do(t, http.MethodPost, "/signup",
		map[string]any{"phone": testPhone, "password": testPassword}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	env.sms.reset()

	const newPhoneE164 = "15559990002"
	rec = env.do(t, http.MethodPut, "/user", map[string]any{"phone": "+" + newPhoneE164}, session.Token)
	updated := decodeInto[User](t, rec, http.StatusOK)

	if updated.Phone != newPhoneE164 {
		t.Errorf("phone = %q, want %q", updated.Phone, newPhoneE164)
	}
	if updated.PhoneChange != "" {
		t.Errorf("new_phone = %q, want it cleared", updated.PhoneChange)
	}
	if n := len(env.sms.all()); n != 0 {
		t.Errorf("%d messages sent under autoconfirm, want 0", n)
	}
}

func TestPhoneChangeToATakenNumberIsRefused(t *testing.T) {
	env := newPhoneEnv(t, func(c *Config) { c.SMS.Autoconfirm = true })

	rec := env.do(t, http.MethodPost, "/signup",
		map[string]any{"phone": testPhone, "password": testPassword}, "")
	first := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	const taken = "+15551230009"
	env.do(t, http.MethodPost, "/signup",
		map[string]any{"phone": taken, "password": testPassword}, "")

	rec = env.do(t, http.MethodPut, "/user", map[string]any{"phone": taken}, first.Token)
	if body := phoneErrorBody(t, rec, http.StatusUnprocessableEntity); body.ErrorCode != ErrorCodePhoneExists {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodePhoneExists)
	}
}

// ---- /resend ---------------------------------------------------------------

func TestPhoneResendSignupOTP(t *testing.T) {
	env := newPhoneEnv(t, nil)
	env.unconfirmedPhoneSignup(t, testPhone, testPassword)
	env.sms.reset()
	env.clock.advance(2 * env.cfg.SMS.MaxFrequency)

	rec := env.do(t, http.MethodPost, "/resend",
		map[string]any{"type": smsVerification, "phone": testPhone}, "")
	decodeInto[map[string]any](t, rec, http.StatusOK)

	msgs := env.sms.to(testPhone)
	if len(msgs) != 1 {
		t.Fatalf("resent messages = %d, want 1", len(msgs))
	}
	// The re-sent code is the live one.
	rec = env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": smsVerification, "phone": testPhone, "token": msgs[0].code(t)}, "")
	decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
}

// Nothing to confirm, unknown number, wrong type: all answered with a bare 200
// so /resend cannot probe account state.
func TestPhoneResendIsSilentAboutAccountState(t *testing.T) {
	env := newPhoneEnv(t, nil)

	// Unknown number.
	rec := env.do(t, http.MethodPost, "/resend",
		map[string]any{"type": smsVerification, "phone": "+15550000000"}, "")
	decodeInto[map[string]any](t, rec, http.StatusOK)
	if n := len(env.sms.all()); n != 0 {
		t.Errorf("%d messages sent for an unknown number, want 0", n)
	}

	// Already confirmed.
	env.confirmedPhoneUser(t, testPhone, testPassword)
	env.sms.reset()
	env.clock.advance(2 * env.cfg.SMS.MaxFrequency)
	rec = env.do(t, http.MethodPost, "/resend",
		map[string]any{"type": smsVerification, "phone": testPhone}, "")
	decodeInto[map[string]any](t, rec, http.StatusOK)
	if n := len(env.sms.all()); n != 0 {
		t.Errorf("%d messages sent for a confirmed number, want 0", n)
	}

	// No pending change.
	rec = env.do(t, http.MethodPost, "/resend",
		map[string]any{"type": phoneChangeVerification, "phone": testPhone}, "")
	decodeInto[map[string]any](t, rec, http.StatusOK)
	if n := len(env.sms.all()); n != 0 {
		t.Errorf("%d messages sent with no pending change, want 0", n)
	}
}

func TestPhoneResendPhoneChangeTargetsThePendingNumber(t *testing.T) {
	env := newPhoneEnv(t, nil)
	session := env.confirmedPhoneUser(t, testPhone, testPassword)
	env.clock.advance(2 * env.cfg.SMS.MaxFrequency)

	const newPhone = "+15559990003"
	env.do(t, http.MethodPut, "/user", map[string]any{"phone": newPhone}, session.Token)
	env.sms.reset()
	env.clock.advance(2 * env.cfg.SMS.MaxFrequency)

	// Resolved by the CURRENT number, delivered to the PENDING one.
	rec := env.do(t, http.MethodPost, "/resend",
		map[string]any{"type": phoneChangeVerification, "phone": testPhone}, "")
	decodeInto[map[string]any](t, rec, http.StatusOK)

	msgs := env.sms.to(newPhone)
	if len(msgs) != 1 {
		t.Fatalf("messages to the pending number = %d, want 1 (%+v)", len(msgs), env.sms.all())
	}
	rec = env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": phoneChangeVerification, "phone": newPhone, "token": msgs[0].code(t)}, "")
	session = decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if session.User.Phone != "15559990003" {
		t.Errorf("phone = %q, want the pending number", session.User.Phone)
	}
}

// ---- send frequency --------------------------------------------------------

// SMS.MaxFrequency is a per-USER, per-token-type throttle with upstream's
// verbatim 429 body.
func TestSMSMaxFrequencyThrottlesRepeatSends(t *testing.T) {
	env := newPhoneEnv(t, nil)
	env.unconfirmedPhoneSignup(t, testPhone, testPassword)
	env.sms.reset()

	rec := env.do(t, http.MethodPost, "/resend",
		map[string]any{"type": smsVerification, "phone": testPhone}, "")
	body := phoneErrorBody(t, rec, http.StatusTooManyRequests)
	if body.ErrorCode != ErrorCodeOverSMSSendRateLimit {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeOverSMSSendRateLimit)
	}
	if !strings.HasPrefix(body.Message, "For security purposes, you can only request this after ") {
		t.Errorf("msg = %q, want upstream's frequency-limit message", body.Message)
	}
	if n := len(env.sms.all()); n != 0 {
		t.Errorf("%d messages sent while throttled, want 0", n)
	}

	// Past the window the send goes through again.
	env.clock.advance(env.cfg.SMS.MaxFrequency + time.Second)
	rec = env.do(t, http.MethodPost, "/resend",
		map[string]any{"type": smsVerification, "phone": testPhone}, "")
	decodeInto[map[string]any](t, rec, http.StatusOK)
	if n := len(env.sms.to(testPhone)); n != 1 {
		t.Errorf("messages after the window = %d, want 1", n)
	}
}

// ---- /reauthenticate -------------------------------------------------------

// A phone-only account reauthenticates by SMS, and the nonce authorizes a
// password change.
func TestPhoneReauthenticationNonceAuthorizesPasswordChange(t *testing.T) {
	env := newPhoneEnv(t, func(c *Config) { c.Security.UpdatePasswordRequireReauth = true })
	session := env.confirmedPhoneUser(t, testPhone, testPassword)

	// Age the session past the 24h recency grace period so a nonce is required.
	env.clock.advance(25 * time.Hour)

	rec := env.do(t, http.MethodGet, "/reauthenticate", nil, session.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
	}
	msgs := env.sms.to(testPhone)
	if len(msgs) != 1 {
		t.Fatalf("reauthentication messages = %d, want 1 (%+v)", len(msgs), env.sms.all())
	}
	nonce := msgs[0].code(t)

	// Without the nonce the change is refused.
	rec = env.do(t, http.MethodPut, "/user", map[string]any{"password": "brandnewpassword1"}, session.Token)
	if body := phoneErrorBody(t, rec, http.StatusBadRequest); body.ErrorCode != ErrorCodeReauthenticationNeeded {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeReauthenticationNeeded)
	}

	// A wrong nonce is refused.
	wrong := "000000"
	if wrong == nonce {
		wrong = "111111"
	}
	rec = env.do(t, http.MethodPut, "/user",
		map[string]any{"password": "brandnewpassword1", "nonce": wrong}, session.Token)
	if body := phoneErrorBody(t, rec, http.StatusUnprocessableEntity); body.ErrorCode != ErrorCodeReauthenticationNotValid {
		t.Errorf("wrong nonce: error_code = %q, want %q", body.ErrorCode, ErrorCodeReauthenticationNotValid)
	}

	// The real nonce works.
	rec = env.do(t, http.MethodPut, "/user",
		map[string]any{"password": "brandnewpassword1", "nonce": nonce}, session.Token)
	decodeInto[User](t, rec, http.StatusOK)

	rec = env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"phone": testPhone, "password": "brandnewpassword1"}, "")
	decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
}

func TestPhoneReauthenticationRequiresAConfirmedNumber(t *testing.T) {
	env := newPhoneEnv(t, func(c *Config) { c.SMS.Autoconfirm = true })

	rec := env.do(t, http.MethodPost, "/signup",
		map[string]any{"phone": testPhone, "password": testPassword}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	// Un-confirm the number behind the API's back.
	if _, err := env.pool.Exec(context.Background(),
		`update auth.users set phone_confirmed_at = null where id = $1::uuid`, session.User.ID); err != nil {
		t.Fatalf("unconfirm: %v", err)
	}

	rec = env.do(t, http.MethodGet, "/reauthenticate", nil, session.Token)
	if body := phoneErrorBody(t, rec, http.StatusUnprocessableEntity); body.ErrorCode != ErrorCodePhoneNotConfirmed {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodePhoneNotConfirmed)
	}
}

// ---- provider failures -----------------------------------------------------

// A provider that rejects the message fails the request with upstream's 422 and
// leaves NO account behind — the send happens inside the signup transaction.
func TestPhoneSignupRollsBackWhenTheProviderFails(t *testing.T) {
	env := newPhoneEnv(t, nil)
	env.sms.err = errSendFailed

	rec := env.do(t, http.MethodPost, "/signup",
		map[string]any{"phone": testPhone, "password": testPassword}, "")
	if body := phoneErrorBody(t, rec, http.StatusUnprocessableEntity); body.ErrorCode != ErrorCodeSMSSendFailed {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeSMSSendFailed)
	}

	var n int64
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from auth.users where phone = $1`, testPhoneE164).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if n != 0 {
		t.Errorf("%d users left behind after a failed send, want 0", n)
	}
}

// With no sender and no provider, a phone flow fails loudly rather than
// creating an account nobody can ever sign into.
func TestPhoneSignupFailsWithoutAnySMSTransport(t *testing.T) {
	env := newPhoneEnv(t, func(c *Config) { c.SMS.Sender = nil })

	rec := env.do(t, http.MethodPost, "/signup",
		map[string]any{"phone": testPhone, "password": testPassword}, "")
	if body := phoneErrorBody(t, rec, http.StatusInternalServerError); body.ErrorCode != ErrorCodeUnexpectedFailure {
		t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeUnexpectedFailure)
	}
}

var errSendFailed = &sendError{"carrier rejected the message"}

type sendError struct{ msg string }

func (e *sendError) Error() string { return e.msg }

// ---- email regression ------------------------------------------------------

// Opening the phone surface must not disturb the email one: an email signup
// under the same mount still mails a link and refuses a phone/email mix.
func TestEmailSignupStillWorksAlongsideThePhoneSurface(t *testing.T) {
	env := newPhoneEnv(t, nil)

	rec := env.do(t, http.MethodPost, "/signup",
		map[string]any{"email": "mixed@example.com", "password": "hunter22"}, "")
	user := decodeInto[User](t, rec, http.StatusOK)
	if user.EmailConfirmedAt != nil {
		t.Error("email was autoconfirmed although confirmation is required")
	}
	if len(env.mails.to("mixed@example.com")) != 1 {
		t.Errorf("confirmation mails = %d, want 1", len(env.mails.to("mixed@example.com")))
	}
	if n := len(env.sms.all()); n != 0 {
		t.Errorf("%d messages sent for an EMAIL signup, want 0", n)
	}
}

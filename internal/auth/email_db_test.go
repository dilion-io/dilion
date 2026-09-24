package auth

// Database-backed tests for the email lifecycle and PKCE.
//
// Like handlers_db_test.go these only run when DILION_TEST_DB is set:
//
//	DILION_TEST_DB=postgres://dilion:dilion@localhost:55432/dilion_test_b \
//	  go test -race -count=1 ./internal/auth/...

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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

// recordedMail is one message the API handed to ports.Mailer.
type recordedMail struct {
	To      string
	Subject string
	Text    string
}

type recordingMailer struct {
	mu   sync.Mutex
	sent []recordedMail
}

func (m *recordingMailer) Send(_ context.Context, to, subject, text, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, recordedMail{To: to, Subject: subject, Text: text})
	return nil
}

func (m *recordingMailer) all() []recordedMail {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]recordedMail(nil), m.sent...)
}

func (m *recordingMailer) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = nil
}

// to returns every message delivered to one address.
func (m *recordingMailer) to(address string) []recordedMail {
	var out []recordedMail
	for _, msg := range m.all() {
		if msg.To == address {
			out = append(out, msg)
		}
	}
	return out
}

// stepClock is a manually advanced clock, so expiry can be tested without
// sleeping. It is only given to the API — the TokenService keeps the system
// clock, which lets a test age a SESSION without invalidating its JWT.
type stepClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *stepClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *stepClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type emailEnv struct {
	*testEnv
	mails *recordingMailer
	clock *stepClock
	cfg   *Config
}

// maxMailFrequency is the window a repeated send of the same kind must clear
// (Mailer.MaxFrequency, mailflow.go).
func (e *emailEnv) maxMailFrequency() time.Duration {
	if e.cfg == nil {
		return time.Minute
	}
	return e.cfg.Mailer.MaxFrequency
}

// emailTestConfig is the configuration the email flows are exercised under:
// confirmation required (the upstream default, and the only setting where the
// flows are observable) and an allow-list that admits exactly one app origin.
func emailTestConfig() *Config {
	cfg := testConfig()
	cfg.SiteURL = "https://app.test"
	cfg.URIAllowList = []string{"https://app.test/**"}
	cfg.Mailer.Autoconfirm = false
	return cfg
}

func newEmailEnv(t *testing.T, cfg *Config) *emailEnv {
	t.Helper()

	dsn := os.Getenv("DILION_TEST_DB")
	if dsn == "" {
		t.Skip("DILION_TEST_DB not set; skipping database-backed tests")
	}
	if !strings.HasPrefix(dsn, "postgres") {
		dsn = defaultTestDSN
	}
	if cfg == nil {
		cfg = emailTestConfig()
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
	truncateAll(t, pool)
	truncateEmailTables(t, pool)

	env := &emailEnv{
		testEnv: &testEnv{
			pool:   pool,
			tokens: NewTokenServiceHS(testSecret()),
			hooks:  hooks.NewRegistry(),
			mailer: &captureMailer{},
		},
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

// applyEmailSchema installs the migrations this feature owns. They are separate
// files upstream-side too, and the shared harness only applies 0100.
func applyEmailSchema(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	if !firstApply("applyEmailSchema") {
		return
	}
	for _, name := range []string{"0110_auth_one_time_tokens.sql", "0111_auth_flow_state.sql"} {
		path := filepath.Join("..", "..", "migrations", name)
		sql, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if _, err := pool.Exec(context.Background(), string(sql)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
}

func truncateEmailTables(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	// DELETE rather than TRUNCATE: auth.saml_relay_states (migration 0113, owned
	// by another feature) may hold a foreign key onto auth.flow_state, which
	// TRUNCATE refuses to work around.
	if _, err := pool.Exec(context.Background(),
		`delete from auth.one_time_tokens; delete from auth.flow_state;`); err != nil {
		t.Fatalf("clear email tables: %v", err)
	}
}

// ---- mail parsing ----------------------------------------------------------

var (
	mailLinkPattern = regexp.MustCompile(`https?://\S+`)
	mailOTPPattern  = regexp.MustCompile(`Or enter this code: (\d+)`)
)

// link returns the action link the message carries.
func (m recordedMail) link(t *testing.T) string {
	t.Helper()
	found := mailLinkPattern.FindString(m.Text)
	if found == "" {
		t.Fatalf("no action link in mail to %s:\n%s", m.To, m.Text)
	}
	return found
}

// otp returns the code the message carries.
func (m recordedMail) otp(t *testing.T) string {
	t.Helper()
	found := mailOTPPattern.FindStringSubmatch(m.Text)
	if found == nil {
		t.Fatalf("no OTP in mail to %s:\n%s", m.To, m.Text)
	}
	return found[1]
}

// token returns the `token` query parameter of the action link, i.e. the stored
// token hash (prefixed "pkce_" for a PKCE flow).
func (m recordedMail) token(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(m.link(t))
	if err != nil {
		t.Fatalf("parse action link %q: %v", m.link(t), err)
	}
	tok := u.Query().Get("token")
	if tok == "" {
		t.Fatalf("action link has no token: %s", u)
	}
	return tok
}

// ---- redirect helpers ------------------------------------------------------

// redirectOf asserts a 303 and returns the parsed Location.
func redirectOf(t *testing.T, rec interface{ Result() *http.Response }, body string) *url.URL {
	t.Helper()
	resp := rec.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303; body = %s", resp.StatusCode, body)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatal("no Location header on redirect")
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location %q: %v", loc, err)
	}
	return u
}

// fragmentOf parses the URL fragment as a query string — where the implicit
// flow puts the session.
func fragmentOf(t *testing.T, u *url.URL) url.Values {
	t.Helper()
	v, err := url.ParseQuery(u.Fragment)
	if err != nil {
		t.Fatalf("parse fragment %q: %v", u.Fragment, err)
	}
	return v
}

// ---- account helpers -------------------------------------------------------

// unconfirmedSignup performs a signup that requires confirmation and returns the
// user object plus the confirmation mail.
func (e *emailEnv) unconfirmedSignup(t *testing.T, email, password string) (User, recordedMail) {
	t.Helper()
	e.mails.reset()
	rec := e.do(t, http.MethodPost, "/signup",
		map[string]any{"email": email, "password": password}, "")
	user := decodeInto[User](t, rec, http.StatusOK)

	mails := e.mails.to(email)
	if len(mails) != 1 {
		t.Fatalf("confirmation mails to %s = %d, want 1", email, len(mails))
	}
	return user, mails[0]
}

// confirmedUser signs an account up and follows its confirmation link, leaving a
// usable account and a live session.
func (e *emailEnv) confirmedUser(t *testing.T, email, password string) AccessTokenResponse {
	t.Helper()
	_, mail := e.unconfirmedSignup(t, email, password)

	rec := e.do(t, http.MethodPost, "/verify",
		map[string]any{"type": mailSignup, "token_hash": mail.token(t)}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	e.mails.reset()
	return session
}

// ---- signup confirmation ---------------------------------------------------

// The headline flow: signup returns a USER and no session, the account is
// unconfirmed, and following the mailed link both confirms it and signs in.
func TestSignupConfirmationThenVerifyThenLogin(t *testing.T) {
	env := newEmailEnv(t, nil)

	user, mail := env.unconfirmedSignup(t, "confirm@example.com", "hunter22")

	if user.EmailConfirmedAt != nil {
		t.Errorf("email_confirmed_at = %v, want NULL before confirmation", user.EmailConfirmedAt)
	}
	if user.ConfirmationSentAt == nil {
		t.Error("confirmation_sent_at was not stamped")
	}
	if user.ID == "" || user.Email != "confirm@example.com" {
		t.Errorf("signup returned %+v", user)
	}
	if mail.Subject != "Confirm your email address" {
		t.Errorf("subject = %q", mail.Subject)
	}
	// The link resolves under the /auth/v1 mount, not upstream's bare /verify.
	if !strings.HasPrefix(mail.link(t), "https://app.test"+DefaultMailerURLPath+"?") {
		t.Errorf("action link = %q, want it under SiteURL", mail.link(t))
	}

	// The password grant must not hand out a session for an unconfirmed
	// account... but see the gap noted in the report: the check lives in
	// grant.go, which this wave does not own. What IS guaranteed here is that
	// the account exists and is unconfirmed.
	var confirmedAt *time.Time
	if err := env.pool.QueryRow(context.Background(),
		`select email_confirmed_at from auth.users where id = $1::uuid`, user.ID).Scan(&confirmedAt); err != nil {
		t.Fatalf("read user: %v", err)
	}
	if confirmedAt != nil {
		t.Fatal("account was confirmed without following the link")
	}

	// Follow the link.
	rec := env.do(t, http.MethodGet,
		"/verify?type=signup&token="+url.QueryEscape(mail.token(t))+
			"&redirect_to="+url.QueryEscape("https://app.test/done"), nil, "")
	loc := redirectOf(t, rec, rec.Body.String())

	if loc.Scheme+"://"+loc.Host+loc.Path != "https://app.test/done" {
		t.Errorf("redirect target = %q, want https://app.test/done", loc)
	}
	frag := fragmentOf(t, loc)
	if frag.Get("access_token") == "" || frag.Get("refresh_token") == "" {
		t.Errorf("fragment = %v, want an implicit-flow session", frag)
	}
	if frag.Get("type") != "signup" {
		t.Errorf("fragment type = %q, want signup", frag.Get("type"))
	}

	// The account is now usable with its password.
	rec = env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"email": "confirm@example.com", "password": "hunter22"}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if session.User.EmailConfirmedAt == nil {
		t.Error("email_confirmed_at is still NULL after verification")
	}
	if v, _ := session.User.UserMetaData["email_verified"].(bool); !v {
		t.Errorf("user_metadata.email_verified = %v, want true", session.User.UserMetaData["email_verified"])
	}
	if len(session.User.Identities) != 1 {
		t.Fatalf("identities = %+v", session.User.Identities)
	}
	if v, _ := session.User.Identities[0].IdentityData["email_verified"].(bool); !v {
		t.Error("identity email_verified was not updated")
	}

	// The one-time token is gone: a link is single use.
	assertNoLiveTokens(t, env, session.User.ID)
}

// Autoconfirm is the Dilion default and must keep returning a session directly.
func TestSignupWithAutoconfirmStillReturnsSession(t *testing.T) {
	cfg := emailTestConfig()
	cfg.Mailer.Autoconfirm = true
	env := newEmailEnv(t, cfg)

	rec := env.do(t, http.MethodPost, "/signup",
		map[string]any{"email": "auto@example.com", "password": "hunter22"}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if session.Token == "" || session.User == nil || session.User.EmailConfirmedAt == nil {
		t.Fatalf("autoconfirm signup = %+v", session)
	}
	if got := len(env.mails.all()); got != 0 {
		t.Errorf("mails sent = %d, want 0 under autoconfirm", got)
	}
}

// A repeated signup on a confirmed address must not reveal that the address is
// taken while confirmation is pending.
func TestRepeatedSignupDoesNotLeakExistence(t *testing.T) {
	env := newEmailEnv(t, nil)
	session := env.confirmedUser(t, "taken@example.com", "hunter22")

	rec := env.do(t, http.MethodPost, "/signup",
		map[string]any{"email": "taken@example.com", "password": "otherpass1"}, "")
	fake := decodeInto[User](t, rec, http.StatusOK)

	if fake.ID == session.User.ID {
		t.Error("the real user id was disclosed for an existing address")
	}
	if fake.EmailConfirmedAt != nil || len(fake.Identities) != 0 {
		t.Errorf("fabricated user leaks account state: %+v", fake)
	}
}

// A signup repeated while confirmation is still pending re-sends the mail
// against the SAME account.
func TestSignupResendsWhileUnconfirmed(t *testing.T) {
	env := newEmailEnv(t, nil)
	first, _ := env.unconfirmedSignup(t, "pending@example.com", "hunter22")
	// Past Mailer.MaxFrequency, or the repeat send is suppressed with a 429
	// (mailflow.go checkMailFrequency).
	env.clock.advance(env.maxMailFrequency() + time.Second)
	second, mail := env.unconfirmedSignup(t, "pending@example.com", "hunter22")

	if first.ID != second.ID {
		t.Errorf("a second signup created a new account: %s != %s", first.ID, second.ID)
	}
	// The newest token is the one that works.
	rec := env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": mailSignup, "token_hash": mail.token(t)}, "")
	decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
}

// ---- /verify ---------------------------------------------------------------

// A token may only be redeemed once.
func TestVerifyTokenIsSingleUse(t *testing.T) {
	env := newEmailEnv(t, nil)
	_, mail := env.unconfirmedSignup(t, "once@example.com", "hunter22")
	token := mail.token(t)

	rec := env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": mailSignup, "token_hash": token}, "")
	decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	rec = env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": mailSignup, "token_hash": token}, "")
	e := decodeInto[HTTPError](t, rec, http.StatusForbidden)
	if e.ErrorCode != ErrorCodeOTPExpired {
		t.Errorf("error_code = %q, want %q", e.ErrorCode, ErrorCodeOTPExpired)
	}
}

// Past Mailer.OTPExp a token is refused, with the same body an unknown token
// gets.
func TestVerifyRejectsExpiredToken(t *testing.T) {
	cfg := emailTestConfig()
	cfg.Mailer.OTPExp = 600
	env := newEmailEnv(t, cfg)

	_, mail := env.unconfirmedSignup(t, "stale@example.com", "hunter22")
	env.clock.advance(601 * time.Second)

	rec := env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": mailSignup, "token_hash": mail.token(t)}, "")
	e := decodeInto[HTTPError](t, rec, http.StatusForbidden)
	if e.ErrorCode != ErrorCodeOTPExpired {
		t.Errorf("error_code = %q, want %q", e.ErrorCode, ErrorCodeOTPExpired)
	}
}

// The typed-OTP form: POST /verify {type, email, token}.
func TestVerifyWithEmailAndTypedOTP(t *testing.T) {
	env := newEmailEnv(t, nil)
	env.confirmedUser(t, "typed@example.com", "hunter22")

	rec := env.do(t, http.MethodPost, "/recover", map[string]any{"email": "typed@example.com"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("/recover = %d: %s", rec.Code, rec.Body.String())
	}
	mails := env.mails.to("typed@example.com")
	if len(mails) != 1 {
		t.Fatalf("recovery mails = %d, want 1", len(mails))
	}

	rec = env.do(t, http.MethodPost, "/verify", map[string]any{
		"type": mailRecovery, "email": "typed@example.com", "token": mails[0].otp(t),
	}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if session.Token == "" {
		t.Error("recovery OTP did not produce a session")
	}

	// A wrong code is refused.
	rec = env.do(t, http.MethodPost, "/verify", map[string]any{
		"type": mailRecovery, "email": "typed@example.com", "token": "000000",
	}, "")
	decodeInto[HTTPError](t, rec, http.StatusForbidden)
}

// GET /verify must never redirect to an origin outside the allow list.
func TestVerifyRedirectAllowList(t *testing.T) {
	env := newEmailEnv(t, nil)
	_, mail := env.unconfirmedSignup(t, "redir@example.com", "hunter22")

	rec := env.do(t, http.MethodGet,
		"/verify?type=signup&token="+url.QueryEscape(mail.token(t))+
			"&redirect_to="+url.QueryEscape("https://evil.test/steal"), nil, "")
	loc := redirectOf(t, rec, rec.Body.String())

	if strings.Contains(loc.Host, "evil.test") {
		t.Fatalf("redirected to a disallowed origin: %s", loc)
	}
	if loc.Scheme+"://"+loc.Host != "https://app.test" {
		t.Errorf("fallback target = %q, want SiteURL", loc)
	}
	// The session still went out, but only to the trusted origin.
	if fragmentOf(t, loc).Get("access_token") == "" {
		t.Error("no session in the fragment of the fallback redirect")
	}
}

// A failed GET /verify redirects with upstream's error parameters instead of
// rendering an error page.
func TestVerifyGetErrorRedirect(t *testing.T) {
	env := newEmailEnv(t, nil)

	rec := env.do(t, http.MethodGet,
		"/verify?type=signup&token=deadbeef&redirect_to="+url.QueryEscape("https://app.test/done"), nil, "")
	loc := redirectOf(t, rec, rec.Body.String())

	frag := fragmentOf(t, loc)
	if frag.Get("error_code") != ErrorCodeOTPExpired {
		t.Errorf("fragment error_code = %q, want %q", frag.Get("error_code"), ErrorCodeOTPExpired)
	}
	if frag.Get("error") != "access_denied" {
		t.Errorf("fragment error = %q, want access_denied (403)", frag.Get("error"))
	}
	if frag.Get("error_description") == "" {
		t.Error("no error_description in the fragment")
	}
	// The implicit flow keeps the details out of the query string.
	if loc.Query().Get("error_code") != "" {
		t.Errorf("implicit flow leaked the error into the query string: %s", loc.RawQuery)
	}
}

// ---- /otp and /magiclink ---------------------------------------------------

func TestMagicLinkForExistingUser(t *testing.T) {
	env := newEmailEnv(t, nil)
	env.confirmedUser(t, "magic@example.com", "hunter22")

	rec := env.do(t, http.MethodPost, "/otp", map[string]any{"email": "magic@example.com"}, "")
	if body := rec.Body.String(); rec.Code != http.StatusOK || strings.TrimSpace(body) != "{}" {
		t.Fatalf("/otp = %d %s, want 200 {}", rec.Code, body)
	}
	mails := env.mails.to("magic@example.com")
	if len(mails) != 1 || mails[0].Subject != "Your sign-in link" {
		t.Fatalf("magic link mails = %+v", mails)
	}

	rec = env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": mailMagicLink, "token_hash": mails[0].token(t)}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if session.User.Email != "magic@example.com" {
		t.Errorf("session user = %+v", session.User)
	}
}

// The `email` verification type accepts either a confirmation or a recovery
// token, which is what supabase-js sends for "verify OTP".
func TestVerifyEmailTypeAcceptsMagicLinkToken(t *testing.T) {
	env := newEmailEnv(t, nil)
	env.confirmedUser(t, "anytype@example.com", "hunter22")

	env.do(t, http.MethodPost, "/magiclink", map[string]any{"email": "anytype@example.com"}, "")
	mails := env.mails.to("anytype@example.com")
	if len(mails) != 1 {
		t.Fatalf("magic link mails = %d", len(mails))
	}

	rec := env.do(t, http.MethodPost, "/verify", map[string]any{
		"type": mailEmailOTP, "email": "anytype@example.com", "token": mails[0].otp(t),
	}, "")
	decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
}

// create_user=false must not sign an unknown address up.
func TestOTPCreateUserFalse(t *testing.T) {
	env := newEmailEnv(t, nil)

	rec := env.do(t, http.MethodPost, "/otp",
		map[string]any{"email": "nobody@example.com", "create_user": false}, "")
	e := decodeInto[HTTPError](t, rec, http.StatusUnprocessableEntity)
	if e.ErrorCode != ErrorCodeOTPDisabled {
		t.Errorf("error_code = %q, want %q", e.ErrorCode, ErrorCodeOTPDisabled)
	}
	if got := len(env.mails.all()); got != 0 {
		t.Errorf("mails sent = %d, want 0", got)
	}

	var n int
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from auth.users where email = 'nobody@example.com'`).Scan(&n); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if n != 0 {
		t.Errorf("users created = %d, want 0", n)
	}
}

// A phone-shaped request is refused explicitly rather than silently ignored.
func TestPhonePathsAreRefused(t *testing.T) {
	env := newEmailEnv(t, nil)

	for _, tc := range []struct {
		path string
		body map[string]any
	}{
		{"/otp", map[string]any{"phone": "+821012345678"}},
		{"/resend", map[string]any{"type": "sms", "phone": "+821012345678"}},
		{"/resend", map[string]any{"type": "phone_change", "phone": "+821012345678"}},
	} {
		rec := env.do(t, http.MethodPost, tc.path, tc.body, "")
		e := decodeInto[HTTPError](t, rec, http.StatusBadRequest)
		if e.ErrorCode != ErrorCodePhoneProviderDisabled {
			t.Errorf("%s %v: error_code = %q, want %q", tc.path, tc.body, e.ErrorCode, ErrorCodePhoneProviderDisabled)
		}
	}
}

// ---- /recover --------------------------------------------------------------

func TestRecoverThenVerifyGivesSession(t *testing.T) {
	env := newEmailEnv(t, nil)
	env.confirmedUser(t, "reset@example.com", "hunter22")

	rec := env.do(t, http.MethodPost, "/recover", map[string]any{"email": "reset@example.com"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("/recover = %d: %s", rec.Code, rec.Body.String())
	}
	mails := env.mails.to("reset@example.com")
	if len(mails) != 1 || mails[0].Subject != "Reset your password" {
		t.Fatalf("recovery mails = %+v", mails)
	}

	rec = env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": mailRecovery, "token_hash": mails[0].token(t)}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	// The session is what lets the client finish with PUT /user.
	rec = env.do(t, http.MethodPut, "/user", map[string]any{"password": "brandnew99"}, session.Token)
	decodeInto[User](t, rec, http.StatusOK)

	rec = env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"email": "reset@example.com", "password": "brandnew99"}, "")
	decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
}

// An unknown address gets the same answer as a known one, and no mail.
func TestRecoverDoesNotLeakExistence(t *testing.T) {
	env := newEmailEnv(t, nil)

	rec := env.do(t, http.MethodPost, "/recover", map[string]any{"email": "ghost@example.com"}, "")
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "{}" {
		t.Fatalf("/recover for unknown address = %d %s", rec.Code, rec.Body.String())
	}
	if got := len(env.mails.all()); got != 0 {
		t.Errorf("mails sent = %d, want 0", got)
	}
}

// ---- /resend ---------------------------------------------------------------

func TestResendSignupConfirmation(t *testing.T) {
	env := newEmailEnv(t, nil)
	env.unconfirmedSignup(t, "resend@example.com", "hunter22")
	env.mails.reset()
	// A resend inside Mailer.MaxFrequency is a 429 (see the dedicated tests in
	// mailfreq_db_test.go); this test is about the resend itself.
	env.clock.advance(env.maxMailFrequency() + time.Second)

	rec := env.do(t, http.MethodPost, "/resend",
		map[string]any{"type": mailSignup, "email": "resend@example.com"}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("/resend = %d: %s", rec.Code, rec.Body.String())
	}
	mails := env.mails.to("resend@example.com")
	if len(mails) != 1 {
		t.Fatalf("resent mails = %d, want 1", len(mails))
	}

	rec = env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": mailSignup, "token_hash": mails[0].token(t)}, "")
	decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
}

// Nothing pending, nothing sent — and still a 200 {}.
func TestResendIsQuietWhenNothingIsPending(t *testing.T) {
	env := newEmailEnv(t, nil)
	env.confirmedUser(t, "done@example.com", "hunter22")

	for _, body := range []map[string]any{
		{"type": mailSignup, "email": "done@example.com"},      // already confirmed
		{"type": mailEmailChange, "email": "done@example.com"}, // no change pending
		{"type": mailSignup, "email": "unknown@example.com"},   // no such account
	} {
		rec := env.do(t, http.MethodPost, "/resend", body, "")
		if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "{}" {
			t.Errorf("/resend %v = %d %s", body, rec.Code, rec.Body.String())
		}
	}
	if got := len(env.mails.all()); got != 0 {
		t.Errorf("mails sent = %d, want 0", got)
	}
}

func TestResendRejectsUnknownType(t *testing.T) {
	env := newEmailEnv(t, nil)
	rec := env.do(t, http.MethodPost, "/resend",
		map[string]any{"type": "nonsense", "email": "x@example.com"}, "")
	e := decodeInto[HTTPError](t, rec, http.StatusBadRequest)
	if e.ErrorCode != ErrorCodeValidationFailed {
		t.Errorf("error_code = %q", e.ErrorCode)
	}
}

// ---- email change ----------------------------------------------------------

// With SecureEmailChangeEnabled the change needs BOTH links.
func TestSecureEmailChangeNeedsBothConfirmations(t *testing.T) {
	env := newEmailEnv(t, nil)
	session := env.confirmedUser(t, "old@example.com", "hunter22")

	rec := env.do(t, http.MethodPut, "/user", map[string]any{"email": "new@example.com"}, session.Token)
	updated := decodeInto[User](t, rec, http.StatusOK)

	if updated.Email != "old@example.com" {
		t.Errorf("email = %q, want the change to be pending", updated.Email)
	}
	if updated.EmailChange != "new@example.com" {
		t.Errorf("new_email = %q, want new@example.com", updated.EmailChange)
	}

	toNew := env.mails.to("new@example.com")
	toOld := env.mails.to("old@example.com")
	if len(toNew) != 1 || len(toOld) != 1 {
		t.Fatalf("mails: new=%d old=%d, want 1 each", len(toNew), len(toOld))
	}

	// First link: accepted, but the change does not land yet.
	rec = env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": mailEmailChange, "token_hash": toNew[0].token(t)}, "")
	var half map[string]string
	half = decodeInto[map[string]string](t, rec, http.StatusOK)
	if half["msg"] != singleConfirmationAccepted {
		t.Fatalf("first confirmation = %v", half)
	}
	if emailOf(t, env, session.User.ID) != "old@example.com" {
		t.Fatal("the address changed after only one confirmation")
	}

	// Second link: applied.
	rec = env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": mailEmailChange, "token_hash": toOld[0].token(t)}, "")
	final := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if final.User.Email != "new@example.com" {
		t.Errorf("email = %q, want new@example.com", final.User.Email)
	}
	if final.User.EmailChange != "" {
		t.Errorf("new_email = %q, want it cleared", final.User.EmailChange)
	}
	if final.User.Identities[0].IdentityData["email"] != "new@example.com" {
		t.Errorf("identity was not updated: %+v", final.User.Identities[0].IdentityData)
	}
	assertNoLiveTokens(t, env, session.User.ID)
}

// With secure email change OFF, one confirmation from the new address is enough.
func TestInsecureEmailChangeNeedsOneConfirmation(t *testing.T) {
	cfg := emailTestConfig()
	cfg.Mailer.SecureEmailChangeEnabled = false
	env := newEmailEnv(t, cfg)

	session := env.confirmedUser(t, "single-old@example.com", "hunter22")
	rec := env.do(t, http.MethodPut, "/user", map[string]any{"email": "single-new@example.com"}, session.Token)
	decodeInto[User](t, rec, http.StatusOK)

	if got := len(env.mails.to("single-old@example.com")); got != 0 {
		t.Errorf("mails to the old address = %d, want 0 when secure email change is off", got)
	}
	toNew := env.mails.to("single-new@example.com")
	if len(toNew) != 1 {
		t.Fatalf("mails to the new address = %d, want 1", len(toNew))
	}

	rec = env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": mailEmailChange, "token_hash": toNew[0].token(t)}, "")
	final := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if final.User.Email != "single-new@example.com" {
		t.Errorf("email = %q", final.User.Email)
	}
}

// Changing to an address someone else already holds is refused up front.
func TestEmailChangeRejectsTakenAddress(t *testing.T) {
	env := newEmailEnv(t, nil)
	session := env.confirmedUser(t, "mover@example.com", "hunter22")
	env.confirmedUser(t, "occupied@example.com", "hunter22")

	rec := env.do(t, http.MethodPut, "/user", map[string]any{"email": "occupied@example.com"}, session.Token)
	e := decodeInto[HTTPError](t, rec, http.StatusUnprocessableEntity)
	if e.ErrorCode != ErrorCodeEmailExists {
		t.Errorf("error_code = %q, want %q", e.ErrorCode, ErrorCodeEmailExists)
	}
}

// ---- reauthentication ------------------------------------------------------

func TestReauthenticationNonceGatesPasswordChange(t *testing.T) {
	cfg := emailTestConfig()
	cfg.Security.UpdatePasswordRequireReauth = true
	env := newEmailEnv(t, cfg)

	session := env.confirmedUser(t, "reauth@example.com", "hunter22")

	// A session younger than 24h is proof enough (upstream's rule).
	rec := env.do(t, http.MethodPut, "/user", map[string]any{"password": "freshpass1"}, session.Token)
	decodeInto[User](t, rec, http.StatusOK)

	// Age the session past the window. The JWT keeps its own (system) clock, so
	// the caller stays authenticated while the SESSION is now stale.
	env.clock.advance(25 * time.Hour)

	rec = env.do(t, http.MethodPut, "/user", map[string]any{"password": "secondpass1"}, session.Token)
	e := decodeInto[HTTPError](t, rec, http.StatusBadRequest)
	if e.ErrorCode != ErrorCodeReauthenticationNeeded {
		t.Fatalf("error_code = %q, want %q", e.ErrorCode, ErrorCodeReauthenticationNeeded)
	}

	// A wrong nonce is refused.
	rec = env.do(t, http.MethodPut, "/user",
		map[string]any{"password": "secondpass1", "nonce": "000000"}, session.Token)
	e = decodeInto[HTTPError](t, rec, http.StatusUnprocessableEntity)
	if e.ErrorCode != ErrorCodeReauthenticationNotValid {
		t.Fatalf("error_code = %q, want %q", e.ErrorCode, ErrorCodeReauthenticationNotValid)
	}

	// Ask for a nonce and use it.
	env.mails.reset()
	rec = env.do(t, http.MethodGet, "/reauthenticate", nil, session.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("/reauthenticate = %d: %s", rec.Code, rec.Body.String())
	}
	mails := env.mails.to("reauth@example.com")
	if len(mails) != 1 {
		t.Fatalf("reauthentication mails = %d, want 1", len(mails))
	}
	nonce := mails[0].otp(t)
	if !strings.Contains(mails[0].Subject, nonce) {
		t.Errorf("subject = %q, want it to carry the code", mails[0].Subject)
	}

	rec = env.do(t, http.MethodPut, "/user",
		map[string]any{"password": "secondpass1", "nonce": nonce}, session.Token)
	decodeInto[User](t, rec, http.StatusOK)

	rec = env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"email": "reauth@example.com", "password": "secondpass1"}, "")
	decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	// The nonce is single use.
	rec = env.do(t, http.MethodPut, "/user",
		map[string]any{"password": "thirdpass11", "nonce": nonce}, session.Token)
	e = decodeInto[HTTPError](t, rec, http.StatusUnprocessableEntity)
	if e.ErrorCode != ErrorCodeReauthenticationNotValid {
		t.Errorf("nonce was reusable: %q", e.ErrorCode)
	}
}

func TestReauthenticateRequiresAuthentication(t *testing.T) {
	env := newEmailEnv(t, nil)
	rec := env.do(t, http.MethodGet, "/reauthenticate", nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// ---- /invite ---------------------------------------------------------------

func TestInviteCreatesUnconfirmedUserAndMails(t *testing.T) {
	env := newEmailEnv(t, nil)
	admin := env.serviceRoleToken(t)

	rec := env.do(t, http.MethodPost, "/invite",
		map[string]any{"email": "invited@example.com", "data": map[string]any{"team": "ops"}}, admin)
	user := decodeInto[User](t, rec, http.StatusOK)

	if user.InvitedAt == nil {
		t.Error("invited_at was not stamped")
	}
	if user.EmailConfirmedAt != nil {
		t.Error("an invited user must start unconfirmed")
	}
	if user.UserMetaData["team"] != "ops" {
		t.Errorf("user_metadata = %v", user.UserMetaData)
	}

	mails := env.mails.to("invited@example.com")
	if len(mails) != 1 || mails[0].Subject != "You've been invited" {
		t.Fatalf("invite mails = %+v", mails)
	}

	// Accepting the invitation confirms the account and signs the user in.
	rec = env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": mailInvite, "token_hash": mails[0].token(t)}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if session.User.EmailConfirmedAt == nil {
		t.Error("accepting the invite did not confirm the account")
	}
}

func TestInviteRequiresAdminAndRejectsConfirmedAddress(t *testing.T) {
	env := newEmailEnv(t, nil)

	rec := env.do(t, http.MethodPost, "/invite", map[string]any{"email": "x@example.com"}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated /invite = %d, want 401", rec.Code)
	}

	session := env.confirmedUser(t, "member@example.com", "hunter22")
	rec = env.do(t, http.MethodPost, "/invite", map[string]any{"email": "y@example.com"}, session.Token)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-admin /invite = %d, want 403", rec.Code)
	}

	admin := env.serviceRoleToken(t)
	rec = env.do(t, http.MethodPost, "/invite", map[string]any{"email": "member@example.com"}, admin)
	e := decodeInto[HTTPError](t, rec, http.StatusUnprocessableEntity)
	if e.ErrorCode != ErrorCodeEmailExists {
		t.Errorf("error_code = %q, want %q", e.ErrorCode, ErrorCodeEmailExists)
	}
}

// ---- /admin/generate_link --------------------------------------------------

func TestGenerateLinkAllTypes(t *testing.T) {
	env := newEmailEnv(t, nil)
	admin := env.serviceRoleToken(t)

	// signup, for an address with no account, honouring the supplied password.
	rec := env.do(t, http.MethodPost, "/admin/generate_link", map[string]any{
		"type": mailSignup, "email": "gen@example.com", "password": "generated9",
		"redirect_to": "https://app.test/welcome",
	}, admin)
	resp := decodeInto[GenerateLinkResponse](t, rec, http.StatusOK)

	if resp.ActionLink == "" || resp.EmailOtp == "" || resp.HashedToken == "" {
		t.Fatalf("incomplete response: %+v", resp)
	}
	if resp.VerificationType != mailSignup {
		t.Errorf("verification_type = %q", resp.VerificationType)
	}
	if resp.RedirectTo != "https://app.test/welcome" {
		t.Errorf("redirect_to = %q", resp.RedirectTo)
	}
	if resp.HashedToken != generateTokenHash("gen@example.com", resp.EmailOtp) {
		t.Error("hashed_token is not sha224(email+otp)")
	}
	if got := len(env.mails.all()); got != 0 {
		t.Errorf("generate_link sent %d mails, want 0", got)
	}

	// The link is live: redeeming it confirms the account.
	rec = env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": mailSignup, "token_hash": resp.HashedToken}, "")
	decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	// ...and the password that was passed in works.
	rec = env.do(t, http.MethodPost, "/token?grant_type=password",
		map[string]any{"email": "gen@example.com", "password": "generated9"}, "")
	decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	// recovery + magiclink for the now-existing account.
	for _, typ := range []string{mailRecovery, mailMagicLink} {
		rec = env.do(t, http.MethodPost, "/admin/generate_link",
			map[string]any{"type": typ, "email": "gen@example.com"}, admin)
		r := decodeInto[GenerateLinkResponse](t, rec, http.StatusOK)
		if r.VerificationType != typ {
			t.Errorf("verification_type = %q, want %q", r.VerificationType, typ)
		}
		rec = env.do(t, http.MethodPost, "/verify",
			map[string]any{"type": typ, "token_hash": r.HashedToken}, "")
		decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	}

	// invite for a fresh address.
	rec = env.do(t, http.MethodPost, "/admin/generate_link",
		map[string]any{"type": mailInvite, "email": "geninv@example.com"}, admin)
	inv := decodeInto[GenerateLinkResponse](t, rec, http.StatusOK)
	if inv.InvitedAt == nil {
		t.Error("invited_at was not stamped by generate_link")
	}

	// email_change_new / email_change_current.
	for _, typ := range []string{mailEmailChangeNew, mailEmailChangeCurrent} {
		rec = env.do(t, http.MethodPost, "/admin/generate_link", map[string]any{
			"type": typ, "email": "gen@example.com", "new_email": "gen2@example.com",
		}, admin)
		r := decodeInto[GenerateLinkResponse](t, rec, http.StatusOK)
		if r.EmailChange != "gen2@example.com" {
			t.Errorf("%s: new_email = %q", typ, r.EmailChange)
		}
		wantRelatesTo := "gen@example.com"
		if typ == mailEmailChangeNew {
			wantRelatesTo = "gen2@example.com"
		}
		if r.HashedToken != generateTokenHash(wantRelatesTo, r.EmailOtp) {
			t.Errorf("%s: hashed_token is not bound to %s", typ, wantRelatesTo)
		}
	}

	// recovery for an unknown address is a 404, not a fabricated link.
	rec = env.do(t, http.MethodPost, "/admin/generate_link",
		map[string]any{"type": mailRecovery, "email": "nobody@example.com"}, admin)
	e := decodeInto[HTTPError](t, rec, http.StatusNotFound)
	if e.ErrorCode != ErrorCodeUserNotFound {
		t.Errorf("error_code = %q, want %q", e.ErrorCode, ErrorCodeUserNotFound)
	}

	// An unknown type is rejected.
	rec = env.do(t, http.MethodPost, "/admin/generate_link",
		map[string]any{"type": "nonsense", "email": "gen@example.com"}, admin)
	decodeInto[HTTPError](t, rec, http.StatusBadRequest)
}

func TestGenerateLinkRequiresAdmin(t *testing.T) {
	env := newEmailEnv(t, nil)
	session := env.confirmedUser(t, "plain@example.com", "hunter22")

	rec := env.do(t, http.MethodPost, "/admin/generate_link",
		map[string]any{"type": mailRecovery, "email": "plain@example.com"}, session.Token)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

// email_change_current without secure email change is refused, matching
// upstream.
func TestGenerateLinkEmailChangeCurrentNeedsSecureEmailChange(t *testing.T) {
	cfg := emailTestConfig()
	cfg.Mailer.SecureEmailChangeEnabled = false
	env := newEmailEnv(t, cfg)
	admin := env.serviceRoleToken(t)

	env.confirmedUser(t, "ec@example.com", "hunter22")
	rec := env.do(t, http.MethodPost, "/admin/generate_link", map[string]any{
		"type": mailEmailChangeCurrent, "email": "ec@example.com", "new_email": "ec2@example.com",
	}, admin)
	e := decodeInto[HTTPError](t, rec, http.StatusBadRequest)
	if e.ErrorCode != ErrorCodeValidationFailed {
		t.Errorf("error_code = %q", e.ErrorCode)
	}
}

// ---- PKCE ------------------------------------------------------------------

// pkcePair returns a verifier and its S256 challenge.
func pkcePair() (verifier, challenge string) {
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// The full PKCE round trip: signup -> mailed pkce_ token -> GET /verify -> ?code=
// -> grant_type=pkce -> session.
func TestPKCESignupEndToEnd(t *testing.T) {
	env := newEmailEnv(t, nil)
	verifier, challenge := pkcePair()

	rec := env.do(t, http.MethodPost, "/signup", map[string]any{
		"email": "pkce@example.com", "password": "hunter22",
		"code_challenge": challenge, "code_challenge_method": "s256",
	}, "")
	decodeInto[User](t, rec, http.StatusOK)

	mails := env.mails.to("pkce@example.com")
	if len(mails) != 1 {
		t.Fatalf("confirmation mails = %d", len(mails))
	}
	token := mails[0].token(t)
	if !strings.HasPrefix(token, pkcePrefix) {
		t.Fatalf("token = %q, want a %q prefix in a PKCE flow", token, pkcePrefix)
	}

	rec = env.do(t, http.MethodGet,
		"/verify?type=signup&token="+url.QueryEscape(token)+
			"&redirect_to="+url.QueryEscape("https://app.test/callback"), nil, "")
	loc := redirectOf(t, rec, rec.Body.String())

	if loc.Fragment != "" {
		t.Errorf("PKCE redirect carries a fragment: %q", loc.Fragment)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no ?code= on the PKCE redirect: %s", loc)
	}

	// A wrong verifier is refused before anything is consumed.
	rec = env.do(t, http.MethodPost, "/token?grant_type=pkce",
		map[string]any{"auth_code": code, "code_verifier": verifier + "x"}, "")
	e := decodeInto[HTTPError](t, rec, http.StatusBadRequest)
	if e.ErrorCode != ErrorCodeBadCodeVerifier {
		t.Fatalf("error_code = %q, want %q", e.ErrorCode, ErrorCodeBadCodeVerifier)
	}

	// The right one produces a session.
	rec = env.do(t, http.MethodPost, "/token?grant_type=pkce",
		map[string]any{"auth_code": code, "code_verifier": verifier}, "")
	session := decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
	if session.Token == "" || session.User.Email != "pkce@example.com" {
		t.Fatalf("pkce session = %+v", session)
	}
	if session.User.EmailConfirmedAt == nil {
		t.Error("the account was not confirmed by the PKCE verification")
	}

	// The code is single use.
	rec = env.do(t, http.MethodPost, "/token?grant_type=pkce",
		map[string]any{"auth_code": code, "code_verifier": verifier}, "")
	e = decodeInto[HTTPError](t, rec, http.StatusNotFound)
	if e.ErrorCode != ErrorCodeFlowStateNotFound {
		t.Errorf("error_code = %q, want %q", e.ErrorCode, ErrorCodeFlowStateNotFound)
	}
}

func TestPKCERecoveryAndExpiry(t *testing.T) {
	cfg := emailTestConfig()
	cfg.FlowStateExpiry = 5 * time.Minute
	env := newEmailEnv(t, cfg)
	verifier, challenge := pkcePair()

	env.confirmedUser(t, "pkcerec@example.com", "hunter22")

	rec := env.do(t, http.MethodPost, "/recover", map[string]any{
		"email": "pkcerec@example.com", "code_challenge": challenge, "code_challenge_method": "s256",
	}, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("/recover = %d: %s", rec.Code, rec.Body.String())
	}
	mails := env.mails.to("pkcerec@example.com")
	if len(mails) != 1 {
		t.Fatalf("recovery mails = %d", len(mails))
	}

	rec = env.do(t, http.MethodGet,
		"/verify?type=recovery&token="+url.QueryEscape(mails[0].token(t))+
			"&redirect_to="+url.QueryEscape("https://app.test/reset"), nil, "")
	code := redirectOf(t, rec, rec.Body.String()).Query().Get("code")
	if code == "" {
		t.Fatal("no auth code on the recovery redirect")
	}

	// Past FlowStateExpiry the code is dead.
	env.clock.advance(6 * time.Minute)
	rec = env.do(t, http.MethodPost, "/token?grant_type=pkce",
		map[string]any{"auth_code": code, "code_verifier": verifier}, "")
	e := decodeInto[HTTPError](t, rec, http.StatusUnprocessableEntity)
	if e.ErrorCode != ErrorCodeFlowStateExpired {
		t.Errorf("error_code = %q, want %q", e.ErrorCode, ErrorCodeFlowStateExpired)
	}
}

func TestPKCEGrantValidation(t *testing.T) {
	env := newEmailEnv(t, nil)

	rec := env.do(t, http.MethodPost, "/token?grant_type=pkce", map[string]any{"auth_code": ""}, "")
	e := decodeInto[HTTPError](t, rec, http.StatusBadRequest)
	if e.ErrorCode != ErrorCodeValidationFailed {
		t.Errorf("error_code = %q", e.ErrorCode)
	}

	rec = env.do(t, http.MethodPost, "/token?grant_type=pkce",
		map[string]any{"auth_code": "e6b3f0f0-0000-4000-8000-000000000000", "code_verifier": "x"}, "")
	e = decodeInto[HTTPError](t, rec, http.StatusNotFound)
	if e.ErrorCode != ErrorCodeFlowStateNotFound {
		t.Errorf("error_code = %q, want %q", e.ErrorCode, ErrorCodeFlowStateNotFound)
	}
}

// A failed PKCE verification repeats the error in the QUERY string, because the
// client reads it server-side.
func TestPKCEErrorRedirectUsesQueryString(t *testing.T) {
	env := newEmailEnv(t, nil)

	rec := env.do(t, http.MethodGet,
		"/verify?type=signup&token="+url.QueryEscape("pkce_deadbeef")+
			"&redirect_to="+url.QueryEscape("https://app.test/callback"), nil, "")
	loc := redirectOf(t, rec, rec.Body.String())

	if loc.Query().Get("error_code") != ErrorCodeOTPExpired {
		t.Errorf("query error_code = %q, want %q", loc.Query().Get("error_code"), ErrorCodeOTPExpired)
	}
	if fragmentOf(t, loc).Get("error_code") != ErrorCodeOTPExpired {
		t.Error("the fragment must carry the error too")
	}
}

// ---- assertions ------------------------------------------------------------

// assertNoLiveTokens checks that a successful redemption retired every pending
// one-time token on the account (upstream ClearAllOneTimeTokensForUser).
func assertNoLiveTokens(t *testing.T, env *emailEnv, userID string) {
	t.Helper()
	var n int
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from auth.one_time_tokens where user_id = $1::uuid`, userID).Scan(&n); err != nil {
		t.Fatalf("count one_time_tokens: %v", err)
	}
	if n != 0 {
		t.Errorf("one_time_tokens left for %s = %d, want 0", userID, n)
	}
}

func emailOf(t *testing.T, env *emailEnv, userID string) string {
	t.Helper()
	var email string
	if err := env.pool.QueryRow(context.Background(),
		`select coalesce(email, '') from auth.users where id = $1::uuid`, userID).Scan(&email); err != nil {
		t.Fatalf("read email: %v", err)
	}
	return email
}

// ---- one-time token storage ------------------------------------------------

// The UNIQUE (user_id, token_type) index means a second request of the same kind
// REPLACES the first, so only the newest link ever works.
func TestOneTimeTokenUpsertKeepsOneLiveTokenPerType(t *testing.T) {
	env := newEmailEnv(t, nil)
	env.confirmedUser(t, "upsert@example.com", "hunter22")

	env.do(t, http.MethodPost, "/recover", map[string]any{"email": "upsert@example.com"}, "")
	env.clock.advance(env.maxMailFrequency() + time.Second)
	env.do(t, http.MethodPost, "/recover", map[string]any{"email": "upsert@example.com"}, "")

	mails := env.mails.to("upsert@example.com")
	if len(mails) != 2 {
		t.Fatalf("recovery mails = %d, want 2", len(mails))
	}

	var n int
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from auth.one_time_tokens where token_type = 'recovery_token'`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("live recovery tokens = %d, want 1", n)
	}

	// The superseded link is dead.
	rec := env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": mailRecovery, "token_hash": mails[0].token(t)}, "")
	decodeInto[HTTPError](t, rec, http.StatusForbidden)

	// The newest one works.
	rec = env.do(t, http.MethodPost, "/verify",
		map[string]any{"type": mailRecovery, "token_hash": mails[1].token(t)}, "")
	decodeInto[AccessTokenResponse](t, rec, http.StatusOK)
}

// created_at/updated_at are `timestamp without time zone`; a token issued now
// must not look hours old (or in the future) to the expiry check.
func TestOneTimeTokenTimestampsAreUTC(t *testing.T) {
	env := newEmailEnv(t, nil)
	user, _ := env.unconfirmedSignup(t, "tz@example.com", "hunter22")

	ctx := context.Background()
	var createdAt time.Time
	if err := env.pool.QueryRow(ctx,
		`select created_at from auth.one_time_tokens where user_id = $1::uuid`, user.ID).Scan(&createdAt); err != nil {
		t.Fatalf("read created_at: %v", err)
	}
	drift := utcNaive(createdAt).Sub(env.clock.Now())
	if drift < -time.Minute || drift > time.Minute {
		t.Errorf("created_at drifts from the clock by %v; the timestamp is not stored as UTC", drift)
	}
}

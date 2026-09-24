package auth

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bytemare/opaque"
	"github.com/dilion-io/dilion/ports"
	"github.com/go-chi/chi/v5"
)

func opaquePrepareSignup(t *testing.T, e *testEnv, email, password string) (map[string]string, []byte) {
	t.Helper()
	client, err := opaque.DefaultConfiguration().Client()
	if err != nil {
		t.Fatal(err)
	}
	request, err := client.RegistrationInit([]byte(password))
	if err != nil {
		t.Fatal(err)
	}
	start := decodeInto[opaqueStartResponse](t, e.do(t, "POST", "/opaque/signup/start", map[string]any{
		"email": email, "registration_request": opaqueEncode(request.Serialize()), "data": map[string]any{"name": "New user", "role": "service_role"}, "redirect_to": "https://evil.example/",
	}, ""), 200)
	data, err := opaqueBytes(start.Response)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Deserialize.RegistrationResponse(data)
	if err != nil {
		t.Fatal(err)
	}
	record, export, err := client.RegistrationFinalize(response, []byte(start.Client), []byte(start.Server))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"handshake_id": start.ID, "registration_record": opaqueEncode(record.Serialize())}, export
}

func TestOpaqueSignupAutoconfirm(t *testing.T) {
	e := newTestEnvWithConfig(t, opaqueTestConfig())
	ctx := context.Background()
	finish, export := opaquePrepareSignup(t, e, "NEW@example.com", "opaque-only-password")
	var users int
	if err := e.pool.QueryRow(ctx, `select count(*) from auth.users`).Scan(&users); err != nil || users != 0 {
		t.Fatal("start created an account", err)
	}
	result := decodeInto[opaqueSignupResponse](t, e.do(t, "POST", "/opaque/signup/finish", finish, ""), 200)
	if result.Session != nil || result.ConfirmationRequired || result.User.EmailConfirmedAt == nil {
		t.Fatal("wrong signup result")
	}
	if result.User.EncryptedPassword != nil || result.User.Role != RoleAuthenticated {
		t.Fatal("legacy hash/privileged role created")
	}
	var sessions int
	if err := e.pool.QueryRow(ctx, `select count(*) from auth.sessions`).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatal("registration issued session", err)
	}
	if e.do(t, "POST", "/opaque/signup/finish", finish, "").Code == 200 {
		t.Fatal("replay accepted")
	}
	body, _, restored := opaqueBeginTest(t, e, "new@example.com", "opaque-only-password")
	if !bytes.Equal(export, restored) {
		t.Fatal("export key changed")
	}
	token := decodeInto[opaqueTokenResponse](t, e.do(t, "POST", "/opaque/login/finish", body, ""), 200)
	if token.User.ID != result.User.ID {
		t.Fatal("wrong account")
	}
	if e.do(t, "POST", "/token?grant_type=password", map[string]string{"email": "new@example.com", "password": "opaque-only-password"}, "").Code == 200 {
		t.Fatal("legacy password grant authenticated")
	}
	duplicate, _ := opaquePrepareSignup(t, e, "new@example.com", "replacement")
	if e.do(t, "POST", "/opaque/signup/finish", duplicate, "").Code != 422 {
		t.Fatal("duplicate autoconfirm signup succeeded")
	}
	_, _, again := opaqueBeginTest(t, e, "new@example.com", "opaque-only-password")
	if !bytes.Equal(export, again) {
		t.Fatal("duplicate replaced credential")
	}
}

func TestOpaqueSignupEmailConfirmation(t *testing.T) {
	cfg := opaqueTestConfig()
	cfg.Mailer.Autoconfirm = false
	cfg.SiteURL = "https://app.test"
	e := newEmailEnv(t, cfg)
	finish, export := opaquePrepareSignup(t, e.testEnv, "verify-opaque@example.com", "private-password")
	reply := decodeInto[opaqueSignupResponse](t, e.do(t, "POST", "/opaque/signup/finish", finish, ""), 200)
	if !reply.ConfirmationRequired || reply.Session != nil {
		t.Fatal("confirmation policy bypassed")
	}
	real, err := findUserByEmail(context.Background(), e.pool, "verify-opaque@example.com", AudienceAuthenticated)
	if err != nil {
		t.Fatal(err)
	}
	if real.EmailConfirmedAt != nil || real.EncryptedPassword != nil || real.ID == reply.User.ID {
		t.Fatal("unsafe pending account response")
	}
	body, _, _ := opaqueBeginTest(t, e.testEnv, "verify-opaque@example.com", "private-password")
	if e.do(t, "POST", "/opaque/login/finish", body, "").Code == 200 {
		t.Fatal("unconfirmed account logged in")
	}
	duplicate, _ := opaquePrepareSignup(t, e.testEnv, "verify-opaque@example.com", "attacker-password")
	second := decodeInto[opaqueSignupResponse](t, e.do(t, "POST", "/opaque/signup/finish", duplicate, ""), 200)
	if second.User.ID == real.ID || second.Session != nil {
		t.Fatal("duplicate leaked real account")
	}
	mails := e.mails.to(real.Email)
	if len(mails) != 1 {
		t.Fatalf("mail count %d", len(mails))
	}
	if strings.Contains(mails[0].Text, "evil.example") {
		t.Fatal("untrusted redirect accepted")
	}
	decodeInto[AccessTokenResponse](t, e.do(t, "POST", "/verify", map[string]string{"type": mailSignup, "token_hash": mails[0].token(t)}, ""), 200)
	body, _, restored := opaqueBeginTest(t, e.testEnv, real.Email, "private-password")
	if !bytes.Equal(export, restored) {
		t.Fatal("confirmation changed OPAQUE record")
	}
	decodeInto[opaqueTokenResponse](t, e.do(t, "POST", "/opaque/login/finish", body, ""), 200)
	// Confirmed accounts receive the same sanitized duplicate response too.
	duplicate, _ = opaquePrepareSignup(t, e.testEnv, real.Email, "another-password")
	third := decodeInto[opaqueSignupResponse](t, e.do(t, "POST", "/opaque/signup/finish", duplicate, ""), 200)
	if !third.ConfirmationRequired || third.User.ID == real.ID || len(third.User.Identities) != 0 {
		t.Fatal("existing confirmed account disclosed")
	}
}

func TestOpaqueSignupGuardsAndHooks(t *testing.T) {
	cfg := opaqueTestConfig()
	e := newTestEnvWithConfig(t, cfg)
	ctx := context.Background()
	created := 0
	e.hooks.Register(ports.BeforeSignup, func(_ context.Context, p map[string]any) (map[string]any, error) {
		if p["authentication_method"] != "opaque" {
			t.Fatal("hook did not identify OPAQUE")
		}
		if _, ok := p["password"]; ok {
			t.Fatal("hook received password")
		}
		p["user_metadata"] = map[string]any{"checked": true}
		return p, nil
	})
	e.hooks.Register(ports.AfterSignup, func(_ context.Context, p map[string]any) (map[string]any, error) { created++; return p, nil })
	finish, _ := opaquePrepareSignup(t, e, "hooks-opaque@example.com", "private")
	result := decodeInto[opaqueSignupResponse](t, e.do(t, "POST", "/opaque/signup/finish", finish, ""), 200)
	if result.User.UserMetaData["checked"] != true || created != 1 {
		t.Fatal("signup hooks not applied")
	}
	finish, _ = opaquePrepareSignup(t, e, "disabled-midway@example.com", "private")
	cfg.DisableSignup = true
	if e.do(t, "POST", "/opaque/signup/finish", finish, "").Code != 422 {
		t.Fatal("disabled midway still created user")
	}
	if e.do(t, "POST", "/opaque/signup/start", map[string]string{}, "").Code != 422 {
		t.Fatal("disabled signup allowed start")
	}
	cfg.DisableSignup = false
	if e.do(t, "POST", "/opaque/signup/finish", finish, "").Code == 200 {
		t.Fatal("disabled attempt not consumed")
	}
	provider := cfg.External[ProviderEmail]
	provider.Enabled = false
	cfg.External[ProviderEmail] = provider
	if e.do(t, "POST", "/opaque/signup/start", map[string]string{}, "").Code != 422 {
		t.Fatal("disabled email provider allowed signup")
	}
	provider.Enabled = true
	cfg.External[ProviderEmail] = provider
	if e.do(t, "POST", "/opaque/signup/start", map[string]string{"email": "x@example.com", "password": "plaintext"}, "").Code != 400 {
		t.Fatal("plaintext field accepted")
	}
	finish, _ = opaquePrepareSignup(t, e, "expired-signup@example.com", "private")
	clock := &stepClock{t: time.Now().Add(5 * time.Minute)}
	router := chi.NewRouter()
	Register(router, Deps{Pool: e.pool, Tokens: e.tokens, Config: cfg, Clock: clock})
	e.router = router
	if e.do(t, "POST", "/opaque/signup/finish", finish, "").Code == 200 {
		t.Fatal("expired signup accepted")
	}
	if _, err := findUserByEmail(ctx, e.pool, "expired-signup@example.com", AudienceAuthenticated); !isNoRows(err) {
		t.Fatal("expired signup created a user")
	}
}

type opaqueFailMailer struct{}

func TestOpaqueSignupBrowserPreflight(t *testing.T) {
	router := chi.NewRouter()
	Register(router, Deps{Config: opaqueTestConfig()})
	req := httptest.NewRequest("OPTIONS", "/opaque/signup/start", nil)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "apikey,content-type,x-client-info")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	if response.Code < 200 || response.Code >= 300 || !strings.Contains(strings.ToLower(response.Header().Get("Access-Control-Allow-Headers")), "apikey") {
		t.Fatalf("SDK signup preflight rejected: %d %v", response.Code, response.Header())
	}
}

func (opaqueFailMailer) Send(context.Context, string, string, string, string) error {
	return errors.New("simulated mail outage")
}

func TestOpaqueSignupMailFailureRollback(t *testing.T) {
	cfg := opaqueTestConfig()
	cfg.Mailer.Autoconfirm = false
	e := newTestEnvWithConfig(t, cfg)
	router := chi.NewRouter()
	Register(router, Deps{Pool: e.pool, Tokens: e.tokens, Config: cfg, Mailer: opaqueFailMailer{}})
	e.router = router
	finish, _ := opaquePrepareSignup(t, e, "outage@example.com", "private")
	if e.do(t, "POST", "/opaque/signup/finish", finish, "").Code != 500 {
		t.Fatal("mail outage accepted")
	}
	var count int
	if err := e.pool.QueryRow(context.Background(), `select count(*) from auth.users`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed mail left account", err)
	}
	if err := e.pool.QueryRow(context.Background(), `select count(*) from dilion_auth.opaque_credentials`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed mail left credential", err)
	}
}

func TestOpaqueSignupConcurrentFinish(t *testing.T) {
	e := newTestEnvWithConfig(t, opaqueTestConfig())
	first, _ := opaquePrepareSignup(t, e, "concurrent-signup@example.com", "first")
	second, _ := opaquePrepareSignup(t, e, "concurrent-signup@example.com", "second")
	results := make(chan int, 2)
	var wg sync.WaitGroup
	for _, body := range []map[string]string{first, second} {
		wg.Go(func() { results <- e.do(t, "POST", "/opaque/signup/finish", body, "").Code })
	}
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for status := range results {
		if status == 200 {
			successes++
		} else if status == 422 {
			conflicts++
		} else {
			t.Fatalf("unexpected status %d", status)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatal("concurrent signup did not create exactly one account")
	}
}

func TestOpaqueSignupCaptchaAndCeremonyBinding(t *testing.T) {
	cfg := opaqueTestConfig()
	e := newTestEnvWithConfig(t, cfg)
	finish, _ := opaquePrepareSignup(t, e, "binding@example.com", "private")
	if e.do(t, "POST", "/opaque/login/finish", map[string]string{"handshake_id": finish["handshake_id"], "ke3": opaqueEncode(make([]byte, 64))}, "").Code != 400 {
		t.Fatal("cross-ceremony state accepted")
	}
	req := httptest.NewRequest("POST", "/opaque/signup/finish", strings.NewReader(`{"handshake_id":"`+finish["handshake_id"]+`","registration_record":"`+finish["registration_record"]+`"}`))
	req.Header.Set("X-JWT-AUD", "other-audience")
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatal("cross-audience signup accepted")
	}
	cfg.Security.Captcha.Enabled = true
	if e.do(t, "POST", "/opaque/signup/start", map[string]string{"email": "captcha@example.com"}, "").Code != 400 {
		t.Fatal("missing captcha token accepted")
	}
}

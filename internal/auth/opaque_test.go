package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bytemare/opaque"
	"github.com/dilion-io/dilion/ports"
	"github.com/go-chi/chi/v5"
)

func opaqueTestConfig() *Config {
	c := DefaultConfig()
	c.Opaque = OpaqueConfig{Enabled: true, MasterKey: opaqueEncode(bytes.Repeat([]byte{71}, 32))}
	return c
}

func TestOpaqueStorageIsolation(t *testing.T) {
	a := newAPI(Deps{Config: opaqueTestConfig()})
	ctx := context.Background()
	sealed := a.sealOpaque(ctx, "registration:test", []byte("sensitive"))
	if bytes.Contains(sealed, []byte("sensitive")) {
		t.Fatal("plaintext storage")
	}
	plain, err := a.openOpaque(ctx, "registration:test", sealed)
	if err != nil || string(plain) != "sensitive" {
		t.Fatal("roundtrip failed")
	}
	if _, err := a.openOpaque(ctx, "login:test", sealed); err == nil {
		t.Fatal("cross ceremony accepted")
	}
	if _, err := a.openOpaque(ports.ContextWithInstance(ctx, "other"), "registration:test", sealed); err == nil {
		t.Fatal("cross instance accepted")
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := a.openOpaque(ctx, "registration:test", sealed); err == nil {
		t.Fatal("tamper accepted")
	}
	c := opaqueTestConfig()
	c.Opaque.MasterKey = "bad"
	if c.Validate() == nil {
		t.Fatal("invalid master accepted")
	}
	encoded, _ := json.Marshal(opaqueTestConfig())
	if bytes.Contains(encoded, []byte(opaqueTestConfig().Opaque.MasterKey)) {
		t.Fatal("config exposes master key")
	}
}

func TestOpaqueDisabledAndMalformedRequests(t *testing.T) {
	router := chi.NewRouter()
	Register(router, Deps{})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("POST", "/opaque/login/start", strings.NewReader(`{}`)))
	if w.Code != 404 {
		t.Fatalf("disabled endpoint status %d", w.Code)
	}
	router = chi.NewRouter()
	Register(router, Deps{Config: opaqueTestConfig()})
	for _, body := range []string{`{"password":"must not be accepted"}`, `{} {}`, strings.Repeat(" ", 17<<10) + `{}`} {
		w = httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest("POST", "/opaque/login/start", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatalf("malformed request status %d", w.Code)
		}
	}
}

type opaqueStartResponse struct {
	ID       string `json:"handshake_id"`
	Client   string `json:"client_identity"`
	Server   string `json:"server_identity"`
	Response string `json:"registration_response"`
	KE2      string `json:"ke2"`
}
type opaqueTokenResponse struct {
	AccessTokenResponse
	KeyID string `json:"key_id"`
}

func opaqueRegisterTest(t *testing.T, e *testEnv, token, password string) []byte {
	t.Helper()
	client, err := opaque.DefaultConfiguration().Client()
	if err != nil {
		t.Fatal(err)
	}
	request, err := client.RegistrationInit([]byte(password))
	if err != nil {
		t.Fatal(err)
	}
	start := decodeInto[opaqueStartResponse](t, e.do(t, "POST", "/opaque/registration/start", map[string]string{"registration_request": opaqueEncode(request.Serialize())}, token), 200)
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
	body := map[string]string{"handshake_id": start.ID, "registration_record": opaqueEncode(record.Serialize())}
	decodeInto[map[string]bool](t, e.do(t, "POST", "/opaque/registration/finish", body, token), 200)
	if e.do(t, "POST", "/opaque/registration/finish", body, token).Code == 200 {
		t.Fatal("registration replay accepted")
	}
	return export
}

func opaqueBeginTest(t *testing.T, e *testEnv, email, password string) (map[string]string, []byte, []byte) {
	t.Helper()
	client, err := opaque.DefaultConfiguration().Client()
	if err != nil {
		t.Fatal(err)
	}
	ke1, err := client.GenerateKE1([]byte(password))
	if err != nil {
		t.Fatal(err)
	}
	start := decodeInto[opaqueStartResponse](t, e.do(t, "POST", "/opaque/login/start", map[string]string{"email": email, "ke1": opaqueEncode(ke1.Serialize())}, ""), 200)
	data, _ := opaqueBytes(start.KE2)
	ke2, err := client.Deserialize.KE2(data)
	if err != nil {
		t.Fatal(err)
	}
	ke3, key, export, err := client.GenerateKE3(ke2, []byte(start.Client), []byte(start.Server))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{"handshake_id": start.ID, "ke3": opaqueEncode(ke3.Serialize())}, key, export
}

func TestOpaqueDatabaseLifecycle(t *testing.T) {
	e := newTestEnvWithConfig(t, opaqueTestConfig())
	ctx := context.Background()
	// State and rate budgets deliberately outlive users; reset synthetic test state.
	if _, err := e.pool.Exec(ctx, `truncate dilion_auth.opaque_handshakes,dilion_auth.opaque_attempts`); err != nil {
		t.Fatal(err)
	}
	first := e.signup(t, "opaque@example.com", "initial-password")
	export := opaqueRegisterTest(t, e, first.Token, "opaque-password")
	body, key, recovered := opaqueBeginTest(t, e, "opaque@example.com", "opaque-password")
	if !bytes.Equal(export, recovered) {
		t.Fatal("export key changed")
	}
	// A second mount simulates another process/replica completing the handshake.
	router := chi.NewRouter()
	mount := Register(router, Deps{Pool: e.pool, Tokens: e.tokens, Config: opaqueTestConfig()})
	e.router = router
	token := decodeInto[opaqueTokenResponse](t, e.do(t, "POST", "/opaque/login/finish", body, ""), 200)
	claims, err := e.tokens.Verify(ctx, token.Token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Extra["aal"] != AAL1 {
		t.Fatal("OPAQUE must not claim MFA")
	}
	var retained []byte
	err = mount.WithOpaqueSessionKey(ctx, token.Token, token.KeyID, func(serverKey []byte) error {
		if !bytes.Equal(serverKey, key) {
			t.Fatal("client/server keys differ")
		}
		retained = serverKey
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retained, make([]byte, 64)) {
		t.Fatal("callback key was not wiped")
	}
	if mount.WithOpaqueSessionKey(ctx, first.Token, token.KeyID, func([]byte) error { return nil }) == nil {
		t.Fatal("wrong session accessed key")
	}
	if e.do(t, "POST", "/opaque/login/finish", body, "").Code == 200 {
		t.Fatal("login replay accepted")
	}
	t.Run("MFA and ban gates", func(t *testing.T) {
		_, err := e.pool.Exec(ctx, `insert into auth.mfa_factors(id,user_id,factor_type,status,created_at,updated_at) values(gen_random_uuid(),$1,'totp','verified',now(),now())`, first.User.ID)
		if err != nil {
			t.Fatal(err)
		}
		if mount.WithOpaqueSessionKey(ctx, token.Token, token.KeyID, func([]byte) error { return nil }) == nil {
			t.Fatal("AAL1 used MFA account key")
		}
		c, _ := opaque.DefaultConfiguration().Client()
		req, _ := c.RegistrationInit([]byte("new"))
		if e.do(t, "POST", "/opaque/registration/start", map[string]string{"registration_request": opaqueEncode(req.Serialize())}, first.Token).Code != 403 {
			t.Fatal("AAL1 enrolled MFA account")
		}
		if err := addAMRClaimToSession(ctx, e.pool, sessionIDFrom(claims), AMRMethodTOTP, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := mount.WithOpaqueSessionKey(ctx, token.Token, token.KeyID, func([]byte) error { return nil }); err != nil {
			t.Fatal(err)
		}
		if _, err := e.pool.Exec(ctx, `delete from auth.mfa_factors where user_id=$1`, first.User.ID); err != nil {
			t.Fatal(err)
		}
		p, _, _ := opaqueBeginTest(t, e, "opaque@example.com", "opaque-password")
		if _, err := e.pool.Exec(ctx, `update auth.users set banned_until=now()+interval '1 hour' where id=$1`, first.User.ID); err != nil {
			t.Fatal(err)
		}
		if e.do(t, "POST", "/opaque/login/finish", p, "").Code == 200 {
			t.Fatal("banned login accepted")
		}
		if mount.WithOpaqueSessionKey(ctx, token.Token, token.KeyID, func([]byte) error { return nil }) == nil {
			t.Fatal("banned account used key")
		}
		if _, err := e.pool.Exec(ctx, `update auth.users set banned_until=null where id=$1`, first.User.ID); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("failed proof is consumed", func(t *testing.T) {
		p, _, _ := opaqueBeginTest(t, e, "opaque@example.com", "opaque-password")
		good := p["ke3"]
		p["ke3"] = opaqueEncode(make([]byte, 64))
		if e.do(t, "POST", "/opaque/login/finish", p, "").Code == 200 {
			t.Fatal("bad proof accepted")
		}
		p["ke3"] = good
		if e.do(t, "POST", "/opaque/login/finish", p, "").Code == 200 {
			t.Fatal("failed proof replay accepted")
		}
	})
	t.Run("expiry", func(t *testing.T) {
		p, _, _ := opaqueBeginTest(t, e, "opaque@example.com", "opaque-password")
		a := mount.a
		state, err := a.takeOpaqueState(ctx, "login", p["handshake_id"])
		if err != nil {
			t.Fatal(err)
		}
		state.Expires = time.Now().Add(-time.Hour)
		plain, _ := json.Marshal(state)
		_, err = e.pool.Exec(ctx, `insert into dilion_auth.opaque_handshakes(id,scope,kind,state,expires_at) values($1,'default','login',$2,$3)`, p["handshake_id"], a.sealOpaque(ctx, "login:"+p["handshake_id"], plain), state.Expires)
		if err != nil {
			t.Fatal(err)
		}
		if e.do(t, "POST", "/opaque/login/finish", p, "").Code == 200 {
			t.Fatal("expired login accepted")
		}
	})
	t.Run("concurrent consume", func(t *testing.T) {
		id, err := mount.a.putOpaqueState(ctx, "login", &opaqueState{})
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		results := make(chan bool, 8)
		for range 8 {
			wg.Go(func() { _, err := mount.a.takeOpaqueState(ctx, "login", id); results <- err == nil })
		}
		wg.Wait()
		close(results)
		successes := 0
		for ok := range results {
			if ok {
				successes++
			}
		}
		if successes != 1 {
			t.Fatalf("consumed %d times", successes)
		}
	})
	t.Run("password reset invalidation", func(t *testing.T) {
		p, _, _ := opaqueBeginTest(t, e, "opaque@example.com", "opaque-password")
		if _, err := e.pool.Exec(ctx, `update auth.users set encrypted_password='reset-test' where id=$1`, first.User.ID); err != nil {
			t.Fatal(err)
		}
		if e.do(t, "POST", "/opaque/login/finish", p, "").Code == 200 {
			t.Fatal("reset credential accepted")
		}
		if mount.WithOpaqueSessionKey(ctx, token.Token, token.KeyID, func([]byte) error { return nil }) == nil {
			t.Fatal("reset key survived")
		}
	})
}

func TestOpaqueEnrollmentAndUnknownAccounts(t *testing.T) {
	e := newTestEnvWithConfig(t, opaqueTestConfig())
	ctx := context.Background()
	if _, err := e.pool.Exec(ctx, `truncate dilion_auth.opaque_handshakes,dilion_auth.opaque_attempts`); err != nil {
		t.Fatal(err)
	}
	first := e.signup(t, "gates@example.com", "initial-password")
	client, _ := opaque.DefaultConfiguration().Client()
	request, _ := client.RegistrationInit([]byte("password"))
	body := map[string]string{"registration_request": opaqueEncode(request.Serialize())}
	if e.do(t, "POST", "/opaque/registration/start", body, "").Code == 200 {
		t.Fatal("anonymous enrollment")
	}
	claims, _ := e.tokens.Verify(ctx, first.Token)
	if _, err := e.pool.Exec(ctx, `update auth.sessions set created_at=now()-interval '10 minutes' where id=$1`, sessionIDFrom(claims)); err != nil {
		t.Fatal(err)
	}
	if e.do(t, "POST", "/opaque/registration/start", body, first.Token).Code != 403 {
		t.Fatal("stale session enrolled")
	}
	if _, err := e.pool.Exec(ctx, `delete from auth.sessions where id=$1`, sessionIDFrom(claims)); err != nil {
		t.Fatal(err)
	}
	if e.do(t, "POST", "/opaque/registration/start", body, first.Token).Code != 403 {
		t.Fatal("revoked session enrolled")
	}
	unknown, _ := opaque.DefaultConfiguration().Client()
	ke1, _ := unknown.GenerateKE1([]byte("wrong"))
	login := map[string]string{"email": "absent@example.com", "ke1": opaqueEncode(ke1.Serialize())}
	start := decodeInto[opaqueStartResponse](t, e.do(t, "POST", "/opaque/login/start", login, ""), 200)
	data, _ := opaqueBytes(start.KE2)
	ke2, err := unknown.Deserialize.KE2(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := unknown.GenerateKE3(ke2, []byte(start.Client), []byte(start.Server)); err == nil {
		t.Fatal("fake record authenticated")
	}
	for range 9 {
		decodeInto[opaqueStartResponse](t, e.do(t, "POST", "/opaque/login/start", login, ""), 200)
	}
	if e.do(t, "POST", "/opaque/login/start", login, "").Code != 429 {
		t.Fatal("shared account rate limit missing")
	}
}

// Optional locally, mandatory in the JS HTTP integration CI job. This launches
// the actual published SDK against real Dilion routes and PostgreSQL.
func TestOpaqueSDKHTTP(t *testing.T) {
	if os.Getenv("DILION_OPAQUE_SDK_HTTP") != "1" {
		t.Skip("set DILION_OPAQUE_SDK_HTTP=1 and build js first")
	}
	e := newTestEnvWithConfig(t, opaqueTestConfig())
	first := e.signup(t, "sdk-http@example.com", "bootstrap-password")
	router := chi.NewRouter()
	authRouter := chi.NewRouter()
	mount := Register(authRouter, Deps{Pool: e.pool, Tokens: e.tokens, Config: opaqueTestConfig()})
	router.Mount("/auth/v1", authRouter)
	server := httptest.NewServer(router)
	defer server.Close()
	cmd := exec.Command("node", "../../js/packages/auth-js/test/server-http.mjs", server.URL, first.Token, first.RefreshToken)
	output, err := cmd.Output()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			t.Fatalf("SDK HTTP: %v: %s", err, e.Stderr)
		}
		t.Fatal(err)
	}
	var result struct {
		Token string
		KeyID string
		Key   string
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}
	key, err := opaqueBytes(result.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := mount.WithOpaqueSessionKey(context.Background(), result.Token, result.KeyID, func(serverKey []byte) error {
		if !bytes.Equal(key, serverKey) {
			t.Fatal("SDK/HTTP server key mismatch")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Logout must revoke server key use even while the old JWT is unexpired.
	if rec := e.do(t, "POST", "/logout", nil, result.Token); rec.Code != 204 {
		t.Fatalf("logout: %d %s", rec.Code, rec.Body.String())
	}
	if mount.WithOpaqueSessionKey(context.Background(), result.Token, result.KeyID, func([]byte) error { return nil }) == nil {
		t.Fatal("logout key survived")
	}
}

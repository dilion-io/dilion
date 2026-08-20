package auth

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

// newSecurityTestAPI builds an *api with no database: every check in this file
// runs before a handler would touch one.
func newSecurityTestAPI(t *testing.T, cfg *Config) *api {
	t.Helper()
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	return newAPI(Deps{
		Config: cfg,
		Tokens: NewTokenServiceHS(testSecret()),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

// captchaTestConfig enables captcha for a provider and points verification at
// a fake siteverify endpoint.
func captchaTestConfig(provider, verifyURL string) *Config {
	cfg := DefaultConfig()
	cfg.Security.Captcha.Enabled = true
	cfg.Security.Captcha.Provider = provider
	cfg.Security.Captcha.Secret = "0xsecret"
	cfg.Security.Captcha.VerifyURL = verifyURL
	return cfg
}

// fakeCaptchaServer answers siteverify and records what it was asked.
type fakeCaptchaServer struct {
	*httptest.Server
	lastForm url.Values
}

func newFakeCaptchaServer(t *testing.T, success bool, errorCodes ...string) *fakeCaptchaServer {
	t.Helper()
	f := &fakeCaptchaServer{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("captcha server: parse form: %v", err)
		}
		f.lastForm = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(captchaVerificationResponse{
			Success:    success,
			ErrorCodes: errorCodes,
			Hostname:   "app.test",
		})
	}))
	t.Cleanup(f.Close)
	return f
}

func captchaRequestFor(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/signup", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "203.0.113.9:1234"
	return r
}

// Both providers must accept a good token and forward secret/response/remoteip.
func TestCaptchaAcceptsValidTokenForEachProvider(t *testing.T) {
	for _, provider := range []string{"hcaptcha", "turnstile"} {
		t.Run(provider, func(t *testing.T) {
			server := newFakeCaptchaServer(t, true)
			a := newSecurityTestAPI(t, captchaTestConfig(provider, server.URL))

			r := captchaRequestFor(`{"email":"a@b.test","gotrue_meta_security":{"captcha_token":"tok-123"}}`)
			if err := a.verifyCaptcha(r); err != nil {
				t.Fatalf("verifyCaptcha: %v", err)
			}
			if got := server.lastForm.Get("secret"); got != "0xsecret" {
				t.Errorf("secret = %q, want the configured secret", got)
			}
			if got := server.lastForm.Get("response"); got != "tok-123" {
				t.Errorf("response = %q, want the submitted token", got)
			}
			if got := server.lastForm.Get("remoteip"); got != "203.0.113.9" {
				t.Errorf("remoteip = %q, want the client IP", got)
			}

			// The body must survive the check: the handler decodes it next.
			params := &SignupParams{}
			if err := decodeBody(r, params); err != nil {
				t.Fatalf("decodeBody after verifyCaptcha: %v", err)
			}
			if params.Email != "a@b.test" {
				t.Errorf("email = %q; verifyCaptcha consumed the body", params.Email)
			}
		})
	}
}

func TestCaptchaRejectsProviderFailure(t *testing.T) {
	for _, provider := range []string{"hcaptcha", "turnstile"} {
		t.Run(provider, func(t *testing.T) {
			server := newFakeCaptchaServer(t, false, "invalid-input-response")
			a := newSecurityTestAPI(t, captchaTestConfig(provider, server.URL))

			err := a.verifyCaptcha(captchaRequestFor(`{"gotrue_meta_security":{"captcha_token":"bad"}}`))
			herr, ok := err.(*HTTPError)
			if !ok {
				t.Fatalf("err = %v (%T), want *HTTPError", err, err)
			}
			if herr.HTTPStatus != http.StatusBadRequest || herr.ErrorCode != ErrorCodeCaptchaFailed {
				t.Fatalf("got %d/%s, want 400/%s", herr.HTTPStatus, herr.ErrorCode, ErrorCodeCaptchaFailed)
			}
			if !strings.Contains(herr.Message, "invalid-input-response") {
				t.Errorf("msg = %q, want the provider's error codes", herr.Message)
			}
		})
	}
}

func TestCaptchaRejectsMissingToken(t *testing.T) {
	server := newFakeCaptchaServer(t, true)
	a := newSecurityTestAPI(t, captchaTestConfig("hcaptcha", server.URL))

	for name, body := range map[string]string{
		"no field":     `{"email":"a@b.test"}`,
		"empty token":  `{"gotrue_meta_security":{"captcha_token":"   "}}`,
		"empty body":   ``,
		"wrong nested": `{"captcha_token":"tok"}`,
	} {
		t.Run(name, func(t *testing.T) {
			err := a.verifyCaptcha(captchaRequestFor(body))
			herr, ok := err.(*HTTPError)
			if !ok {
				t.Fatalf("err = %v (%T), want *HTTPError", err, err)
			}
			if herr.ErrorCode != ErrorCodeCaptchaFailed || !strings.Contains(herr.Message, "no captcha_token found") {
				t.Errorf("got %s %q, want captcha_failed / no captcha_token found", herr.ErrorCode, herr.Message)
			}
		})
	}
}

// With captcha off the token is never looked at — and no HTTP call is made.
func TestCaptchaDisabledIsNoOp(t *testing.T) {
	a := newSecurityTestAPI(t, DefaultConfig())
	if err := a.verifyCaptcha(captchaRequestFor(`{"email":"a@b.test"}`)); err != nil {
		t.Fatalf("verifyCaptcha with captcha disabled: %v", err)
	}
}

// An unreachable provider fails CLOSED with upstream's 500 (unlike HIBP).
func TestCaptchaProviderOutageFailsClosed(t *testing.T) {
	server := newFakeCaptchaServer(t, true)
	url := server.URL
	server.Close()

	a := newSecurityTestAPI(t, captchaTestConfig("hcaptcha", url))
	err := a.verifyCaptcha(captchaRequestFor(`{"gotrue_meta_security":{"captcha_token":"tok"}}`))
	herr, ok := err.(*HTTPError)
	if !ok {
		t.Fatalf("err = %v (%T), want *HTTPError", err, err)
	}
	if herr.HTTPStatus != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", herr.HTTPStatus)
	}
	if herr.Message != "captcha verification process failed" {
		t.Errorf("msg = %q, want upstream's message", herr.Message)
	}
}

// The siteverify endpoints are part of the contract with the providers.
func TestCaptchaProviderEndpoints(t *testing.T) {
	for provider, want := range map[string]string{
		"hcaptcha":  "https://hcaptcha.com/siteverify",
		"turnstile": "https://challenges.cloudflare.com/turnstile/v0/siteverify",
	} {
		got, err := captchaVerifyURL(provider)
		if err != nil {
			t.Fatalf("captchaVerifyURL(%q): %v", provider, err)
		}
		if got != want {
			t.Errorf("captchaVerifyURL(%q) = %q, want %q", provider, got, want)
		}
	}
	if _, err := captchaVerifyURL("recaptcha"); err == nil {
		t.Error("an unknown provider must be an error")
	}
}

// verifyCaptchaRequest is the seam /token and /verify integrate through: it
// takes body bytes the caller already consumed.
func TestVerifyCaptchaRequestWithPreReadBody(t *testing.T) {
	server := newFakeCaptchaServer(t, true)
	a := newSecurityTestAPI(t, captchaTestConfig("hcaptcha", server.URL))

	body := []byte(`{"grant_type":"password","gotrue_meta_security":{"captcha_token":"tok"}}`)
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	if err := a.verifyCaptchaRequest(r, body); err != nil {
		t.Fatalf("verifyCaptchaRequest: %v", err)
	}
	if err := a.verifyCaptchaRequest(r, []byte(`{"grant_type":"password"}`)); err == nil {
		t.Error("a body with no captcha_token must be rejected")
	}
}

// Every captcha-gated route must refuse a request with no token BEFORE it
// touches the database (the router below has no pool at all).
func TestCaptchaGatedRoutesRejectWithoutToken(t *testing.T) {
	server := newFakeCaptchaServer(t, true)
	cfg := captchaTestConfig("hcaptcha", server.URL)

	router := chi.NewRouter()
	Register(router, Deps{
		Config: cfg,
		Tokens: NewTokenServiceHS(testSecret()),
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	for _, path := range []string{"/signup", "/recover", "/otp", "/magiclink", "/resend"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path,
				strings.NewReader(`{"email":"user@app.test","type":"signup","password":"correct-horse"}`))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
			}
			var body HTTPError
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal %q: %v", rec.Body.String(), err)
			}
			if body.ErrorCode != ErrorCodeCaptchaFailed {
				t.Errorf("error_code = %q, want %q", body.ErrorCode, ErrorCodeCaptchaFailed)
			}
		})
	}
}

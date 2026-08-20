package auth

// CAPTCHA verification for the endpoints an unauthenticated caller can use to
// make the server do work (create accounts, send mail).
//
// Reproduces github.com/supabase/auth/internal/api/middleware.go
// (captchaRequest / verifyCaptcha) and internal/security/captcha.go
// (HTTPCaptchaVerifier).
//
// # The contract
//
// The token travels in the JSON body, NOT in a header:
//
//	{"email": "...", "gotrue_meta_security": {"captcha_token": "..."}}
//
// which is what supabase-js sends as `options.captchaToken`. Two providers are
// supported, both with the same "POST form, get {success, error-codes}" shape:
//
//	hcaptcha   https://hcaptcha.com/siteverify
//	turnstile  https://challenges.cloudflare.com/turnstile/v0/siteverify
//
// # Where it is enforced
//
// Upstream installs verifyCaptcha as a middleware in front of /signup,
// /recover, /otp, /magiclink, /resend, /token (password grant only) and
// /verify. Dilion calls a.verifyCaptcha at the TOP of each handler instead,
// because the handlers own their bodies (decodeBody) and a middleware would
// have to read and restore the body anyway — which is exactly what
// requestBodyBytes does here, once, for both.
//
// # Deviations
//
//   - Upstream skips the check when the request carries ADMIN credentials
//     (requireAdminCredentials). Dilion's admin surface lives under /admin/*,
//     which is never captcha-gated to begin with, and the public endpoints
//     below do not read the Authorization header — so there is nothing to skip.
//   - Upstream's failure to REACH the provider is a 500
//     ("captcha verification process failed"); that is reproduced verbatim, so
//     a captcha outage fails CLOSED (unlike the HIBP check, which fails open).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ErrorCodeCaptchaFailed is upstream apierrors.ErrorCodeCaptchaFailed: the 400
// returned when no captcha token was supplied or the provider rejected it.
//
// It is declared here rather than in errors.go because that file is shared by
// every feature; the constant belongs to the feature that raises it.
const ErrorCodeCaptchaFailed = "captcha_failed"

// captchaRequest is the sliver of a request body that carries the token
// (upstream api.captchaRequest). Every captcha-gated endpoint accepts its own
// body shape PLUS this field.
type captchaRequest struct {
	Security captchaSecurity `json:"gotrue_meta_security"`
}

type captchaSecurity struct {
	Token string `json:"captcha_token"`
}

// captchaVerificationResponse is the provider's answer. hCaptcha and Turnstile
// agree on `success` and `error-codes`, which is all that is inspected
// (upstream security.VerificationResponse).
type captchaVerificationResponse struct {
	Success    bool     `json:"success"`
	ErrorCodes []string `json:"error-codes"`
	Hostname   string   `json:"hostname"`
}

// verifyCaptcha is the guard a captcha-gated handler calls FIRST, before it
// decodes its own body. It is a no-op when captcha is disabled.
//
// The body is read once and put back on the request, so the handler's own
// decodeBody still sees it.
func (a *api) verifyCaptcha(r *http.Request) error {
	if !a.cfg.Security.Captcha.Enabled {
		return nil
	}
	body, err := requestBodyBytes(r)
	if err != nil {
		return err
	}
	return a.verifyCaptchaRequest(r, body)
}

// verifyCaptchaRequest is verifyCaptcha for a caller that has ALREADY consumed
// the request body — POST /token, which parses form-encoded and JSON bodies
// itself.
//
// INTEGRATION TODO (/token): upstream gates the PASSWORD grant with captcha and
// exempts the pkce / refresh_token / id_token grants (isIgnoreCaptchaRoute).
// token.go / grant.go are owned by another change, so the call is not wired
// here; the owner should add, right after the grant type is known and the body
// bytes are in hand:
//
//	if params.GrantType == "password" {
//	    if err := a.verifyCaptchaRequest(r, bodyBytes); err != nil {
//	        return err
//	    }
//	}
//
// INTEGRATION TODO (/verify): upstream also gates POST /verify. verify.go is
// owned by another change; the same one-liner (unconditional, no grant check)
// belongs at the top of the POST /verify handler.
func (a *api) verifyCaptchaRequest(r *http.Request, body []byte) error {
	if !a.cfg.Security.Captcha.Enabled {
		return nil
	}

	token := ""
	if len(bytes.TrimSpace(body)) > 0 {
		var cr captchaRequest
		// A body that is not JSON is not a captcha failure: the handler's own
		// decoder reports it as bad_json. Only the ABSENCE of a token is.
		if err := json.Unmarshal(body, &cr); err == nil {
			token = strings.TrimSpace(cr.Security.Token)
		}
	}
	if token == "" {
		return badRequestError(ErrorCodeCaptchaFailed,
			"captcha protection: request disallowed (no captcha_token found)")
	}

	res, err := a.verifyCaptchaToken(r, token)
	if err != nil {
		return internalServerError("captcha verification process failed").withInternal(err)
	}
	if !res.Success {
		return badRequestError(ErrorCodeCaptchaFailed,
			"captcha protection: request disallowed (%s)", strings.Join(res.ErrorCodes, ", "))
	}
	return nil
}

// verifyCaptchaToken performs the siteverify call (upstream
// HTTPCaptchaVerifier.verifyCaptchaCode).
func (a *api) verifyCaptchaToken(r *http.Request, token string) (*captchaVerificationResponse, error) {
	cfg := a.cfg.Security.Captcha

	endpoint := strings.TrimSpace(cfg.VerifyURL)
	if endpoint == "" {
		var err error
		endpoint, err = captchaVerifyURL(cfg.Provider)
		if err != nil {
			return nil, err
		}
	}

	form := url.Values{}
	form.Set("secret", strings.TrimSpace(cfg.Secret))
	form.Set("response", token)
	form.Set("remoteip", clientIP(r))

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("auth: build captcha request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultCaptchaTimeout
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: captcha verification request: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
	}()

	var out captchaVerificationResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("auth: decode captcha response: %w", err)
	}
	return &out, nil
}

// captchaVerifyURL is upstream security.getCaptchaURL. Config.Validate already
// rejects an unknown provider, so the error is a defence in depth.
func captchaVerifyURL(provider string) (string, error) {
	switch provider {
	case "hcaptcha":
		return "https://hcaptcha.com/siteverify", nil
	case "turnstile":
		return "https://challenges.cloudflare.com/turnstile/v0/siteverify", nil
	default:
		return "", fmt.Errorf("auth: captcha provider %q could not be found", provider)
	}
}

// requestBodyBytes reads the request body and PUTS IT BACK, so a later
// decodeBody still sees it. It is upstream's retrieveRequestParams + the body
// restoration its middleware does.
func requestBodyBytes(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
	if err != nil {
		return nil, badRequestError(ErrorCodeBadJSON, "Could not read body")
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

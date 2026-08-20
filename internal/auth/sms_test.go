package auth

// Unit tests for the phone surface that need no database: number
// normalization, template rendering, provider selection, and the Twilio REST
// sender against an httptest server.

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// ---- E.164 normalization ---------------------------------------------------

// The matrix upstream's formatPhoneNumber + validateE164Format accept and
// reject. Note what is NOT normalization: dashes, parentheses and dots are
// rejected rather than stripped, because upstream only removes "+" and spaces.
func TestPhoneE164NormalizationMatrix(t *testing.T) {
	cases := []struct {
		in    string
		want  string // "" means the number must be rejected
		about string
	}{
		{"+15551234567", "15551234567", "leading plus is stripped"},
		{"15551234567", "15551234567", "already bare"},
		{"+1 555 123 4567", "15551234567", "spaces are stripped"},
		{"  +447700900123  ", "447700900123", "surrounding whitespace"},
		{"+821012345678", "821012345678", "KR mobile"},
		{"+12", "12", "shortest accepted form is 2 digits"},
		{"+123456789012345", "123456789012345", "15 digits is the E.164 maximum"},

		{"", "", "empty"},
		{"+", "", "plus only"},
		{"+1", "", "a single digit is not E.164"},
		{"+0155512345", "", "country code may not start with 0"},
		{"01012345678", "", "national format is not E.164"},
		{"+1234567890123456", "", "16 digits is too long"},
		{"+1-555-123-4567", "", "dashes are not stripped"},
		{"+1 (555) 123-4567", "", "punctuation is not stripped"},
		{"+1555123456a", "", "letters"},
		{"++15551234567", "", "only ONE leading plus is removed"},
	}

	for _, tc := range cases {
		got, err := validatePhone(tc.in)
		switch {
		case tc.want == "" && err == nil:
			t.Errorf("validatePhone(%q) = %q, want rejected (%s)", tc.in, got, tc.about)
		case tc.want == "":
			he, ok := err.(*HTTPError)
			if !ok || he.HTTPStatus != http.StatusBadRequest || he.ErrorCode != ErrorCodeValidationFailed {
				t.Errorf("validatePhone(%q) error = %v, want 400 validation_failed", tc.in, err)
			}
		case err != nil:
			t.Errorf("validatePhone(%q) = error %v, want %q (%s)", tc.in, err, tc.want, tc.about)
		case got != tc.want:
			t.Errorf("validatePhone(%q) = %q, want %q (%s)", tc.in, got, tc.want, tc.about)
		}
	}
}

// The stored number never carries a "+" — that is what auth.users.phone holds
// and what the token hash is computed over.
func TestPhoneTokenHashIsBoundToTheNormalizedNumber(t *testing.T) {
	plus := generateTokenHash(formatPhoneNumber("+15551234567"), "123456")
	bare := generateTokenHash("15551234567", "123456")
	if plus != bare {
		t.Errorf("hash over +E.164 (%s) != hash over bare E.164 (%s)", plus, bare)
	}
	other := generateTokenHash("15551234568", "123456")
	if plus == other {
		t.Error("the same OTP hashes identically for two different numbers")
	}
}

// ---- template --------------------------------------------------------------

func TestRenderSMSUsesUpstreamDefaultTemplate(t *testing.T) {
	a := testAPI(t, nil)
	got, err := a.renderSMS("424242")
	if err != nil {
		t.Fatalf("renderSMS: %v", err)
	}
	if want := "Your code is 424242"; got != want {
		t.Errorf("renderSMS = %q, want %q", got, want)
	}
}

func TestRenderSMSHonoursConfiguredTemplate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SMS.Template = "{{ .Code }} is your Acme code. Do not share it."
	a := testAPI(t, cfg)

	got, err := a.renderSMS("998877")
	if err != nil {
		t.Fatalf("renderSMS: %v", err)
	}
	if want := "998877 is your Acme code. Do not share it."; got != want {
		t.Errorf("renderSMS = %q, want %q", got, want)
	}
}

// A template that cannot be parsed must fail the CONFIGURATION, not the first
// OTP of the day.
func TestConfigRejectsUnparsableSMSTemplate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SMS.Template = "{{ .Code "
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted an unparsable SMS template")
	}
}

// ---- provider selection ----------------------------------------------------

type stubSender struct {
	to   string
	body string
	err  error
}

func (s *stubSender) Send(_ context.Context, to, body string) error {
	s.to, s.body = to, body
	return s.err
}

// An injected ports.SMSSender OUTRANKS Config.SMS.Provider, so an embedder that
// supplies a sender never accidentally talks to Twilio.
func TestInjectedSenderIsPreferredOverTwilio(t *testing.T) {
	stub := &stubSender{}
	cfg := DefaultConfig()
	cfg.SMS.Sender = stub
	cfg.SMS.Provider = "twilio"
	cfg.SMS.Twilio = TwilioConfig{AccountSID: "AC1", AuthToken: "tok", MessageServiceSID: "MG1"}
	a := testAPI(t, cfg)

	p, err := a.smsProviderFor()
	if err != nil {
		t.Fatalf("smsProviderFor: %v", err)
	}
	if _, ok := p.(portSender); !ok {
		t.Fatalf("smsProviderFor returned %T, want the injected port sender", p)
	}

	if _, err := p.SendMessage(context.Background(), "15551234567", "Your code is 111111", channelSMS, "111111"); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	// The port receives the number in dialable +E.164 form.
	if stub.to != "+15551234567" {
		t.Errorf("to = %q, want %q", stub.to, "+15551234567")
	}
	if stub.body != "Your code is 111111" {
		t.Errorf("body = %q", stub.body)
	}
}

func TestTwilioIsSelectedWhenNoSenderIsInjected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SMS.Provider = "twilio"
	cfg.SMS.Twilio = TwilioConfig{AccountSID: "AC1", AuthToken: "tok", MessageServiceSID: "MG1"}
	a := testAPI(t, cfg)

	p, err := a.smsProviderFor()
	if err != nil {
		t.Fatalf("smsProviderFor: %v", err)
	}
	if _, ok := p.(*twilioSender); !ok {
		t.Fatalf("smsProviderFor returned %T, want *twilioSender", p)
	}
}

func TestNoProviderConfiguredIsAnError(t *testing.T) {
	a := testAPI(t, DefaultConfig())
	if _, err := a.smsProviderFor(); err == nil {
		t.Fatal("smsProviderFor succeeded with neither a sender nor a provider")
	}
}

// whatsapp is only offered where it exists.
func TestMessageChannelValidation(t *testing.T) {
	plain := testAPI(t, DefaultConfig())
	if !plain.isValidMessageChannel(channelSMS) {
		t.Error("sms channel rejected")
	}
	if plain.isValidMessageChannel(channelWhatsApp) {
		t.Error("whatsapp accepted without a provider that supports it")
	}
	if plain.isValidMessageChannel("carrier-pigeon") {
		t.Error("an unknown channel was accepted")
	}

	twilioCfg := DefaultConfig()
	twilioCfg.SMS.Provider = "twilio"
	if !testAPI(t, twilioCfg).isValidMessageChannel(channelWhatsApp) {
		t.Error("whatsapp rejected while Twilio is the provider")
	}
}

// ---- Twilio sender ---------------------------------------------------------

type twilioCapture struct {
	path   string
	method string
	auth   string
	ctype  string
	form   url.Values
}

// twilioStub serves the Messages.json endpoint and records what it was sent.
func twilioStub(t *testing.T, status int, body string) (*httptest.Server, *twilioCapture) {
	t.Helper()
	cap := &twilioCapture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, err := url.ParseQuery(string(raw))
		if err != nil {
			t.Errorf("parse form body %q: %v", raw, err)
		}
		cap.path, cap.method = r.URL.Path, r.Method
		cap.auth = r.Header.Get("Authorization")
		cap.ctype = r.Header.Get("Content-Type")
		cap.form = form
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

func TestTwilioSenderRequestShape(t *testing.T) {
	srv, cap := twilioStub(t, http.StatusCreated,
		`{"sid":"SM123","status":"queued","to":"+15551234567"}`)

	sender, err := newTwilioSender(TwilioConfig{
		AccountSID:        "ACtest",
		AuthToken:         "s3cret",
		MessageServiceSID: "MGtest",
		APIBase:           srv.URL,
	})
	if err != nil {
		t.Fatalf("newTwilioSender: %v", err)
	}

	id, err := sender.SendMessage(context.Background(), "15551234567", "Your code is 424242", channelSMS, "424242")
	if err != nil {
		t.Fatalf("SendMessage: %v", err)
	}
	if id != "SM123" {
		t.Errorf("message id = %q, want SM123", id)
	}

	if cap.method != http.MethodPost {
		t.Errorf("method = %s, want POST", cap.method)
	}
	if want := "/2010-04-01/Accounts/ACtest/Messages.json"; cap.path != want {
		t.Errorf("path = %q, want %q", cap.path, want)
	}
	if cap.ctype != "application/x-www-form-urlencoded" {
		t.Errorf("content-type = %q", cap.ctype)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("ACtest:s3cret"))
	if cap.auth != wantAuth {
		t.Errorf("authorization = %q, want %q", cap.auth, wantAuth)
	}

	// Twilio wants the dialable form even though auth.users.phone has no "+".
	for field, want := range map[string]string{
		"To":      "+15551234567",
		"Channel": "sms",
		"From":    "MGtest",
		"Body":    "Your code is 424242",
	} {
		if got := cap.form.Get(field); got != want {
			t.Errorf("form[%s] = %q, want %q", field, got, want)
		}
	}
}

// The WhatsApp channel prefixes the recipient and, when a content template is
// configured, ships the OTP as ContentVariables instead of a Body.
func TestTwilioSenderWhatsAppWithContentTemplate(t *testing.T) {
	srv, cap := twilioStub(t, http.StatusCreated, `{"sid":"SM999","status":"accepted"}`)

	sender, err := newTwilioSender(TwilioConfig{
		AccountSID:        "ACtest",
		AuthToken:         "s3cret",
		MessageServiceSID: "MGtest",
		ContentSID:        "HXtemplate",
		APIBase:           srv.URL,
	})
	if err != nil {
		t.Fatalf("newTwilioSender: %v", err)
	}
	if _, err := sender.SendMessage(context.Background(), "15551234567", "Your code is 777777", channelWhatsApp, "777777"); err != nil {
		t.Fatalf("SendMessage: %v", err)
	}

	if want := "whatsapp:+15551234567"; cap.form.Get("To") != want {
		t.Errorf("To = %q, want %q", cap.form.Get("To"), want)
	}
	// A Messaging Service SID is not a phone number, so it is NOT prefixed.
	if cap.form.Get("From") != "MGtest" {
		t.Errorf("From = %q, want the bare messaging service sid", cap.form.Get("From"))
	}
	if cap.form.Get("ContentSid") != "HXtemplate" {
		t.Errorf("ContentSid = %q", cap.form.Get("ContentSid"))
	}
	if want := `{"1": "777777"}`; cap.form.Get("ContentVariables") != want {
		t.Errorf("ContentVariables = %q, want %q", cap.form.Get("ContentVariables"), want)
	}
	if cap.form.Has("Body") {
		t.Error("Body was sent alongside a content template")
	}
}

func TestTwilioSenderRejectsUnknownChannel(t *testing.T) {
	sender, err := newTwilioSender(TwilioConfig{AccountSID: "AC", AuthToken: "t", MessageServiceSID: "MG"})
	if err != nil {
		t.Fatalf("newTwilioSender: %v", err)
	}
	if _, err := sender.SendMessage(context.Background(), "15551234567", "hi", "smoke-signal", "1"); err == nil {
		t.Fatal("an unsupported channel was accepted")
	}
}

func TestTwilioSenderSurfacesProviderError(t *testing.T) {
	srv, _ := twilioStub(t, http.StatusBadRequest,
		`{"code":21211,"message":"The 'To' number is not a valid phone number.","more_info":"https://www.twilio.com/docs/errors/21211","status":400}`)

	sender, _ := newTwilioSender(TwilioConfig{
		AccountSID: "AC", AuthToken: "t", MessageServiceSID: "MG", APIBase: srv.URL,
	})
	_, err := sender.SendMessage(context.Background(), "15551234567", "hi", channelSMS, "1")
	if err == nil {
		t.Fatal("a 400 from Twilio was reported as success")
	}
	if !strings.Contains(err.Error(), "not a valid phone number") {
		t.Errorf("error = %v, want Twilio's message", err)
	}
}

// Twilio answers 201 even for a message it has already given up on.
func TestTwilioSenderTreatsFailedStatusAsAnError(t *testing.T) {
	srv, _ := twilioStub(t, http.StatusCreated,
		`{"sid":"SM55","status":"failed","error_code":30006,"error_message":"Landline or unreachable carrier"}`)

	sender, _ := newTwilioSender(TwilioConfig{
		AccountSID: "AC", AuthToken: "t", MessageServiceSID: "MG", APIBase: srv.URL,
	})
	id, err := sender.SendMessage(context.Background(), "15551234567", "hi", channelSMS, "1")
	if err == nil {
		t.Fatal(`a "failed" message status was reported as success`)
	}
	if id != "SM55" {
		t.Errorf("message id = %q, want SM55 so the failure can be traced", id)
	}
}

func TestTwilioSenderRequiresCredentials(t *testing.T) {
	for _, cfg := range []TwilioConfig{
		{AuthToken: "t", MessageServiceSID: "MG"},
		{AccountSID: "AC", MessageServiceSID: "MG"},
		{AccountSID: "AC", AuthToken: "t"},
	} {
		if _, err := newTwilioSender(cfg); err == nil {
			t.Errorf("newTwilioSender(%+v) accepted incomplete credentials", cfg)
		}
	}
}

func TestTwilioSenderDefaultsToTheProductionHost(t *testing.T) {
	s, err := newTwilioSender(TwilioConfig{AccountSID: "ACx", AuthToken: "t", MessageServiceSID: "MG"})
	if err != nil {
		t.Fatalf("newTwilioSender: %v", err)
	}
	want := "https://api.twilio.com/2010-04-01/Accounts/ACx/Messages.json"
	if got := s.(*twilioSender).apiURL; got != want {
		t.Errorf("apiURL = %q, want %q", got, want)
	}
}

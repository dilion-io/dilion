package auth

// The built-in Twilio SMS/WhatsApp sender.
//
// Reproduces github.com/supabase/auth/internal/api/sms_provider/twilio.go: one
// form-encoded POST to the Programmable Messaging API, authenticated with HTTP
// basic auth over (AccountSID, AuthToken).
//
//	POST {APIBase}/2010-04-01/Accounts/{AccountSID}/Messages.json
//	Authorization: Basic base64(AccountSID ":" AuthToken)
//	Content-Type: application/x-www-form-urlencoded
//
//	To=+<E.164>&Channel=sms&From=<MessageServiceSID>&Body=<rendered template>
//
// It is selected by Config.SMS.Provider == "twilio" when no ports.SMSSender is
// injected (smsflow.go smsProviderFor).
//
// # Deviations from upstream
//
//   - APIBase. Upstream hard-codes https://api.twilio.com, which makes the
//     provider untestable without network access. Config.SMS.Twilio.APIBase
//     overrides the host; empty means upstream's value.
//
//   - TIMEOUT. Upstream reads GOTRUE_INTERNAL_HTTP_TIMEOUT in a package init()
//     and log.Fatal()s on a bad value. Dilion uses a fixed 10s client timeout —
//     the same default — and never kills the process over a configuration
//     string.
//
//   - VerifyOTP. Upstream's SmsProvider interface carries a VerifyOTP method for
//     the twilio_verify provider, which delegates OTP storage to Twilio.
//     Dilion always stores its own OTP hash, so there is nothing to delegate and
//     the method does not exist.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// defaultTwilioAPIBase is upstream's defaultTwilioApiBase.
	defaultTwilioAPIBase = "https://api.twilio.com"
	// twilioAPIVersion is upstream's apiVersion path segment.
	twilioAPIVersion = "2010-04-01"
	// twilioTimeout is upstream's defaultTimeout.
	twilioTimeout = 10 * time.Second
	// twilioMaxResponse caps how much of a provider response is read, so a
	// misbehaving endpoint cannot exhaust memory.
	twilioMaxResponse = 1 << 20
)

// twilioSender is the Twilio implementation of smsProvider.
type twilioSender struct {
	cfg    TwilioConfig
	apiURL string
	client *http.Client
}

// newTwilioSender validates the credentials and precomputes the endpoint.
// Upstream's TwilioProviderConfiguration.Validate demands the same three fields.
func newTwilioSender(cfg TwilioConfig) (smsProvider, error) {
	switch {
	case strings.TrimSpace(cfg.AccountSID) == "":
		return nil, errors.New("missing Twilio account SID")
	case strings.TrimSpace(cfg.AuthToken) == "":
		return nil, errors.New("missing Twilio auth token")
	case strings.TrimSpace(cfg.MessageServiceSID) == "":
		return nil, errors.New("missing Twilio message service SID")
	}
	base := strings.TrimRight(strings.TrimSpace(cfg.APIBase), "/")
	if base == "" {
		base = defaultTwilioAPIBase
	}
	return &twilioSender{
		cfg:    cfg,
		apiURL: base + "/" + twilioAPIVersion + "/Accounts/" + url.PathEscape(cfg.AccountSID) + "/Messages.json",
		client: &http.Client{Timeout: twilioTimeout},
	}, nil
}

// twilioMessage is the subset of Twilio's Message resource that decides whether
// a send succeeded (upstream sms_provider.SmsStatus).
type twilioMessage struct {
	To           string `json:"to"`
	From         string `json:"from"`
	MessageSID   string `json:"sid"`
	Status       string `json:"status"`
	ErrorCode    any    `json:"error_code"`
	ErrorMessage string `json:"error_message"`
	Body         string `json:"body"`
}

// twilioError is Twilio's error body (upstream twilioErrResponse).
type twilioError struct {
	Code     int    `json:"code"`
	Message  string `json:"message"`
	MoreInfo string `json:"more_info"`
	Status   int    `json:"status"`
}

func (e *twilioError) Error() string {
	return fmt.Sprintf("%s More information: %s", e.Message, e.MoreInfo)
}

// SendMessage implements smsProvider.
func (t *twilioSender) SendMessage(ctx context.Context, phone, message, channel, otp string) (string, error) {
	switch channel {
	case channelSMS, channelWhatsApp:
		return t.send(ctx, phone, message, channel, otp)
	default:
		return "", fmt.Errorf("channel type %q is not supported for Twilio", channel)
	}
}

func (t *twilioSender) send(ctx context.Context, phone, message, channel, otp string) (string, error) {
	sender := t.cfg.MessageServiceSID
	// Twilio requires the "+" even though auth.users.phone never stores it.
	receiver := "+" + phone

	body := url.Values{
		"To":      {receiver},
		"Channel": {channel},
		"From":    {sender},
		"Body":    {message},
	}

	if channel == channelWhatsApp {
		receiver = channel + ":" + receiver
		// A Messaging Service SID is not a phone number and must NOT be
		// prefixed; a bare sending number must be.
		if validateE164Format(formatPhoneNumber(sender)) {
			sender = channel + ":" + sender
		}
		body = url.Values{
			"To":      {receiver},
			"Channel": {channel},
			"From":    {sender},
		}
		if t.cfg.ContentSID != "" {
			// WhatsApp authentication templates substitute the code
			// themselves; see Twilio's content API.
			body.Set("ContentSid", t.cfg.ContentSID)
			body.Set("ContentVariables", fmt.Sprintf(`{"1": "%s"}`, otp))
		} else {
			body.Set("Body", message)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.apiURL, strings.NewReader(body.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(t.cfg.AccountSID, t.cfg.AuthToken)

	res, err := t.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(res.Body, twilioMaxResponse))
	if err != nil {
		return "", err
	}

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		terr := &twilioError{}
		if jerr := json.Unmarshal(raw, terr); jerr != nil || terr.Message == "" {
			return "", fmt.Errorf("twilio: unexpected status %d: %s", res.StatusCode, strings.TrimSpace(string(raw)))
		}
		return "", terr
	}

	msg := &twilioMessage{}
	if jerr := json.Unmarshal(raw, msg); jerr != nil {
		return "", jerr
	}
	// Twilio answers 201 even for a message it has already given up on.
	if msg.Status == "failed" || msg.Status == "undelivered" {
		return msg.MessageSID, fmt.Errorf("twilio error: %v %v for message %s",
			msg.ErrorMessage, msg.ErrorCode, msg.MessageSID)
	}
	return msg.MessageSID, nil
}

// Package devmail provides the development-default ports.Mailer and
// ports.SMSSender: they deliver nothing and log the message with log/slog.
//
// This is what makes dilion.NewServer(WithDSN(...)) work out of the box (§2.4
// "batteries included"). It must never be used in production: recipients and
// message bodies (magic links, OTP codes) end up in the process log, so
// addresses are masked at info level and full bodies are logged only at debug.
package devmail

import (
	"context"
	"log/slog"
	"strings"

	"github.com/dilion-io/dilion/ports"
)

// Mailer logs outbound email instead of sending it.
type Mailer struct {
	log *slog.Logger
}

var _ ports.Mailer = (*Mailer)(nil)

// NewMailer returns a Mailer logging to log (slog.Default() when nil).
func NewMailer(log *slog.Logger) *Mailer {
	return &Mailer{log: logger(log, "devmail")}
}

// Send logs the message and always succeeds.
func (m *Mailer) Send(ctx context.Context, to, subject, textBody, htmlBody string) error {
	m.log.InfoContext(ctx, "dev mailer: email not sent (no mailer configured)",
		"to", MaskEmail(to), "subject", subject,
		"text_bytes", len(textBody), "html_bytes", len(htmlBody))
	m.log.DebugContext(ctx, "dev mailer: body", "to", MaskEmail(to), "text", textBody, "html", htmlBody)
	return nil
}

// SMS logs outbound SMS instead of sending it.
type SMS struct {
	log *slog.Logger
}

var _ ports.SMSSender = (*SMS)(nil)

// NewSMS returns an SMS sender logging to log (slog.Default() when nil).
func NewSMS(log *slog.Logger) *SMS {
	return &SMS{log: logger(log, "devsms")}
}

// Send logs the message and always succeeds.
func (s *SMS) Send(ctx context.Context, to, body string) error {
	s.log.InfoContext(ctx, "dev sms: message not sent (no sms sender configured)",
		"to", MaskPhone(to), "body_bytes", len(body))
	s.log.DebugContext(ctx, "dev sms: body", "to", MaskPhone(to), "body", body)
	return nil
}

func logger(l *slog.Logger, component string) *slog.Logger {
	if l == nil {
		l = slog.Default()
	}
	return l.With("component", component)
}

// MaskEmail renders an address as "j***@example.com".
func MaskEmail(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return mask(addr)
	}
	if at == 0 {
		return "***" + addr
	}
	return mask(addr[:at]) + addr[at:]
}

// MaskPhone keeps the first three and last two characters: "+82*******78".
func MaskPhone(num string) string {
	r := []rune(num)
	const head, tail = 3, 2
	if len(r) <= head+tail {
		return strings.Repeat("*", len(r))
	}
	return string(r[:head]) + strings.Repeat("*", len(r)-head-tail) + string(r[len(r)-tail:])
}

func mask(s string) string {
	if s == "" {
		return ""
	}
	return s[:1] + "***"
}

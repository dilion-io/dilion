package devmail

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestMaskEmail(t *testing.T) {
	tests := map[string]string{
		"hong@example.com": "h***@example.com",
		"a@b.c":            "a***@b.c",
		"noatsign":         "n***",
		"":                 "",
		"@example.com":     "***@example.com",
	}
	for in, want := range tests {
		if got := MaskEmail(in); got != want {
			t.Errorf("MaskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskPhone(t *testing.T) {
	tests := map[string]string{
		"+821012345678": "+82********78",
		"01012345678":   "010******78",
		"12345":         "*****",
		"":              "",
	}
	for in, want := range tests {
		if got := MaskPhone(in); got != want {
			t.Errorf("MaskPhone(%q) = %q, want %q", in, got, want)
		}
	}
}

// Info-level logs must not leak the full address or the body.
func TestSendDoesNotLogSecretsAtInfo(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx := context.Background()

	if err := NewMailer(log).Send(ctx, "hong@example.com", "Confirm", "code 123456", ""); err != nil {
		t.Fatal(err)
	}
	if err := NewSMS(log).Send(ctx, "+821012345678", "code 654321"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, secret := range []string{"hong@example.com", "123456", "654321", "+821012345678"} {
		if strings.Contains(out, secret) {
			t.Errorf("log leaked %q:\n%s", secret, out)
		}
	}
	if !strings.Contains(out, "h***@example.com") {
		t.Errorf("masked recipient missing:\n%s", out)
	}
}

func TestNilLoggerUsesDefault(t *testing.T) {
	if err := NewMailer(nil).Send(context.Background(), "a@b.c", "s", "t", "h"); err != nil {
		t.Fatal(err)
	}
	if err := NewSMS(nil).Send(context.Background(), "+1555", "b"); err != nil {
		t.Fatal(err)
	}
}

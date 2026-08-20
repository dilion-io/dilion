package auth

import (
	"context"
	"crypto/sha1"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sha1Digest is what the range API keys on.
func sha1Digest(password string) (prefix, suffix string) {
	sum := sha1.Sum([]byte(password))
	digest := strings.ToUpper(fmt.Sprintf("%x", sum))
	return digest[:5], digest[5:]
}

// newFakeHIBPServer serves the range API for one known-pwned password.
func newFakeHIBPServer(t *testing.T, pwned string, count int) *httptest.Server {
	t.Helper()
	wantPrefix, wantSuffix := sha1Digest(pwned)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Add-Padding"); got != "true" {
			t.Errorf("Add-Padding header = %q, want \"true\"", got)
		}
		prefix := strings.TrimPrefix(r.URL.Path, "/range/")
		if len(prefix) != 5 {
			t.Errorf("range prefix = %q, want 5 hex characters", prefix)
		}

		// Every response carries padding rows (count 0) plus one unrelated real
		// row, so a hit is only ever produced by the suffix match below.
		var b strings.Builder
		b.WriteString("0000000000000000000000000000000000A:0\r\n")
		b.WriteString("0000000000000000000000000000000000B:0\r\n")
		b.WriteString("1111111111111111111111111111111111C:42\r\n")
		if prefix == wantPrefix {
			fmt.Fprintf(&b, "%s:%d\r\n", wantSuffix, count)
		}
		_, _ = w.Write([]byte(b.String()))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func hibpConfig(baseURL string) *Config {
	cfg := DefaultConfig()
	cfg.Security.HIBPEnabled = true
	cfg.Security.HIBPBaseURL = baseURL
	return cfg
}

func TestHIBPDetectsPwnedPassword(t *testing.T) {
	srv := newFakeHIBPServer(t, "password123", 24230577)
	a := newSecurityTestAPI(t, hibpConfig(srv.URL))

	pwned, err := a.isPasswordPwned(context.Background(), "password123")
	if err != nil {
		t.Fatalf("isPasswordPwned: %v", err)
	}
	if !pwned {
		t.Error("password123 must be reported as pwned")
	}
}

func TestHIBPMissIsNotPwned(t *testing.T) {
	srv := newFakeHIBPServer(t, "password123", 24230577)
	a := newSecurityTestAPI(t, hibpConfig(srv.URL))

	pwned, err := a.isPasswordPwned(context.Background(), "aX7!qz-unique-passphrase-9931")
	if err != nil {
		t.Fatalf("isPasswordPwned: %v", err)
	}
	if pwned {
		t.Error("an unseen password must not be reported as pwned")
	}
}

// Padded rows carry a count of 0 and must never count as a hit.
func TestHIBPIgnoresZeroCountPadding(t *testing.T) {
	srv := newFakeHIBPServer(t, "padded-only", 0)
	a := newSecurityTestAPI(t, hibpConfig(srv.URL))

	pwned, err := a.isPasswordPwned(context.Background(), "padded-only")
	if err != nil {
		t.Fatalf("isPasswordPwned: %v", err)
	}
	if pwned {
		t.Error("a zero-count (padding) row must not count as a breach hit")
	}
}

func TestHIBPRangeParsing(t *testing.T) {
	body := "AAA:0\r\nBBB:3\r\nCCC:0\n"
	for suffix, want := range map[string]bool{"AAA": false, "BBB": true, "CCC": false, "DDD": false} {
		if got := hibpRangeContains(body, suffix); got != want {
			t.Errorf("hibpRangeContains(%q) = %v, want %v", suffix, got, want)
		}
	}
	// The API answers in upper case; a lower-case comparison must still match.
	if !hibpRangeContains("abc:9\n", "ABC") {
		t.Error("suffix comparison must be case-insensitive")
	}
}

func TestHIBPNetworkErrorIsReported(t *testing.T) {
	srv := newFakeHIBPServer(t, "x", 1)
	url := srv.URL
	srv.Close()

	a := newSecurityTestAPI(t, hibpConfig(url))
	if _, err := a.isPasswordPwned(context.Background(), "anything"); err == nil {
		t.Fatal("an unreachable range API must produce an error")
	}
}

func TestHIBPNon200IsReported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	a := newSecurityTestAPI(t, hibpConfig(srv.URL))
	if _, err := a.isPasswordPwned(context.Background(), "anything"); err == nil {
		t.Fatal("a non-200 range response must produce an error")
	}
}

// A pwned password is a weak_password with reason "pwned".
func TestPasswordStrengthRejectsPwned(t *testing.T) {
	srv := newFakeHIBPServer(t, "password123", 24230577)
	a := newSecurityTestAPI(t, hibpConfig(srv.URL))

	herr := a.checkPasswordStrength(context.Background(), "password123")
	if herr == nil {
		t.Fatal("a pwned password must be rejected")
	}
	assertWeakPassword(t, herr, []string{"pwned"})
	if !strings.Contains(herr.Message, "known to be weak") {
		t.Errorf("msg = %q, want upstream's pwned message", herr.Message)
	}
}

// Upstream default: an unreachable HIBP ACCEPTS the password (fail open).
func TestPasswordStrengthFailsOpenWhenHIBPIsDown(t *testing.T) {
	srv := newFakeHIBPServer(t, "password123", 1)
	url := srv.URL
	srv.Close()

	a := newSecurityTestAPI(t, hibpConfig(url))
	if herr := a.checkPasswordStrength(context.Background(), "password123"); herr != nil {
		t.Fatalf("HIBP outage must not reject the password, got %v", herr)
	}
}

// ... unless Security.HIBPFailClosed is set, which is upstream's 500.
func TestPasswordStrengthFailsClosedWhenConfigured(t *testing.T) {
	srv := newFakeHIBPServer(t, "password123", 1)
	url := srv.URL
	srv.Close()

	cfg := hibpConfig(url)
	cfg.Security.HIBPFailClosed = true
	a := newSecurityTestAPI(t, cfg)

	herr := a.checkPasswordStrength(context.Background(), "password123")
	if herr == nil {
		t.Fatal("with fail-closed set, an HIBP outage must reject the request")
	}
	if herr.HTTPStatus != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", herr.HTTPStatus)
	}
}

// With HIBP off no lookup happens at all: a server that fails the test if hit.
func TestPasswordStrengthSkipsHIBPWhenDisabled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("HIBP must not be queried while Security.HIBPEnabled is false")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := DefaultConfig()
	cfg.Security.HIBPBaseURL = srv.URL
	a := newSecurityTestAPI(t, cfg)

	if herr := a.checkPasswordStrength(context.Background(), "password123"); herr != nil {
		t.Fatalf("checkPasswordStrength: %v", herr)
	}
}

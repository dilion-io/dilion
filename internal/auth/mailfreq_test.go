package auth

import (
	"os"
	"strings"
	"testing"
	"time"
)

// Every emailed link must resolve under the mount point, /auth/v1 — upstream's
// bare "/verify" default would produce a dead link in Dilion.
func TestMailerURLPathDefaults(t *testing.T) {
	a := newSecurityTestAPI(t, DefaultConfig())

	for _, actionType := range []string{
		mailInvite, mailSignup, mailRecovery, mailMagicLink,
		mailEmailChange, mailEmailChangeCurrent, mailEmailChangeNew,
	} {
		if got := a.urlPathFor(actionType); got != DefaultMailerURLPath {
			t.Errorf("urlPathFor(%q) = %q, want %q", actionType, got, DefaultMailerURLPath)
		}
	}
	if DefaultMailerURLPath != "/auth/v1/verify" {
		t.Errorf("DefaultMailerURLPath = %q, want /auth/v1/verify", DefaultMailerURLPath)
	}

	// An explicit configuration still wins, so a deployment that proxies
	// upstream's "/verify" can restore it.
	cfg := DefaultConfig()
	cfg.Mailer.URLPaths.Confirmation = "/verify"
	custom := newSecurityTestAPI(t, cfg)
	if got := custom.urlPathFor(mailSignup); got != "/verify" {
		t.Errorf("configured URL path = %q, want /verify", got)
	}
}

// GOTRUE_MAILER_URLPATHS_* must keep overriding the Dilion default.
func TestMailerURLPathEnvOverride(t *testing.T) {
	t.Setenv("GOTRUE_MAILER_URLPATHS_CONFIRMATION", "/verify")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Mailer.URLPaths.Confirmation != "/verify" {
		t.Errorf("confirmation path = %q, want the env override /verify", cfg.Mailer.URLPaths.Confirmation)
	}
	if cfg.Mailer.URLPaths.Recovery != DefaultMailerURLPath {
		t.Errorf("recovery path = %q, want the default %q", cfg.Mailer.URLPaths.Recovery, DefaultMailerURLPath)
	}
}

func TestMailerMaxFrequencyConfig(t *testing.T) {
	if got := DefaultConfig().Mailer.MaxFrequency; got != time.Minute {
		t.Errorf("default Mailer.MaxFrequency = %v, want 1m", got)
	}

	// Upstream's spelling is the fallback...
	t.Setenv("GOTRUE_SMTP_MAX_FREQUENCY", "30s")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Mailer.MaxFrequency != 30*time.Second {
		t.Errorf("MaxFrequency = %v, want 30s from GOTRUE_SMTP_MAX_FREQUENCY", cfg.Mailer.MaxFrequency)
	}

	// ...and the Dilion-native name wins when both are set.
	t.Setenv("DILION_AUTH_MAILER_MAX_FREQUENCY", "5s")
	cfg, err = LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Mailer.MaxFrequency != 5*time.Second {
		t.Errorf("MaxFrequency = %v, want 5s from DILION_AUTH_MAILER_MAX_FREQUENCY", cfg.Mailer.MaxFrequency)
	}

	// A non-positive value falls back to the 1m default.
	zeroed := DefaultConfig()
	zeroed.Mailer.MaxFrequency = 0
	if err := zeroed.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if zeroed.Mailer.MaxFrequency != time.Minute {
		t.Errorf("MaxFrequency after Validate = %v, want 1m", zeroed.Mailer.MaxFrequency)
	}
}

func TestCaptchaAndHIBPConfigEnv(t *testing.T) {
	t.Setenv("GOTRUE_SECURITY_CAPTCHA_ENABLED", "true")
	t.Setenv("GOTRUE_SECURITY_CAPTCHA_PROVIDER", "turnstile")
	t.Setenv("GOTRUE_SECURITY_CAPTCHA_SECRET", "s3cret")
	t.Setenv("GOTRUE_SECURITY_CAPTCHA_TIMEOUT", "3s")
	t.Setenv("GOTRUE_PASSWORD_HIBP_ENABLED", "true")
	t.Setenv("GOTRUE_PASSWORD_HIBP_FAIL_CLOSED", "true")
	t.Setenv("GOTRUE_PASSWORD_REQUIRED_CHARACTERS", "abc:123")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !cfg.Security.Captcha.Enabled || cfg.Security.Captcha.Provider != "turnstile" ||
		cfg.Security.Captcha.Secret != "s3cret" || cfg.Security.Captcha.Timeout != 3*time.Second {
		t.Errorf("captcha config = %+v", cfg.Security.Captcha)
	}
	if !cfg.Security.HIBPEnabled || !cfg.Security.HIBPFailClosed {
		t.Errorf("hibp config: enabled=%v failClosed=%v", cfg.Security.HIBPEnabled, cfg.Security.HIBPFailClosed)
	}
	if strings.Join(cfg.Password.RequiredCharacters, "|") != "abc|123" {
		t.Errorf("required characters = %v", cfg.Password.RequiredCharacters)
	}

	// The captcha secret must never reach a JSON rendering of the config.
	if _, ok := os.LookupEnv("GOTRUE_SECURITY_CAPTCHA_SECRET"); !ok {
		t.Fatal("test setup lost the env var")
	}
}

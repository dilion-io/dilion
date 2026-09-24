package auth

// Pure unit tests for the passkey feature: the relying-party configuration
// mapping and the small helpers it is built on. No database required.

import (
	"context"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

func TestPasskeyWebAuthnConfigUsesExplicitSettings(t *testing.T) {
	cfg := testConfig()
	cfg.SiteURL = "https://app.example.com"
	cfg.Passkeys.RPID = "example.com"
	cfg.Passkeys.RPOrigins = []string{"https://app.example.com", "https://admin.example.com"}

	got := newAPI(Deps{Config: cfg, Tokens: NewTokenServiceHS(testSecret())}).passkeyWebAuthnConfig(context.Background())

	if got.RPID != "example.com" {
		t.Errorf("RPID = %q, want the configured value", got.RPID)
	}
	if len(got.RPOrigins) != 2 || got.RPOrigins[0] != "https://app.example.com" {
		t.Errorf("RPOrigins = %v, want the configured list", got.RPOrigins)
	}
	// Both are required for a DISCOVERABLE credential to be created at all;
	// losing either silently breaks usernameless login.
	if got.AuthenticatorSelection.ResidentKey != protocol.ResidentKeyRequirementRequired {
		t.Errorf("ResidentKey = %q, want required (discoverable credentials)", got.AuthenticatorSelection.ResidentKey)
	}
	if got.AttestationPreference != protocol.PreferNoAttestation {
		t.Errorf("AttestationPreference = %q, want none", got.AttestationPreference)
	}
}

// TestPasskeyWebAuthnConfigFallsBackToSiteURL pins the documented Dilion
// deviation: upstream refuses to boot without GOTRUE_WEBAUTHN_RP_ID /
// _RP_ORIGINS, Dilion derives both from SITE_URL so the zero-config path works.
func TestPasskeyWebAuthnConfigFallsBackToSiteURL(t *testing.T) {
	cases := []struct {
		siteURL     string
		wantRPID    string
		wantOrigins []string
	}{
		{"http://localhost:5173", "localhost", []string{"http://localhost:5173"}},
		{"https://app.example.com", "app.example.com", []string{"https://app.example.com"}},
		{"https://app.example.com:8443/path", "app.example.com", []string{"https://app.example.com:8443"}},
	}
	for _, c := range cases {
		cfg := testConfig()
		cfg.SiteURL = c.siteURL
		got := newAPI(Deps{Config: cfg, Tokens: NewTokenServiceHS(testSecret())}).passkeyWebAuthnConfig(context.Background())

		if got.RPID != c.wantRPID {
			t.Errorf("SITE_URL %s: RPID = %q, want %q", c.siteURL, got.RPID, c.wantRPID)
		}
		if len(got.RPOrigins) != 1 || got.RPOrigins[0] != c.wantOrigins[0] {
			t.Errorf("SITE_URL %s: RPOrigins = %v, want %v", c.siteURL, got.RPOrigins, c.wantOrigins)
		}
		// RPDisplayName has no Dilion knob; it mirrors the RP ID.
		if got.RPDisplayName != c.wantRPID {
			t.Errorf("SITE_URL %s: RPDisplayName = %q, want %q", c.siteURL, got.RPDisplayName, c.wantRPID)
		}
	}
}

// TestPasskeyWebAuthnConfigExplicitRPIDKeepsSiteURLOrigins covers the mixed
// case: one knob set, the other derived.
func TestPasskeyWebAuthnConfigExplicitRPIDKeepsSiteURLOrigins(t *testing.T) {
	cfg := testConfig()
	cfg.SiteURL = "https://app.example.com"
	cfg.Passkeys.RPID = "example.com"

	got := newAPI(Deps{Config: cfg, Tokens: NewTokenServiceHS(testSecret())}).passkeyWebAuthnConfig(context.Background())
	if got.RPID != "example.com" {
		t.Errorf("RPID = %q, want the explicit value", got.RPID)
	}
	if len(got.RPOrigins) != 1 || got.RPOrigins[0] != "https://app.example.com" {
		t.Errorf("RPOrigins = %v, want the SiteURL-derived origin", got.RPOrigins)
	}
}

func TestPasskeyFriendlyName(t *testing.T) {
	appleAAGUID, err := uuidBytes("fbfc3007-154e-4ecc-8c0b-6e020557d7bd")
	if err != nil {
		t.Fatalf("uuidBytes: %v", err)
	}
	unknown, err := uuidBytes("00000000-0000-4000-8000-00000000dead")
	if err != nil {
		t.Fatalf("uuidBytes: %v", err)
	}

	cases := []struct {
		name   string
		aaguid []byte
		want   string
	}{
		{"known model", appleAAGUID, "Apple Passwords"},
		{"unknown model", unknown, passkeyDefaultFriendlyName},
		{"all-zero aaguid", make([]byte, 16), passkeyDefaultFriendlyName},
		{"no aaguid", nil, passkeyDefaultFriendlyName},
		{"wrong length", []byte{1, 2, 3}, passkeyDefaultFriendlyName},
	}
	for _, c := range cases {
		if got := passkeyFriendlyName(c.aaguid); got != c.want {
			t.Errorf("%s: passkeyFriendlyName = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestFormatUUIDBytesRoundTrip(t *testing.T) {
	const want = "fbfc3007-154e-4ecc-8c0b-6e020557d7bd"
	raw, err := uuidBytes(want)
	if err != nil {
		t.Fatalf("uuidBytes: %v", err)
	}
	if len(raw) != 16 {
		t.Fatalf("uuidBytes returned %d bytes, want 16", len(raw))
	}
	if got := formatUUIDBytes(raw); got != want {
		t.Errorf("round trip = %q, want %q", got, want)
	}

	// The all-zero AAGUID is "no model", not a UUID worth storing.
	if got := formatUUIDBytes(make([]byte, 16)); got != "" {
		t.Errorf("formatUUIDBytes(zero) = %q, want \"\"", got)
	}
	if _, err := uuidBytes("not-a-uuid"); err == nil {
		t.Error("uuidBytes accepted a non-UUID")
	}
}

// TestPasskeyAMRMethodIsNotAAL2 pins the assurance-level semantics: a passkey is
// a SIGN-IN method, so it must never on its own raise a session to aal2.
func TestPasskeyAMRMethodIsNotAAL2(t *testing.T) {
	if AMRMethodPasskey != "passkey" {
		t.Fatalf("AMRMethodPasskey = %q, want %q (upstream models.PasskeyLogin)", AMRMethodPasskey, "passkey")
	}
	if (amrClaim{Method: AMRMethodPasskey}).isAAL2Claim() {
		t.Error("a passkey claim reports aal2; it is a sign-in method, not a second factor")
	}
	aal, amr := computeAAL([]amrClaim{{Method: AMRMethodPasskey}})
	if aal != AAL1 {
		t.Errorf("aal for a passkey-only session = %q, want aal1", aal)
	}
	if len(amr) != 1 {
		t.Errorf("amr = %v, want one entry", amr)
	}
}

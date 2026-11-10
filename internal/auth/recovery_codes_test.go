package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNormalizeRecoveryCode(t *testing.T) {
	for in, want := range map[string]string{
		"K4M9-X7QP-2AB8-HT3Z":     "k4m9x7qp2ab8ht3z",
		" k4m9 x7qp\t2ab8\nht3z ": "k4m9x7qp2ab8ht3z",
		"k4m9x7qp2ab8ht3z":        "k4m9x7qp2ab8ht3z",
		"--- ":                    "",
	} {
		if got := normalizeRecoveryCode(in); got != want {
			t.Errorf("normalizeRecoveryCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGenerateRecoveryCode(t *testing.T) {
	for _, n := range []int{13, 16, 32} {
		code, err := generateRecoveryCode(n)
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != n || strings.Trim(code, recoveryCodeAlphabet) != "" {
			t.Errorf("generateRecoveryCode(%d) = %q", n, code)
		}
	}
}

func TestRecoveryCodeHashRoundTrip(t *testing.T) {
	hash, err := hashRecoveryCode("k4m9x7qp2ab8ht3z")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("hash = %q, want upstream's PHC parameters", hash)
	}
	if err := compareRecoveryCodeHash(hash, "k4m9x7qp2ab8ht3z"); err != nil {
		t.Fatalf("matching code: %v", err)
	}
	if err := compareRecoveryCodeHash(hash, "k4m9x7qp2ab8ht3y"); !errors.Is(err, errRecoveryCodeMismatch) {
		t.Fatalf("other code: %v, want a mismatch", err)
	}
	again, _ := hashRecoveryCode("k4m9x7qp2ab8ht3z")
	if again == hash {
		t.Fatal("two hashes of one code are equal: the salt is not random")
	}
}

// A stored hash whose parameters would make verification expensive, or whose
// salt or digest is too short to mean anything, is refused before argon2 runs.
func TestCompareRecoveryCodeHashRejectsUnsafeParameters(t *testing.T) {
	const salt = "c2FsdHNhbHRzYWx0c2FsdA"                        // 16 bytes
	const digest = "ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGlnZXN0ZGlnZXN0MDA" // 32 bytes
	for name, hash := range map[string]string{
		"argon2i":        "$argon2i$v=19$m=19456,t=2,p=1$" + salt + "$" + digest,
		"version 16":     "$argon2id$v=16$m=19456,t=2,p=1$" + salt + "$" + digest,
		"memory > 1 GiB": "$argon2id$v=19$m=1048577,t=2,p=1$" + salt + "$" + digest,
		"t = 0":          "$argon2id$v=19$m=19456,t=0,p=1$" + salt + "$" + digest,
		"t > 20":         "$argon2id$v=19$m=19456,t=21,p=1$" + salt + "$" + digest,
		"p > 16":         "$argon2id$v=19$m=19456,t=2,p=17$" + salt + "$" + digest,
		"m < 8 per lane": "$argon2id$v=19$m=15,t=2,p=2$" + salt + "$" + digest,
		"short salt":     "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$" + digest,
		"short digest":   "$argon2id$v=19$m=19456,t=2,p=1$" + salt + "$ZGlnZXN0",
		"padded base64":  "$argon2id$v=19$m=19456,t=2,p=1$" + salt + "==$" + digest,
	} {
		err := compareRecoveryCodeHash(hash, "k4m9x7qp2ab8ht3z")
		if err == nil || errors.Is(err, errRecoveryCodeMismatch) {
			t.Errorf("%s: err = %v, want a malformed-hash error", name, err)
		}
	}
}

func TestMFARecoveryCodesConfigValidate(t *testing.T) {
	valid := func() MFARecoveryCodesConfig {
		return MFARecoveryCodesConfig{EnrollEnabled: true, Count: 10, CodeLength: 16,
			MaxVerifyAttempts: 5, LockoutDuration: 15 * time.Minute}
	}
	if c := valid(); c.validate() != nil {
		t.Fatalf("defaults: %v", c.validate())
	}
	for name, mutate := range map[string]func(*MFARecoveryCodesConfig){
		"count 3":        func(c *MFARecoveryCodesConfig) { c.Count = 3 },
		"count 17":       func(c *MFARecoveryCodesConfig) { c.Count = 17 },
		"length 12":      func(c *MFARecoveryCodesConfig) { c.CodeLength = 12 },
		"length 33":      func(c *MFARecoveryCodesConfig) { c.CodeLength = 33 },
		"attempts 2":     func(c *MFARecoveryCodesConfig) { c.MaxVerifyAttempts = 2 },
		"attempts 16":    func(c *MFARecoveryCodesConfig) { c.MaxVerifyAttempts = 16 },
		"lockout 59s":    func(c *MFARecoveryCodesConfig) { c.LockoutDuration = 59 * time.Second },
		"lockout 24h+1s": func(c *MFARecoveryCodesConfig) { c.LockoutDuration = 24*time.Hour + time.Second },
	} {
		c := valid()
		mutate(&c)
		if c.validate() == nil {
			t.Errorf("%s: validate() = nil, want an error", name)
		}
	}
	// The bounds only apply once the feature is on.
	if c := (MFARecoveryCodesConfig{}); c.validate() != nil {
		t.Fatalf("disabled zero config: %v", c.validate())
	}
}

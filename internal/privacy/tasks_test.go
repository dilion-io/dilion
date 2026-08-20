package privacy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSignPayloadMatchesSpec(t *testing.T) {
	secret := "whsec_test"
	body := []byte(`{"event":"privacy.delete","id":"evt_1"}`)
	ts := int64(1786000000)

	// Independent implementation of §3.2: hmac_sha256(secret, "<t>.<body>").
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(strconv.FormatInt(ts, 10) + "." + string(body)))
	want := hex.EncodeToString(m.Sum(nil))

	if got := signPayload(secret, ts, body); got != want {
		t.Fatalf("signPayload = %s, want %s", got, want)
	}
	header := signatureHeader(secret, ts, body)
	if header != fmt.Sprintf("t=%d,v1=%s", ts, want) {
		t.Fatalf("header = %s", header)
	}
}

// verifySignature is what a receiver implements; the test doubles as executable
// documentation of the protocol.
func verifySignature(secret, header string, body []byte, now time.Time, tolerance time.Duration) error {
	var tsPart, sigPart string
	for _, kv := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("malformed element %q", kv)
		}
		switch k {
		case "t":
			tsPart = v
		case "v1":
			sigPart = v
		}
	}
	if tsPart == "" || sigPart == "" {
		return fmt.Errorf("missing t or v1")
	}
	ts, err := strconv.ParseInt(tsPart, 10, 64)
	if err != nil {
		return err
	}
	if d := now.Sub(time.Unix(ts, 0)); d > tolerance || d < -tolerance {
		return fmt.Errorf("timestamp outside tolerance (replay protection)")
	}
	want := signPayload(secret, ts, body)
	if !hmac.Equal([]byte(want), []byte(sigPart)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func TestSignatureVerificationRoundTrip(t *testing.T) {
	secret := "s3cr3t"
	body := []byte(`{"event":"privacy.delete","user_id":"2d5f7f00-0000-4000-8000-000000000000"}`)
	now := time.Unix(1786000123, 0)
	header := signatureHeader(secret, now.Unix(), body)

	if err := verifySignature(secret, header, body, now, time.Minute); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := verifySignature("wrong", header, body, now, time.Minute); err == nil {
		t.Error("wrong secret must fail")
	}
	if err := verifySignature(secret, header, append(body, ' '), now, time.Minute); err == nil {
		t.Error("tampered body must fail")
	}
	if err := verifySignature(secret, header, body, now.Add(10*time.Minute), time.Minute); err == nil {
		t.Error("stale timestamp must fail (replay protection)")
	}
}

func TestBackoffGrowsAndIsCapped(t *testing.T) {
	var prev time.Duration
	for attempt := 1; attempt <= maxTaskAttempts; attempt++ {
		d := backoffFor(attempt)
		if d < backoffBase {
			t.Fatalf("attempt %d: backoff %s below base", attempt, d)
		}
		if d > backoffCap*2 {
			t.Fatalf("attempt %d: backoff %s exceeds cap", attempt, d)
		}
		if attempt > 1 && d < prev {
			t.Fatalf("attempt %d: backoff %s not increasing (prev %s)", attempt, d, prev)
		}
		prev = d
	}
	if got := backoffFor(50); got < backoffCap || got > backoffCap+backoffCap/4 {
		t.Fatalf("backoff not capped: %s", got)
	}
	if got := backoffFor(0); got < backoffBase {
		t.Fatalf("backoff(0) = %s", got)
	}
}

func TestCursorRoundTrip(t *testing.T) {
	ts := time.Date(2026, 8, 12, 3, 4, 5, 123456789, time.UTC)
	c := encodeCursor(ts, "pr_0123456789abcdef0123456789abcdef")
	gotTS, gotID, err := decodeCursor(*c)
	if err != nil {
		t.Fatal(err)
	}
	if !gotTS.Equal(ts) || gotID != "pr_0123456789abcdef0123456789abcdef" {
		t.Fatalf("round trip = %s / %s", gotTS, gotID)
	}
	if _, _, err := decodeCursor("!!!not-base64!!!"); err == nil {
		t.Error("malformed cursor must error")
	}
	if ts, id, err := decodeCursor(""); err != nil || !ts.IsZero() || id != "" {
		t.Error("empty cursor must decode to the zero value")
	}

	id := encodeIDCursor("dst_0123456789abcdef0123456789abcdef")
	if got, err := decodeIDCursor(*id); err != nil || got != "dst_0123456789abcdef0123456789abcdef" {
		t.Fatalf("id cursor round trip = %q (%v)", got, err)
	}
}

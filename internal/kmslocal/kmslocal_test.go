package kmslocal

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/dilion-project/dilion/ports"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := testKey(t)
	ad := aad("11111111-1111-4111-8111-111111111111", ports.KeyScopeDefault)
	plaintext := []byte("hong gil-dong, 010-1234-5678")

	blob, err := sealWithKey(key, ad, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if blob[0] != Version {
		t.Fatalf("version byte = 0x%02x, want 0x%02x", blob[0], Version)
	}
	if want := 1 + nonceSize + len(plaintext) + gcmTagSize; len(blob) != want {
		t.Fatalf("len(blob) = %d, want %d", len(blob), want)
	}
	if bytes.Contains(blob, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}

	got, err := openWithKey(key, ad, blob)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round trip = %q, want %q", got, plaintext)
	}
}

func TestSealNonceIsFresh(t *testing.T) {
	key := testKey(t)
	ad := aad("11111111-1111-4111-8111-111111111111", ports.KeyScopeDefault)
	a, err := sealWithKey(key, ad, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := sealWithKey(key, ad, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext produced identical blobs (nonce reuse)")
	}
}

func TestOpenRejectsTamperingAndWrongContext(t *testing.T) {
	const subjectA = "11111111-1111-4111-8111-111111111111"
	const subjectB = "22222222-2222-4222-8222-222222222222"
	key := testKey(t)
	blob, err := sealWithKey(key, aad(subjectA, ports.KeyScopeDefault), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		key  []byte
		ad   []byte
		blob []byte
	}{
		{"wrong key", testKey(t), aad(subjectA, ports.KeyScopeDefault), blob},
		{"wrong subject", key, aad(subjectB, ports.KeyScopeDefault), blob},
		{"wrong scope", key, aad(subjectA, ports.KeyScopeConsent), blob},
		{"flipped ciphertext bit", key, aad(subjectA, ports.KeyScopeDefault), flip(blob, len(blob)-1)},
		{"flipped nonce bit", key, aad(subjectA, ports.KeyScopeDefault), flip(blob, 3)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := openWithKey(tc.key, tc.ad, tc.blob); err == nil {
				t.Fatal("open succeeded, want failure")
			}
		})
	}
}

func TestOpenRejectsMalformed(t *testing.T) {
	key := testKey(t)
	ad := aad("11111111-1111-4111-8111-111111111111", ports.KeyScopeDefault)
	blob, err := sealWithKey(key, ad, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := openWithKey(key, ad, blob[:len(blob)-1-gcmTagSize]); !errors.Is(err, ErrMalformed) {
		t.Fatalf("truncated: err = %v, want ErrMalformed", err)
	}
	bad := bytes.Clone(blob)
	bad[0] = 0x02
	if _, err := openWithKey(key, ad, bad); !errors.Is(err, ErrMalformed) {
		t.Fatalf("bad version: err = %v, want ErrMalformed", err)
	}
	if _, err := openWithKey(key, ad, nil); !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty: err = %v, want ErrMalformed", err)
	}
}

func TestWrapAADDiffersFromDataAAD(t *testing.T) {
	const subject = "11111111-1111-4111-8111-111111111111"
	if bytes.Equal(aad(subject, ports.KeyScopeDefault), wrapAAD(subject, ports.KeyScopeDefault)) {
		t.Fatal("dek wrapping and data encryption share an AAD")
	}
}

func TestNewRejectsBadMasterKey(t *testing.T) {
	k := New(nil, make([]byte, KeySize))
	if k.err == nil {
		t.Fatal("nil pool accepted")
	}
	for _, n := range []int{0, 16, 31, 33} {
		k := New(nil, make([]byte, n))
		if k.err == nil {
			t.Fatalf("master key of %d bytes accepted", n)
		}
	}
}

func TestValidScope(t *testing.T) {
	if err := ValidScope(ports.KeyScopeDefault); err != nil {
		t.Fatal(err)
	}
	if err := ValidScope(ports.KeyScopeConsent); err != nil {
		t.Fatal(err)
	}
	if err := ValidScope(ports.KeyScope("OTHER")); err == nil {
		t.Fatal("unknown scope accepted")
	}
}

func TestZero(t *testing.T) {
	b := []byte{1, 2, 3}
	zero(b)
	if !bytes.Equal(b, make([]byte, 3)) {
		t.Fatalf("zero left %v", b)
	}
}

func flip(b []byte, i int) []byte {
	out := bytes.Clone(b)
	out[i] ^= 0x01
	return out
}

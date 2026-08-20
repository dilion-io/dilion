// Command genkey mints an ES256 (P-256) signing key for the /auth/v1 surface.
//
// Usage:
//
//	go run ./cmd/genkey                # print a fresh signing key set
//	go run ./cmd/genkey -kid my-key-1  # pin the key id
//	go run ./cmd/genkey -verify-only   # mint a key_ops ["verify"] key (rotation step 1)
//
// The first block is the PRIVATE key set: paste it into
//
//	DILION_AUTH_JWT_KEYS='[...]'      (or the upstream GOTRUE_JWT_KEYS)
//
// The second block is the PUBLIC JWKS the server will publish at
// /auth/v1/.well-known/jwks.json — printed for eyeballing only; the server
// derives it from the private set.
//
// To rotate, append the new key with key_ops ["verify"], deploy, then flip
// key_ops to ["sign"] on the new key and ["verify"] on the old one and deploy
// again (see auth.TokenService's rotation runbook).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
)

func main() {
	kid := flag.String("kid", "", "key id (default: 16 random hex characters)")
	verifyOnly := flag.Bool("verify-only", false, `mint the key with key_ops ["verify"] instead of ["sign"]`)
	flag.Parse()

	if *kid == "" {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			fail(err)
		}
		*kid = hex.EncodeToString(b[:])
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fail(err)
	}

	ops := []string{"sign"}
	if *verifyOnly {
		ops = []string{"verify"}
	}

	private := map[string]any{
		"kty":     "EC",
		"kid":     *kid,
		"crv":     "P-256",
		"alg":     "ES256",
		"use":     "sig",
		"key_ops": ops,
		"x":       b64(key.X),
		"y":       b64(key.Y),
		"d":       b64(key.D),
	}
	public := map[string]any{
		"kty":     "EC",
		"kid":     *kid,
		"crv":     "P-256",
		"alg":     "ES256",
		"use":     "sig",
		"key_ops": []string{"verify"},
		"x":       b64(key.X),
		"y":       b64(key.Y),
	}

	fmt.Println("# DILION_AUTH_JWT_KEYS (private — keep it secret):")
	fmt.Println(compact([]any{private}))
	fmt.Println()
	fmt.Println("# published at /auth/v1/.well-known/jwks.json:")
	fmt.Println(indent(map[string]any{"keys": []any{public}}))
}

// b64 renders an EC scalar as the fixed-width 32 byte base64url string
// RFC 7518 §6.2.1 requires.
func b64(v *big.Int) string {
	b := make([]byte, 32)
	v.FillBytes(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func compact(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		fail(err)
	}
	return string(b)
}

func indent(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fail(err)
	}
	return string(b)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "genkey:", err)
	os.Exit(1)
}

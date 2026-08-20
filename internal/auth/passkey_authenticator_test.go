package auth

// A software WebAuthn authenticator for the passkey tests.
//
// It generates real EC P-256 key pairs and builds attestation objects
// ("none" format) and assertions that the go-webauthn library verifies for
// real: the signatures below are checked against the stored COSE public key,
// the RP ID hash against the configured RPID, and the client data against the
// server's challenge and RPOrigins. Nothing about the crypto is stubbed, so a
// test that passes here exercises the same code path a browser would.
//
// Modelled on upstream's internal/api/passkey_virtual_authenticator_test.go.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol"
)

// virtualAuthenticator is one simulated authenticator (one "device").
type virtualAuthenticator struct {
	// rpID is the RP ID this device hashes into its authenticator data. A
	// mismatch with the server's RPID is what the wrong-RP-ID test exercises.
	rpID string
	// origin is written into clientDataJSON. A mismatch with the server's
	// RPOrigins is what the wrong-origin test exercises.
	origin string
	// aaguid is the 16-byte authenticator model id; nil means the all-zero
	// AAGUID ("I decline to identify my model").
	aaguid []byte

	creds []*virtualCredential
}

type virtualCredential struct {
	id         []byte
	privKey    *ecdsa.PrivateKey
	userHandle []byte
}

func newVirtualAuthenticator(rpID, origin string) *virtualAuthenticator {
	return &virtualAuthenticator{rpID: rpID, origin: origin}
}

// withAAGUID returns a device that reports the given AAGUID (canonical UUID
// string), so the aaguid column and the derived friendly name can be asserted.
func (va *virtualAuthenticator) withAAGUID(t *testing.T, s string) *virtualAuthenticator {
	t.Helper()
	raw, err := uuidBytes(s)
	if err != nil {
		t.Fatalf("bad aaguid %q: %v", s, err)
	}
	va.aaguid = raw
	return va
}

// createCredential answers a registration ceremony: it mints a key pair and
// returns the JSON body the browser would put in `credential`.
func (va *virtualAuthenticator) createCredential(t *testing.T, options *protocol.PublicKeyCredentialCreationOptions) json.RawMessage {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatalf("random credential id: %v", err)
	}

	clientDataJSON, err := json.Marshal(map[string]string{
		"type":      "webauthn.create",
		"challenge": base64.RawURLEncoding.EncodeToString(options.Challenge),
		"origin":    va.origin,
	})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}

	authData := va.attestedAuthData(t, credentialID, privKey)
	attestationObject, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		t.Fatalf("marshal attestation object: %v", err)
	}

	resp := protocol.CredentialCreationResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   base64.RawURLEncoding.EncodeToString(credentialID),
				Type: "public-key",
			},
			RawID: credentialID,
		},
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: clientDataJSON},
			AttestationObject:     attestationObject,
			Transports:            []string{"internal"},
		},
	}
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal creation response: %v", err)
	}

	va.creds = append(va.creds, &virtualCredential{
		id:         credentialID,
		privKey:    privKey,
		userHandle: userHandleOf(t, options),
	})
	return body
}

// getAssertion answers a login ceremony with the device's first credential —
// which is what a discoverable ("usernameless") flow does: the AUTHENTICATOR
// picks, the server never named one.
//
// signCount is the counter the device reports; the caller sets it explicitly so
// a test can drive the replay/clone path (a counter that does not advance).
func (va *virtualAuthenticator) getAssertion(t *testing.T, options *protocol.PublicKeyCredentialRequestOptions, signCount uint32) json.RawMessage {
	t.Helper()
	return va.getAssertionWith(t, va.credential(t, 0), options, signCount)
}

func (va *virtualAuthenticator) credential(t *testing.T, i int) *virtualCredential {
	t.Helper()
	if i >= len(va.creds) {
		t.Fatalf("virtual authenticator holds %d credentials, wanted #%d", len(va.creds), i)
	}
	return va.creds[i]
}

func (va *virtualAuthenticator) getAssertionWith(t *testing.T, cred *virtualCredential, options *protocol.PublicKeyCredentialRequestOptions, signCount uint32) json.RawMessage {
	t.Helper()

	clientDataJSON, err := json.Marshal(map[string]string{
		"type":      "webauthn.get",
		"challenge": base64.RawURLEncoding.EncodeToString(options.Challenge),
		"origin":    va.origin,
	})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}

	// rpIdHash (32) || flags (1) || signCount (4). No attested credential data
	// in an assertion. Flags: UP (bit 0) | UV (bit 2) = 0x05, and BE/BS stay 0
	// so they match what registration recorded — the library rejects a flag
	// that changes between ceremonies.
	rpIDHash := sha256.Sum256([]byte(va.rpID))
	authData := make([]byte, 0, 37)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, 0x05)
	authData = binary.BigEndian.AppendUint32(authData, signCount)

	clientDataHash := sha256.Sum256(clientDataJSON)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, cred.privKey, digest[:])
	if err != nil {
		t.Fatalf("sign assertion: %v", err)
	}

	resp := protocol.CredentialAssertionResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   base64.RawURLEncoding.EncodeToString(cred.id),
				Type: "public-key",
			},
			RawID: cred.id,
		},
		AssertionResponse: protocol.AuthenticatorAssertionResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: clientDataJSON},
			AuthenticatorData:     authData,
			Signature:             sig,
			UserHandle:            cred.userHandle,
		},
	}
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal assertion response: %v", err)
	}
	return body
}

// attestedAuthData builds authenticator data WITH attested credential data:
// rpIdHash (32) || flags (1) || signCount (4) || aaguid (16) || credIdLen (2) ||
// credId || COSE public key.
func (va *virtualAuthenticator) attestedAuthData(t *testing.T, credentialID []byte, privKey *ecdsa.PrivateKey) []byte {
	t.Helper()

	rpIDHash := sha256.Sum256([]byte(va.rpID))
	coseKey := marshalCOSEPublicKey(t, privKey)

	aaguid := va.aaguid
	if aaguid == nil {
		aaguid = make([]byte, 16)
	}

	credIDLen := make([]byte, 2)
	binary.BigEndian.PutUint16(credIDLen, uint16(len(credentialID)))

	out := make([]byte, 0, 64+len(credentialID)+len(coseKey))
	out = append(out, rpIDHash[:]...)
	out = append(out, 0x41) // UP (bit 0) | AT (bit 6)
	out = append(out, 0, 0, 0, 0)
	out = append(out, aaguid...)
	out = append(out, credIDLen...)
	out = append(out, credentialID...)
	out = append(out, coseKey...)
	return out
}

// marshalCOSEPublicKey encodes an ECDSA P-256 public key as a COSE_Key
// (RFC 8152): kty=EC2, alg=ES256, crv=P-256, plus the raw coordinates.
func marshalCOSEPublicKey(t *testing.T, privKey *ecdsa.PrivateKey) []byte {
	t.Helper()

	ecdhKey, err := privKey.PublicKey.ECDH()
	if err != nil {
		t.Fatalf("to ecdh key: %v", err)
	}
	uncompressed := ecdhKey.Bytes() // 0x04 || X (32) || Y (32)

	out, err := cbor.Marshal(map[int]any{
		1:  2,                   // kty: EC2
		3:  -7,                  // alg: ES256
		-1: 1,                   // crv: P-256
		-2: uncompressed[1:33],  // x
		-3: uncompressed[33:65], // y
	})
	if err != nil {
		t.Fatalf("marshal cose key: %v", err)
	}
	return out
}

// userHandleOf extracts the user handle from registration options. After the
// options have travelled over HTTP, User.ID is a base64url STRING; used
// in-process it is still URLEncodedBase64/[]byte.
func userHandleOf(t *testing.T, options *protocol.PublicKeyCredentialCreationOptions) []byte {
	t.Helper()
	switch v := options.User.ID.(type) {
	case protocol.URLEncodedBase64:
		return []byte(v)
	case []byte:
		return v
	case string:
		decoded, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			t.Fatalf("decode user handle %q: %v", v, err)
		}
		return decoded
	default:
		t.Fatalf("unexpected user handle type %T", options.User.ID)
		return nil
	}
}

// recreateCredential re-attests an EXISTING credential id and key pair against a
// new challenge — a misbehaving authenticator that ignores the server's
// excludeCredentials list. The server must refuse it on the unique index over
// webauthn_credentials.credential_id.
func (va *virtualAuthenticator) recreateCredential(t *testing.T, cred *virtualCredential, options *protocol.PublicKeyCredentialCreationOptions) json.RawMessage {
	t.Helper()

	clientDataJSON, err := json.Marshal(map[string]string{
		"type":      "webauthn.create",
		"challenge": base64.RawURLEncoding.EncodeToString(options.Challenge),
		"origin":    va.origin,
	})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}

	authData := va.attestedAuthData(t, cred.id, cred.privKey)
	attestationObject, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		t.Fatalf("marshal attestation object: %v", err)
	}

	resp := protocol.CredentialCreationResponse{
		PublicKeyCredential: protocol.PublicKeyCredential{
			Credential: protocol.Credential{
				ID:   base64.RawURLEncoding.EncodeToString(cred.id),
				Type: "public-key",
			},
			RawID: cred.id,
		},
		AttestationResponse: protocol.AuthenticatorAttestationResponse{
			AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: clientDataJSON},
			AttestationObject:     attestationObject,
			Transports:            []string{"internal"},
		},
	}
	body, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal creation response: %v", err)
	}
	return body
}

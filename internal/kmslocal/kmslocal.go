// Package kmslocal is Dilion's default ports.KMS: AES-256-GCM envelope
// encryption with per-(subject, scope) data keys stored in
// dilion_pii.subject_keys, wrapped by a master key held in process memory.
//
// It is the batteries-included default (project.md §2.4/§2.7). Deployments with
// a real key manager inject their own ports.KMS (AWS KMS, Vault, HSM) instead;
// the master key never leaves this process here, so its protection is only as
// good as the host.
//
// Crypto-shredding (DestroyDEK) overwrites the wrapped DEK with random bytes
// and stamps shredded_at, after which Decrypt fails permanently. Per §2.10 this
// is a *supporting* control: ciphertext in an old backup taken before the shred
// still contains the old wrapped DEK, so restore-time erasure replay remains the
// primary guarantee.
package kmslocal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/ports"
)

const (
	// Version is the format byte prefixed to every ciphertext this package
	// produces: 0x01 || nonce || AES-256-GCM(ciphertext||tag).
	Version byte = 0x01

	// KeySize is the required master key (KEK) and generated DEK size.
	KeySize = 32
)

// Sentinel errors. Callers (erasure pipeline, PII service) branch on these.
var (
	// ErrShredded is returned when the subject key has been destroyed. It is
	// terminal: the plaintext is unrecoverable by design.
	ErrShredded = errors.New("kmslocal: subject key destroyed (crypto-shredded)")
	// ErrNoKey is returned when decrypting for a subject/scope that never had a key.
	ErrNoKey = errors.New("kmslocal: no key for subject/scope")
	// ErrMalformed is returned for ciphertext that is truncated or has an
	// unknown version byte.
	ErrMalformed = errors.New("kmslocal: malformed ciphertext")
	// ErrBadMasterKey is returned by every operation when New was given a key
	// that is not KeySize bytes.
	ErrBadMasterKey = errors.New("kmslocal: master key must be 32 bytes")
)

// KMS implements ports.KMS.
type KMS struct {
	pool *pgxpool.Pool
	kek  cipher.AEAD
	err  error // deferred construction error (New has no error return)
}

var _ ports.KMS = (*KMS)(nil)

// New returns a KMS wrapping subject DEKs with masterKey (exactly 32 bytes).
// A bad key is reported from every operation rather than panicking, so an
// embedder's misconfiguration surfaces as a request error, not a crash.
//
// DEKs are intentionally not cached in memory: every operation re-reads
// dilion_pii.subject_keys so a shred performed by another process takes effect
// immediately.
func New(pool *pgxpool.Pool, masterKey []byte) *KMS {
	k := &KMS{pool: pool}
	if pool == nil {
		k.err = errors.New("kmslocal: nil pool")
		return k
	}
	if len(masterKey) != KeySize {
		k.err = ErrBadMasterKey
		return k
	}
	aead, err := newAEAD(masterKey)
	if err != nil {
		k.err = err
		return k
	}
	k.kek = aead
	return k
}

// ---- ports.KMS ----

func (k *KMS) Encrypt(ctx context.Context, subjectID string, scope ports.KeyScope, plaintext []byte) ([]byte, error) {
	dek, err := k.dek(ctx, subjectID, scope, true)
	if err != nil {
		return nil, err
	}
	defer zero(dek)
	return sealWithKey(dek, aad(subjectID, scope), plaintext)
}

func (k *KMS) Decrypt(ctx context.Context, subjectID string, scope ports.KeyScope, ciphertext []byte) ([]byte, error) {
	dek, err := k.dek(ctx, subjectID, scope, false)
	if err != nil {
		return nil, err
	}
	defer zero(dek)
	return openWithKey(dek, aad(subjectID, scope), ciphertext)
}

// DestroyDEK crypto-shreds the subject key: shredded_at is stamped and the
// wrapped DEK is overwritten with random bytes so it cannot be unwrapped again.
// It is idempotent, and records a tombstone even when no key existed yet so a
// later Encrypt cannot silently mint a fresh key for an erased subject.
func (k *KMS) DestroyDEK(ctx context.Context, subjectID string, scope ports.KeyScope) error {
	uid, err := k.subject(subjectID, scope)
	if err != nil {
		return err
	}
	junk := make([]byte, KeySize+Version1Overhead)
	if _, err := rand.Read(junk); err != nil {
		return fmt.Errorf("kmslocal: rand: %w", err)
	}
	const q = `insert into dilion_pii.subject_keys (user_id, scope, wrapped_dek, shredded_at)
	           values ($1, $2, $3, now())
	           on conflict (user_id, scope) do update
	             set wrapped_dek = excluded.wrapped_dek,
	                 shredded_at = coalesce(dilion_pii.subject_keys.shredded_at, now())`
	if _, err := k.pool.Exec(ctx, q, uid, string(scope), junk); err != nil {
		return fmt.Errorf("kmslocal: destroy dek: %w", err)
	}
	return nil
}

// ---- key material ----

// Version1Overhead is the byte overhead of the v1 format: version byte + GCM
// nonce + GCM tag.
const Version1Overhead = 1 + nonceSize + gcmTagSize

const (
	nonceSize  = 12
	gcmTagSize = 16
)

// dek loads and unwraps the subject DEK, optionally creating it. The caller
// must zero the returned slice.
func (k *KMS) dek(ctx context.Context, subjectID string, scope ports.KeyScope, create bool) ([]byte, error) {
	uid, err := k.subject(subjectID, scope)
	if err != nil {
		return nil, err
	}
	wrapped, shredded, err := k.load(ctx, uid, scope)
	switch {
	case err != nil && !errors.Is(err, pgx.ErrNoRows):
		return nil, err
	case err == nil && shredded:
		return nil, ErrShredded
	case err == nil:
		return k.unwrap(subjectID, scope, wrapped)
	case !create:
		return nil, ErrNoKey
	}

	// No row yet: mint one. A concurrent minter wins the ON CONFLICT race, in
	// which case we re-read and use theirs.
	fresh := make([]byte, KeySize)
	if _, err := rand.Read(fresh); err != nil {
		return nil, fmt.Errorf("kmslocal: rand: %w", err)
	}
	defer zero(fresh)
	newWrapped, err := seal(k.kek, wrapAAD(subjectID, scope), fresh)
	if err != nil {
		return nil, err
	}
	const ins = `insert into dilion_pii.subject_keys (user_id, scope, wrapped_dek)
	             values ($1, $2, $3)
	             on conflict (user_id, scope) do nothing`
	tag, err := k.pool.Exec(ctx, ins, uid, string(scope), newWrapped)
	if err != nil {
		return nil, fmt.Errorf("kmslocal: create dek: %w", err)
	}
	if tag.RowsAffected() == 1 {
		out := make([]byte, KeySize)
		copy(out, fresh)
		return out, nil
	}
	wrapped, shredded, err = k.load(ctx, uid, scope)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNoKey
		}
		return nil, err
	}
	if shredded {
		return nil, ErrShredded
	}
	return k.unwrap(subjectID, scope, wrapped)
}

func (k *KMS) load(ctx context.Context, uid pgtype.UUID, scope ports.KeyScope) (wrapped []byte, shredded bool, err error) {
	const q = `select wrapped_dek, shredded_at is not null
	           from dilion_pii.subject_keys where user_id = $1 and scope = $2`
	if err := k.pool.QueryRow(ctx, q, uid, string(scope)).Scan(&wrapped, &shredded); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, false, err
		}
		return nil, false, fmt.Errorf("kmslocal: load subject key: %w", err)
	}
	return wrapped, shredded, nil
}

func (k *KMS) unwrap(subjectID string, scope ports.KeyScope, wrapped []byte) ([]byte, error) {
	dek, err := open(k.kek, wrapAAD(subjectID, scope), wrapped)
	if err != nil {
		// A shredded row holds random bytes, which also lands here if the
		// shredded_at stamp was lost; treat unwrap failure as unrecoverable.
		return nil, fmt.Errorf("kmslocal: unwrap dek: %w", err)
	}
	if len(dek) != KeySize {
		zero(dek)
		return nil, ErrMalformed
	}
	return dek, nil
}

// subject validates construction state, the scope and the subject UUID.
func (k *KMS) subject(subjectID string, scope ports.KeyScope) (pgtype.UUID, error) {
	var out pgtype.UUID
	if k.err != nil {
		return out, k.err
	}
	if err := ValidScope(scope); err != nil {
		return out, err
	}
	if subjectID == "" {
		return out, errors.New("kmslocal: empty subject id")
	}
	return pgtype.UUID{Bytes: SubjectUUID(subjectID), Valid: true}, nil
}

// subjectNamespace derives storage UUIDs for non-UUID subject identifiers.
var subjectNamespace = uuid.MustParse("6b1a0e2c-9a1f-4c1e-9a3d-1f0a6d7c5b21")

// SubjectUUID maps a ports.KMS subject id onto the uuid primary key of
// dilion_pii.subject_keys. Data subjects are canonical user UUIDs and map to
// themselves; non-UUID subjects (platform pseudo-subjects such as "system",
// which holds webhook secrets) are mapped deterministically with UUIDv5 so they
// can share the table without widening the column.
func SubjectUUID(subjectID string) uuid.UUID {
	if u, err := uuid.Parse(subjectID); err == nil {
		return u
	}
	return uuid.NewSHA1(subjectNamespace, []byte(subjectID))
}

// ValidScope rejects scopes outside the DB check constraint.
func ValidScope(s ports.KeyScope) error {
	switch s {
	case ports.KeyScopeDefault, ports.KeyScopeConsent:
		return nil
	default:
		return fmt.Errorf("kmslocal: unknown key scope %q", string(s))
	}
}

// ---- pure crypto helpers (unit-testable without a database) ----

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("kmslocal: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("kmslocal: gcm: %w", err)
	}
	return aead, nil
}

// aad binds a ciphertext to its subject, scope and format version so a blob
// cannot be replayed under a different user or scope.
func aad(subjectID string, scope ports.KeyScope) []byte {
	b := make([]byte, 0, len(subjectID)+len(scope)+8)
	b = append(b, Version)
	b = append(b, "dilion:pii:"...)
	b = append(b, subjectID...)
	b = append(b, 0x1f)
	b = append(b, scope...)
	return b
}

// wrapAAD is the AAD used for the wrapped DEK itself.
func wrapAAD(subjectID string, scope ports.KeyScope) []byte {
	b := make([]byte, 0, len(subjectID)+len(scope)+8)
	b = append(b, Version)
	b = append(b, "dilion:dek:"...)
	b = append(b, subjectID...)
	b = append(b, 0x1f)
	b = append(b, scope...)
	return b
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// seal produces Version || nonce || ciphertext||tag.
func seal(aead cipher.AEAD, additional, plaintext []byte) ([]byte, error) {
	out := make([]byte, 1+nonceSize, 1+nonceSize+len(plaintext)+gcmTagSize)
	out[0] = Version
	nonce := out[1 : 1+nonceSize]
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("kmslocal: rand: %w", err)
	}
	return aead.Seal(out, nonce, plaintext, additional), nil
}

func open(aead cipher.AEAD, additional, blob []byte) ([]byte, error) {
	if len(blob) < 1+nonceSize+gcmTagSize {
		return nil, ErrMalformed
	}
	if blob[0] != Version {
		return nil, fmt.Errorf("%w: version 0x%02x", ErrMalformed, blob[0])
	}
	pt, err := aead.Open(nil, blob[1:1+nonceSize], blob[1+nonceSize:], additional)
	if err != nil {
		return nil, fmt.Errorf("kmslocal: decrypt: %w", err)
	}
	return pt, nil
}

// sealWithKey / openWithKey build a one-shot AEAD from raw key bytes.
func sealWithKey(key, additional, plaintext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return seal(aead, additional, plaintext)
}

func openWithKey(key, additional, blob []byte) ([]byte, error) {
	// Check the framing before spending a key schedule on it.
	if len(blob) < 1+nonceSize+gcmTagSize {
		return nil, ErrMalformed
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return open(aead, additional, blob)
}

package iam

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/ports"
)

// TokenPrefix is the scoped API key prefix (docs/api-conventions.md).
const TokenPrefix = "dk_"

// tokenRandomLen is the number of url-safe characters after the prefix.
// 36 random bytes base64url-encode to exactly 48 characters.
const tokenRandomLen = 48

// NewToken mints a `dk_<48 url-safe random>` token. The plaintext token is
// returned to the caller exactly once; only SHA-256(token) is persisted.
func NewToken() string {
	var b [36]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("iam: rand failed: %v", err))
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(b[:])
}

// HashToken returns the stored representation of a token.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// ValidTokenFormat reports whether a string looks like a Dilion API key.
func ValidTokenFormat(token string) bool {
	rest, ok := strings.CutPrefix(token, TokenPrefix)
	if !ok || len(rest) != tokenRandomLen {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(rest)
	return err == nil
}

// CreateKey issues a scoped API key (§2.11 "Machine key"). The returned token
// is the only time the plaintext is available.
func (s *Service) CreateKey(ctx context.Context, name string, scopes []string, expires *time.Time) (string, APIKey, error) {
	return s.createKey(ctx, name, scopes, expires, "", "")
}

// CreateKeyBy is CreateKey with the granting actor recorded.
// createdByType is the creator's actor type: a key issued by a user
// (ActorTypeUser) never holds more than that user currently does.
func (s *Service) CreateKeyBy(ctx context.Context, name string, scopes []string, expires *time.Time, createdBy, createdByType string) (string, APIKey, error) {
	return s.createKey(ctx, name, scopes, expires, createdBy, createdByType)
}

func (s *Service) createKey(ctx context.Context, name string, scopes []string, expires *time.Time, createdBy, createdByType string) (string, APIKey, error) {
	pool, err := s.db(ctx)
	if err != nil {
		return "", APIKey{}, err
	}
	sc := dedupe(scopes)
	if len(sc) == 0 {
		return "", APIKey{}, fmt.Errorf("%w: at least one scope is required (least privilege)", ErrInvalid)
	}
	now := s.clock()
	if expires != nil && !expires.After(now) {
		return "", APIKey{}, fmt.Errorf("%w: expires_at must be in the future", ErrInvalid)
	}
	// Scopes must be registered permissions — an API key can never carry a
	// permission that is not registered.
	var known []string
	if err := pool.QueryRow(ctx, `
		select coalesce(array_agg(name), '{}')
		from dilion_authz.permissions
		where name = any($1)`, sc).Scan(&known); err != nil {
		return "", APIKey{}, fmt.Errorf("iam: create key: %w", err)
	}
	for _, p := range sc {
		if !slices.Contains(known, p) {
			return "", APIKey{}, fmt.Errorf("%w: unknown permission %q in scopes", ErrInvalid, p)
		}
		if slices.Contains(OwnerOnlyPermissions, p) {
			return "", APIKey{}, fmt.Errorf("%w: permission %q belongs to the owner role only", ErrInvalid, p)
		}
	}

	token := NewToken()
	k := APIKey{
		ID:        httpapi.NewID("key"),
		Scopes:    sc,
		ExpiresAt: expires,
	}
	if name != "" {
		k.Name = &name
	}
	if createdBy != "" {
		k.CreatedBy = &createdBy
	}
	if err := pool.QueryRow(ctx, `
		insert into dilion_authz.api_keys
			(id, name, key_hash, scopes, created_at, created_by, expires_at, created_by_type)
		values ($1,$2,$3,$4,$5,$6,$7,nullif($8,''))
		returning created_at`,
		k.ID, k.Name, HashToken(token), sc, now, k.CreatedBy, expires, createdByType).Scan(&k.CreatedAt); err != nil {
		return "", APIKey{}, fmt.Errorf("iam: create key: %w", err)
	}
	return token, k, nil
}

// VerifyKey authenticates a plaintext API key token. It returns the actor and
// the key's scopes, and bumps last_used_at. Unknown / revoked / expired keys
// all fail with ErrUnauthenticated (no oracle about which).
func (s *Service) VerifyKey(ctx context.Context, token string) (*ports.Actor, []string, error) {
	pool, err := s.db(ctx)
	if err != nil {
		return nil, nil, err
	}
	if !ValidTokenFormat(token) {
		return nil, nil, ErrUnauthenticated
	}
	hash := HashToken(token)

	var (
		id        string
		scopes    []string
		storedHsh []byte
		expiresAt *time.Time
		revokedAt *time.Time
	)
	err = pool.QueryRow(ctx, `
		select id, scopes, key_hash, expires_at, revoked_at
		from dilion_authz.api_keys where key_hash = $1`, hash).
		Scan(&id, &scopes, &storedHsh, &expiresAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrUnauthenticated
	}
	if err != nil {
		return nil, nil, fmt.Errorf("iam: verify key: %w", err)
	}
	if subtle.ConstantTimeCompare(hash, storedHsh) != 1 {
		return nil, nil, ErrUnauthenticated
	}
	now := s.clock()
	if revokedAt != nil || (expiresAt != nil && !expiresAt.After(now)) {
		return nil, nil, ErrUnauthenticated
	}

	if _, err := pool.Exec(ctx, `
		update dilion_authz.api_keys set last_used_at = $2 where id = $1`, id, now); err != nil {
		return nil, nil, fmt.Errorf("iam: verify key: %w", err)
	}
	return &ports.Actor{ID: id, Type: ActorTypeAPIKey}, scopes, nil
}

// RevokeKey revokes a key. Idempotency is intentionally not offered: revoking
// an already revoked key is a conflict so operators notice stale automation.
func (s *Service) RevokeKey(ctx context.Context, keyID, revokedBy string) (APIKey, error) {
	pool, err := s.db(ctx)
	if err != nil {
		return APIKey{}, err
	}
	var by *string
	if revokedBy != "" {
		by = &revokedBy
	}
	var k APIKey
	err = pool.QueryRow(ctx, `
		update dilion_authz.api_keys set revoked_at = $2, revoked_by = $3
		where id = $1 and revoked_at is null
		returning id, name, scopes, created_at, created_by, expires_at, revoked_at, last_used_at`,
		keyID, s.clock(), by).
		Scan(&k.ID, &k.Name, &k.Scopes, &k.CreatedAt, &k.CreatedBy, &k.ExpiresAt, &k.RevokedAt, &k.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if err2 := pool.QueryRow(ctx, `select exists(select 1 from dilion_authz.api_keys
		                                             where id = $1)`,
			keyID).Scan(&exists); err2 != nil {
			return APIKey{}, fmt.Errorf("iam: revoke key: %w", err2)
		}
		if exists {
			return APIKey{}, fmt.Errorf("%w: key %q is already revoked", ErrConflict, keyID)
		}
		return APIKey{}, ErrNotFound
	}
	if err != nil {
		return APIKey{}, fmt.Errorf("iam: revoke key: %w", err)
	}
	return k, nil
}

func (s *Service) ListKeys(ctx context.Context, p httpapi.ListParams) (httpapi.Page[APIKey], error) {
	var page httpapi.Page[APIKey]
	pool, err := s.db(ctx)
	if err != nil {
		return page, err
	}
	p = p.Norm()
	after, err := decodeCursor(p.Cursor)
	if err != nil {
		return page, err
	}
	rows, err := pool.Query(ctx, `
		select id, name, scopes, created_at, created_by, expires_at, revoked_at, last_used_at
		from dilion_authz.api_keys
		where $1 = '' or id > $1
		order by id asc limit $2`, after, p.Limit+1)
	if err != nil {
		return page, fmt.Errorf("iam: list keys: %w", err)
	}
	defer rows.Close()
	items := []APIKey{}
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.Name, &k.Scopes, &k.CreatedAt,
			&k.CreatedBy, &k.ExpiresAt, &k.RevokedAt, &k.LastUsedAt); err != nil {
			return page, fmt.Errorf("iam: list keys: %w", err)
		}
		items = append(items, k)
	}
	if err := rows.Err(); err != nil {
		return page, fmt.Errorf("iam: list keys: %w", err)
	}
	return paginate(items, p.Limit, func(k APIKey) string { return k.ID }), nil
}

// GetKey reads one key, active or not.
func (s *Service) GetKey(ctx context.Context, keyID string) (APIKey, error) {
	pool, err := s.db(ctx)
	if err != nil {
		return APIKey{}, err
	}
	var k APIKey
	err = pool.QueryRow(ctx, `
		select id, name, scopes, created_at, created_by, expires_at, revoked_at, last_used_at
		from dilion_authz.api_keys where id = $1`, keyID).
		Scan(&k.ID, &k.Name, &k.Scopes, &k.CreatedAt, &k.CreatedBy, &k.ExpiresAt, &k.RevokedAt, &k.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return APIKey{}, ErrNotFound
	}
	if err != nil {
		return APIKey{}, fmt.Errorf("iam: get key: %w", err)
	}
	return k, nil
}

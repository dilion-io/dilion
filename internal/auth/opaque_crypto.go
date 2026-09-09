package auth

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bytemare/opaque"
	"github.com/dilion-io/dilion/ports"
)

const opaqueSuite = "ristretto255-sha512-argon2id-v1"

// LoadConfig enables OpaqueConfig by default when a master key is configured,
// unless OPAQUE_ENABLED explicitly disables it. Programmatic configs use Enabled
// as supplied. The 32-byte base64url master key must be stable,
// external to PostgreSQL, and identical on every replica. Never log it.
type OpaqueConfig struct {
	Enabled   bool   `json:"enabled"`
	MasterKey string `json:"-"`
}

func (c OpaqueConfig) validate() error {
	if !c.Enabled {
		return nil
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(c.MasterKey)
	defer clear(key)
	if err != nil || len(key) != 32 {
		return fmt.Errorf("auth: OPAQUE_MASTER_KEY must be 32 random bytes encoded as unpadded base64url")
	}
	return nil
}

func opaqueScope(ctx context.Context) string { return ports.InstanceFromContext(ctx) }

func (a *api) opaqueMAC(ctx context.Context, purpose string, input []byte) []byte {
	key, _ := base64.RawURLEncoding.DecodeString(a.cfg.Opaque.MasterKey)
	defer clear(key)
	mac := hmac.New(sha512.New, key)
	// JSON framing avoids delimiter ambiguity across tenant IDs and purposes.
	prefix, _ := json.Marshal([]string{"dilion-opaque-v1", opaqueScope(ctx), purpose})
	mac.Write(prefix)
	mac.Write(input)
	return mac.Sum(nil)
}

func (a *api) opaqueAEAD(ctx context.Context) cipher.AEAD {
	key := a.opaqueMAC(ctx, "storage", nil)
	defer clear(key)
	block, _ := aes.NewCipher(key[:32])
	gcm, _ := cipher.NewGCM(block)
	return gcm
}

func (a *api) sealOpaque(ctx context.Context, label string, plain []byte) []byte {
	gcm := a.opaqueAEAD(ctx)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	return gcm.Seal(nonce, nonce, plain, []byte(label))
}

func (a *api) openOpaque(ctx context.Context, label string, sealed []byte) ([]byte, error) {
	gcm := a.opaqueAEAD(ctx)
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("invalid OPAQUE storage")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], []byte(label))
}

// A separate random setup is persisted per instance. An ON CONFLICT insert
// followed by a read makes concurrent first boots agree without local caches.
func (a *api) opaqueServer(ctx context.Context, q querier) (*opaque.Server, string, error) {
	scope := opaqueScope(ctx)
	conf := opaque.DefaultConfiguration()
	var sealed []byte
	err := q.QueryRow(ctx, `select material from auth.opaque_setup where scope=$1`, scope).Scan(&sealed)
	if isNoRows(err) {
		sk, pk := conf.KeyGen()
		material := &opaque.ServerKeyMaterial{PrivateKey: sk, PublicKeyBytes: pk.Encode(), OPRFGlobalSeed: conf.GenerateOPRFSeed(), Identity: []byte("dilion:" + scope)}
		plain := material.Encode()
		encrypted := a.sealOpaque(ctx, "setup", plain)
		clear(plain)
		material.Flush()
		if _, err = q.Exec(ctx, `insert into auth.opaque_setup(scope,material) values($1,$2) on conflict do nothing`, scope, encrypted); err != nil {
			return nil, "", err
		}
		err = q.QueryRow(ctx, `select material from auth.opaque_setup where scope=$1`, scope).Scan(&sealed)
	}
	if err != nil {
		return nil, "", err
	}
	plain, err := a.openOpaque(ctx, "setup", sealed)
	if err != nil {
		return nil, "", err
	}
	defer clear(plain)
	material, err := conf.DecodeServerKeyMaterial(plain)
	if err != nil {
		return nil, "", err
	}
	server, err := conf.Server()
	if err != nil {
		return nil, "", err
	}
	// SetKeyMaterial retains material: do not Flush it while the server uses it.
	if err = server.SetKeyMaterial(material); err != nil {
		return nil, "", err
	}
	return server, string(material.Identity), nil
}

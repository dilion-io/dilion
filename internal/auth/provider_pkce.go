package auth

// PKCE toward the external provider: Dilion as the OAuth CLIENT.
//
// This is the other half from the app-facing PKCE in external.go's flow state
// (code_challenge on GET /authorize, redeemed with grant_type=pkce), which
// protects the app's exchange with Dilion. Here Dilion protects its OWN
// exchange with the provider: GET /authorize mints a verifier, sends its S256
// challenge to the provider, and keeps the verifier server-side; the callback
// sends it with the code. OAuth 2.1 requires this of every client, confidential
// ones included, and a server that follows it — Dilion's own OAuth server is one
// — refuses an authorization request without a challenge.
//
// # Upstream parity
//
// Reproduces github.com/supabase/auth internal/api/external.go
// (GetExternalProviderRedirectURL) and external_oauth.go (oAuthCallback): the
// verifier lives in auth.oauth_client_states, the flow state points at it
// through oauth_client_state_id, and the callback finds-and-deletes the row, so
// a verifier is usable exactly once, and checks its provider and age before
// using it. A stored custom provider uses PKCE when its pkce_enabled column says
// so (the column defaults to true); a provider defined in code always does.
// Built-in providers do not, as in upstream for every wave-III provider.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
)

// pkceProvider is implemented by a provider that can use PKCE toward its IdP.
type pkceProvider interface {
	// requiresPKCE reports whether this provider's flows use PKCE.
	requiresPKCE() bool
	// setPKCEVerifier gives the provider this request's verifier: authCodeURL
	// then sends its challenge, and exchange sends the verifier itself.
	setPKCEVerifier(verifier string)
}

func (p *customRuntimeProvider) requiresPKCE() bool              { return p.pkce }
func (p *customRuntimeProvider) setPKCEVerifier(verifier string) { p.pkceVerifier = verifier }

// providerRequiresPKCE reports whether p uses PKCE toward its IdP.
func providerRequiresPKCE(p externalProvider) (pkceProvider, bool) {
	pp, ok := p.(pkceProvider)
	return pp, ok && pp.requiresPKCE()
}

// newPKCEVerifier mints an RFC 7636 code verifier: 32 random bytes, base64url
// without padding, i.e. 43 characters — what golang.org/x/oauth2's
// GenerateVerifier produces for upstream.
func newPKCEVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceS256Challenge is the RFC 7636 S256 challenge for verifier.
func pkceS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// insertOAuthClientState stores the verifier for one external flow and returns
// the row id the flow state links to.
func insertOAuthClientState(ctx context.Context, q querier, providerType, verifier string, now time.Time) (string, error) {
	id := uuid.NewString()
	_, err := q.Exec(ctx, `
		insert into auth.oauth_client_states (id, provider_type, code_verifier, created_at)
		values ($1::uuid, $2, $3, $4)`, id, providerType, verifier, now)
	if err != nil {
		return "", err
	}
	return id, nil
}

// errOAuthClientStateInvalid covers every way a stored verifier can be
// unusable: missing, already used, for another provider, or expired. The
// callback does not distinguish them to the caller.
var errOAuthClientStateInvalid = errors.New("oauth client state is missing, used, mismatched or expired")

// takeOAuthClientState is upstream's FindAndDeleteOAuthClientStateByID plus its
// two checks. The row is deleted by the same statement that reads it, so a
// second callback for the same flow finds nothing, whether or not the first one
// went on to succeed.
func takeOAuthClientState(ctx context.Context, q querier, id, providerType string, now time.Time, ttl time.Duration) (string, error) {
	var (
		gotProvider string
		verifier    *string
		createdAt   time.Time
	)
	err := q.QueryRow(ctx, `
		delete from auth.oauth_client_states where id = $1::uuid
		returning provider_type, code_verifier, created_at`, id).
		Scan(&gotProvider, &verifier, &createdAt)
	if err != nil {
		if isNoRows(err) {
			return "", errOAuthClientStateInvalid
		}
		return "", err
	}
	switch {
	case gotProvider != providerType:
		return "", fmt.Errorf("%w: stored for %q, used for %q", errOAuthClientStateInvalid, gotProvider, providerType)
	case verifier == nil || *verifier == "":
		return "", errOAuthClientStateInvalid
	case now.After(createdAt.Add(ttl)):
		return "", fmt.Errorf("%w: expired", errOAuthClientStateInvalid)
	}
	return *verifier, nil
}

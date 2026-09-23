package auth

// OAuth 2.1 server clients decided in code (ports.OAuthClientResolver).
//
// # Where the rules come from
//
// Every client lookup on the request path — /oauth/authorize, POST
// /oauth/token, the consent endpoints and the user's grant list — goes through
// oauthClientByID, which asks the resolver first and auth.oauth_clients only
// when the resolver claims nothing. A client the resolver returns is carried as
// an ordinary *oauthClient with `code` set, and the few places that judge a
// client (redirect targets, auth method, secret, consent) consult `code`
// instead of the stored columns. The admin client API is untouched: it manages
// stored clients only and never sees a code-defined one.
//
// # Why a code-defined client still has a row
//
// auth.oauth_authorizations, auth.oauth_consents and auth.sessions all hold a
// foreign key to auth.oauth_clients(id). Dropping those constraints would break
// the schema's upstream compatibility (project.md §2.2), so instead a client
// the resolver claims gets a SHADOW row the first time it authorizes anything:
// same id, no secret, no redirect URIs, and deleted_at already set.
//
// deleted_at is what keeps the shadow inert. Every read of auth.oauth_clients
// filters it out, so the shadow can never be validated as a stored client, is
// invisible to the admin API, and — if the resolver later stops claiming that
// id — leaves behind a client that simply does not exist rather than one that
// accepts anything. The foreign keys do not care about deleted_at, and nothing
// hard-deletes soft-deleted clients, so the sessions that reference it live on.
//
// The insert is `on conflict do nothing`: if a real, stored client already has
// that id, it is left exactly as it is. The resolver still wins for as long as
// it claims the id.

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dilion-io/dilion/ports"
)

// codeClientGrantTypes are the grants a code-defined client may use: all the
// server supports.
var codeClientGrantTypes = GrantTypeAuthorizationCode + "," + GrantTypeRefreshToken

// oauthClientByID resolves a client for the request path. Not found is
// pgx.ErrNoRows, so every caller's isNoRows check keeps working unchanged.
func (a *api) oauthClientByID(ctx context.Context, q querier, id string) (*oauthClient, error) {
	if c, err := a.codeOAuthClient(ctx, id); err != nil || c != nil {
		return c, err
	}
	return findOAuthClientByID(ctx, q, id)
}

// codeOAuthClient asks the resolver for id. (nil, nil) means it does not
// define that client.
func (a *api) codeOAuthClient(ctx context.Context, id string) (*oauthClient, error) {
	if a.oauthClients == nil {
		return nil, nil
	}
	spec, err := a.oauthClients(ctx, ports.InstanceFromContext(ctx), id)
	if err != nil {
		return nil, fmt.Errorf("oauth client resolver: %w", err)
	}
	if spec == nil {
		return nil, nil
	}
	// The resolver answered a question about `id`; an answer about some other
	// client is a bug that must not authenticate anything.
	if spec.ID != id {
		return nil, fmt.Errorf("oauth client resolver: asked for %q, answered for %q", id, spec.ID)
	}
	if _, err := uuid.Parse(spec.ID); err != nil {
		return nil, fmt.Errorf("oauth client resolver: client id %q is not a uuid", spec.ID)
	}

	c := &oauthClient{
		ID:                      spec.ID,
		RegistrationType:        OAuthRegistrationManual,
		ClientType:              OAuthClientTypeConfidential,
		TokenEndpointAuthMethod: TokenEndpointAuthMethodClientSecretBasic,
		GrantTypes:              codeClientGrantTypes,
		ClientName:              nilIfEmpty(spec.Name),
		ClientURI:               nilIfEmpty(spec.URI),
		LogoURI:                 nilIfEmpty(spec.LogoURI),
		code:                    spec,
	}
	if spec.Public {
		c.ClientType = OAuthClientTypePublic
		c.TokenEndpointAuthMethod = TokenEndpointAuthMethodNone
	}
	return c, nil
}

// isFirstParty reports whether c skips the consent step.
func (c *oauthClient) isFirstParty() bool { return c.code != nil && c.code.FirstParty }

// codeRedirectURIAllowed is the redirect check for a code-defined client:
// AllowRedirectURI when set, otherwise an exact match against RedirectURIs —
// the same whole-string rule a stored client gets.
func (c *oauthClient) codeRedirectURIAllowed(uri string) bool {
	if c.code.AllowRedirectURI != nil {
		return c.code.AllowRedirectURI(uri)
	}
	return slices.Contains(c.code.RedirectURIs, uri)
}

// codeAuthMethodAllowed is the token-endpoint auth method check for a
// code-defined client. A confidential one may send its secret either way the
// server accepts; which one is a transport detail, not something the client
// registered.
func (c *oauthClient) codeAuthMethodAllowed(used string) bool {
	if c.IsPublic() {
		return used == TokenEndpointAuthMethodNone
	}
	return used == TokenEndpointAuthMethodClientSecretBasic || used == TokenEndpointAuthMethodClientSecretPost
}

// codeSecretValid checks a confidential code-defined client's secret. Without
// a verifier there is nothing to check against, and the client fails closed.
func (c *oauthClient) codeSecretValid(secret string) bool {
	if c.code.VerifySecret == nil || secret == "" {
		return false
	}
	return c.code.VerifySecret(secret)
}

// ensureOAuthClientRow writes the inert shadow row a code-defined client needs
// before anything can reference it (see the package comment above). It is a
// no-op for a stored client, and for a code-defined one that already has a
// row.
func ensureOAuthClientRow(ctx context.Context, q querier, c *oauthClient, now time.Time) error {
	if c.code == nil {
		return nil
	}
	_, err := q.Exec(ctx, `
		insert into auth.oauth_clients (
			id, client_secret_hash, registration_type, redirect_uris, grant_types,
			client_name, client_uri, logo_uri, client_type, token_endpoint_auth_method,
			created_at, updated_at, deleted_at)
		values ($1::uuid, null, $2::auth.oauth_registration_type, '', $3,
			$4, $5, $6, $7::auth.oauth_client_type, $8,
			$9, $9, $9)
		on conflict (id) do nothing`,
		c.ID, c.RegistrationType, c.GrantTypes,
		truncateRunes(deref(c.ClientName), 1024), truncateRunes(deref(c.ClientURI), 2048), truncateRunes(deref(c.LogoURI), 2048),
		c.ClientType, c.TokenEndpointAuthMethod, now)
	if err != nil {
		return fmt.Errorf("oauth: shadow row for code-defined client %s: %w", c.ID, err)
	}
	return nil
}

// truncateRunes keeps a display value inside the column's length check, so a
// long name from the resolver cannot fail the authorization it is shown on.
// An empty value is stored as NULL.
func truncateRunes(s string, max int) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if r := []rune(s); len(r) > max {
		s = string(r[:max])
	}
	return &s
}

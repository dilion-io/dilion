package auth

// External OIDC providers defined in code (ports.ProviderSource).
//
// A code-defined provider is an ordinary custom OIDC provider that happens not
// to live in auth.custom_oauth_providers: it is mapped onto the same
// customOAuthProvider value and built by the same buildCustomProvider, so
// discovery, id_token verification, userinfo and claim mapping are shared with
// the stored kind rather than reimplemented. Two things only a code-defined
// provider can do:
//
//   - carry an explicit redirect URI (stored providers always derive theirs
//     from the request), and
//   - link by subject (ports.OIDCProvider.LinkBySubject), which lets the
//     provider decide which LOCAL user a sign-in is. That is authority over
//     every account in the instance, so it is deliberately not something an
//     admin API call can switch on for an arbitrary provider row.
//
// Precedence: the source is asked first, before the built-in providers. It is
// the most specific configuration there is — per instance, in the embedder's
// own code — so a code-defined "google" replaces the process-wide one for that
// instance rather than being shadowed by it.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/dilion-io/dilion/ports"
)

// defaultCodeProviderScopes are requested when a code-defined provider names
// none. openid is what makes it an OIDC request at all; email is required to
// complete a sign-in (the callback refuses a profile without one).
var defaultCodeProviderScopes = []string{"openid", "email", "profile"}

// codeProvider asks the source for name. ok is false when the source defines
// no such provider, which is not an error: the caller moves on to the next
// source.
func (a *api) codeProvider(ctx context.Context, name, scopes string) (p externalProvider, ok bool, err error) {
	if a.providers == nil {
		return nil, false, nil
	}
	spec, err := a.providers(ctx, ports.InstanceFromContext(ctx), name)
	if err != nil {
		// The embedder's error may name internal hosts or credentials, and
		// the caller of /authorize is unauthenticated: log it, answer a 500
		// that says nothing about it. A failing source is this server's
		// problem, not a bad request.
		return nil, false, internalServerError("Error resolving provider").withInternal(
			fmt.Errorf("provider source for %q: %w", name, err))
	}
	if spec == nil {
		return nil, false, nil
	}
	p, err = a.buildCodeProvider(ctx, name, spec, scopes)
	if err != nil {
		return nil, false, err
	}
	return p, true, nil
}

// buildCodeProvider validates a code-defined provider and builds its runtime
// form through the stored-provider builder.
func (a *api) buildCodeProvider(ctx context.Context, name string, spec *ports.OIDCProvider, scopes string) (externalProvider, error) {
	issuer := strings.TrimSpace(spec.Issuer)
	switch {
	case issuer == "":
		return nil, fmt.Errorf("code-defined provider %q has no issuer", name)
	case spec.ClientID == "":
		return nil, fmt.Errorf("code-defined provider %q has no client id", name)
	case spec.ClientSecret == "":
		return nil, fmt.Errorf("code-defined provider %q has no client secret", name)
	}

	cp := &customOAuthProvider{
		ProviderType: customProviderTypeOIDC,
		Identifier:   name,
		Name:         name,
		ClientID:     spec.ClientID,
		ClientSecret: spec.ClientSecret,
		Scopes:       spec.Scopes,
		Enabled:      true,
		Issuer:       &issuer,
		// OAuth 2.1 requires PKCE of every client, and an IdP that follows it
		// refuses a request without a challenge. There is no reason for a
		// provider defined in code to opt out.
		PKCEEnabled: true,
	}
	if len(cp.Scopes) == 0 {
		cp.Scopes = defaultCodeProviderScopes
	}
	if d := strings.TrimSpace(spec.DiscoveryURL); d != "" {
		cp.DiscoveryURL = &d
	}

	built, err := a.buildCustomProvider(ctx, a.trustedHTTPClient(), cp, scopes)
	if err != nil {
		return nil, err
	}
	rt, ok := built.(*customRuntimeProvider)
	if !ok {
		return nil, errors.New("code-defined provider: unexpected runtime provider")
	}
	// An explicit redirect URI is set now, and survives setRedirectURI, which
	// only fills an empty one.
	rt.oauth.RedirectURL = strings.TrimSpace(spec.RedirectURI)
	rt.linkBySubject = spec.LinkBySubject
	rt.trusted = true
	return rt, nil
}

// subjectLinkedProvider is implemented by a provider whose `sub` claim is the
// local user id (ports.OIDCProvider.LinkBySubject).
type subjectLinkedProvider interface {
	linksBySubject() bool
}

func (p *customRuntimeProvider) linksBySubject() bool { return p.linkBySubject }

// providerLinksBySubject reports whether sign-ins through p resolve users by
// subject rather than by email.
func providerLinksBySubject(p externalProvider) bool {
	s, ok := p.(subjectLinkedProvider)
	return ok && s.linksBySubject()
}

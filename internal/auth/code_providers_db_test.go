package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/internal/hooks"
	"github.com/dilion-io/dilion/ports"
)

// codeProviderEnv is an /auth/v1 mount whose external providers come from a
// ports.ProviderSource, in front of a fake OIDC issuer.
type codeProviderEnv struct {
	*testEnv
	oidc *fakeOIDCProvider
	// asked records every (instance, name) the source was consulted for.
	asked []string
}

func newCodeProviderEnv(t *testing.T, define func(env *codeProviderEnv, instanceID, name string) (*ports.OIDCProvider, error)) *codeProviderEnv {
	t.Helper()
	dsn := os.Getenv("DILION_TEST_DB")
	if dsn == "" {
		t.Skip("DILION_TEST_DB not set; skipping database-backed tests")
	}
	if !strings.HasPrefix(dsn, "postgres") {
		dsn = defaultTestDSN
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect %s: %v", dsn, err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping %s: %v", dsn, err)
	}
	applySchema(t, pool)
	applyEmailSchema(t, pool)
	applyExternalExtraSchema(t, pool)
	applyOAuthServerSchema(t, pool)
	truncateAll(t, pool)
	clearTables(t, pool, "auth.flow_state", "auth.oauth_client_states", "auth.custom_oauth_providers")

	cfg := DefaultConfig()
	cfg.SiteURL = "https://app.test"
	cfg.URIAllowList = []string{"https://app.test/**"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}

	env := &codeProviderEnv{
		testEnv: &testEnv{
			pool:   pool,
			tokens: NewTokenServiceHS(testSecret()),
			hooks:  hooks.NewRegistry(),
			mailer: &captureMailer{},
		},
		oidc: newFakeOIDCProvider(t),
	}
	resetOIDCCache()
	t.Cleanup(resetOIDCCache)

	env.router = chi.NewRouter()
	Register(env.router, Deps{
		Pool:   pool,
		Tokens: env.tokens,
		Mailer: env.mailer,
		Hooks:  env.hooks,
		Config: cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Providers: func(_ context.Context, instanceID, name string) (*ports.OIDCProvider, error) {
			env.asked = append(env.asked, instanceID+"/"+name)
			return define(env, instanceID, name)
		},
	})
	return env
}

// platform is the provider the tests define: the fake issuer, with the
// client id its id_tokens are audienced at.
func (e *codeProviderEnv) platform() *ports.OIDCProvider {
	return &ports.OIDCProvider{
		Issuer:       e.oidc.srv.URL,
		ClientID:     "google-client-id",
		ClientSecret: "platform-secret",
	}
}

// authorize runs GET /authorize?provider=name on host and returns the
// provider-bound redirect.
func (e *codeProviderEnv) authorize(t *testing.T, name, host string) *url.URL {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet,
		"/authorize?provider="+url.QueryEscape(name)+"&redirect_to="+url.QueryEscape("https://app.test/welcome"), nil)
	req.Host = host
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("authorize status = %d; body = %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	return loc
}

// callback completes the flow the authorize redirect started, on host.
func (e *codeProviderEnv) callback(t *testing.T, loc *url.URL, host string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet,
		"/callback?state="+url.QueryEscape(loc.Query().Get("state"))+"&code=the-code", nil)
	req.Host = host
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

// signIn runs the whole flow and returns the created or resolved user id.
func (e *codeProviderEnv) signIn(t *testing.T, name string) string {
	t.Helper()
	loc := e.authorize(t, name, "tenant.api.test")
	cb := redirectLocation(t, e.callback(t, loc, "tenant.api.test"), http.StatusFound)
	frag := fragmentValues(t, cb)
	claims, err := e.tokens.Verify(context.Background(), frag.Get("access_token"))
	if err != nil {
		t.Fatalf("verify session token: %v (redirect %s)", err, cb)
	}
	return claims.Subject
}

// A code-defined provider is found before the database, derives its callback
// from the host the request arrived on, and presents that SAME redirect_uri at
// the token exchange — which is what lets one definition serve every tenant
// host, and what a provider enforcing exact redirect URIs demands.
func TestCodeProviderSignInDerivesCallbackFromHost(t *testing.T) {
	env := newCodeProviderEnv(t, func(env *codeProviderEnv, _, name string) (*ports.OIDCProvider, error) {
		if name != "platform" {
			return nil, nil
		}
		return env.platform(), nil
	})

	loc := env.authorize(t, "platform", "acme.api.test")
	if !strings.HasPrefix(loc.String(), env.oidc.srv.URL) {
		t.Fatalf("authorize went to %s, want the provider", loc)
	}
	const want = "https://acme.api.test/callback"
	if got := loc.Query().Get("redirect_uri"); got != want {
		t.Errorf("authorize redirect_uri = %q, want %q", got, want)
	}
	if got := loc.Query().Get("client_id"); got != "google-client-id" {
		t.Errorf("client_id = %q", got)
	}
	if got := loc.Query().Get("scope"); got != "openid email profile" {
		t.Errorf("scope = %q, want the openid/email/profile default", got)
	}

	cb := redirectLocation(t, env.callback(t, loc, "acme.api.test"), http.StatusFound)
	if got := env.oidc.tokenRedirectURI; got != want {
		t.Errorf("token exchange redirect_uri = %q, want %q", got, want)
	}
	if fragmentValues(t, cb).Get("access_token") == "" {
		t.Fatalf("no session after callback: %s", cb)
	}
	if len(env.asked) == 0 || env.asked[0] != ports.DefaultInstanceID+"/platform" {
		t.Errorf("source consulted as %v, want the request's instance and provider name", env.asked)
	}
}

// An explicit RedirectURI is sent verbatim at both steps, for a proxy that
// rewrites the host or path on the way in.
func TestCodeProviderExplicitRedirectURI(t *testing.T) {
	const fixed = "https://public.example.com/auth/v1/callback"
	env := newCodeProviderEnv(t, func(env *codeProviderEnv, _, name string) (*ports.OIDCProvider, error) {
		p := env.platform()
		p.RedirectURI = fixed
		return p, nil
	})
	loc := env.authorize(t, "platform", "internal.local")
	if got := loc.Query().Get("redirect_uri"); got != fixed {
		t.Errorf("authorize redirect_uri = %q, want the configured %q", got, fixed)
	}
	redirectLocation(t, env.callback(t, loc, "internal.local"), http.StatusFound)
	if got := env.oidc.tokenRedirectURI; got != fixed {
		t.Errorf("token exchange redirect_uri = %q, want the configured %q", got, fixed)
	}
}

// The source only answers for the names it defines; everything else falls
// through to the built-ins and the database. Its errors fail the request
// rather than falling through, as a 500 whose body says nothing of the cause:
// the caller of /authorize is unauthenticated, and the embedder's error may
// name internal hosts.
func TestCodeProviderFallThroughAndErrors(t *testing.T) {
	const secretCause = "dial tcp 10.0.3.7:5432: tenant registry unavailable"
	env := newCodeProviderEnv(t, func(_ *codeProviderEnv, _, name string) (*ports.OIDCProvider, error) {
		switch name {
		case "broken":
			return nil, errors.New(secretCause)
		case "incomplete":
			return &ports.OIDCProvider{Issuer: "https://idp.test"}, nil
		}
		return nil, nil
	})
	for name, want := range map[string]int{
		"nosuch":     http.StatusBadRequest, // nobody defines it
		"incomplete": http.StatusBadRequest, // defined, but unusable
		"broken":     http.StatusInternalServerError,
	} {
		rec := env.do(t, http.MethodGet, "/authorize?provider="+name, nil, "")
		if rec.Code != want {
			t.Errorf("%s: status = %d, want %d; body = %s", name, rec.Code, want, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "10.0.3.7") || strings.Contains(rec.Body.String(), "registry") {
			t.Errorf("%s: the source's error reached the client: %s", name, rec.Body.String())
		}
	}
}

// A stored custom provider has no redirect column, so it too must derive its
// callback from the request. It never did: applyRequestRedirectURI existed
// but nothing called it, so the authorization request went out with no
// redirect_uri at all — which OIDC requires, and which a provider that matches
// redirect URIs exactly (Dilion's own OAuth server among them) rejects. The
// existing flow test could not notice, because its fake provider never looked.
func TestStoredCustomProviderNowSendsRedirectURI(t *testing.T) {
	env := newCustomEnv(t)
	create := map[string]any{
		"provider_type": "oidc", "identifier": "custom:stored", "name": "Stored",
		"client_id": "google-client-id", "client_secret": "s",
		"issuer": env.oidc.srv.URL, "scopes": []string{"openid", "email"},
	}
	if rec := env.do(t, http.MethodPost, "/admin/custom-providers", create, env.admin); rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d; body = %s", rec.Code, rec.Body.String())
	}

	// httptest requests arrive on http://example.com.
	const want = "http://example.com/callback"
	loc := redirectLocation(t, env.do(t, http.MethodGet,
		"/authorize?provider=custom:stored&redirect_to="+url.QueryEscape("https://app.test/welcome"), nil, ""),
		http.StatusFound)
	if got := loc.Query().Get("redirect_uri"); got != want {
		t.Errorf("authorize redirect_uri = %q, want %q", got, want)
	}
	redirectLocation(t, env.do(t, http.MethodGet,
		"/callback?state="+url.QueryEscape(loc.Query().Get("state"))+"&code=the-code", nil, ""),
		http.StatusFound)
	if got := env.oidc.tokenRedirectURI; got != want {
		t.Errorf("token exchange redirect_uri = %q, want %q", got, want)
	}
}

// ---- link by subject -------------------------------------------------------

func linkBySubjectEnv(t *testing.T) *codeProviderEnv {
	return newCodeProviderEnv(t, func(env *codeProviderEnv, _, _ string) (*ports.OIDCProvider, error) {
		p := env.platform()
		p.LinkBySubject = true
		return p, nil
	})
}

func (e *codeProviderEnv) insertUser(t *testing.T, id, email string) {
	t.Helper()
	// instance_id is the gotrue sentinel every real user carries; the email
	// lookups filter on it, so a row without it would be invisible to them.
	if _, err := e.pool.Exec(context.Background(), `
		insert into auth.users (instance_id, id, aud, role, email, email_confirmed_at, created_at, updated_at)
		values ($1::uuid, $2::uuid, 'authenticated', 'authenticated', nullif($3, ''), now(), now(), now())`,
		nilUUID, id, email); err != nil {
		t.Fatalf("insert user: %v", err)
	}
}

func (e *codeProviderEnv) userEmail(t *testing.T, id string) string {
	t.Helper()
	var email *string
	if err := e.pool.QueryRow(context.Background(),
		`select email from auth.users where id = $1::uuid`, id).Scan(&email); err != nil {
		t.Fatalf("load user %s: %v", id, err)
	}
	return deref(email)
}

// The provider's subject picks the account, even when its email says
// otherwise. With email matching, this sign-in would have landed on the OTHER
// user, who owns the address the provider reported.
func TestLinkBySubjectPrefersIDOverEmail(t *testing.T) {
	env := linkBySubjectEnv(t)
	subject, other := uuid.NewString(), uuid.NewString()
	env.insertUser(t, subject, "old-address@example.com")
	env.insertUser(t, other, env.oidc.email)
	env.oidc.sub = subject

	if got := env.signIn(t, "platform"); got != subject {
		t.Fatalf("signed in as %s, want the subject %s (email matching would give %s)", got, subject, other)
	}
	// Linking does not rewrite the account's own email.
	if got := env.userEmail(t, subject); got != "old-address@example.com" {
		t.Errorf("subject's email = %q, want it untouched", got)
	}
	// And the second sign-in goes through the identity it now has.
	if got := env.signIn(t, "platform"); got != subject {
		t.Errorf("second sign-in as %s, want %s", got, subject)
	}
}

// A subject with no local user yet becomes one, under that very id.
func TestLinkBySubjectCreatesUserUnderSubject(t *testing.T) {
	env := linkBySubjectEnv(t)
	subject := uuid.NewString()
	env.oidc.sub = subject

	if got := env.signIn(t, "platform"); got != subject {
		t.Fatalf("created user %s, want id = subject %s", got, subject)
	}
	if got := env.userEmail(t, subject); got != env.oidc.email {
		t.Errorf("created user's email = %q, want the provider's %q", got, env.oidc.email)
	}
}

// When another user already owns the provider's address, the subject's account
// is still created — without the address — rather than failing the sign-in or
// merging into that user.
func TestLinkBySubjectEmailConflictCreatesWithoutEmail(t *testing.T) {
	env := linkBySubjectEnv(t)
	subject, owner := uuid.NewString(), uuid.NewString()
	env.insertUser(t, owner, env.oidc.email)
	env.oidc.sub = subject

	if got := env.signIn(t, "platform"); got != subject {
		t.Fatalf("signed in as %s, want %s", got, subject)
	}
	if got := env.userEmail(t, subject); got != "" {
		t.Errorf("subject's email = %q, want none (the address belongs to %s)", got, owner)
	}
	if got := env.userEmail(t, owner); got != env.oidc.email {
		t.Errorf("owner's email changed to %q", got)
	}
}

// A subject that is not a user id cannot name a user, and a soft-deleted user
// is not revived by a sign-in.
func TestLinkBySubjectRefusals(t *testing.T) {
	env := linkBySubjectEnv(t)

	env.oidc.sub = "not-a-uuid"
	loc := env.authorize(t, "platform", "tenant.api.test")
	cb := redirectLocation(t, env.callback(t, loc, "tenant.api.test"), http.StatusFound)
	if frag := fragmentValues(t, cb); frag.Get("access_token") != "" || !strings.Contains(cb.String(), "error") {
		t.Errorf("non-uuid subject signed in: %s", cb)
	}

	deleted := uuid.NewString()
	env.insertUser(t, deleted, "gone@example.com")
	if _, err := env.pool.Exec(context.Background(),
		`update auth.users set deleted_at = now() where id = $1::uuid`, deleted); err != nil {
		t.Fatalf("soft-delete: %v", err)
	}
	env.oidc.sub = deleted
	loc = env.authorize(t, "platform", "tenant.api.test")
	cb = redirectLocation(t, env.callback(t, loc, "tenant.api.test"), http.StatusFound)
	if fragmentValues(t, cb).Get("access_token") != "" {
		t.Errorf("a soft-deleted subject signed in: %s", cb)
	}
}

// Without LinkBySubject the same provider keeps the email-based linking every
// other provider has: the subject means nothing locally.
func TestCodeProviderWithoutLinkBySubjectLinksByEmail(t *testing.T) {
	env := newCodeProviderEnv(t, func(env *codeProviderEnv, _, _ string) (*ports.OIDCProvider, error) {
		return env.platform(), nil
	})
	owner := uuid.NewString()
	env.insertUser(t, owner, env.oidc.email)
	env.oidc.sub = uuid.NewString() // a different id, which must be ignored

	if got := env.signIn(t, "platform"); got != owner {
		t.Errorf("signed in as %s, want the email owner %s", got, owner)
	}
}

// ---- PKCE and client authentication toward the provider -------------------

// A code-defined provider always uses PKCE toward its IdP: the authorization
// request carries an S256 challenge, the token request the verifier behind it,
// and the verifier is stored server-side for exactly one exchange. Credentials
// go by HTTP Basic, which RFC 6749 obliges every server to accept.
func TestCodeProviderUsesPKCEAndBasicAuth(t *testing.T) {
	env := newCodeProviderEnv(t, func(env *codeProviderEnv, _, _ string) (*ports.OIDCProvider, error) {
		return env.platform(), nil
	})

	loc := env.authorize(t, "platform", "tenant.api.test")
	challenge := loc.Query().Get("code_challenge")
	if challenge == "" || loc.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization request carries no S256 challenge: %s", loc)
	}
	var stored int
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from auth.oauth_client_states where provider_type = 'platform'`).Scan(&stored); err != nil {
		t.Fatalf("count client states: %v", err)
	}
	if stored != 1 {
		t.Fatalf("stored verifiers = %d, want 1", stored)
	}

	cb := env.callback(t, loc, "tenant.api.test")
	redirect := redirectLocation(t, cb, http.StatusFound)
	if fragmentValues(t, redirect).Get("access_token") == "" {
		t.Fatalf("no session after callback: %s", redirect)
	}
	if got := pkceS256Challenge(env.oidc.tokenCodeVerifier); got != challenge {
		t.Errorf("token request verifier does not match the challenge sent (%q vs %q)", got, challenge)
	}
	if !env.oidc.tokenBasic {
		t.Error("client credentials were not sent by HTTP Basic")
	}
	if err := env.pool.QueryRow(context.Background(),
		`select count(*) from auth.oauth_client_states`).Scan(&stored); err != nil {
		t.Fatalf("count client states: %v", err)
	}
	if stored != 0 {
		t.Errorf("verifier rows after the callback = %d, want 0: it must be single use", stored)
	}
}

// A verifier serves one exchange. A flow whose verifier is gone — replayed,
// or started before the provider required PKCE — cannot reach the provider.
func TestCodeProviderPKCEVerifierIsSingleUse(t *testing.T) {
	env := newCodeProviderEnv(t, func(env *codeProviderEnv, _, _ string) (*ports.OIDCProvider, error) {
		return env.platform(), nil
	})
	loc := env.authorize(t, "platform", "tenant.api.test")
	if _, err := env.pool.Exec(context.Background(), `delete from auth.oauth_client_states`); err != nil {
		t.Fatalf("drop verifier: %v", err)
	}
	before := env.oidc.tokenRequests
	cb := redirectLocation(t, env.callback(t, loc, "tenant.api.test"), http.StatusFound)
	if fragmentValues(t, cb).Get("access_token") != "" {
		t.Fatalf("signed in without the stored verifier: %s", cb)
	}
	if env.oidc.tokenRequests != before {
		t.Error("the provider was asked to exchange a code with no verifier to send")
	}
}

// A token endpoint that refuses HTTP Basic gets the credentials in the body on
// a second attempt, as x/oauth2's auto-detection does for upstream — the
// first attempt failed client authentication, so the code is still unused.
func TestCodeProviderFallsBackToBodyCredentials(t *testing.T) {
	env := newCodeProviderEnv(t, func(env *codeProviderEnv, _, _ string) (*ports.OIDCProvider, error) {
		return env.platform(), nil
	})
	env.oidc.rejectBasic = true

	loc := env.authorize(t, "platform", "tenant.api.test")
	cb := redirectLocation(t, env.callback(t, loc, "tenant.api.test"), http.StatusFound)
	if fragmentValues(t, cb).Get("access_token") == "" {
		t.Fatalf("no session after a body-credentials retry: %s", cb)
	}
	if env.oidc.tokenRequests != 2 || env.oidc.tokenBasic {
		t.Errorf("token requests = %d, last by Basic = %v; want a Basic attempt then a body one",
			env.oidc.tokenRequests, env.oidc.tokenBasic)
	}
	if env.oidc.tokenCodeVerifier == "" {
		t.Error("the retry dropped the PKCE verifier")
	}
}

// A stored custom provider follows its pkce_enabled column, which defaults to
// true — as upstream's does. Before this, the column was stored and ignored.
func TestStoredCustomProviderHonoursPKCEFlag(t *testing.T) {
	env := newCustomEnv(t)
	for identifier, pkce := range map[string]bool{"custom:with-pkce": true, "custom:without-pkce": false} {
		create := map[string]any{
			"provider_type": "oidc", "identifier": identifier, "name": identifier,
			"client_id": "google-client-id", "client_secret": "s",
			"issuer": env.oidc.srv.URL, "scopes": []string{"openid", "email"},
		}
		if !pkce {
			create["pkce_enabled"] = false
		}
		if rec := env.do(t, http.MethodPost, "/admin/custom-providers", create, env.admin); rec.Code != http.StatusCreated {
			t.Fatalf("%s: create status = %d; body = %s", identifier, rec.Code, rec.Body.String())
		}

		loc := redirectLocation(t, env.do(t, http.MethodGet,
			"/authorize?provider="+identifier+"&redirect_to="+url.QueryEscape("https://app.test/welcome"), nil, ""),
			http.StatusFound)
		challenge := loc.Query().Get("code_challenge")
		if (challenge != "") != pkce {
			t.Errorf("%s: challenge sent = %v, want %v", identifier, challenge != "", pkce)
		}
		redirectLocation(t, env.do(t, http.MethodGet,
			"/callback?state="+url.QueryEscape(loc.Query().Get("state"))+"&code=the-code", nil, ""),
			http.StatusFound)
		if pkce && pkceS256Challenge(env.oidc.tokenCodeVerifier) != challenge {
			t.Errorf("%s: verifier does not match the challenge", identifier)
		}
		if !pkce && env.oidc.tokenCodeVerifier != "" {
			t.Errorf("%s: a verifier was sent with PKCE off", identifier)
		}
	}
}

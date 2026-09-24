package api

// The management plane admits a user token only from the user's own, still
// open, second-factor-verified sign-in. Enable with:
//
//	DILION_TEST_DB=1 go test ./internal/api/...

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/internal/store"
	"github.com/dilion-io/dilion/ports"
)

func TestManagementPlaneChecksTheSession(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if err := store.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	user, banned := uuid.NewString(), uuid.NewString()
	for _, u := range []string{user, banned} {
		if _, err := pool.Exec(ctx, `insert into auth.users (id, aud, role, created_at, updated_at)
			values ($1::uuid, 'authenticated', 'authenticated', now(), now())`, u); err != nil {
			t.Fatalf("user: %v", err)
		}
	}
	if _, err := pool.Exec(ctx, `update auth.users set banned_until = now() + interval '1 day' where id = $1::uuid`, banned); err != nil {
		t.Fatalf("ban: %v", err)
	}
	client := uuid.NewString()
	if _, err := pool.Exec(ctx, `insert into auth.oauth_clients
		(id, registration_type, redirect_uris, grant_types, client_type, token_endpoint_auth_method)
		values ($1::uuid, 'dynamic', 'https://app.example/cb', 'authorization_code', 'public', 'none')`, client); err != nil {
		t.Fatalf("client: %v", err)
	}
	oauthSession := seedSession(t, pool, user, "totp", time.Minute)
	if _, err := pool.Exec(ctx, `update auth.sessions set oauth_client_id = $2::uuid where id = $1::uuid`, oauthSession, client); err != nil {
		t.Fatalf("oauth session: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `delete from auth.sessions where user_id = any($1::uuid[])`, []string{user, banned})
		_, _ = pool.Exec(bg, `delete from auth.users where id = any($1::uuid[])`, []string{user, banned})
		_, _ = pool.Exec(bg, `delete from auth.oauth_clients where id = $1::uuid`, client)
	})

	for _, tc := range []struct {
		name       string
		user       string
		session    string
		noAdminMFA bool
		want       int
		code       string
	}{
		{"aal2 sign-in", user, seedSession(t, pool, user, "totp", time.Minute), false, http.StatusOK, ""},
		{"aal1 sign-in", user, seedSession(t, pool, user, "password", time.Minute), false, http.StatusForbidden, httpapi.CodeInsufficientAAL},
		{"aal1 sign-in, WithoutAdminMFA", user, seedSession(t, pool, user, "password", time.Minute), true, http.StatusOK, ""},
		{"ended session", user, uuid.NewString(), false, http.StatusUnauthorized, httpapi.CodeUnauthenticated},
		{"OAuth application's session", user, oauthSession, false, http.StatusForbidden, httpapi.CodePermissionDenied},
		{"banned user", banned, seedSession(t, pool, banned, "totp", time.Minute), false, http.StatusForbidden, httpapi.CodePermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tapi := newAPI(t, &fakePrivacy{}, Deps{
				Pool: pool,
				Verifier: fakeVerifier{claims: &ports.Claims{Subject: tc.user, Role: "authenticated",
					Extra: map[string]any{"session_id": tc.session, "aal": "aal2"}}},
				Authz:            fakeAuthorizer{allow: map[string]bool{"audit.read": true}},
				Audit:            &recordingSink{},
				AdminMFADisabled: tc.noAdminMFA,
			})
			resp := tapi.Get("/iam/v1/roles", bearer)
			if resp.Code != tc.want {
				t.Fatalf("status = %d, want %d (body=%s)", resp.Code, tc.want, resp.Body.String())
			}
			if tc.code != "" {
				var p Problem
				_ = json.Unmarshal(resp.Body.Bytes(), &p)
				if p.Code != tc.code {
					t.Errorf("code = %q, want %s", p.Code, tc.code)
				}
			}
		})
	}
}

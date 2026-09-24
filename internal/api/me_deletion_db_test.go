package api

// Self-service deletion reads the session's assurance from the database.
// Enable with:
//
//	DILION_TEST_DB=1 go test ./internal/api/...

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/httpapi"
	"github.com/dilion-io/dilion/internal/privacy"
	"github.com/dilion-io/dilion/internal/store"
	"github.com/dilion-io/dilion/ports"
)

// seedSession writes a session for user whose sign-in (method) happened ago.
func seedSession(t *testing.T, pool *pgxpool.Pool, user, method string, ago time.Duration) string {
	t.Helper()
	ctx := context.Background()
	id := uuid.NewString()
	at := time.Now().Add(-ago)
	if _, err := pool.Exec(ctx, `insert into auth.sessions (id, user_id, created_at, updated_at, aal)
		values ($1::uuid, $2::uuid, $3, $3, 'aal1')`, id, user, at); err != nil {
		t.Fatalf("session: %v", err)
	}
	if _, err := pool.Exec(ctx, `insert into auth.mfa_amr_claims (id, session_id, created_at, updated_at, authentication_method)
		values ($1::uuid, $2::uuid, $3, $3, $4)`, uuid.NewString(), id, at, method); err != nil {
		t.Fatalf("amr: %v", err)
	}
	return id
}

func TestMeDeletionNeedsAssuredSession(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	if err := store.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	plain, withMFA := uuid.NewString(), uuid.NewString()
	for _, u := range []string{plain, withMFA} {
		if _, err := pool.Exec(ctx, `insert into auth.users (id, aud, role, created_at, updated_at)
			values ($1::uuid, 'authenticated', 'authenticated', now(), now())`, u); err != nil {
			t.Fatalf("user: %v", err)
		}
	}
	if _, err := pool.Exec(ctx, `insert into auth.mfa_factors (id, user_id, factor_type, status, created_at, updated_at)
		values ($1::uuid, $2::uuid, 'totp', 'verified', now(), now())`, uuid.NewString(), withMFA); err != nil {
		t.Fatalf("factor: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `delete from auth.users where id = any($1::uuid[])`, []string{plain, withMFA})
		_, _ = pool.Exec(context.Background(), `delete from auth.sessions where user_id = any($1::uuid[])`, []string{plain, withMFA})
		_, _ = pool.Exec(context.Background(), `delete from auth.mfa_factors where user_id = $1::uuid`, withMFA)
	})

	// A token claiming a sign-in a moment ago, whatever the database says: a
	// claims hook could mint exactly that.
	freshAMR := []any{map[string]any{"method": "totp", "timestamp": float64(time.Now().Unix())}}

	for _, tc := range []struct {
		name    string
		user    string
		session string
		typ     string
		want    int
		code    string
	}{
		{"fresh password sign-in", plain, seedSession(t, pool, plain, "password", time.Minute), "DELETION", http.StatusAccepted, ""},
		{"old sign-in, however fresh the token claims", plain, seedSession(t, pool, plain, "password", time.Hour), "DELETION", http.StatusForbidden, httpapi.CodeReauthenticationNeeded},
		{"no such session", plain, uuid.NewString(), "DELETION", http.StatusForbidden, httpapi.CodeReauthenticationNeeded},
		{"another user's session", withMFA, seedSession(t, pool, plain, "password", time.Minute), "DELETION", http.StatusForbidden, httpapi.CodeReauthenticationNeeded},
		{"MFA user at aal1", withMFA, seedSession(t, pool, withMFA, "password", time.Minute), "DELETION", http.StatusForbidden, httpapi.CodeInsufficientAAL},
		{"MFA user at aal2", withMFA, seedSession(t, pool, withMFA, "totp", time.Minute), "DELETION", http.StatusAccepted, ""},
		{"old sign-in, export", plain, seedSession(t, pool, plain, "password", time.Hour), "EXPORT", http.StatusAccepted, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &fakePrivacy{
				createRequest: func(_ context.Context, in privacy.CreateRequestInput) (*privacy.Request, error) {
					r := sampleRequest()
					r.UserID, r.Type = in.UserID, in.Type
					return r, nil
				},
			}
			tapi := newAPI(t, svc, Deps{
				Pool: pool,
				Verifier: fakeVerifier{claims: &ports.Claims{Subject: tc.user, Role: "authenticated",
					Extra: map[string]any{"session_id": tc.session, "aal": "aal2", "amr": freshAMR}}},
				Authz:                fakeAuthorizer{},
				Audit:                &recordingSink{},
				DeletionReauthWindow: 10 * time.Minute,
			})
			resp := tapi.Post("/privacy/v1/me/requests", bearer, map[string]any{"type": tc.typ})
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

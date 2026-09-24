package dilion

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/internal/auth"
	"github.com/dilion-io/dilion/ports"
)

// Self-service deletion reads the sign-in time from a real access token's
// `amr` claim, so this runs the whole path: sign up, then ask to be deleted
// with the token that sign-up issued.
func TestSelfDeletionNeedsRecentSignIn(t *testing.T) {
	for _, tc := range []struct {
		name   string
		window time.Duration
		want   int
	}{
		{"within the window", 10 * time.Minute, http.StatusAccepted},
		{"outside the window", time.Nanosecond, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := auth.DefaultConfig()
			cfg.Mailer.Autoconfirm = true
			cfg.Security.DeletionReauthWindow = tc.window
			srv, h1, h2 := twoInstanceServer(t, WithAuthConfig(cfg))
			email := "reauth-" + uuid.NewString()[:8] + "@example.com"
			t.Cleanup(func() {
				for _, p := range []*pgxpool.Pool{h1, h2} {
					_, _ = p.Exec(context.Background(), `delete from dilion_privacy.personal_data_requests
						where user_id in (select id from auth.users where email = $1)`, email)
					_, _ = p.Exec(context.Background(), `delete from auth.users where email = $1`, email)
				}
			})

			send := func(path, token, body string) *httptest.ResponseRecorder {
				req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				if token != "" {
					req.Header.Set("Authorization", "Bearer "+token)
				}
				req = req.WithContext(ports.ContextWithInstance(req.Context(), "h1"))
				rec := httptest.NewRecorder()
				srv.Handler().ServeHTTP(rec, req)
				return rec
			}
			rec := send("/auth/v1/signup", "", `{"email":"`+email+`","password":"correct-horse-battery"}`)
			var session struct {
				AccessToken string `json:"access_token"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &session); err != nil || session.AccessToken == "" {
				t.Fatalf("signup = %d %s", rec.Code, rec.Body.String())
			}

			rec = send("/privacy/v1/me/requests", session.AccessToken, `{"type":"DELETION"}`)
			if rec.Code != tc.want {
				t.Fatalf("self deletion = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want == http.StatusForbidden && !strings.Contains(rec.Body.String(), "reauthentication_needed") {
				t.Errorf("refusal = %s, want reauthentication_needed", rec.Body.String())
			}
		})
	}
}

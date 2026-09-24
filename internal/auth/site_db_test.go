package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/dilion-io/dilion/ports"
)

// Each instance's site URL and redirect allow list come from the settings
// source; an instance it says nothing about keeps the server's. Email links
// are where both show: redirect_to is kept only when the instance allows it,
// and the link is built on the instance's site.
func TestInstanceSiteSettings(t *testing.T) {
	env := newTestEnv(t)
	env.signup(t, "site@example.com", "correct-horse-battery")

	cfg := testConfig()
	cfg.SiteURL = "https://server.example"
	cfg.URIAllowList = []string{"https://server.example/**"}
	sites := map[string]*ports.AuthSettings{
		"tenant-a": {SiteURL: "https://a.example", URIAllowList: []string{"https://a.example/**"}},
	}
	router := chi.NewRouter()
	Register(router, Deps{
		Pool: env.pool, Tokens: env.tokens, Mailer: env.mailer, Config: cfg,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Settings: func(_ context.Context, id string) (*ports.AuthSettings, error) {
			if id == "broken" {
				return nil, errors.New("settings store down")
			}
			return sites[id], nil
		},
	})
	admin := env.serviceRoleToken(t)

	link := func(instance, redirectTo string) (int, GenerateLinkResponse) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"type": "magiclink", "email": "site@example.com", "redirect_to": redirectTo})
		req := httptest.NewRequest(http.MethodPost, "/admin/generate_link", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+admin)
		req = req.WithContext(ports.ContextWithInstance(req.Context(), instance))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		var out GenerateLinkResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	for _, tc := range []struct {
		instance, redirectTo, wantRedirect, wantSite string
	}{
		{"tenant-a", "https://a.example/welcome", "https://a.example/welcome", "https://a.example"},
		{"tenant-a", "https://server.example/welcome", "https://a.example", "https://a.example"},
		{ports.DefaultInstanceID, "https://server.example/welcome", "https://server.example/welcome", "https://server.example"},
		{ports.DefaultInstanceID, "https://a.example/welcome", "https://server.example", "https://server.example"},
	} {
		code, out := link(tc.instance, tc.redirectTo)
		if code != http.StatusOK {
			t.Fatalf("%s: generate_link = %d", tc.instance, code)
		}
		if out.RedirectTo != tc.wantRedirect {
			t.Errorf("%s redirect_to %s: got %q, want %q", tc.instance, tc.redirectTo, out.RedirectTo, tc.wantRedirect)
		}
		if !strings.HasPrefix(out.ActionLink, tc.wantSite+"/") {
			t.Errorf("%s: action_link %q is not on %s", tc.instance, out.ActionLink, tc.wantSite)
		}
	}

	// The instance's list must not leak into the server's own matchers.
	if !cfg.IsRedirectAllowed("https://server.example/x") || cfg.IsRedirectAllowed("https://a.example/x") {
		t.Error("an instance's allow list changed the server configuration")
	}
	if code, _ := link("broken", ""); code != http.StatusInternalServerError {
		t.Errorf("failing settings source = %d, want 500", code)
	}
}

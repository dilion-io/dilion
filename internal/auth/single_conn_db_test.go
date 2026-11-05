package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A request holds at most one pool connection: while its transaction is open
// it must not wait for a second one (the per-account attempt count, a hook
// setting, a pg-functions delivery hook). With N concurrent requests and N
// connections, such a wait never ends. Here the pool has a single connection,
// so a second acquisition fails the request at its deadline.
func TestRequestsNeedOnlyOneConnection(t *testing.T) {
	env := newEmailEnv(t, nil)
	env.confirmedUser(t, "oneconn@example.com", "hunter22")
	if _, err := env.pool.Exec(t.Context(), `
		create schema if not exists hooktest;
		create table if not exists hooktest.sent_codes (email text, token text);
		delete from hooktest.sent_codes;
		create or replace function hooktest.send_email(input jsonb) returns jsonb language sql as $$
			insert into hooktest.sent_codes values (input->'user'->>'email', input->'email_data'->>'token');
			select '{}'::jsonb
		$$;`); err != nil {
		t.Fatalf("hook function: %v", err)
	}

	pcfg, err := pgxpool.ParseConfig(env.pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	pcfg.MaxConns = 1
	one, err := pgxpool.NewWithConfig(t.Context(), pcfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(one.Close)

	cfg := *env.cfg
	cfg.Hooks.SendEmail = HookEndpointConfig{Enabled: true, Locked: true, URI: "pg-functions://dilion/hooktest/send_email"}
	router := chi.NewRouter()
	Register(router, Deps{Pool: one, Tokens: env.tokens, Hooks: env.hooks, Config: &cfg, Clock: env.clock,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	do := func(path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		b, _ := json.Marshal(body)
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	// The magic link goes out through the pg-functions send_email hook.
	if rec := do("/otp", map[string]any{"email": "oneconn@example.com"}); rec.Code != http.StatusOK {
		t.Fatalf("/otp = %d %s", rec.Code, rec.Body.String())
	}
	var code string
	if err := env.pool.QueryRow(t.Context(),
		`select token from hooktest.sent_codes where email = 'oneconn@example.com'`).Scan(&code); err != nil {
		t.Fatalf("the hook saw no code: %v", err)
	}
	// A typed code is counted per account around its transaction.
	rec := do("/verify", map[string]any{"type": mailMagicLink, "email": "oneconn@example.com", "token": code})
	decodeInto[AccessTokenResponse](t, rec, http.StatusOK)

	// Built-in mail goes out after the transaction commits: a mailer that
	// needs the pool's only connection while it sends gets it.
	cfg.Hooks.SendEmail = HookEndpointConfig{Locked: true}
	router = chi.NewRouter()
	Register(router, Deps{Pool: one, Tokens: env.tokens, Hooks: env.hooks, Config: &cfg, Clock: env.clock,
		Mailer: connMailer{pool: one}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	env.clock.advance(2 * cfg.Mailer.MaxFrequency)
	if rec := do("/otp", map[string]any{"email": "oneconn@example.com"}); rec.Code != http.StatusOK {
		t.Fatalf("/otp with a mailer that needs a connection = %d %s", rec.Code, rec.Body.String())
	}
}

// connMailer takes a pool connection for every send, as a mailer writing an
// outbox or a delivery log would.
type connMailer struct{ pool *pgxpool.Pool }

func (m connMailer) Send(ctx context.Context, _, _, _, _ string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, err := m.pool.Exec(ctx, `select 1`)
	return err
}

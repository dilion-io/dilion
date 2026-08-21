package auth

// Postgres-function driver for the external auth hooks.
//
// This is Dilion's port of github.com/supabase/auth/internal/hooks/hookspgfunc.
// A hook configured with a pg-functions:// URI is a Postgres function invoked
// IN-TRANSACTION on the auth database:
//
//	pg-functions://<db>/<schema>/<func>
//	                                 -> select "<schema>"."<func>"($1::jsonb)
//
// The function takes the hook payload as a single jsonb argument and returns
// jsonb. A `{"error":{"http_code","message"}}` object in the returned jsonb is a
// rejection (checkHookError), everything else is decoded into the output struct.
//
// # Transaction
//
// The call runs inside the caller's transaction when one is supplied (tx != nil):
// custom_access_token runs in the token-issuance transaction and
// before_user_created in the signup transaction, so the function sees the same
// uncommitted state the request is building and cannot deadlock against it. When
// tx is nil the driver opens its own short transaction on the auth pool.
//
// A per-call statement_timeout is set with `SET LOCAL`, matching upstream, so a
// runaway function is bounded by Postgres rather than by a Go timer. `SET LOCAL`
// is scoped to the surrounding transaction and reset to default afterwards.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// pgHookTimeout bounds one Postgres-function invocation (upstream's 2s default).
const pgHookTimeout = 2 * time.Second

// dispatchPGHook invokes the pg-functions hook and decodes the returned jsonb
// into out. tx is the caller's transaction, or nil to open a fresh one.
func (a *api) dispatchPGHook(ctx context.Context, cfg HookEndpointConfig, tx querier, in, out any) error {
	hookName, err := pgHookName(cfg.URI)
	if err != nil {
		return internalServerError("invalid pg-functions hook URI %q", cfg.URI).withInternal(err)
	}
	payload, err := marshalHookInput(in)
	if err != nil {
		return err
	}

	run := func(q querier) ([]byte, error) { return invokePGHook(ctx, q, hookName, payload) }

	var body []byte
	if tx != nil {
		body, err = run(tx)
	} else {
		body, err = a.pgHookInOwnTx(ctx, run)
	}
	if err != nil {
		return internalServerError("Error running hook URI: %s", cfg.URI).withInternal(err)
	}

	if cErr := checkHookError(body); cErr != nil {
		return cErr
	}
	if len(body) > 0 && out != nil {
		if uErr := unmarshalHookOutput(body, out); uErr != nil {
			return uErr
		}
	}
	return nil
}

// pgHookInOwnTx runs fn inside a fresh transaction on the auth pool.
func (a *api) pgHookInOwnTx(ctx context.Context, fn func(querier) ([]byte, error)) ([]byte, error) {
	pool, err := a.db(ctx)
	if err != nil {
		return nil, err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	body, err := fn(tx)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return body, nil
}

// invokePGHook sets the per-call statement timeout, calls the function, and
// resets the timeout — all on q, which must be a transaction for SET LOCAL to
// take effect.
func invokePGHook(ctx context.Context, q querier, hookName string, payload []byte) ([]byte, error) {
	timeoutMS := int(pgHookTimeout / time.Millisecond)
	if _, err := q.Exec(ctx, fmt.Sprintf("set local statement_timeout to '%d'", timeoutMS)); err != nil {
		return nil, err
	}

	var response []byte
	// hookName is a pre-validated, double-quoted "schema"."func" identifier
	// (pgHookName), never request-derived, so it is safe to interpolate; the
	// payload is bound as a parameter.
	sql := fmt.Sprintf("select %s($1::jsonb)", hookName)
	if err := q.QueryRow(ctx, sql, payload).Scan(&response); err != nil {
		if isNoRows(err) {
			// A function returning SQL NULL / no row is not an error: the hook
			// simply made no changes (upstream tolerates an empty response).
			response = nil
		} else {
			return nil, err
		}
	}

	if _, err := q.Exec(ctx, "set local statement_timeout to default"); err != nil {
		return nil, err
	}
	return response, nil
}

// pgHookName parses a pg-functions:// URI into the double-quoted "schema"."func"
// identifier upstream builds (PopulateExtensibilityPoint). The path is
// slash-separated: pg-functions://<db>/<schema>/<func>.
func pgHookName(uri string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(uri))
	if err != nil {
		return "", err
	}
	if u.Scheme != "pg-functions" {
		return "", fmt.Errorf("not a pg-functions URI: %q", uri)
	}
	parts := strings.Split(u.Path, "/")
	if len(parts) < 3 || parts[1] == "" || parts[2] == "" {
		return "", fmt.Errorf("URI path does not contain <schema>/<function>: %q", u.Path)
	}
	schema, fn := parts[1], parts[2]
	if !pgIdentifier(schema) || !pgIdentifier(fn) {
		return "", fmt.Errorf("invalid schema/function name in %q", u.Path)
	}
	return fmt.Sprintf("%q.%q", schema, fn), nil
}

// pgIdentifier is upstream's postgresNamesRegexp check, kept simple: a Postgres
// unquoted identifier (letter/underscore, then letters/digits/underscores).
func pgIdentifier(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_':
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

// marshalHookInput / unmarshalHookOutput centralize the JSON codec so both the
// pg and http drivers surface the same error envelope.
func marshalHookInput(in any) ([]byte, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return nil, internalServerError("Error marshaling hook JSON input").withInternal(err)
	}
	return b, nil
}

func unmarshalHookOutput(body []byte, out any) error {
	if err := json.Unmarshal(body, out); err != nil {
		// A custom UnmarshalJSON (e.g. CustomAccessTokenOutput) may already return
		// an *HTTPError; propagate it unchanged.
		var he *HTTPError
		if errors.As(err, &he) {
			return he
		}
		return internalServerError("Error unmarshaling hook JSON output").withInternal(err)
	}
	return nil
}

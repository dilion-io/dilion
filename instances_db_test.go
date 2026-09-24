package dilion

// Two-instance integration test: one Server, two fully isolated databases,
// selected per request with ports.ContextWithInstance.
//
// It runs only with DILION_TEST_DB set:
//
//	docker exec dilion-db createdb -U dilion dilion_test_h1
//	docker exec dilion-db createdb -U dilion dilion_test_h2
//	DILION_TEST_DB=1 go test .
//
// DSN overrides: DILION_TEST_DB_DSN_H1 / DILION_TEST_DB_DSN_H2.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/internal/privacy"
	"github.com/dilion-io/dilion/internal/store"
	"github.com/dilion-io/dilion/ports"
)

const (
	defaultH1DSN = "postgres://dilion:dilion@localhost:55432/dilion_test_h1"
	defaultH2DSN = "postgres://dilion:dilion@localhost:55432/dilion_test_h2"
)

// h1 pins its PII vault fields; h2 stays free-form. Same server, different
// contract per instance.
var h1PIIFields = []byte("pii-fields:\n  email: {hint: EMAIL}\n  full_name: {hint: NAME}\n")

// twoInstances is a minimal embedder-style ports.InstanceResolver.
type twoInstances struct {
	pools map[string]*pgxpool.Pool
	kms   map[string]ports.KMS
	jwt   map[string]ports.JWTKeys
	pii   map[string][]byte
}

func (r *twoInstances) get(id string) error {
	if _, ok := r.pools[id]; !ok {
		return errors.New("unknown instance " + id)
	}
	return nil
}

// unlistedInstance is served by Pool but deliberately absent from List, the way
// a resolver publishes an instance only once its schema is in place
// (TestMigrateInstance).
const unlistedInstance = "h1-again"

func (r *twoInstances) Pool(_ context.Context, id string) (*pgxpool.Pool, error) {
	return r.pools[id], r.get(id)
}

func (r *twoInstances) KMS(_ context.Context, id string) (ports.KMS, error) {
	return r.kms[id], r.get(id)
}

func (r *twoInstances) JWT(_ context.Context, id string) (ports.JWTKeys, error) {
	return r.jwt[id], r.get(id)
}

func (r *twoInstances) PolicyYAML(_ context.Context, id string) ([]byte, error) {
	return nil, r.get(id)
}

func (r *twoInstances) PIIFields(_ context.Context, id string) ([]byte, error) {
	return r.pii[id], r.get(id)
}

func (r *twoInstances) List(context.Context) ([]string, error) { return []string{"h1", "h2"}, nil }

func testPool(t *testing.T, envKey, fallback string) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv(envKey)
	if dsn == "" {
		dsn = fallback
	}
	pool, err := store.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect %s: %v", dsn, err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// twoInstanceServer builds a migrated two-instance server plus its pools.
func twoInstanceServer(t *testing.T, extra ...Option) (*Server, *pgxpool.Pool, *pgxpool.Pool) {
	t.Helper()
	if os.Getenv("DILION_TEST_DB") == "" {
		t.Skip("DILION_TEST_DB not set")
	}
	h1 := testPool(t, "DILION_TEST_DB_DSN_H1", defaultH1DSN)
	h2 := testPool(t, "DILION_TEST_DB_DSN_H2", defaultH2DSN)

	key := make([]byte, LocalKMSKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	res := &twoInstances{
		pools: map[string]*pgxpool.Pool{"h1": h1, "h2": h2, unlistedInstance: h1},
		// Built through the public constructor an embedder would use for its
		// own per-instance KMS, not the internal package.
		kms: map[string]ports.KMS{
			"h1": mustLocalKMS(t, h1, key),
			"h2": mustLocalKMS(t, h2, key),
		},
		// Each instance signs with its own secret: that is what binds a
		// token to its instance (TestTokenIsBoundToInstance).
		jwt: map[string]ports.JWTKeys{
			"h1": {Secret: "h1-secret-h1-secret-h1-secret-h1", Issuer: "https://h1.example/auth/v1"},
			"h2": {Secret: "h2-secret-h2-secret-h2-secret-h2", Issuer: "https://h2.example/auth/v1"},
		},
		pii: map[string][]byte{"h1": h1PIIFields}, // h2: free-form
	}

	srv, err := NewServer(append([]Option{
		WithInstanceResolver(res),
		WithMasterKey(key),
		WithJWTSecret([]byte("test-secret-test-secret-test-sec")),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	}, extra...)...)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	// Migrate walks List(): both databases must end up with the full schema.
	if err := srv.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return srv, h1, h2
}

func mustLocalKMS(t *testing.T, pool *pgxpool.Pool, kek []byte) ports.KMS {
	t.Helper()
	k, err := NewLocalKMS(pool, kek)
	if err != nil {
		t.Fatalf("NewLocalKMS: %v", err)
	}
	return k
}

func instanceCtx(t *testing.T, id string) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(ports.ContextWithInstance(context.Background(), id), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// Migrate applies the schema to every instance the resolver lists.
func TestMigrateAppliesToEveryInstance(t *testing.T) {
	_, h1, h2 := twoInstanceServer(t)
	for name, pool := range map[string]*pgxpool.Pool{"h1": h1, "h2": h2} {
		var applied int
		if err := pool.QueryRow(context.Background(),
			`select count(*) from public.schema_migrations`).Scan(&applied); err != nil {
			t.Fatalf("%s: schema_migrations: %v", name, err)
		}
		if applied == 0 {
			t.Errorf("%s: no migrations applied", name)
		}
		var exists bool
		if err := pool.QueryRow(context.Background(),
			`select to_regclass('dilion_pii.user_profiles') is not null`).Scan(&exists); err != nil {
			t.Fatalf("%s: to_regclass: %v", name, err)
		}
		if !exists {
			t.Errorf("%s: dilion_pii.user_profiles missing", name)
		}
	}
}

// Writes and reads follow the instance on the context: the same user id is two
// unrelated subjects in two databases.
func TestInstanceIsolation(t *testing.T) {
	srv, h1, h2 := twoInstanceServer(t)
	userID := uuid.NewString()
	ctx1, ctx2 := instanceCtx(t, "h1"), instanceCtx(t, "h2")

	e1, err := srv.instances.Engine(ctx1)
	if err != nil {
		t.Fatalf("engine h1: %v", err)
	}
	e2, err := srv.instances.Engine(ctx2)
	if err != nil {
		t.Fatalf("engine h2: %v", err)
	}
	if e1 == e2 {
		t.Fatal("both instances share one engine")
	}
	t.Cleanup(func() {
		for _, p := range []*pgxpool.Pool{h1, h2} {
			_, _ = p.Exec(context.Background(),
				`delete from dilion_pii.user_profiles where user_id = $1::uuid`, userID)
			_, _ = p.Exec(context.Background(),
				`delete from dilion_pii.subject_keys where user_id = $1::uuid`, userID)
			_, _ = p.Exec(context.Background(), `delete from auth.users where id = $1::uuid`, userID)
		}
	})

	// A profile written to h1 exists only there.
	if _, err := e1.UpdateProfile(ctx1, userID,
		map[string]privacy.ProfileField{"email": {Value: "joseph@example.com"}}, nil); err != nil {
		t.Fatalf("h1 UpdateProfile: %v", err)
	}
	got, err := e1.GetProfile(ctx1, userID, false)
	if err != nil {
		t.Fatalf("h1 GetProfile: %v", err)
	}
	// The hint came from h1's definition even though the write omitted it.
	if got.Fields["email"].Hint != privacy.HintEmail {
		t.Errorf("h1 stored hint = %q, want EMAIL", got.Fields["email"].Hint)
	}
	if got.Fields["email"].Value != "j**@example.com" {
		t.Errorf("h1 masked value = %q, want j**@example.com", got.Fields["email"].Value)
	}
	if _, err := e2.GetProfile(ctx2, userID, false); !errors.Is(err, privacy.ErrNotFound) {
		t.Fatalf("h2 GetProfile = %v, want ErrNotFound — h1's write leaked", err)
	}
	// And the row really is in h1's database only.
	for name, pool := range map[string]*pgxpool.Pool{"h1": h1, "h2": h2} {
		var n int
		if err := pool.QueryRow(context.Background(),
			`select count(*) from dilion_pii.user_profiles where user_id = $1::uuid`, userID).Scan(&n); err != nil {
			t.Fatalf("%s: count profiles: %v", name, err)
		}
		want := 0
		if name == "h1" {
			want = 1
		}
		if n != want {
			t.Errorf("%s: %d profile rows, want %d", name, n, want)
		}
	}

	// A user row written to h1 is likewise invisible in h2.
	if _, err := h1.Exec(context.Background(),
		`insert into auth.users (id, aud, role, email) values ($1::uuid,'authenticated','authenticated',$2)`,
		userID, "joseph@example.com"); err != nil {
		t.Fatalf("h1 insert user: %v", err)
	}
	for name, pool := range map[string]*pgxpool.Pool{"h1": h1, "h2": h2} {
		var n int
		if err := pool.QueryRow(context.Background(),
			`select count(*) from auth.users where id = $1::uuid`, userID).Scan(&n); err != nil {
			t.Fatalf("%s: count users: %v", name, err)
		}
		want := 0
		if name == "h1" {
			want = 1
		}
		if n != want {
			t.Errorf("%s: %d user rows, want %d", name, n, want)
		}
	}
}

// Each instance enforces its own PII field definitions.
func TestPerInstancePIIFieldDefinitions(t *testing.T) {
	srv, h1, h2 := twoInstanceServer(t)
	userID := uuid.NewString()
	ctx1, ctx2 := instanceCtx(t, "h1"), instanceCtx(t, "h2")
	t.Cleanup(func() {
		for _, p := range []*pgxpool.Pool{h1, h2} {
			_, _ = p.Exec(context.Background(),
				`delete from dilion_pii.user_profiles where user_id = $1::uuid`, userID)
			_, _ = p.Exec(context.Background(),
				`delete from dilion_pii.subject_keys where user_id = $1::uuid`, userID)
		}
	})

	e1, err := srv.instances.Engine(ctx1)
	if err != nil {
		t.Fatalf("engine h1: %v", err)
	}
	e2, err := srv.instances.Engine(ctx2)
	if err != nil {
		t.Fatalf("engine h2: %v", err)
	}

	// h1 defines its fields: an undefined key is rejected...
	_, err = e1.UpdateProfile(ctx1, userID,
		map[string]privacy.ProfileField{"nickname": {Value: "jo", Hint: privacy.HintGeneric}}, nil)
	if !errors.Is(err, privacy.ErrInvalidInput) {
		t.Fatalf("h1 undefined key = %v, want ErrInvalidInput", err)
	}
	// ...and so is a hint that disagrees with the definition.
	_, err = e1.UpdateProfile(ctx1, userID,
		map[string]privacy.ProfileField{"email": {Value: "a@b.c", Hint: privacy.HintGeneric}}, nil)
	if !errors.Is(err, privacy.ErrInvalidInput) {
		t.Fatalf("h1 conflicting hint = %v, want ErrInvalidInput", err)
	}

	// h2 is free-form: the same undefined key is accepted.
	if _, err := e2.UpdateProfile(ctx2, userID,
		map[string]privacy.ProfileField{"nickname": {Value: "jo", Hint: privacy.HintGeneric}}, nil); err != nil {
		t.Fatalf("h2 free-form write: %v", err)
	}
	got, err := e2.GetProfile(ctx2, userID, false)
	if err != nil {
		t.Fatalf("h2 GetProfile: %v", err)
	}
	if _, ok := got.Fields["nickname"]; !ok {
		t.Error("h2 did not store the free-form field")
	}
}

// The mounted HTTP API serves whichever instance the request context selects.
func TestHTTPRequestFollowsContextInstance(t *testing.T) {
	srv, h1, h2 := twoInstanceServer(t)
	userID := uuid.NewString()
	ctx1 := instanceCtx(t, "h1")
	t.Cleanup(func() {
		for _, p := range []*pgxpool.Pool{h1, h2} {
			_, _ = p.Exec(context.Background(),
				`delete from dilion_pii.user_profiles where user_id = $1::uuid`, userID)
			_, _ = p.Exec(context.Background(),
				`delete from dilion_pii.subject_keys where user_id = $1::uuid`, userID)
		}
	})

	e1, err := srv.instances.Engine(ctx1)
	if err != nil {
		t.Fatalf("engine h1: %v", err)
	}
	if _, err := e1.UpdateProfile(ctx1, userID,
		map[string]privacy.ProfileField{"full_name": {Value: "홍길동"}}, nil); err != nil {
		t.Fatalf("h1 UpdateProfile: %v", err)
	}

	// Each request carries a token minted by the instance it targets: tokens
	// are bound to their instance by key material (TestTokenIsBoundToInstance).
	get := func(instance string) *httptest.ResponseRecorder {
		tokens, err := srv.instances.TokensFor(context.Background(), instance)
		if err != nil {
			t.Fatalf("tokens %s: %v", instance, err)
		}
		token, err := tokens.Sign(context.Background(), ports.Claims{
			Subject:   "svc-1",
			Role:      "service_role",
			Audience:  "authenticated",
			ExpiresAt: time.Now().Add(time.Hour),
		})
		if err != nil {
			t.Fatalf("sign %s: %v", instance, err)
		}
		req := httptest.NewRequest(http.MethodGet, "/privacy/v1/users/"+userID+"/profile", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req = req.WithContext(ports.ContextWithInstance(req.Context(), instance))
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	rec := get("h1")
	if rec.Code != http.StatusOK {
		t.Fatalf("h1 status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Fields map[string]struct {
			Value string `json:"value"`
			Hint  string `json:"hint"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Fields["full_name"].Hint != "NAME" || body.Fields["full_name"].Value != "홍**" {
		t.Errorf("h1 field = %+v, want the masked NAME projection", body.Fields["full_name"])
	}

	// Same request, other instance: the subject does not exist there.
	if rec := get("h2"); rec.Code != http.StatusNotFound {
		t.Fatalf("h2 status = %d, want 404 (%s)", rec.Code, rec.Body.String())
	}
}

// A token is bound to the instance that minted it by that instance's key
// material, not by a claim: the same user UUID exists in both databases, yet
// h1's token is rejected at h2's /auth/v1/user. The same signature check is
// what any PostgREST trusting h2's keys performs, so the guarantee holds
// outside Dilion's middleware too.
func TestTokenIsBoundToInstance(t *testing.T) {
	srv, h1, h2 := twoInstanceServer(t)
	userID := uuid.NewString()
	ctx1, ctx2 := instanceCtx(t, "h1"), instanceCtx(t, "h2")
	t.Cleanup(func() {
		for _, p := range []*pgxpool.Pool{h1, h2} {
			_, _ = p.Exec(context.Background(), `delete from auth.users where id = $1::uuid`, userID)
		}
	})
	for name, pool := range map[string]*pgxpool.Pool{"h1": h1, "h2": h2} {
		if _, err := pool.Exec(context.Background(),
			`insert into auth.users (id, aud, role, email) values ($1::uuid,'authenticated','authenticated',$2)`,
			userID, "same@example.com"); err != nil {
			t.Fatalf("%s insert user: %v", name, err)
		}
	}

	t1, err := srv.instances.TokensFor(ctx1, "h1")
	if err != nil {
		t.Fatalf("tokens h1: %v", err)
	}
	token, err := t1.Sign(ctx1, ports.Claims{Subject: userID, Role: "authenticated", Email: "same@example.com"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	get := func(path, instance string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req = req.WithContext(ports.ContextWithInstance(req.Context(), instance))
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}
	if rec := get("/auth/v1/user", "h1"); rec.Code != http.StatusOK {
		t.Fatalf("h1 /auth/v1/user = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	rec := get("/auth/v1/user", "h2")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("h2 /auth/v1/user = %d, want 403 — h1's token was accepted by h2 (%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Code string `json:"error_code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Code != "bad_jwt" {
		t.Errorf("h2 error_code = %q (%v), want bad_jwt: %s", body.Code, err, rec.Body.String())
	}
	// Dilion's own API verifies through the same per-instance keys.
	if rec := get("/privacy/v1/me/consents", "h1"); rec.Code != http.StatusOK {
		t.Errorf("h1 /privacy/v1/me/consents = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if rec := get("/privacy/v1/me/consents", "h2"); rec.Code != http.StatusUnauthorized {
		t.Errorf("h2 /privacy/v1/me/consents = %d, want 401 (%s)", rec.Code, rec.Body.String())
	}

	// Discovery is per instance too: each advertises its own issuer.
	issuers := map[string]string{}
	for _, id := range []string{"h1", "h2"} {
		rec := get("/auth/v1/.well-known/openid-configuration", id)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s discovery = %d", id, rec.Code)
		}
		var doc struct {
			Issuer string `json:"issuer"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("%s discovery body: %v", id, err)
		}
		issuers[id] = doc.Issuer
	}
	if issuers["h1"] != "https://h1.example/auth/v1" || issuers["h2"] != "https://h2.example/auth/v1" {
		t.Errorf("issuers = %v, want each instance's own", issuers)
	}
	_ = ctx2
}

// MigrateInstance provisions ONE instance, which is what adding an instance to
// a running deployment needs. It reaches an instance the resolver does not list
// yet, and it does not touch the others.
func TestMigrateInstance(t *testing.T) {
	srv, h1, _ := twoInstanceServer(t)
	ctx := context.Background()

	// An id the resolver serves a pool for but does not list: List returns
	// h1 and h2 only, so Migrate would never reach it.
	const id = unlistedInstance
	if err := srv.MigrateInstance(ctx, id); err != nil {
		t.Fatalf("MigrateInstance(%s): %v", id, err)
	}
	var exists bool
	if err := h1.QueryRow(ctx,
		`select to_regclass('dilion_pii.user_profiles') is not null`).Scan(&exists); err != nil {
		t.Fatalf("to_regclass: %v", err)
	}
	if !exists {
		t.Error("the instance's schema is not in place after MigrateInstance")
	}

	// Re-running is a no-op rather than an error, so provisioning can be retried.
	if err := srv.MigrateInstance(ctx, id); err != nil {
		t.Fatalf("second MigrateInstance: %v", err)
	}

	// An instance the resolver cannot serve fails, and names itself.
	err := srv.MigrateInstance(ctx, "nope")
	if err == nil {
		t.Fatal("MigrateInstance for an unknown instance succeeded")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error = %v, want it to name the instance", err)
	}
}

// Hooks are registered once for the whole server. An in-process hook tells the
// instances apart by its context, which carries the instance the event
// happened in — not whichever instance happens to be the default.
func TestHooksSeeTheirInstance(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []string
	)
	srv, h1, h2 := twoInstanceServer(t, WithHook(AfterSignup,
		func(ctx context.Context, _ map[string]any) (map[string]any, error) {
			mu.Lock()
			seen = append(seen, ports.InstanceFromContext(ctx))
			mu.Unlock()
			return nil, nil
		}))
	email := "hook-" + uuid.NewString()[:8] + "@example.com"
	t.Cleanup(func() {
		for _, p := range []*pgxpool.Pool{h1, h2} {
			_, _ = p.Exec(context.Background(), `delete from auth.users where email = $1`, email)
		}
	})

	body := strings.NewReader(`{"email":"` + email + `","password":"correct-horse-battery"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/v1/signup", body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(ports.ContextWithInstance(req.Context(), "h2"))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("signup on h2 = %d; body = %s", rec.Code, rec.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != "h2" {
		t.Errorf("AfterSignup saw instances %v, want [h2]", seen)
	}
}

// An auth hook set through one instance's /admin/hooks runs for that instance
// only: the setting lives in the instance's own database.
func TestAuthHookSettingIsPerInstance(t *testing.T) {
	srv, h1, h2 := twoInstanceServer(t)
	emails := []string{"hooked-" + uuid.NewString()[:8] + "@example.com", "free-" + uuid.NewString()[:8] + "@example.com"}
	t.Cleanup(func() {
		for _, p := range []*pgxpool.Pool{h1, h2} {
			_, _ = p.Exec(context.Background(), `delete from dilion_auth.hooks`)
			_, _ = p.Exec(context.Background(), `delete from auth.users where email = any($1)`, emails)
		}
	})
	if _, err := h1.Exec(context.Background(), `
		create schema if not exists hooktest;
		create or replace function hooktest.h1_only(input jsonb) returns jsonb language sql as $$
			select '{"error":{"http_code":403,"message":"h1 says no"}}'::jsonb
		$$;`); err != nil {
		t.Fatalf("create h1 hook function: %v", err)
	}

	send := func(instance, method, path, body string) *httptest.ResponseRecorder {
		tokens, err := srv.instances.TokensFor(context.Background(), instance)
		if err != nil {
			t.Fatalf("tokens %s: %v", instance, err)
		}
		token, err := tokens.Sign(context.Background(), ports.Claims{
			Subject: uuid.NewString(), Role: "service_role", Audience: "authenticated",
			ExpiresAt: time.Now().Add(time.Hour),
		})
		if err != nil {
			t.Fatalf("sign %s: %v", instance, err)
		}
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req = req.WithContext(ports.ContextWithInstance(req.Context(), instance))
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}
	signup := func(instance, email string) int {
		return send(instance, http.MethodPost, "/auth/v1/signup",
			`{"email":"`+email+`","password":"correct-horse-battery"}`).Code
	}

	if rec := send("h1", http.MethodPut, "/auth/v1/admin/hooks/before_user_created",
		`{"enabled":true,"uri":"pg-functions://dilion/hooktest/h1_only"}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT on h1 = %d %s", rec.Code, rec.Body.String())
	}
	if code := signup("h1", emails[0]); code != http.StatusForbidden {
		t.Errorf("signup on h1 = %d, want its hook's 403", code)
	}
	if code := signup("h2", emails[1]); code != http.StatusOK {
		t.Errorf("signup on h2 = %d, want 200: h1's hook must not run there", code)
	}
	if rec := send("h2", http.MethodGet, "/auth/v1/admin/hooks/before_user_created", ""); !strings.Contains(rec.Body.String(), `"source":"server"`) {
		t.Errorf("h2 view = %s, want the server setting", rec.Body.String())
	}
}

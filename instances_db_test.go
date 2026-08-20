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
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-project/dilion/internal/kmslocal"
	"github.com/dilion-project/dilion/internal/privacy"
	"github.com/dilion-project/dilion/internal/store"
	"github.com/dilion-project/dilion/ports"
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
	pii   map[string][]byte
}

func (r *twoInstances) get(id string) error {
	if _, ok := r.pools[id]; !ok {
		return errors.New("unknown instance " + id)
	}
	return nil
}

func (r *twoInstances) Pool(_ context.Context, id string) (*pgxpool.Pool, error) {
	return r.pools[id], r.get(id)
}

func (r *twoInstances) KMS(_ context.Context, id string) (ports.KMS, error) {
	return r.kms[id], r.get(id)
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
func twoInstanceServer(t *testing.T) (*Server, *pgxpool.Pool, *pgxpool.Pool) {
	t.Helper()
	if os.Getenv("DILION_TEST_DB") == "" {
		t.Skip("DILION_TEST_DB not set")
	}
	h1 := testPool(t, "DILION_TEST_DB_DSN_H1", defaultH1DSN)
	h2 := testPool(t, "DILION_TEST_DB_DSN_H2", defaultH2DSN)

	key := make([]byte, kmslocal.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	res := &twoInstances{
		pools: map[string]*pgxpool.Pool{"h1": h1, "h2": h2},
		kms: map[string]ports.KMS{
			"h1": kmslocal.New(h1, key),
			"h2": kmslocal.New(h2, key),
		},
		pii: map[string][]byte{"h1": h1PIIFields}, // h2: free-form
	}

	srv, err := NewServer(
		WithInstanceResolver(res),
		WithMasterKey(key),
		WithJWTSecret([]byte("test-secret-test-secret-test-sec")),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
	)
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
	if _, err := e1.UpdateProfile(ctx1, "default", userID,
		map[string]privacy.ProfileField{"email": {Value: "joseph@example.com"}}, nil); err != nil {
		t.Fatalf("h1 UpdateProfile: %v", err)
	}
	got, err := e1.GetProfile(ctx1, "default", userID, false)
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
	if _, err := e2.GetProfile(ctx2, "default", userID, false); !errors.Is(err, privacy.ErrNotFound) {
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
	_, err = e1.UpdateProfile(ctx1, "default", userID,
		map[string]privacy.ProfileField{"nickname": {Value: "jo", Hint: privacy.HintGeneric}}, nil)
	if !errors.Is(err, privacy.ErrInvalidInput) {
		t.Fatalf("h1 undefined key = %v, want ErrInvalidInput", err)
	}
	// ...and so is a hint that disagrees with the definition.
	_, err = e1.UpdateProfile(ctx1, "default", userID,
		map[string]privacy.ProfileField{"email": {Value: "a@b.c", Hint: privacy.HintGeneric}}, nil)
	if !errors.Is(err, privacy.ErrInvalidInput) {
		t.Fatalf("h1 conflicting hint = %v, want ErrInvalidInput", err)
	}

	// h2 is free-form: the same undefined key is accepted.
	if _, err := e2.UpdateProfile(ctx2, "default", userID,
		map[string]privacy.ProfileField{"nickname": {Value: "jo", Hint: privacy.HintGeneric}}, nil); err != nil {
		t.Fatalf("h2 free-form write: %v", err)
	}
	got, err := e2.GetProfile(ctx2, "default", userID, false)
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
	if _, err := e1.UpdateProfile(ctx1, "default", userID,
		map[string]privacy.ProfileField{"full_name": {Value: "홍길동"}}, nil); err != nil {
		t.Fatalf("h1 UpdateProfile: %v", err)
	}

	token, err := srv.tokens.Sign(context.Background(), ports.Claims{
		Subject:   "svc-1",
		Role:      "service_role",
		Audience:  "authenticated",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	get := func(instance string) *httptest.ResponseRecorder {
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

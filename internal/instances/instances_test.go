package instances

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/ports"
)

type fakeKMS struct{ ports.KMS }

func TestStaticResolverServesOnlyItsOwnInstance(t *testing.T) {
	kms := fakeKMS{}
	policy := []byte("compliance: {}")
	pii := []byte("pii-fields: {email: {hint: EMAIL}}")
	r := NewStaticResolver("", nil, kms, ports.JWTKeys{Secret: "s"}, policy, pii)

	if r.ID() != ports.DefaultInstanceID {
		t.Fatalf("ID = %q, want %q", r.ID(), ports.DefaultInstanceID)
	}
	ctx := context.Background()

	ids, err := r.List(ctx)
	if err != nil || len(ids) != 1 || ids[0] != ports.DefaultInstanceID {
		t.Fatalf("List = (%v, %v), want ([default], nil)", ids, err)
	}

	// The configured instance answers with the configured values.
	if got, err := r.KMS(ctx, ports.DefaultInstanceID); err != nil || got != ports.KMS(kms) {
		t.Fatalf("KMS = (%v, %v), want the configured KMS", got, err)
	}
	if got, err := r.PolicyYAML(ctx, ports.DefaultInstanceID); err != nil || string(got) != string(policy) {
		t.Fatalf("PolicyYAML = (%q, %v), want the configured document", got, err)
	}
	if got, err := r.PIIFields(ctx, ports.DefaultInstanceID); err != nil || string(got) != string(pii) {
		t.Fatalf("PIIFields = (%q, %v), want the configured document", got, err)
	}
	if got, err := r.Pool(ctx, ports.DefaultInstanceID); err != nil || got != (*pgxpool.Pool)(nil) {
		t.Fatalf("Pool = (%v, %v), want (nil, nil)", got, err)
	}

	// Any other instance id is an error on every method: a single-instance
	// deployment must never silently serve a foreign instance's request.
	for _, probe := range []struct {
		name string
		call func() error
	}{
		{"Pool", func() error { _, err := r.Pool(ctx, "other"); return err }},
		{"KMS", func() error { _, err := r.KMS(ctx, "other"); return err }},
		{"PolicyYAML", func() error { _, err := r.PolicyYAML(ctx, "other"); return err }},
		{"PIIFields", func() error { _, err := r.PIIFields(ctx, "other"); return err }},
	} {
		if err := probe.call(); !errors.Is(err, ErrUnknownInstance) {
			t.Errorf("%s(other) error = %v, want ErrUnknownInstance", probe.name, err)
		}
	}
}

func TestStaticResolverCustomID(t *testing.T) {
	r := NewStaticResolver("h1", nil, nil, ports.JWTKeys{Secret: "s"}, nil, nil)
	ids, err := r.List(context.Background())
	if err != nil || len(ids) != 1 || ids[0] != "h1" {
		t.Fatalf("List = (%v, %v), want ([h1], nil)", ids, err)
	}
	if _, err := r.Pool(context.Background(), ports.DefaultInstanceID); !errors.Is(err, ErrUnknownInstance) {
		t.Fatalf("Pool(default) error = %v, want ErrUnknownInstance", err)
	}
}

func TestRegistryRequiresResolver(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New without a resolver succeeded, want an error")
	}
}

// The registry resolves against the instance selected on the context, not the
// process-wide default.
func TestRegistryUsesContextInstance(t *testing.T) {
	reg, err := New(Config{Resolver: NewStaticResolver("h1", nil, nil, ports.JWTKeys{Secret: "s"}, nil, nil), TombstoneKey: []byte("k")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := reg.Pool(ctx); err == nil {
		t.Fatal("Pool with the default instance succeeded, want an error")
	}
	// Selecting h1 reaches the resolver, which has no pool configured — the
	// "no pool" error proves the id was routed, the unknown-instance error
	// would prove the opposite.
	_, err = reg.Pool(ports.ContextWithInstance(ctx, "h1"))
	if err == nil || errors.Is(err, ErrUnknownInstance) {
		t.Fatalf("Pool(h1) error = %v, want a nil-pool error", err)
	}
}

func TestCurrentDefaultsToDefaultInstance(t *testing.T) {
	if got := Current(context.Background()); got != ports.DefaultInstanceID {
		t.Fatalf("Current = %q, want %q", got, ports.DefaultInstanceID)
	}
	if got := Current(ports.ContextWithInstance(context.Background(), "h2")); got != "h2" {
		t.Fatalf("Current = %q, want h2", got)
	}
}

// twoKeyResolver serves two instances that differ only in JWT key material.
type twoKeyResolver struct {
	*StaticResolver
	keys map[string]ports.JWTKeys
}

func (r twoKeyResolver) JWT(_ context.Context, id string) (ports.JWTKeys, error) {
	k, ok := r.keys[id]
	if !ok {
		return ports.JWTKeys{}, ErrUnknownInstance
	}
	return k, nil
}

func (r twoKeyResolver) List(context.Context) ([]string, error) { return []string{"h1", "h2"}, nil }

// Each instance gets its own token service, built from its own keys, and the
// registry's Verify uses the keys of the instance on the context: a token
// minted for h1 is rejected under h2.
func TestRegistryTokensAreBoundToInstance(t *testing.T) {
	res := twoKeyResolver{
		StaticResolver: NewStaticResolver("h1", nil, nil, ports.JWTKeys{}, nil, nil),
		keys: map[string]ports.JWTKeys{
			"h1": {Secret: "h1-secret-h1-secret-h1-secret-h1"},
			"h2": {Secret: "h2-secret-h2-secret-h2-secret-h2"},
		},
	}
	reg, err := New(Config{Resolver: res, TombstoneKey: []byte("k")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx1 := ports.ContextWithInstance(context.Background(), "h1")
	ctx2 := ports.ContextWithInstance(context.Background(), "h2")

	t1, err := reg.Tokens(ctx1)
	if err != nil {
		t.Fatalf("Tokens(h1): %v", err)
	}
	t2, err := reg.Tokens(ctx2)
	if err != nil {
		t.Fatalf("Tokens(h2): %v", err)
	}
	if t1 == t2 {
		t.Fatal("both instances share one token service")
	}
	if again, _ := reg.Tokens(ctx1); again != t1 {
		t.Error("token service not cached per instance")
	}

	token, err := t1.Sign(ctx1, ports.Claims{Subject: "u1"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := reg.Verify(ctx1, token); err != nil {
		t.Errorf("h1 token rejected under h1: %v", err)
	}
	if _, err := reg.Verify(ctx2, token); err == nil {
		t.Error("h1 token verified under h2")
	}
	if _, err := reg.Tokens(ports.ContextWithInstance(context.Background(), "nope")); err == nil {
		t.Error("Tokens for an unknown instance succeeded")
	}
}

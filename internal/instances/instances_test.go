package instances

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-project/dilion/ports"
)

type fakeKMS struct{ ports.KMS }

func TestStaticResolverServesOnlyItsOwnInstance(t *testing.T) {
	kms := fakeKMS{}
	policy := []byte("compliance: {}")
	pii := []byte("pii-fields: {email: {hint: EMAIL}}")
	r := NewStaticResolver("", nil, kms, policy, pii)

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
	r := NewStaticResolver("h1", nil, nil, nil, nil)
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
	reg, err := New(Config{Resolver: NewStaticResolver("h1", nil, nil, nil, nil), TombstoneKey: []byte("k")})
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

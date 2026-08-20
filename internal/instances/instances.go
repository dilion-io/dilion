// Package instances resolves the per-request Dilion instance.
//
// An "instance" is a fully isolated database (auth.* + dilion_*), a scope
// larger than a tenant/project. Multi-instance operation is an embedder
// customisation (ports.InstanceResolver + dilion.WithInstanceResolver): the
// built-in daemon and every example run a single instance under
// ports.DefaultInstanceID, served by StaticResolver, and behave exactly as they
// did before instances existed.
//
// Instance selection is entirely the embedder's business: there is no built-in
// HTTP routing and no token↔instance binding. The embedder puts the instance id
// on the context with ports.ContextWithInstance (typically in its own
// middleware) and every Dilion component below resolves its resources from that
// context through a Registry.
//
// Caching: constructed per-instance objects (today: the privacy Engine) are
// cached by instance id and never invalidated. A resolver must therefore return
// stable results for a given id — changing the pool, KMS, policy or PII field
// definitions behind an id requires a restart.
package instances

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/internal/hooks"
	"github.com/dilion-io/dilion/internal/privacy"
	"github.com/dilion-io/dilion/ports"
)

// PoolFunc resolves the database pool of the instance selected on ctx. It is
// the narrow dependency the request-path packages (auth, api, iam, audit) take
// instead of a fixed *pgxpool.Pool.
type PoolFunc func(context.Context) (*pgxpool.Pool, error)

// ---- StaticResolver ----

// StaticResolver is a ports.InstanceResolver over one fixed set of resources.
// It backs the single-instance default: WithPool/WithDSN, WithKMS,
// WithPolicyYAML and WithPIIFieldsYAML are wrapped under ports.DefaultInstanceID.
type StaticResolver struct {
	id     string
	pool   *pgxpool.Pool
	kms    ports.KMS
	policy []byte
	pii    []byte
}

var _ ports.InstanceResolver = (*StaticResolver)(nil)

// NewStaticResolver builds a resolver serving exactly one instance id. An empty
// id defaults to ports.DefaultInstanceID. policyYAML and piiFieldsYAML may be
// nil (built-in policies / free-form PII fields).
func NewStaticResolver(id string, pool *pgxpool.Pool, kms ports.KMS, policyYAML, piiFieldsYAML []byte) *StaticResolver {
	if id == "" {
		id = ports.DefaultInstanceID
	}
	return &StaticResolver{id: id, pool: pool, kms: kms, policy: policyYAML, pii: piiFieldsYAML}
}

// ID is the single instance id this resolver serves.
func (s *StaticResolver) ID() string { return s.id }

func (s *StaticResolver) check(instanceID string) error {
	if instanceID == s.id {
		return nil
	}
	return fmt.Errorf("%w: %q (this deployment serves only %q)", ErrUnknownInstance, instanceID, s.id)
}

func (s *StaticResolver) Pool(_ context.Context, instanceID string) (*pgxpool.Pool, error) {
	if err := s.check(instanceID); err != nil {
		return nil, err
	}
	return s.pool, nil
}

func (s *StaticResolver) KMS(_ context.Context, instanceID string) (ports.KMS, error) {
	if err := s.check(instanceID); err != nil {
		return nil, err
	}
	return s.kms, nil
}

func (s *StaticResolver) PolicyYAML(_ context.Context, instanceID string) ([]byte, error) {
	if err := s.check(instanceID); err != nil {
		return nil, err
	}
	return s.policy, nil
}

func (s *StaticResolver) PIIFields(_ context.Context, instanceID string) ([]byte, error) {
	if err := s.check(instanceID); err != nil {
		return nil, err
	}
	return s.pii, nil
}

func (s *StaticResolver) List(context.Context) ([]string, error) { return []string{s.id}, nil }

// ErrUnknownInstance is returned when a context selects an instance the
// resolver does not serve.
var ErrUnknownInstance = errors.New("instances: unknown instance")

// ---- Registry ----

// Config are the cross-instance dependencies of the Registry. Everything
// instance-specific (pool, KMS, policy, PII field definitions) comes from the
// resolver instead.
type Config struct {
	Resolver ports.InstanceResolver
	// Hooks, Clock, Connectors and TombstoneKey are deployment-wide and shared
	// by every instance's privacy Engine.
	Hooks        *hooks.Registry
	Clock        ports.Clock
	Connectors   map[string]ports.Connector
	TombstoneKey []byte
	Logger       *slog.Logger
}

// Registry resolves instance resources from a context and owns the lazily
// constructed per-instance objects.
type Registry struct {
	cfg Config
	log *slog.Logger

	mu      sync.Mutex
	engines map[string]*privacy.Engine
}

// New builds a Registry over a resolver.
func New(cfg Config) (*Registry, error) {
	if cfg.Resolver == nil {
		return nil, errors.New("instances: Config.Resolver is required")
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	return &Registry{cfg: cfg, log: log.With("component", "instances"), engines: map[string]*privacy.Engine{}}, nil
}

// Resolver exposes the underlying resolver.
func (r *Registry) Resolver() ports.InstanceResolver { return r.cfg.Resolver }

// Current returns the instance id selected on ctx.
func Current(ctx context.Context) string { return ports.InstanceFromContext(ctx) }

// List enumerates the known instance ids.
func (r *Registry) List(ctx context.Context) ([]string, error) { return r.cfg.Resolver.List(ctx) }

// Pool resolves the pool of the instance selected on ctx. Its signature is
// PoolFunc, so it can be handed straight to auth/api/iam/audit.
func (r *Registry) Pool(ctx context.Context) (*pgxpool.Pool, error) {
	return r.PoolFor(ctx, Current(ctx))
}

// PoolFor resolves an explicit instance's pool.
func (r *Registry) PoolFor(ctx context.Context, id string) (*pgxpool.Pool, error) {
	pool, err := r.cfg.Resolver.Pool(ctx, id)
	if err != nil {
		return nil, err
	}
	if pool == nil {
		return nil, fmt.Errorf("instances: no pool for instance %q", id)
	}
	return pool, nil
}

// KMS resolves the KMS of the instance selected on ctx.
func (r *Registry) KMS(ctx context.Context) (ports.KMS, error) { return r.KMSFor(ctx, Current(ctx)) }

// KMSFor resolves an explicit instance's KMS.
func (r *Registry) KMSFor(ctx context.Context, id string) (ports.KMS, error) {
	kms, err := r.cfg.Resolver.KMS(ctx, id)
	if err != nil {
		return nil, err
	}
	if kms == nil {
		return nil, fmt.Errorf("instances: no KMS for instance %q", id)
	}
	return kms, nil
}

// PolicyYAML resolves the compliance policy document of the instance on ctx.
func (r *Registry) PolicyYAML(ctx context.Context) ([]byte, error) {
	return r.cfg.Resolver.PolicyYAML(ctx, Current(ctx))
}

// PIIFields resolves the fixed PII field definitions of the instance on ctx.
func (r *Registry) PIIFields(ctx context.Context) ([]byte, error) {
	return r.cfg.Resolver.PIIFields(ctx, Current(ctx))
}

// Engine returns the compliance engine of the instance selected on ctx,
// constructing it on first use. Engines are cached per instance id forever.
func (r *Registry) Engine(ctx context.Context) (*privacy.Engine, error) {
	return r.EngineFor(ctx, Current(ctx))
}

// EngineFor returns an explicit instance's compliance engine.
func (r *Registry) EngineFor(ctx context.Context, id string) (*privacy.Engine, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.engines[id]; ok {
		return e, nil
	}
	pool, err := r.PoolFor(ctx, id)
	if err != nil {
		return nil, err
	}
	kms, err := r.KMSFor(ctx, id)
	if err != nil {
		return nil, err
	}
	policy, err := r.cfg.Resolver.PolicyYAML(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("instances: policy for instance %q: %w", id, err)
	}
	pii, err := r.cfg.Resolver.PIIFields(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("instances: pii fields for instance %q: %w", id, err)
	}
	// NewEngine performs no I/O: it only validates and loads policy data, so
	// holding the registry lock here is cheap.
	e, err := privacy.NewEngine(privacy.EngineDeps{
		Pool:          pool,
		KMS:           kms,
		Hooks:         r.cfg.Hooks,
		Clock:         r.cfg.Clock,
		PolicyYAML:    policy,
		PIIFieldsYAML: pii,
		Connectors:    r.cfg.Connectors,
		TombstoneKey:  r.cfg.TombstoneKey,
	})
	if err != nil {
		return nil, fmt.Errorf("instances: engine for instance %q: %w", id, err)
	}
	r.engines[id] = e
	return e, nil
}

// PrivacyService is the api.ServiceProvider form of Engine.
func (r *Registry) PrivacyService(ctx context.Context) (privacy.Service, error) {
	e, err := r.Engine(ctx)
	if err != nil {
		return nil, err
	}
	return e, nil
}

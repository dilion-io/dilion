package iam

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/ports"
)

type authorizer struct {
	pools PoolFunc
}

// NewAuthorizer returns the builtin RBAC Authorizer (§2.11): deny-by-default,
// decided from active role assignments plus (for API key
// actors) the key's own scopes. It decides only — callers still audit the
// decision and apply masked-by-default projections.
//
// The pool is fixed: every decision is made against it. Multi-instance
// deployments use NewAuthorizerFor instead, which resolves the pool of the
// instance selected on the request context.
func NewAuthorizer(pool *pgxpool.Pool) ports.Authorizer {
	return &authorizer{pools: StaticPool(pool)}
}

// NewAuthorizerFor returns the builtin RBAC Authorizer over a per-request pool
// provider (internal/instances.Registry.Pool).
func NewAuthorizerFor(pools PoolFunc) ports.Authorizer { return &authorizer{pools: pools} }

// Can reports whether actor holds permission. resource is accepted for
// interface compatibility but is not consulted: the model is flat RBAC, not
// ABAC/ReBAC, so that "who can do what" stays enumerable for audits (§2.11).
func (a *authorizer) Can(ctx context.Context, actor ports.Actor, permission string, resource string) (bool, error) {
	// service_role is the Supabase-compatible all-powerful key. It is allowed
	// unconditionally; its every use is a "매우 민감" audit event recorded by the
	// caller (§2.11 Machine key).
	if actor.Type == ActorTypeServiceRole {
		return true, nil
	}
	if actor.ID == "" || permission == "" {
		return false, nil
	}
	pool, err := resolvePool(ctx, a.pools)
	if err != nil {
		return false, err
	}

	var allowed bool
	err = pool.QueryRow(ctx, `
		select
			exists(
				select 1
				from dilion_authz.role_assignments ra
				join dilion_authz.roles r
				  on r.id = ra.role_id
				where ra.actor_id = $1
				  and ra.revoked_at is null
				  and $2 = any(r.permissions)
			)
			or exists(
				select 1
				from dilion_authz.api_keys k
				where k.id = $1
				  and k.revoked_at is null
				  and (k.expires_at is null or k.expires_at > now())
				  and $2 = any(k.scopes)
			)`, actor.ID, permission).Scan(&allowed)
	if err != nil {
		return false, fmt.Errorf("iam: authorize: %w", err)
	}
	return allowed, nil
}

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

// Permissions lists the permissions actor holds through its active role
// assignments (plus, for an API key, its scopes).
func (a *authorizer) Permissions(ctx context.Context, actor ports.Actor) ([]string, error) {
	if actor.ID == "" {
		return nil, nil
	}
	pool, err := resolvePool(ctx, a.pools)
	if err != nil {
		return nil, err
	}
	var perms []string
	if err := pool.QueryRow(ctx, `
		select coalesce(array_agg(distinct p), '{}') from (
			select unnest(r.permissions) as p
			from dilion_authz.role_assignments ra
			join dilion_authz.roles r on r.id = ra.role_id
			where ra.actor_id = $1 and ra.revoked_at is null
			union
			select p from dilion_authz.api_keys k, unnest(k.scopes) p
			where k.id = $1 and k.revoked_at is null
			  and (k.expires_at is null or k.expires_at > now())
			  and (k.created_by_type is distinct from 'user' or exists(
				select 1
				from dilion_authz.role_assignments cra
				join dilion_authz.roles cr on cr.id = cra.role_id
				where cra.actor_id = k.created_by
				  and cra.revoked_at is null
				  and p = any(cr.permissions)))
		) held`, actor.ID).Scan(&perms); err != nil {
		return nil, fmt.Errorf("iam: permissions: %w", err)
	}
	return perms, nil
}

var _ ports.PermissionLister = (*authorizer)(nil)

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
				  -- A key a user issued holds nothing its creator no longer does.
				  and (k.created_by_type is distinct from 'user' or exists(
					select 1
					from dilion_authz.role_assignments cra
					join dilion_authz.roles cr on cr.id = cra.role_id
					where cra.actor_id = k.created_by
					  and cra.revoked_at is null
					  and $2 = any(cr.permissions)))
			)`, actor.ID, permission).Scan(&allowed)
	if err != nil {
		return false, fmt.Errorf("iam: authorize: %w", err)
	}
	return allowed, nil
}

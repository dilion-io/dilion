// Package iam implements the management-plane RBAC of project.md §2.11:
// flat permission strings bundled into roles, history-preserving role
// assignments (grant/revoke rows are never deleted — 안전성 확보조치 기준 제5조),
// scoped API keys, and the default Authorizer.
//
// The Authorizer only decides. Audit logging and masked-by-default projections
// are enforced by callers (internal/api) regardless of which Authorizer is
// installed.
package iam

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/dilion-io/dilion/httpapi"
)

// Actor types (ports.Actor.Type).
const (
	ActorTypeAdmin  = "admin"
	ActorTypeAPIKey = "api_key"
	// ActorTypeUser is a regular end-user access token (`role=authenticated`)
	// acting on the management plane. Its authority comes exclusively from
	// role_assignments keyed by the user UUID (§2.11, deny-by-default).
	ActorTypeUser        = "user"
	ActorTypeServiceRole = "service_role"
)

// RoleAuthenticated is the Supabase JWT `role` claim of a regular signed-in
// user. It mirrors auth.RoleAuthenticated (the packages must not import each
// other).
const RoleAuthenticated = "authenticated"

// Builtin permissions (§2.11). Un-namespaced names are reserved: custom
// permissions must be namespaced and may not collide with these.
const (
	PermUsersRead = "users.read"
	PermPIIRead   = "pii.read"
	PermPIIReveal = "pii.reveal"
	PermPIIExport = "pii.export"
	// PermPIIWrite guards mutation of a subject's stored personal data
	// (§5.2 "개인정보 수정"). Seeded by migration 0302.
	PermPIIWrite = "pii.write"
	// PermConsentsWrite guards recording a consent change (ledger append). It
	// is deliberately separate from privacy.requests.manage so a signup-flow
	// API key can record consent without holding DSR authority. Seeded by
	// migration 0304.
	PermConsentsWrite         = "consents.write"
	PermPrivacyRequestsManage = "privacy.requests.manage"
	PermHoldsManage           = "holds.manage"
	PermPoliciesManage        = "policies.manage"
	PermDestinationsManage    = "destinations.manage"
	PermKeysManage            = "keys.manage"
	PermAuditRead             = "audit.read"
	// PermUsersAdmin authorises the Supabase-compatible admin surface
	// (/auth/v1/admin/*) for a regular user access token. Seeded by migration
	// 0303 and bundled into the builtin `owner` role only.
	PermUsersAdmin = "users.admin"
)

// BuiltinPermissions is the authoritative list seeded by migrations 0300
// (all but pii.write), 0302 (pii.write), 0303 (users.admin) and 0304
// (consents.write).
var BuiltinPermissions = []string{
	PermUsersRead, PermPIIRead, PermPIIReveal, PermPIIWrite, PermPIIExport,
	PermConsentsWrite, PermPrivacyRequestsManage, PermHoldsManage, PermPoliciesManage,
	PermDestinationsManage, PermKeysManage, PermAuditRead, PermUsersAdmin,
}

// Builtin role ids seeded by migration 0300.
const (
	RoleViewer         = "role_00000000000000000000000000000001"
	RoleSupport        = "role_00000000000000000000000000000002"
	RolePrivacyOfficer = "role_00000000000000000000000000000003"
	RoleSecurityAdmin  = "role_00000000000000000000000000000004"
	RoleOwner          = "role_00000000000000000000000000000005"
)

// customPermissionRe enforces the namespace requirement of §2.11
// (e.g. `myapp.orders.refund`).
var customPermissionRe = regexp.MustCompile(`^[a-z][a-z0-9-]*\.[a-z0-9.-]+$`)

// ---- Sentinel errors (internal/api maps these to problem+json codes) ----

type Error string

func (e Error) Error() string { return string(e) }

const (
	ErrNotFound        Error = "iam: not found"
	ErrConflict        Error = "iam: conflict"
	ErrInvalid         Error = "iam: invalid argument"
	ErrUnauthenticated Error = "iam: invalid credentials"
	ErrBuiltin         Error = "iam: builtin object is immutable"
)

// ---- Models ----

type Permission struct {
	Name      string
	Builtin   bool
	CreatedAt time.Time
}

type Role struct {
	ID          string
	Name        string
	Permissions []string
	Builtin     bool
	CreatedAt   time.Time
}

type Assignment struct {
	ID        int64
	ActorID   string
	RoleID    string
	GrantedBy *string
	GrantedAt time.Time
	RevokedBy *string
	RevokedAt *time.Time
}

// Holder is one row of the CC6.3 recertification report: an actor currently
// holding a permission, together with the grant metadata that justifies it.
type Holder struct {
	ActorID   string
	RoleID    string
	RoleName  string
	GrantedBy *string
	GrantedAt time.Time
}

type APIKey struct {
	ID         string
	Name       *string
	Scopes     []string
	CreatedAt  time.Time
	CreatedBy  *string
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
}

// Active reports whether the key may still authenticate at time now.
func (k APIKey) Active(now time.Time) bool {
	if k.RevokedAt != nil {
		return false
	}
	if k.ExpiresAt != nil && !k.ExpiresAt.After(now) {
		return false
	}
	return true
}

// ---- Service ----

// Service is the RBAC + API key store. It is safe for concurrent use.
type Service struct {
	pools PoolFunc
	now   func() time.Time
}

// New builds the service over one fixed pool (single-instance default).
func New(pool *pgxpool.Pool) *Service { return NewFor(StaticPool(pool)) }

// NewFor builds the service over a per-request pool provider, so each call is
// served by the database of the instance selected on the context.
func NewFor(pools PoolFunc) *Service {
	return &Service{pools: pools, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) clock() time.Time {
	if s.now == nil {
		return time.Now().UTC()
	}
	return s.now()
}

// db resolves the pool for this request's instance.
func (s *Service) db(ctx context.Context) (*pgxpool.Pool, error) {
	if s == nil {
		return nil, fmt.Errorf("iam: nil pool")
	}
	return resolvePool(ctx, s.pools)
}

// ---- Permissions ----

// ValidateCustomPermission enforces §2.11: custom permissions must be
// namespaced and must not collide with a builtin (un-namespaced) permission.
func ValidateCustomPermission(name string) error {
	if !customPermissionRe.MatchString(name) {
		return fmt.Errorf("%w: permission %q must be namespaced (e.g. myapp.orders.refund)", ErrInvalid, name)
	}
	if slices.Contains(BuiltinPermissions, name) {
		return fmt.Errorf("%w: permission %q collides with a builtin permission", ErrInvalid, name)
	}
	return nil
}

// CreatePermission registers a custom (namespaced) permission.
func (s *Service) CreatePermission(ctx context.Context, name string) (Permission, error) {
	pool, err := s.db(ctx)
	if err != nil {
		return Permission{}, err
	}
	if err := ValidateCustomPermission(name); err != nil {
		return Permission{}, err
	}
	p := Permission{Name: name}
	err = pool.QueryRow(ctx, `
		insert into dilion_authz.permissions (name, builtin)
		values ($1,false)
		on conflict (name) do nothing
		returning created_at`, name).Scan(&p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Permission{}, fmt.Errorf("%w: permission %q already exists", ErrConflict, name)
	}
	if err != nil {
		return Permission{}, fmt.Errorf("iam: create permission: %w", err)
	}
	return p, nil
}

func (s *Service) ListPermissions(ctx context.Context, p httpapi.ListParams) (httpapi.Page[Permission], error) {
	var page httpapi.Page[Permission]
	pool, err := s.db(ctx)
	if err != nil {
		return page, err
	}
	p = p.Norm()
	after, err := decodeCursor(p.Cursor)
	if err != nil {
		return page, err
	}
	rows, err := pool.Query(ctx, `
		select name, builtin, created_at
		from dilion_authz.permissions
		where $1 = '' or name > $1
		order by name asc limit $2`, after, p.Limit+1)
	if err != nil {
		return page, fmt.Errorf("iam: list permissions: %w", err)
	}
	defer rows.Close()
	items := []Permission{}
	for rows.Next() {
		var it Permission
		if err := rows.Scan(&it.Name, &it.Builtin, &it.CreatedAt); err != nil {
			return page, fmt.Errorf("iam: list permissions: %w", err)
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return page, fmt.Errorf("iam: list permissions: %w", err)
	}
	return paginate(items, p.Limit, func(it Permission) string { return it.Name }), nil
}

// ---- Roles ----

// CreateRole registers a custom role. Every listed permission must already be
// registered (builtin seed or a custom permission).
func (s *Service) CreateRole(ctx context.Context, name string, permissions []string) (Role, error) {
	pool, err := s.db(ctx)
	if err != nil {
		return Role{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Role{}, fmt.Errorf("%w: role name is required", ErrInvalid)
	}
	perms := dedupe(permissions)
	if len(perms) == 0 {
		return Role{}, fmt.Errorf("%w: role must grant at least one permission", ErrInvalid)
	}
	// Every permission must be registered — deny-by-default requires the set of
	// grantable permissions to stay enumerable (§2.11).
	var known []string
	if err := pool.QueryRow(ctx, `
		select coalesce(array_agg(name), '{}')
		from dilion_authz.permissions
		where name = any($1)`, perms).Scan(&known); err != nil {
		return Role{}, fmt.Errorf("iam: create role: %w", err)
	}
	for _, p := range perms {
		if !slices.Contains(known, p) {
			return Role{}, fmt.Errorf("%w: unknown permission %q", ErrInvalid, p)
		}
	}

	r := Role{ID: httpapi.NewID("role"), Name: name, Permissions: perms}
	err = pool.QueryRow(ctx, `
		insert into dilion_authz.roles (id, name, permissions, builtin)
		values ($1,$2,$3,false)
		on conflict (name) do nothing
		returning created_at`, r.ID, name, perms).Scan(&r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Role{}, fmt.Errorf("%w: role %q already exists", ErrConflict, name)
	}
	if err != nil {
		return Role{}, fmt.Errorf("iam: create role: %w", err)
	}
	return r, nil
}

func (s *Service) GetRole(ctx context.Context, roleID string) (Role, error) {
	pool, err := s.db(ctx)
	if err != nil {
		return Role{}, err
	}
	var r Role
	err = pool.QueryRow(ctx, `
		select id, name, permissions, builtin, created_at
		from dilion_authz.roles where id = $1`, roleID).
		Scan(&r.ID, &r.Name, &r.Permissions, &r.Builtin, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Role{}, ErrNotFound
	}
	if err != nil {
		return Role{}, fmt.Errorf("iam: get role: %w", err)
	}
	return r, nil
}

func (s *Service) ListRoles(ctx context.Context, p httpapi.ListParams) (httpapi.Page[Role], error) {
	var page httpapi.Page[Role]
	pool, err := s.db(ctx)
	if err != nil {
		return page, err
	}
	p = p.Norm()
	after, err := decodeCursor(p.Cursor)
	if err != nil {
		return page, err
	}
	rows, err := pool.Query(ctx, `
		select id, name, permissions, builtin, created_at
		from dilion_authz.roles
		where $1 = '' or name > $1
		order by name asc limit $2`, after, p.Limit+1)
	if err != nil {
		return page, fmt.Errorf("iam: list roles: %w", err)
	}
	defer rows.Close()
	items := []Role{}
	for rows.Next() {
		var it Role
		if err := rows.Scan(&it.ID, &it.Name, &it.Permissions, &it.Builtin, &it.CreatedAt); err != nil {
			return page, fmt.Errorf("iam: list roles: %w", err)
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return page, fmt.Errorf("iam: list roles: %w", err)
	}
	return paginate(items, p.Limit, func(it Role) string { return it.Name }), nil
}

// ---- Assignments (history preserving) ----

// GrantRole records a new active assignment. Re-granting an already active
// (actor, role) pair is a conflict — the history table must stay unambiguous.
func (s *Service) GrantRole(ctx context.Context, roleID, actorID, grantedBy string) (Assignment, error) {
	pool, err := s.db(ctx)
	if err != nil {
		return Assignment{}, err
	}
	if strings.TrimSpace(actorID) == "" {
		return Assignment{}, fmt.Errorf("%w: actor_id is required", ErrInvalid)
	}
	if _, err := s.GetRole(ctx, roleID); err != nil {
		return Assignment{}, err
	}
	var active bool
	if err := pool.QueryRow(ctx, `
		select exists(select 1 from dilion_authz.role_assignments
		              where role_id = $1 and actor_id = $2 and revoked_at is null)`,
		roleID, actorID).Scan(&active); err != nil {
		return Assignment{}, fmt.Errorf("iam: grant role: %w", err)
	}
	if active {
		return Assignment{}, fmt.Errorf("%w: actor %q already holds role %q", ErrConflict, actorID, roleID)
	}

	a := Assignment{ActorID: actorID, RoleID: roleID}
	if grantedBy != "" {
		a.GrantedBy = &grantedBy
	}
	if err := pool.QueryRow(ctx, `
		insert into dilion_authz.role_assignments (actor_id, role_id, granted_by, granted_at)
		values ($1,$2,$3,$4) returning id, granted_at`,
		actorID, roleID, a.GrantedBy, s.clock()).Scan(&a.ID, &a.GrantedAt); err != nil {
		return Assignment{}, fmt.Errorf("iam: grant role: %w", err)
	}
	return a, nil
}

// RevokeAssignment marks an assignment revoked. The row is preserved.
func (s *Service) RevokeAssignment(ctx context.Context, id int64, revokedBy string) (Assignment, error) {
	pool, err := s.db(ctx)
	if err != nil {
		return Assignment{}, err
	}
	var by *string
	if revokedBy != "" {
		by = &revokedBy
	}
	var a Assignment
	err = pool.QueryRow(ctx, `
		update dilion_authz.role_assignments
		set revoked_by = $2, revoked_at = $3
		where id = $1 and revoked_at is null
		returning id, actor_id, role_id, granted_by, granted_at, revoked_by, revoked_at`,
		id, by, s.clock()).
		Scan(&a.ID, &a.ActorID, &a.RoleID, &a.GrantedBy, &a.GrantedAt, &a.RevokedBy, &a.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		// Either it does not exist (404) or it is already revoked (409).
		var exists bool
		if err2 := pool.QueryRow(ctx, `select exists(select 1 from dilion_authz.role_assignments
		                                             where id = $1)`,
			id).Scan(&exists); err2 != nil {
			return Assignment{}, fmt.Errorf("iam: revoke assignment: %w", err2)
		}
		if exists {
			return Assignment{}, fmt.Errorf("%w: assignment %d is already revoked", ErrConflict, id)
		}
		return Assignment{}, ErrNotFound
	}
	if err != nil {
		return Assignment{}, fmt.Errorf("iam: revoke assignment: %w", err)
	}
	return a, nil
}

// AssignmentFilter narrows ListAssignments. Zero value = every active
// assignment.
type AssignmentFilter struct {
	RoleID         string
	ActorID        string
	IncludeRevoked bool // history view (권한 이력 = 컴플라이언스 데이터)
}

func (s *Service) ListAssignments(ctx context.Context, f AssignmentFilter, p httpapi.ListParams) (httpapi.Page[Assignment], error) {
	var page httpapi.Page[Assignment]
	pool, err := s.db(ctx)
	if err != nil {
		return page, err
	}
	p = p.Norm()
	after, err := decodeCursor(p.Cursor)
	if err != nil {
		return page, err
	}
	afterID := int64(0)
	if after != "" {
		afterID, err = strconv.ParseInt(after, 10, 64)
		if err != nil {
			return page, fmt.Errorf("%w: malformed cursor", ErrInvalid)
		}
	}
	rows, err := pool.Query(ctx, `
		select id, actor_id, role_id, granted_by, granted_at, revoked_by, revoked_at
		from dilion_authz.role_assignments
		where ($1 = '' or role_id = $1)
		  and ($2 = '' or actor_id = $2)
		  and ($3 or revoked_at is null)
		  and id > $4
		order by id asc limit $5`,
		f.RoleID, f.ActorID, f.IncludeRevoked, afterID, p.Limit+1)
	if err != nil {
		return page, fmt.Errorf("iam: list assignments: %w", err)
	}
	defer rows.Close()
	items := []Assignment{}
	for rows.Next() {
		var it Assignment
		if err := rows.Scan(&it.ID, &it.ActorID, &it.RoleID,
			&it.GrantedBy, &it.GrantedAt, &it.RevokedBy, &it.RevokedAt); err != nil {
			return page, fmt.Errorf("iam: list assignments: %w", err)
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return page, fmt.Errorf("iam: list assignments: %w", err)
	}
	return paginate(items, p.Limit, func(it Assignment) string { return strconv.FormatInt(it.ID, 10) }), nil
}

// Recertification answers "who currently holds permission X, and on what
// grant basis" (CC6.3 recertification report, §2.11).
func (s *Service) Recertification(ctx context.Context, permission string) ([]Holder, error) {
	pool, err := s.db(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(permission) == "" {
		return nil, fmt.Errorf("%w: permission is required", ErrInvalid)
	}
	rows, err := pool.Query(ctx, `
		select ra.actor_id, r.id, r.name, ra.granted_by, ra.granted_at
		from dilion_authz.role_assignments ra
		join dilion_authz.roles r
		  on r.id = ra.role_id
		where ra.revoked_at is null and $1 = any(r.permissions)
		order by ra.actor_id asc, ra.granted_at asc`, permission)
	if err != nil {
		return nil, fmt.Errorf("iam: recertification: %w", err)
	}
	defer rows.Close()
	holders := []Holder{}
	for rows.Next() {
		var h Holder
		if err := rows.Scan(&h.ActorID, &h.RoleID, &h.RoleName, &h.GrantedBy, &h.GrantedAt); err != nil {
			return nil, fmt.Errorf("iam: recertification: %w", err)
		}
		holders = append(holders, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iam: recertification: %w", err)
	}
	return holders, nil
}

// ---- helpers ----

func dedupe(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// paginate trims the (limit+1) probe row and derives the opaque next cursor.
func paginate[T any](items []T, limit int, key func(T) string) httpapi.Page[T] {
	page := httpapi.Page[T]{Items: items}
	if len(items) > limit {
		page.Items = items[:limit]
		c := encodeCursor(key(page.Items[len(page.Items)-1]))
		page.NextCursor = &c
	}
	if page.Items == nil {
		page.Items = []T{}
	}
	return page
}

func encodeCursor(v string) string { return base64.RawURLEncoding.EncodeToString([]byte(v)) }

func decodeCursor(c string) (string, error) {
	if c == "" {
		return "", nil
	}
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return "", fmt.Errorf("%w: malformed cursor", ErrInvalid)
	}
	return string(b), nil
}

package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/dilion-io/dilion/internal/audit"
	"github.com/dilion-io/dilion/internal/iam"
)

// ---- DTOs ----

// Role is a bundle of permissions (§2.11).
type Role struct {
	ID          string    `json:"id" example:"role_1f0c0b6a7d5e4a2b9c8d7e6f5a4b3c2d"`
	Name        string    `json:"name"`
	Permissions []string  `json:"permissions" nullable:"false"`
	Builtin     bool      `json:"builtin" doc:"Builtin roles are seeded by Dilion and cannot be redefined."`
	CreatedAt   time.Time `json:"created_at"`
}

type CreateRoleBody struct {
	Name        string   `json:"name" minLength:"1" doc:"Unique role name within the project."`
	Permissions []string `json:"permissions" nullable:"false" minItems:"1" doc:"Permissions bundled by this role. Each must already be registered."`
}

type RolePage struct {
	Items      []Role  `json:"items" nullable:"false"`
	NextCursor *string `json:"next_cursor" nullable:"true"`
}

// Permission is a flat permission string registered in the project.
type Permission struct {
	Name      string    `json:"name" example:"myapp.orders.refund"`
	Builtin   bool      `json:"builtin"`
	CreatedAt time.Time `json:"created_at"`
}

type CreatePermissionBody struct {
	Name string `json:"name" pattern:"^[a-z][a-z0-9-]*\\.[a-z0-9.-]+$" doc:"Namespaced permission name, e.g. myapp.orders.refund. Builtin names are reserved."`
}

type PermissionPage struct {
	Items      []Permission `json:"items" nullable:"false"`
	NextCursor *string      `json:"next_cursor" nullable:"true"`
}

// RoleAssignment is one grant in the history-preserving assignment ledger.
type RoleAssignment struct {
	ID        int64      `json:"id"`
	ActorID   string     `json:"actor_id"`
	RoleID    string     `json:"role_id"`
	GrantedBy *string    `json:"granted_by" nullable:"true"`
	GrantedAt time.Time  `json:"granted_at"`
	RevokedBy *string    `json:"revoked_by" nullable:"true"`
	RevokedAt *time.Time `json:"revoked_at" nullable:"true"`
	Actor     *Actor     `json:"actor,omitempty" doc:"Operational view of the actor; present only with expand=actor."`
}

type CreateRoleAssignmentBody struct {
	ActorID string `json:"actor_id" minLength:"1" doc:"Operator or API key id receiving the role."`
}

type RoleAssignmentPage struct {
	Items      []RoleAssignment `json:"items" nullable:"false"`
	NextCursor *string          `json:"next_cursor" nullable:"true"`
}

// PermissionHolder is one row of the CC6.3 recertification report.
type PermissionHolder struct {
	ActorID   string    `json:"actor_id"`
	RoleID    string    `json:"role_id"`
	RoleName  string    `json:"role_name"`
	GrantedBy *string   `json:"granted_by" nullable:"true"`
	GrantedAt time.Time `json:"granted_at"`
	Actor     *Actor    `json:"actor,omitempty" doc:"Operational view of the actor; present only with expand=actor."`
}

// Actor is the non-PII operational view of the actor a grant names, returned
// with `expand=actor`. It answers "can this actor still use the grant?" without
// a request per actor.
//
// It deliberately carries NO personal data: no email, no name. The management
// plane does not inline personal data into unrelated reports, so a caller that
// needs to show who an operator is reads the masked profile surface, which is
// separately permissioned and separately audited.
type Actor struct {
	ActorType    string     `json:"actor_type" enum:"user,api_key,unknown" doc:"What the actor id names. An actor that is neither a user nor an API key reports unknown, which is a grant left behind by a deleted actor."`
	Active       bool       `json:"active" doc:"Whether the actor can still exercise the grant: not banned, deleted or revoked."`
	CreatedAt    *time.Time `json:"created_at" nullable:"true"`
	LastSignInAt *time.Time `json:"last_sign_in_at" nullable:"true" doc:"Users only."`
	BannedUntil  *time.Time `json:"banned_until" nullable:"true" doc:"Users only."`
	DeletedAt    *time.Time `json:"deleted_at" nullable:"true" doc:"Users only."`
	RevokedAt    *time.Time `json:"revoked_at" nullable:"true" doc:"API keys only."`
}

type PermissionHolderPage struct {
	Items      []PermissionHolder `json:"items" nullable:"false"`
	NextCursor *string            `json:"next_cursor" nullable:"true" doc:"Always null: recertification returns the full set."`
}

// APIKey is a scoped machine credential. The plaintext token is never returned
// after creation.
type APIKey struct {
	ID         string     `json:"id" example:"key_1f0c0b6a7d5e4a2b9c8d7e6f5a4b3c2d"`
	Name       *string    `json:"name" nullable:"true"`
	Scopes     []string   `json:"scopes" nullable:"false"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at" nullable:"true"`
	RevokedAt  *time.Time `json:"revoked_at" nullable:"true"`
	LastUsedAt *time.Time `json:"last_used_at" nullable:"true"`
}

// APIKeyWithToken is the creation response: the only time the plaintext token
// is available.
type APIKeyWithToken struct {
	APIKey
	Token string `json:"token" example:"dk_..." doc:"Plaintext API key. Shown once — store it now."`
}

type CreateAPIKeyBody struct {
	Name      *string    `json:"name,omitempty" doc:"Human-readable label."`
	Scopes    []string   `json:"scopes" nullable:"false" minItems:"1" doc:"Permissions this key may exercise (least privilege)."`
	ExpiresAt *time.Time `json:"expires_at,omitempty" doc:"RFC 3339 expiry. Omit for a non-expiring key."`
}

type APIKeyPage struct {
	Items      []APIKey `json:"items" nullable:"false"`
	NextCursor *string  `json:"next_cursor" nullable:"true"`
}

// ---- conversions ----

func toRole(in iam.Role) Role {
	perms := in.Permissions
	if perms == nil {
		perms = []string{}
	}
	return Role{ID: in.ID, Name: in.Name, Permissions: perms, Builtin: in.Builtin, CreatedAt: in.CreatedAt}
}

func toPermission(in iam.Permission) Permission {
	return Permission{Name: in.Name, Builtin: in.Builtin, CreatedAt: in.CreatedAt}
}

func toAssignment(in iam.Assignment) RoleAssignment {
	return RoleAssignment{
		ID: in.ID, ActorID: in.ActorID, RoleID: in.RoleID,
		GrantedBy: in.GrantedBy, GrantedAt: in.GrantedAt,
		RevokedBy: in.RevokedBy, RevokedAt: in.RevokedAt,
	}
}

// toActor renders the operational view. Active is computed here, once, so a
// reviewer does not have to re-derive it from four nullable timestamps.
func toActor(in iam.ActorDetail, now time.Time) *Actor {
	return &Actor{
		ActorType:    in.Type,
		Active:       in.Active(now),
		CreatedAt:    in.CreatedAt,
		LastSignInAt: in.LastSignInAt,
		BannedUntil:  in.BannedUntil,
		DeletedAt:    in.DeletedAt,
		RevokedAt:    in.RevokedAt,
	}
}

func toHolder(in iam.Holder) PermissionHolder {
	return PermissionHolder{
		ActorID: in.ActorID, RoleID: in.RoleID, RoleName: in.RoleName,
		GrantedBy: in.GrantedBy, GrantedAt: in.GrantedAt,
	}
}

func toAPIKey(in iam.APIKey) APIKey {
	scopes := in.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	return APIKey{
		ID: in.ID, Name: in.Name, Scopes: scopes, CreatedAt: in.CreatedAt,
		ExpiresAt: in.ExpiresAt, RevokedAt: in.RevokedAt, LastUsedAt: in.LastUsedAt,
	}
}

// ---- inputs / outputs ----

type listInput struct {
	Limit  int    `query:"limit" default:"20" minimum:"1" maximum:"100"`
	Cursor string `query:"cursor"`
}

type rolePageOutput struct {
	Body RolePage
}

type createRoleInput struct {
	Body CreateRoleBody
}

type roleOutput struct {
	Location string `header:"Location"`
	Body     Role
}

type listRoleAssignmentsInput struct {
	RoleID         string `path:"roleId" pattern:"^role_[0-9a-f]{32}$"`
	Limit          int    `query:"limit" default:"20" minimum:"1" maximum:"100"`
	Cursor         string `query:"cursor"`
	ActorID        string `query:"actor_id" doc:"Filter by actor."`
	IncludeRevoked bool   `query:"include_revoked" doc:"Include revoked assignments (권한 이력 조회)."`
	Expand         string `query:"expand" enum:"actor" doc:"Set to actor to include each actor's operational view. Requires users.read in addition to this operation's permission."`
}

type roleAssignmentPageOutput struct {
	Body RoleAssignmentPage
}

type createRoleAssignmentInput struct {
	RoleID string `path:"roleId" pattern:"^role_[0-9a-f]{32}$"`
	Body   CreateRoleAssignmentBody
}

type roleAssignmentOutput struct {
	Location string `header:"Location"`
	Body     RoleAssignment
}

type assignmentIDInput struct {
	AssignmentID int64 `path:"assignmentId" minimum:"1"`
}

type permissionPageOutput struct {
	Body PermissionPage
}

type createPermissionInput struct {
	Body CreatePermissionBody
}

type permissionOutput struct {
	Location string `header:"Location"`
	Body     Permission
}

type permissionHoldersInput struct {
	PermissionName string `path:"permissionName" pattern:"^[a-z][a-z0-9-]*\\.[a-z0-9.-]+$"`
	Expand         string `query:"expand" enum:"actor" doc:"Set to actor to include each actor's operational view. Requires users.read in addition to this operation's permission."`
}

type permissionHolderPageOutput struct {
	Body PermissionHolderPage
}

type apiKeyPageOutput struct {
	Body APIKeyPage
}

type createAPIKeyInput struct {
	Body CreateAPIKeyBody
}

type apiKeyWithTokenOutput struct {
	Location string `header:"Location"`
	Body     APIKeyWithToken
}

type apiKeyIDInput struct {
	KeyID string `path:"keyId" pattern:"^key_[0-9a-f]{32}$"`
}

// ---- registration ----

// RegisterIAMAPI mounts /iam/v1 on the given huma API. Reads require
// `audit.read`, mutations require `keys.manage` — both are held by the builtin
// security-admin role.
func RegisterIAMAPI(api huma.API, d Deps) {
	installErrorModel()
	r := newRegistrar(api, d, nil)
	r.registerRoles()
	r.registerPermissions()
	r.registerAPIKeys()
	r.registerAudit()
}

func (r *registrar) registerRoles() {
	huma.Register(r.api, r.op("listRoles", http.MethodGet, "/iam/v1/roles",
		"List roles", iam.PermAuditRead, "iam", http.StatusOK),
		func(ctx context.Context, in *listInput) (*rolePageOutput, error) {
			page, err := r.keys.ListRoles(ctx, listParams(in.Limit, in.Cursor, ""))
			if err != nil {
				return nil, mapIAMError(ctx, err)
			}
			items := mapItems(page.Items, toRole)
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionIAMRead,
				Resource:    "roles",
				AccessLevel: audit.AccessNA,
				ResultCount: len(items),
			})
			return &rolePageOutput{Body: RolePage{
				Items: items, NextCursor: page.NextCursor,
			}}, nil
		})

	huma.Register(r.api, r.op("createRole", http.MethodPost, "/iam/v1/roles",
		"Create a custom role", iam.PermKeysManage, "iam", http.StatusCreated),
		func(ctx context.Context, in *createRoleInput) (*roleOutput, error) {
			role, err := r.keys.CreateRole(ctx, in.Body.Name, in.Body.Permissions)
			if err != nil {
				return nil, mapIAMError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action: audit.ActionRoleCreated, Resource: "role:" + role.ID,
				AccessLevel: audit.AccessNA, ResultCount: 1,
			})
			return &roleOutput{Location: "/iam/v1/roles/" + role.ID, Body: toRole(role)}, nil
		})

	huma.Register(r.api, r.op("listRoleAssignments", http.MethodGet, "/iam/v1/roles/{roleId}/assignments",
		"List assignments of a role", iam.PermAuditRead, "iam", http.StatusOK),
		func(ctx context.Context, in *listRoleAssignmentsInput) (*roleAssignmentPageOutput, error) {
			resource := "role:" + in.RoleID + " assignments"
			if err := r.authorizeExpand(ctx, resource, in.Expand); err != nil {
				return nil, err
			}
			page, err := r.keys.ListAssignments(ctx, iam.AssignmentFilter{
				RoleID:         in.RoleID,
				ActorID:        in.ActorID,
				IncludeRevoked: in.IncludeRevoked,
			}, listParams(in.Limit, in.Cursor, ""))
			if err != nil {
				return nil, mapIAMError(ctx, err)
			}
			items := mapItems(page.Items, toAssignment)
			// Assignments list actors, not data subjects: the subject manifest
			// (§5.3) stays empty.
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionIAMRead,
				Resource:    resource,
				AccessLevel: audit.AccessNA,
				ResultCount: len(items),
			})
			if err := r.expandActors(ctx, resource, in.Expand,
				func(i int) string { return items[i].ActorID },
				func(i int, a *Actor) { items[i].Actor = a },
				len(items)); err != nil {
				return nil, err
			}
			return &roleAssignmentPageOutput{Body: RoleAssignmentPage{
				Items: items, NextCursor: page.NextCursor,
			}}, nil
		})

	huma.Register(r.api, r.op("createRoleAssignment", http.MethodPost, "/iam/v1/roles/{roleId}/assignments",
		"Grant a role to an actor", iam.PermKeysManage, "iam", http.StatusCreated),
		func(ctx context.Context, in *createRoleAssignmentInput) (*roleAssignmentOutput, error) {
			a, err := r.keys.GrantRole(ctx, in.RoleID, in.Body.ActorID,
				requestInfoFrom(ctx).Actor.ID)
			if err != nil {
				return nil, mapIAMError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionRoleGranted,
				Resource:    "role:" + a.RoleID + " actor:" + a.ActorID,
				AccessLevel: audit.AccessNA,
				ResultCount: 1,
			})
			return &roleAssignmentOutput{
				Location: "/iam/v1/assignments/" + strconv.FormatInt(a.ID, 10),
				Body:     toAssignment(a),
			}, nil
		})

	huma.Register(r.api, r.op("revokeRoleAssignment", http.MethodDelete, "/iam/v1/assignments/{assignmentId}",
		"Revoke a role assignment", iam.PermKeysManage, "iam", http.StatusNoContent),
		func(ctx context.Context, in *assignmentIDInput) (*struct{}, error) {
			a, err := r.keys.RevokeAssignment(ctx, in.AssignmentID,
				requestInfoFrom(ctx).Actor.ID)
			if err != nil {
				return nil, mapIAMError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionRoleRevoked,
				Resource:    "role:" + a.RoleID + " actor:" + a.ActorID,
				AccessLevel: audit.AccessNA,
				ResultCount: 1,
			})
			return nil, nil
		})
}

func (r *registrar) registerPermissions() {
	huma.Register(r.api, r.op("listPermissions", http.MethodGet, "/iam/v1/permissions",
		"List permissions", iam.PermAuditRead, "iam", http.StatusOK),
		func(ctx context.Context, in *listInput) (*permissionPageOutput, error) {
			page, err := r.keys.ListPermissions(ctx, listParams(in.Limit, in.Cursor, ""))
			if err != nil {
				return nil, mapIAMError(ctx, err)
			}
			items := mapItems(page.Items, toPermission)
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionIAMRead,
				Resource:    "permissions",
				AccessLevel: audit.AccessNA,
				ResultCount: len(items),
			})
			return &permissionPageOutput{Body: PermissionPage{
				Items: items, NextCursor: page.NextCursor,
			}}, nil
		})

	huma.Register(r.api, r.op("createPermission", http.MethodPost, "/iam/v1/permissions",
		"Register a custom permission", iam.PermKeysManage, "iam", http.StatusCreated),
		func(ctx context.Context, in *createPermissionInput) (*permissionOutput, error) {
			p, err := r.keys.CreatePermission(ctx, in.Body.Name)
			if err != nil {
				return nil, mapIAMError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action: audit.ActionPermissionCreated, Resource: "permission:" + p.Name,
				AccessLevel: audit.AccessNA, ResultCount: 1,
			})
			return &permissionOutput{Location: "/iam/v1/permissions/" + p.Name, Body: toPermission(p)}, nil
		})

	huma.Register(r.api, r.op("listPermissionHolders", http.MethodGet, "/iam/v1/permissions/{permissionName}/holders",
		"List actors currently holding a permission (recertification)", iam.PermAuditRead, "iam", http.StatusOK),
		func(ctx context.Context, in *permissionHoldersInput) (*permissionHolderPageOutput, error) {
			resource := "permission:" + in.PermissionName + " holders"
			if err := r.authorizeExpand(ctx, resource, in.Expand); err != nil {
				return nil, err
			}
			holders, err := r.keys.Recertification(ctx, in.PermissionName)
			if err != nil {
				return nil, mapIAMError(ctx, err)
			}
			items := mapItems(holders, toHolder)
			// The holders are ACTOR ids, not data subjects. SubjectIDs is the
			// data-subject manifest (§5.3) used for reverse lookup ("who
			// accessed user X?"), so it must stay empty here — putting actor
			// ids in it would make operators look like data subjects.
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionIAMRead,
				Resource:    resource,
				AccessLevel: audit.AccessNA,
				ResultCount: len(items),
			})
			if err := r.expandActors(ctx, resource, in.Expand,
				func(i int) string { return items[i].ActorID },
				func(i int, a *Actor) { items[i].Actor = a },
				len(items)); err != nil {
				return nil, err
			}
			return &permissionHolderPageOutput{Body: PermissionHolderPage{
				Items: items,
			}}, nil
		})
}

// expandActor names the one value of the `expand` option.
const expandActor = "actor"

// authorizeExpand gates expand=actor on users.read, on top of the permission
// the operation already required. Whether an operator is banned, deleted or
// dormant is a fact about a person, so authority to read the grant ledger is
// not by itself authority to learn it.
//
// It runs BEFORE the report is built, so a request that will be refused does
// no work and leaves no IAM_READ access record behind.
func (r *registrar) authorizeExpand(ctx context.Context, resource, expand string) error {
	if expand != expandActor {
		return nil
	}
	return r.d.authorize(ctx, iam.PermUsersRead, resource)
}

// expandActors attaches the operational actor view to a page of grants when
// the caller asked for it with expand=actor. It is a no-op otherwise, so the
// default response, its permission and its audit event are exactly what they
// were before the option existed.
//
// The actors that turn out to be users go into a USER_LIST_READ access record
// with a subject manifest, because that read really did touch data subjects.
// The report's own IAM_READ event stays subject-free (§5.3).
//
// The lookup is two queries for the whole page, which is the point: the
// alternative was one request per actor.
func (r *registrar) expandActors(ctx context.Context, resource, expand string,
	actorID func(int) string, attach func(int, *Actor), n int) error {
	if expand != expandActor {
		return nil
	}
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		ids = append(ids, actorID(i))
	}
	details, err := r.keys.ActorDetails(ctx, ids)
	if err != nil {
		return mapIAMError(ctx, err)
	}
	now := time.Now().UTC()
	for i := 0; i < n; i++ {
		d, ok := details[actorID(i)]
		if !ok {
			d = iam.ActorDetail{ActorID: actorID(i), Type: iam.ActorTypeUnknown}
		}
		attach(i, toActor(d, now))
	}
	if subjects := iam.UserActorIDs(details, ids); len(subjects) > 0 {
		r.d.emit(ctx, auditOpts{
			Action:      audit.ActionUserListRead,
			Resource:    resource + " (expand=actor)",
			AccessLevel: audit.AccessMasked,
			ResultCount: len(subjects),
			SubjectIDs:  subjects,
		})
	}
	return nil
}

func (r *registrar) registerAPIKeys() {
	huma.Register(r.api, r.op("listApiKeys", http.MethodGet, "/iam/v1/api-keys",
		"List API keys", iam.PermAuditRead, "iam", http.StatusOK),
		func(ctx context.Context, in *listInput) (*apiKeyPageOutput, error) {
			page, err := r.keys.ListKeys(ctx, listParams(in.Limit, in.Cursor, ""))
			if err != nil {
				return nil, mapIAMError(ctx, err)
			}
			items := mapItems(page.Items, toAPIKey)
			r.d.emit(ctx, auditOpts{
				Action:      audit.ActionIAMRead,
				Resource:    "api_keys",
				AccessLevel: audit.AccessNA,
				ResultCount: len(items),
			})
			return &apiKeyPageOutput{Body: APIKeyPage{
				Items: items, NextCursor: page.NextCursor,
			}}, nil
		})

	huma.Register(r.api, r.op("createApiKey", http.MethodPost, "/iam/v1/api-keys",
		"Issue a scoped API key", iam.PermKeysManage, "iam", http.StatusCreated),
		func(ctx context.Context, in *createAPIKeyInput) (*apiKeyWithTokenOutput, error) {
			name := ""
			if in.Body.Name != nil {
				name = *in.Body.Name
			}
			token, key, err := r.keys.CreateKeyBy(ctx, name, in.Body.Scopes,
				in.Body.ExpiresAt, requestInfoFrom(ctx).Actor.ID)
			if err != nil {
				return nil, mapIAMError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action: audit.ActionAPIKeyCreated, Resource: "api_key:" + key.ID,
				AccessLevel: audit.AccessNA, ResultCount: 1,
			})
			return &apiKeyWithTokenOutput{
				Location: "/iam/v1/api-keys/" + key.ID,
				Body:     APIKeyWithToken{APIKey: toAPIKey(key), Token: token},
			}, nil
		})

	huma.Register(r.api, r.op("revokeApiKey", http.MethodDelete, "/iam/v1/api-keys/{keyId}",
		"Revoke an API key", iam.PermKeysManage, "iam", http.StatusNoContent),
		func(ctx context.Context, in *apiKeyIDInput) (*struct{}, error) {
			key, err := r.keys.RevokeKey(ctx, in.KeyID, requestInfoFrom(ctx).Actor.ID)
			if err != nil {
				return nil, mapIAMError(ctx, err)
			}
			r.d.emit(ctx, auditOpts{
				Action: audit.ActionAPIKeyRevoked, Resource: "api_key:" + key.ID,
				AccessLevel: audit.AccessNA, ResultCount: 1,
			})
			return nil, nil
		})
}

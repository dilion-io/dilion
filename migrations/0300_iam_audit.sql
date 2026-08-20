-- 0300_iam_audit.sql — management-plane RBAC (project.md §2.11) + audit log (§5).
-- Owner: agent D (platform API). Schemas are created by 0001_core.sql; the
-- `create schema if not exists` below keeps this file standalone-appliable for
-- the package tests (DILION_TEST_DB).

create schema if not exists dilion_authz;
create schema if not exists dilion_audit;

-- ---------------------------------------------------------------- permissions

create table if not exists dilion_authz.permissions (
    project_id text not null default 'default',
    name       text not null,
    builtin    boolean not null default false,
    created_at timestamptz not null default now(),
    primary key (project_id, name)
);

-- --------------------------------------------------------------------- roles

create table if not exists dilion_authz.roles (
    id          text primary key,
    project_id  text not null default 'default',
    name        text not null,
    permissions text[] not null,
    builtin     boolean not null default false,
    created_at  timestamptz not null default now(),
    unique (project_id, name)
);

-- ---------------------------------------------------------- role assignments
-- History preserving (안전성 확보조치 기준 제5조): revoke never deletes a row.

create table if not exists dilion_authz.role_assignments (
    id         bigserial primary key,
    project_id text not null default 'default',
    actor_id   text not null,
    role_id    text not null,
    granted_by text,
    granted_at timestamptz not null default now(),
    revoked_by text,
    revoked_at timestamptz
);

create index if not exists role_assignments_actor_idx
    on dilion_authz.role_assignments (project_id, actor_id)
    where revoked_at is null;

create index if not exists role_assignments_role_idx
    on dilion_authz.role_assignments (project_id, role_id);

-- ------------------------------------------------------------------ api keys

create table if not exists dilion_authz.api_keys (
    id           text primary key,
    project_id   text not null default 'default',
    name         text,
    key_hash     bytea not null,
    scopes       text[] not null,
    created_at   timestamptz default now(),
    created_by   text,
    expires_at   timestamptz,
    revoked_at   timestamptz,
    revoked_by   text,
    last_used_at timestamptz
);

create unique index if not exists api_keys_hash_idx on dilion_authz.api_keys (key_hash);

-- -------------------------------------------------------------------- audit
-- Append-only (§5.4): the application only ever INSERTs into these tables.

create table if not exists dilion_audit.events (
    event_id     text primary key,
    project_id   text not null default 'default',
    actor_id     text,
    actor_type   text,
    action       text not null,
    resource     text,
    access_level text,
    request_id   text,
    result_count int,
    ip           text,
    user_agent   text,
    created_at   timestamptz not null default now()
);

create index if not exists events_created_idx on dilion_audit.events (created_at desc);
create index if not exists events_actor_idx   on dilion_audit.events (project_id, actor_id, created_at desc);
create index if not exists events_action_idx  on dilion_audit.events (project_id, action, created_at desc);

-- Subject manifest (§5.3): reverse lookup "who accessed subject X".
create table if not exists dilion_audit.subjects (
    event_id   text not null,
    subject_id text not null,
    primary key (event_id, subject_id)
);

create index if not exists subjects_subject_idx on dilion_audit.subjects (subject_id);

-- ------------------------------------------------------------- builtin seed
-- Builtin permissions (§2.11). Un-namespaced names are reserved for builtins;
-- custom permissions must be namespaced (`myapp.orders.refund`).

insert into dilion_authz.permissions (project_id, name, builtin) values
    ('default', 'users.read',              true),
    ('default', 'pii.read',                true),
    ('default', 'pii.reveal',              true),
    ('default', 'pii.export',              true),
    ('default', 'privacy.requests.manage', true),
    ('default', 'holds.manage',            true),
    ('default', 'policies.manage',         true),
    ('default', 'destinations.manage',     true),
    ('default', 'keys.manage',             true),
    ('default', 'audit.read',              true)
on conflict (project_id, name) do nothing;

-- Builtin roles (§2.11), cumulative bundles. IDs are fixed so that seeds are
-- reproducible across environments (`role_` + 32 hex).
insert into dilion_authz.roles (id, project_id, name, permissions, builtin) values
    ('role_00000000000000000000000000000001', 'default', 'viewer',
        array['users.read'], true),
    ('role_00000000000000000000000000000002', 'default', 'support',
        array['users.read','pii.read'], true),
    ('role_00000000000000000000000000000003', 'default', 'privacy-officer',
        array['users.read','pii.read','pii.export','privacy.requests.manage','holds.manage'], true),
    ('role_00000000000000000000000000000004', 'default', 'security-admin',
        array['users.read','pii.read','pii.export','privacy.requests.manage','holds.manage','audit.read','keys.manage'], true),
    ('role_00000000000000000000000000000005', 'default', 'owner',
        array['users.read','pii.read','pii.reveal','pii.export','privacy.requests.manage','holds.manage','policies.manage','destinations.manage','keys.manage','audit.read'], true)
on conflict (id) do nothing;

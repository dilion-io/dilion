-- 0116_auth_oauth_server.sql — the OAuth 2.1 authorization-server surface:
-- auth.oauth_clients, auth.oauth_authorizations, auth.oauth_consents,
-- auth.oauth_client_states, auth.custom_oauth_providers.
--
-- Squashed from the upstream migration chain (github.com/supabase/auth,
-- master as of 2026-08):
--   * 20250731150234_add_oauth_clients_table.up.sql            (oauth_clients, oauth_registration_type enum)
--   * 20250804100000_add_oauth_authorizations_consents.up.sql  (oauth_authorizations, oauth_consents,
--       oauth_response_type + oauth_authorization_status enums)
--   * 20250901200500_add_oauth_client_type.up.sql              (oauth_clients.client_type, oauth_client_type enum)
--   * 20250903112500_remove_oauth_client_id_column.up.sql      (drops oauth_clients.client_id — absent here)
--   * 20250904133000_add_oauth_client_id_to_session.up.sql     (sessions.oauth_client_id FK + index)
--   * 20251104100000_add_nonce_to_oauth_authorizations.up.sql  (oauth_authorizations.nonce)
--   * 20251201000000_add_oauth_client_states_table.up.sql      (oauth_client_states)
--   * 20260121000000_add_token_endpoint_auth_method.up.sql     (oauth_clients.token_endpoint_auth_method)
--   * 20260219120000_add_custom_oauth_providers.up.sql         (custom_oauth_providers)
--   * 20260625000000_add_custom_claims_allowlist.up.sql        (custom_oauth_providers.custom_claims_allowlist)
-- Verified by applying the FULL upstream chain to Postgres 16 and diffing
-- `pg_dump --schema-only --schema=auth`.
--
-- NOTE: upstream does NOT enable row level security on any table in this file.

-- ---------------------------------------------------------------------------
-- enum types
-- ---------------------------------------------------------------------------

do $$
begin
    create type auth.oauth_registration_type as enum ('dynamic', 'manual');
exception
    when duplicate_object then null;
end
$$;

do $$
begin
    create type auth.oauth_client_type as enum ('public', 'confidential');
exception
    when duplicate_object then null;
end
$$;

do $$
begin
    create type auth.oauth_response_type as enum ('code');
exception
    when duplicate_object then null;
end
$$;

do $$
begin
    create type auth.oauth_authorization_status as enum ('pending', 'approved', 'denied', 'expired');
exception
    when duplicate_object then null;
end
$$;

-- auth.code_challenge_method is created by 0111 (flow_state); repeated here so
-- this file stands alone if the ordering ever changes.
do $$
begin
    create type auth.code_challenge_method as enum ('s256', 'plain');
exception
    when duplicate_object then null;
end
$$;

-- ---------------------------------------------------------------------------
-- auth.oauth_clients
-- ---------------------------------------------------------------------------
-- The public `client_id` text column was dropped by 20250903112500: the client
-- identifier IS the uuid primary key.

create table if not exists auth.oauth_clients (
    id                        uuid not null,
    client_secret_hash        text,
    registration_type         auth.oauth_registration_type not null,
    redirect_uris             text not null,
    grant_types               text not null,
    client_name               text,
    client_uri                text,
    logo_uri                  text,
    created_at                timestamptz not null default now(),
    updated_at                timestamptz not null default now(),
    deleted_at                timestamptz,
    client_type               auth.oauth_client_type not null default 'confidential'::auth.oauth_client_type,
    token_endpoint_auth_method text not null,
    constraint oauth_clients_pkey primary key (id),
    constraint oauth_clients_client_name_length check (char_length(client_name) <= 1024),
    constraint oauth_clients_client_uri_length  check (char_length(client_uri)  <= 2048),
    constraint oauth_clients_logo_uri_length    check (char_length(logo_uri)    <= 2048),
    constraint oauth_clients_token_endpoint_auth_method_check
        check (token_endpoint_auth_method = any (array['client_secret_basic'::text, 'client_secret_post'::text, 'none'::text]))
);

create index if not exists oauth_clients_deleted_at_idx on auth.oauth_clients using btree (deleted_at);

-- auth.sessions.oauth_client_id gained its FK in 20250904133000, i.e. only once
-- auth.oauth_clients exists. 0100 created the column and the index but had to
-- leave the FK out; it is attached here.
do $$
begin
    alter table auth.sessions
        add constraint sessions_oauth_client_id_fkey
        foreign key (oauth_client_id) references auth.oauth_clients (id) on delete cascade;
exception
    when duplicate_object then null;
end
$$;

create index if not exists sessions_oauth_client_id_idx on auth.sessions using btree (oauth_client_id);

-- ---------------------------------------------------------------------------
-- auth.oauth_authorizations
-- ---------------------------------------------------------------------------

create table if not exists auth.oauth_authorizations (
    id                    uuid not null,
    authorization_id      text not null,
    client_id             uuid not null,
    user_id               uuid,
    redirect_uri          text not null,
    scope                 text not null,
    state                 text,
    resource              text,
    code_challenge        text,
    code_challenge_method auth.code_challenge_method,
    response_type         auth.oauth_response_type         not null default 'code'::auth.oauth_response_type,
    status                auth.oauth_authorization_status  not null default 'pending'::auth.oauth_authorization_status,
    authorization_code    text,
    created_at            timestamptz not null default now(),
    expires_at            timestamptz not null default (now() + '00:03:00'::interval),
    approved_at           timestamptz,
    nonce                 text,
    constraint oauth_authorizations_pkey primary key (id),
    constraint oauth_authorizations_authorization_id_key   unique (authorization_id),
    constraint oauth_authorizations_authorization_code_key unique (authorization_code),
    constraint oauth_authorizations_redirect_uri_length       check (char_length(redirect_uri)       <= 2048),
    constraint oauth_authorizations_scope_length              check (char_length(scope)              <= 4096),
    constraint oauth_authorizations_state_length              check (char_length(state)              <= 4096),
    constraint oauth_authorizations_resource_length           check (char_length(resource)           <= 2048),
    constraint oauth_authorizations_code_challenge_length     check (char_length(code_challenge)     <= 128),
    constraint oauth_authorizations_authorization_code_length check (char_length(authorization_code) <= 255),
    constraint oauth_authorizations_nonce_length              check (char_length(nonce)              <= 255),
    constraint oauth_authorizations_expires_at_future         check (expires_at > created_at),
    constraint oauth_authorizations_client_id_fkey foreign key (client_id) references auth.oauth_clients (id) on delete cascade,
    constraint oauth_authorizations_user_id_fkey   foreign key (user_id)   references auth.users (id)        on delete cascade
);

create index if not exists oauth_auth_pending_exp_idx on auth.oauth_authorizations using btree (expires_at) where (status = 'pending'::auth.oauth_authorization_status);

-- ---------------------------------------------------------------------------
-- auth.oauth_consents
-- ---------------------------------------------------------------------------

create table if not exists auth.oauth_consents (
    id         uuid not null,
    user_id    uuid not null,
    client_id  uuid not null,
    scopes     text not null,
    granted_at timestamptz not null default now(),
    revoked_at timestamptz,
    constraint oauth_consents_pkey primary key (id),
    constraint oauth_consents_user_client_unique unique (user_id, client_id),
    constraint oauth_consents_scopes_length      check (char_length(scopes) <= 2048),
    constraint oauth_consents_scopes_not_empty   check (char_length(trim(both from scopes)) > 0),
    constraint oauth_consents_revoked_after_granted check (revoked_at is null or revoked_at >= granted_at),
    constraint oauth_consents_user_id_fkey   foreign key (user_id)   references auth.users (id)        on delete cascade,
    constraint oauth_consents_client_id_fkey foreign key (client_id) references auth.oauth_clients (id) on delete cascade
);

create index if not exists oauth_consents_active_user_client_idx on auth.oauth_consents using btree (user_id, client_id) where (revoked_at is null);
create index if not exists oauth_consents_active_client_idx      on auth.oauth_consents using btree (client_id)          where (revoked_at is null);
create index if not exists oauth_consents_user_order_idx         on auth.oauth_consents using btree (user_id, granted_at desc);

-- ---------------------------------------------------------------------------
-- auth.oauth_client_states
-- ---------------------------------------------------------------------------
-- The other direction: Dilion/Supabase acting as the OAuth *client* against a
-- third-party IdP. Referenced by auth.flow_state.oauth_client_state_id (no FK
-- upstream).

create table if not exists auth.oauth_client_states (
    id            uuid not null,
    provider_type text not null,
    code_verifier text,
    created_at    timestamptz not null,
    constraint oauth_client_states_pkey primary key (id)
);

comment on table auth.oauth_client_states is 'Stores OAuth states for third-party provider authentication flows where Supabase acts as the OAuth client.';

create index if not exists idx_oauth_client_states_created_at on auth.oauth_client_states using btree (created_at);

-- ---------------------------------------------------------------------------
-- auth.custom_oauth_providers
-- ---------------------------------------------------------------------------
-- Runtime-configurable OAuth2/OIDC providers. provider_type is a CHECKed text
-- column ('oauth2' | 'oidc'), not an enum.

create table if not exists auth.custom_oauth_providers (
    id                      uuid   not null default gen_random_uuid(),
    provider_type           text   not null,
    identifier              text   not null,
    name                    text   not null,
    client_id               text   not null,
    client_secret           text   not null,
    acceptable_client_ids   text[] not null default '{}'::text[],
    scopes                  text[] not null default '{}'::text[],
    pkce_enabled            boolean not null default true,
    attribute_mapping       jsonb  not null default '{}'::jsonb,
    authorization_params    jsonb  not null default '{}'::jsonb,
    enabled                 boolean not null default true,
    email_optional          boolean not null default false,
    issuer                  text,
    discovery_url           text,
    skip_nonce_check        boolean not null default false,
    cached_discovery        jsonb,
    discovery_cached_at     timestamptz,
    authorization_url       text,
    token_url               text,
    userinfo_url            text,
    jwks_uri                text,
    created_at              timestamptz not null default now(),
    updated_at              timestamptz not null default now(),
    custom_claims_allowlist text[] not null default '{}'::text[],
    constraint custom_oauth_providers_pkey primary key (id),
    constraint custom_oauth_providers_identifier_key unique (identifier),
    constraint custom_oauth_providers_provider_type_check check (provider_type = any (array['oauth2'::text, 'oidc'::text])),
    constraint custom_oauth_providers_identifier_format check (identifier ~ '^[a-z0-9][a-z0-9:-]{0,48}[a-z0-9]$'::text),
    constraint custom_oauth_providers_name_length      check (char_length(name) >= 1 and char_length(name) <= 100),
    constraint custom_oauth_providers_client_id_length check (char_length(client_id) >= 1 and char_length(client_id) <= 512),
    constraint custom_oauth_providers_issuer_length        check (issuer is null or (char_length(issuer) >= 1 and char_length(issuer) <= 2048)),
    constraint custom_oauth_providers_discovery_url_length check (discovery_url is null or char_length(discovery_url) <= 2048),
    constraint custom_oauth_providers_authorization_url_length check (authorization_url is null or char_length(authorization_url) <= 2048),
    constraint custom_oauth_providers_token_url_length        check (token_url    is null or char_length(token_url)    <= 2048),
    constraint custom_oauth_providers_userinfo_url_length     check (userinfo_url is null or char_length(userinfo_url) <= 2048),
    constraint custom_oauth_providers_jwks_uri_length         check (jwks_uri     is null or char_length(jwks_uri)     <= 2048),
    constraint custom_oauth_providers_authorization_url_https check (authorization_url is null or authorization_url like 'https://%'),
    constraint custom_oauth_providers_token_url_https         check (token_url    is null or token_url    like 'https://%'),
    constraint custom_oauth_providers_userinfo_url_https      check (userinfo_url is null or userinfo_url like 'https://%'),
    constraint custom_oauth_providers_jwks_uri_https          check (jwks_uri     is null or jwks_uri     like 'https://%'),
    constraint custom_oauth_providers_oidc_requires_issuer    check (provider_type <> 'oidc'::text or issuer is not null),
    constraint custom_oauth_providers_oidc_issuer_https       check (provider_type <> 'oidc'::text or issuer is null or issuer like 'https://%'),
    constraint custom_oauth_providers_oidc_discovery_url_https check (provider_type <> 'oidc'::text or discovery_url is null or discovery_url like 'https://%'),
    constraint custom_oauth_providers_oauth2_requires_endpoints
        check (provider_type <> 'oauth2'::text
               or (authorization_url is not null and token_url is not null and userinfo_url is not null))
);

create index if not exists custom_oauth_providers_identifier_idx    on auth.custom_oauth_providers using btree (identifier);
create index if not exists custom_oauth_providers_provider_type_idx on auth.custom_oauth_providers using btree (provider_type);
create index if not exists custom_oauth_providers_enabled_idx       on auth.custom_oauth_providers using btree (enabled);
create index if not exists custom_oauth_providers_created_at_idx    on auth.custom_oauth_providers using btree (created_at);

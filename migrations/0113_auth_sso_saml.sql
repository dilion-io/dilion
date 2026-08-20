-- 0113_auth_sso_saml.sql — auth.sso_providers / sso_domains / saml_providers /
-- saml_relay_states.
--
-- Squashed from the upstream migration chain (github.com/supabase/auth,
-- master as of 2026-08):
--   * 20221021082433_add_saml.up.sql                                (4 tables + indexes)
--   * 20230508135423_add_cleanup_indexes.up.sql                     (saml_relay_states_created_at_idx)
--   * 20230818113222_add_flow_state_to_relay_state.up.sql           (saml_relay_states.flow_state_id + FK)
--   * 20240115144230_remove_ip_address_from_saml_relay_state.up.sql (drops saml_relay_states.from_ip_address)
--   * 20240314092811_add_saml_name_id_format.up.sql                 (saml_providers.name_id_format)
--   * 20240612123726_enable_rls_update_grants.up.sql                (RLS)
--   * 20250717082212_add_disabled_to_sso_providers.up.sql           (sso_providers.disabled)
-- Verified by applying the FULL upstream chain to Postgres 16 and diffing
-- `pg_dump --schema-only --schema=auth`.
--
-- Requires auth.flow_state (0111) for the saml_relay_states FK.

-- ---------------------------------------------------------------------------
-- auth.sso_providers
-- ---------------------------------------------------------------------------
-- NOTE: the `resource_id not empty` CHECK is written `resource_id = null` (not
-- `is null`) upstream, which is always NULL/unknown and therefore only rejects
-- a non-null empty string. Reproduced verbatim so the constraint definition
-- matches a stock Supabase database byte for byte.

create table if not exists auth.sso_providers (
    id          uuid not null,
    resource_id text,
    created_at  timestamptz,
    updated_at  timestamptz,
    disabled    boolean,
    constraint sso_providers_pkey primary key (id),
    constraint "resource_id not empty" check (resource_id = null or char_length(resource_id) > 0)
);

comment on table auth.sso_providers is 'Auth: Manages SSO identity provider information; see saml_providers for SAML.';
comment on column auth.sso_providers.resource_id is 'Auth: Uniquely identifies a SSO provider according to a user-chosen resource ID (case insensitive), useful in infrastructure as code.';

create unique index if not exists sso_providers_resource_id_idx         on auth.sso_providers using btree (lower(resource_id));
create index        if not exists sso_providers_resource_id_pattern_idx on auth.sso_providers using btree (resource_id text_pattern_ops);

-- ---------------------------------------------------------------------------
-- auth.sso_domains
-- ---------------------------------------------------------------------------

create table if not exists auth.sso_domains (
    id              uuid not null,
    sso_provider_id uuid not null,
    domain          text not null,
    created_at      timestamptz,
    updated_at      timestamptz,
    constraint sso_domains_pkey primary key (id),
    constraint "domain not empty" check (char_length(domain) > 0),
    constraint sso_domains_sso_provider_id_fkey foreign key (sso_provider_id) references auth.sso_providers (id) on delete cascade
);

comment on table auth.sso_domains is 'Auth: Manages SSO email address domain mapping to an SSO Identity Provider.';

create index        if not exists sso_domains_sso_provider_id_idx on auth.sso_domains using btree (sso_provider_id);
create unique index if not exists sso_domains_domain_idx          on auth.sso_domains using btree (lower(domain));

-- ---------------------------------------------------------------------------
-- auth.saml_providers
-- ---------------------------------------------------------------------------

create table if not exists auth.saml_providers (
    id                uuid not null,
    sso_provider_id   uuid not null,
    entity_id         text not null,
    metadata_xml      text not null,
    metadata_url      text,
    attribute_mapping jsonb,
    created_at        timestamptz,
    updated_at        timestamptz,
    name_id_format    text,
    constraint saml_providers_pkey primary key (id),
    constraint saml_providers_entity_id_key unique (entity_id),
    constraint "entity_id not empty"   check (char_length(entity_id) > 0),
    constraint "metadata_xml not empty" check (char_length(metadata_xml) > 0),
    constraint "metadata_url not empty" check (metadata_url = null or char_length(metadata_url) > 0),
    constraint saml_providers_sso_provider_id_fkey foreign key (sso_provider_id) references auth.sso_providers (id) on delete cascade
);

comment on table auth.saml_providers is 'Auth: Manages SAML Identity Provider connections.';

create index if not exists saml_providers_sso_provider_id_idx on auth.saml_providers using btree (sso_provider_id);

-- ---------------------------------------------------------------------------
-- auth.saml_relay_states
-- ---------------------------------------------------------------------------
-- NOTE: the original `from_ip_address inet` column was dropped upstream by
-- 20240115144230 and is therefore absent here.

create table if not exists auth.saml_relay_states (
    id              uuid not null,
    sso_provider_id uuid not null,
    request_id      text not null,
    for_email       text,
    redirect_to     text,
    created_at      timestamptz,
    updated_at      timestamptz,
    flow_state_id   uuid default null,
    constraint saml_relay_states_pkey primary key (id),
    constraint "request_id not empty" check (char_length(request_id) > 0),
    constraint saml_relay_states_sso_provider_id_fkey foreign key (sso_provider_id) references auth.sso_providers (id) on delete cascade,
    constraint saml_relay_states_flow_state_id_fkey foreign key (flow_state_id) references auth.flow_state (id) on delete cascade
);

comment on table auth.saml_relay_states is 'Auth: Contains SAML Relay State information for each Service Provider initiated login.';

create index if not exists saml_relay_states_sso_provider_id_idx on auth.saml_relay_states using btree (sso_provider_id);
create index if not exists saml_relay_states_for_email_idx       on auth.saml_relay_states using btree (for_email);
create index if not exists saml_relay_states_created_at_idx      on auth.saml_relay_states using btree (created_at desc);

alter table auth.sso_providers     enable row level security;
alter table auth.sso_domains       enable row level security;
alter table auth.saml_providers    enable row level security;
alter table auth.saml_relay_states enable row level security;

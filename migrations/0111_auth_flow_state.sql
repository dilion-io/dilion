-- 0111_auth_flow_state.sql — auth.flow_state (PKCE / OAuth / SSO login flows).
--
-- Squashed from the upstream migration chain (github.com/supabase/auth,
-- master as of 2026-08):
--   * 20230322519590_add_flow_state_table.up.sql                       (table, code_challenge_method enum, idx_auth_code)
--   * 20230402418590_add_authentication_method_to_flow_state_table.up.sql (authentication_method, idx_user_id_auth_method)
--   * 20230508135423_add_cleanup_indexes.up.sql                        (flow_state_created_at_idx)
--   * 20240306115329_add_issued_at_to_flow_state.up.sql                (auth_code_issued_at)
--   * 20240612123726_enable_rls_update_grants.up.sql                   (RLS)
--   * 20260115000000_add_flow_state_oauth_context.up.sql               (invite_token, referrer,
--       oauth_client_state_id, linking_target_id, email_optional; drops NOT NULL from the
--       three PKCE columns so the implicit flow can be represented)
-- Verified by applying the FULL upstream chain to Postgres 16 and diffing
-- `pg_dump --schema-only --schema=auth`.

-- ---------------------------------------------------------------------------
-- enum type — also used by auth.oauth_authorizations (0116).
-- ---------------------------------------------------------------------------

do $$
begin
    create type auth.code_challenge_method as enum ('s256', 'plain');
exception
    when duplicate_object then null;
end
$$;

-- ---------------------------------------------------------------------------
-- auth.flow_state
-- ---------------------------------------------------------------------------
-- NOTE: auth_code / code_challenge / code_challenge_method are NULLABLE in the
-- final upstream shape (they were NOT NULL when the table was created and were
-- relaxed by 20260115000000 for the implicit flow).

create table if not exists auth.flow_state (
    id                     uuid    not null,
    user_id                uuid,
    auth_code              text,
    code_challenge_method  auth.code_challenge_method,
    code_challenge         text,
    provider_type          text    not null,
    provider_access_token  text,
    provider_refresh_token text,
    created_at             timestamptz,
    updated_at             timestamptz,
    authentication_method  text    not null,
    auth_code_issued_at    timestamptz,
    invite_token           text,
    referrer               text,
    oauth_client_state_id  uuid,
    linking_target_id      uuid,
    email_optional         boolean not null default false,
    constraint flow_state_pkey primary key (id)
);

comment on table auth.flow_state is 'Stores metadata for all OAuth/SSO login flows';

-- Upstream has NO foreign key on flow_state.user_id, oauth_client_state_id or
-- linking_target_id — none are added here either.

create index if not exists idx_auth_code            on auth.flow_state using btree (auth_code);
create index if not exists idx_user_id_auth_method  on auth.flow_state using btree (user_id, authentication_method);
create index if not exists flow_state_created_at_idx on auth.flow_state using btree (created_at desc);

alter table auth.flow_state enable row level security;

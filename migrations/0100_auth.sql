-- 0100_auth.sql — Supabase Auth (gotrue) compatible schema. Wave 1 scope:
-- auth.users, auth.identities, auth.sessions, auth.refresh_tokens.
--
-- Column names, types, defaults, constraints and index names are taken verbatim
-- from the upstream migration chain (github.com/supabase/auth/migrations, master
-- as of 2026-08), squashed into the final shape. Verified by applying the full
-- upstream chain to Postgres 16 and diffing `pg_dump --schema-only`.
--
-- project.md §2.2: NO Dilion-specific columns may be added to auth.*. Extensions
-- live in dilion_* schemas.
--
-- Deliberate wave-1 omissions (upstream objects out of scope, added in later waves):
--   * auth.mfa_factors / mfa_challenges / mfa_amr_claims  -> sessions.factor_id has no FK yet
--   * auth.oauth_clients                                  -> sessions.oauth_client_id has no FK yet
--   * auth.flow_state, one_time_tokens, sso_*, saml_*, webauthn_*, instances,
--     audit_log_entries, schema_migrations
-- The columns themselves ARE present so that migrating an existing Supabase
-- database (or adding the remaining tables later) needs no ALTER of these tables.

create schema if not exists auth;

-- ---------------------------------------------------------------------------
-- enum types
-- ---------------------------------------------------------------------------

do $$
begin
    create type auth.aal_level as enum ('aal1', 'aal2', 'aal3');
exception
    when duplicate_object then null;
end
$$;

-- ---------------------------------------------------------------------------
-- auth.users
-- ---------------------------------------------------------------------------

create table if not exists auth.users (
    instance_id                uuid,
    id                         uuid         not null,
    aud                        varchar(255),
    role                       varchar(255),
    email                      varchar(255),
    encrypted_password         varchar(255),
    email_confirmed_at         timestamptz,
    invited_at                 timestamptz,
    confirmation_token         varchar(255),
    confirmation_sent_at       timestamptz,
    recovery_token             varchar(255),
    recovery_sent_at           timestamptz,
    email_change_token_new     varchar(255),
    email_change               varchar(255),
    email_change_sent_at       timestamptz,
    last_sign_in_at            timestamptz,
    raw_app_meta_data          jsonb,
    raw_user_meta_data         jsonb,
    is_super_admin             boolean,
    created_at                 timestamptz,
    updated_at                 timestamptz,
    phone                      text         default null::character varying,
    phone_confirmed_at         timestamptz,
    phone_change               text         default ''::character varying,
    phone_change_token         varchar(255) default ''::character varying,
    phone_change_sent_at       timestamptz,
    confirmed_at               timestamptz generated always as (least(email_confirmed_at, phone_confirmed_at)) stored,
    email_change_token_current varchar(255) default ''::character varying,
    email_change_confirm_status smallint    default 0,
    banned_until               timestamptz,
    reauthentication_token     varchar(255) default ''::character varying,
    reauthentication_sent_at   timestamptz,
    is_sso_user                boolean      not null default false,
    deleted_at                 timestamptz,
    is_anonymous               boolean      not null default false,
    constraint users_pkey primary key (id),
    constraint users_phone_key unique (phone),
    constraint users_email_change_confirm_status_check
        check (email_change_confirm_status >= 0 and email_change_confirm_status <= 2)
);

comment on table auth.users is 'Auth: Stores user login data within a secure schema.';
comment on column auth.users.is_sso_user is 'Auth: Set this column to true when the account comes from SSO. These accounts can have duplicate emails.';

create index if not exists users_instance_id_idx       on auth.users using btree (instance_id);
create index if not exists users_instance_id_email_idx on auth.users using btree (instance_id, email);
create index if not exists users_is_anonymous_idx      on auth.users using btree (is_anonymous);

-- Partial unique index (not a UNIQUE constraint): SSO users may share an email.
create unique index if not exists users_email_partial_key on auth.users using btree (email) where (is_sso_user = false);
comment on index auth.users_email_partial_key is 'Auth: A partial unique index that applies only when is_sso_user is false';

create unique index if not exists confirmation_token_idx          on auth.users using btree (confirmation_token)          where confirmation_token::text          !~ '^[0-9 ]*$';
create unique index if not exists recovery_token_idx              on auth.users using btree (recovery_token)              where recovery_token::text              !~ '^[0-9 ]*$';
create unique index if not exists email_change_token_current_idx  on auth.users using btree (email_change_token_current)  where email_change_token_current::text  !~ '^[0-9 ]*$';
create unique index if not exists email_change_token_new_idx      on auth.users using btree (email_change_token_new)      where email_change_token_new::text      !~ '^[0-9 ]*$';
create unique index if not exists reauthentication_token_idx      on auth.users using btree (reauthentication_token)      where reauthentication_token::text      !~ '^[0-9 ]*$';

-- ---------------------------------------------------------------------------
-- auth.sessions
-- ---------------------------------------------------------------------------

create table if not exists auth.sessions (
    id                     uuid not null,
    user_id                uuid not null,
    created_at             timestamptz,
    updated_at             timestamptz,
    factor_id              uuid,
    aal                    auth.aal_level,
    not_after              timestamptz,
    refreshed_at           timestamp without time zone,
    user_agent             text,
    ip                     inet,
    tag                    text,
    oauth_client_id        uuid,
    refresh_token_hmac_key text,
    refresh_token_counter  bigint,
    scopes                 text,
    constraint sessions_pkey primary key (id),
    constraint sessions_scopes_length check (char_length(scopes) <= 4096),
    constraint sessions_user_id_fkey foreign key (user_id) references auth.users (id) on delete cascade
);

comment on table auth.sessions is 'Auth: Stores session data associated to a user.';
comment on column auth.sessions.not_after is 'Auth: Not after is a nullable column that contains a timestamp after which the session should be regarded as expired.';
comment on column auth.sessions.refresh_token_hmac_key is 'Holds a HMAC-SHA256 key used to sign refresh tokens for this session.';
comment on column auth.sessions.refresh_token_counter is 'Holds the ID (counter) of the last issued refresh token.';

create index if not exists sessions_user_id_idx         on auth.sessions using btree (user_id);
create index if not exists sessions_not_after_idx       on auth.sessions using btree (not_after desc);
create index if not exists sessions_oauth_client_id_idx on auth.sessions using btree (oauth_client_id);
create index if not exists user_id_created_at_idx       on auth.sessions using btree (user_id, created_at);

-- ---------------------------------------------------------------------------
-- auth.refresh_tokens
-- ---------------------------------------------------------------------------
-- NOTE: user_id is varchar(255) upstream (holds the UUID in text form) — kept
-- as-is for byte-level compatibility with existing Supabase deployments.

create table if not exists auth.refresh_tokens (
    instance_id uuid,
    id          bigserial    not null,
    token       varchar(255),
    user_id     varchar(255),
    revoked     boolean,
    created_at  timestamptz,
    updated_at  timestamptz,
    parent      varchar(255),
    session_id  uuid,
    constraint refresh_tokens_pkey primary key (id),
    constraint refresh_tokens_token_unique unique (token),
    constraint refresh_tokens_session_id_fkey foreign key (session_id) references auth.sessions (id) on delete cascade
);

comment on table auth.refresh_tokens is 'Auth: Store of tokens used to refresh JWT tokens once they expire.';

create index if not exists refresh_tokens_instance_id_idx            on auth.refresh_tokens using btree (instance_id);
create index if not exists refresh_tokens_instance_id_user_id_idx    on auth.refresh_tokens using btree (instance_id, user_id);
create index if not exists refresh_tokens_parent_idx                 on auth.refresh_tokens using btree (parent);
create index if not exists refresh_tokens_session_id_revoked_idx     on auth.refresh_tokens using btree (session_id, revoked);
create index if not exists refresh_tokens_updated_at_idx             on auth.refresh_tokens using btree (updated_at desc);

-- ---------------------------------------------------------------------------
-- auth.identities
-- ---------------------------------------------------------------------------

create table if not exists auth.identities (
    provider_id     text not null,
    user_id         uuid not null,
    identity_data   jsonb not null,
    provider        text not null,
    last_sign_in_at timestamptz,
    created_at      timestamptz,
    updated_at      timestamptz,
    email           text generated always as (lower(identity_data ->> 'email')) stored,
    id              uuid not null default gen_random_uuid(),
    constraint identities_pkey primary key (id),
    constraint identities_provider_id_provider_unique unique (provider_id, provider),
    constraint identities_user_id_fkey foreign key (user_id) references auth.users (id) on delete cascade
);

comment on table auth.identities is 'Auth: Stores identities associated to a user.';
comment on column auth.identities.email is 'Auth: Email is a generated column that references the optional email property in the identity_data';

create index if not exists identities_user_id_idx on auth.identities using btree (user_id);
create index if not exists identities_email_idx   on auth.identities using btree (email text_pattern_ops);
comment on index auth.identities_email_idx is 'Auth: Ensures indexed queries on the email column';

-- ---------------------------------------------------------------------------
-- RLS — upstream enables RLS on every auth table (no policies: only the auth
-- service role, which bypasses RLS as table owner, may read them).
-- ---------------------------------------------------------------------------

alter table auth.users          enable row level security;
alter table auth.sessions       enable row level security;
alter table auth.refresh_tokens enable row level security;
alter table auth.identities     enable row level security;

-- ---------------------------------------------------------------------------
-- Helper functions used by RLS policies in downstream Supabase projects.
-- ---------------------------------------------------------------------------

create or replace function auth.uid() returns uuid
    language sql stable
as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;

create or replace function auth.role() returns text
    language sql stable
as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.role', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role')
  )::text
$$;

create or replace function auth.email() returns text
    language sql stable
as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.email', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'email')
  )::text
$$;

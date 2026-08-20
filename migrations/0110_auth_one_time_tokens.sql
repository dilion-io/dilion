-- 0110_auth_one_time_tokens.sql — auth.one_time_tokens (Supabase Auth parity).
--
-- Squashed from the upstream migration chain (github.com/supabase/auth,
-- master as of 2026-08):
--   * 20240427152123_add_one_time_tokens_table.up.sql
--   * 20240612123726_enable_rls_update_grants.up.sql   (RLS only)
-- Verified by applying the FULL upstream chain to Postgres 16 and diffing
-- `pg_dump --schema-only --schema=auth`.
--
-- project.md §2.2: NO Dilion-specific columns may be added to auth.*.

-- ---------------------------------------------------------------------------
-- enum type
-- ---------------------------------------------------------------------------

do $$
begin
    create type auth.one_time_token_type as enum (
        'confirmation_token',
        'reauthentication_token',
        'recovery_token',
        'email_change_token_new',
        'email_change_token_current',
        'phone_change_token'
    );
exception
    when duplicate_object then null;
end
$$;

-- ---------------------------------------------------------------------------
-- auth.one_time_tokens
-- ---------------------------------------------------------------------------
-- NOTE: created_at/updated_at are `timestamp without time zone` upstream (the
-- only auth.* table where that is the case) — kept verbatim.

create table if not exists auth.one_time_tokens (
    id         uuid                     not null,
    user_id    uuid                     not null,
    token_type auth.one_time_token_type not null,
    token_hash text                     not null,
    relates_to text                     not null,
    created_at timestamp without time zone not null default now(),
    updated_at timestamp without time zone not null default now(),
    constraint one_time_tokens_pkey primary key (id),
    constraint one_time_tokens_token_hash_check check (char_length(token_hash) > 0),
    constraint one_time_tokens_user_id_fkey foreign key (user_id) references auth.users (id) on delete cascade
);

-- One live token per (user, type): the service upserts on this key.
create unique index if not exists one_time_tokens_user_id_token_type_key on auth.one_time_tokens using btree (user_id, token_type);

-- Hash indexes: lookups are strict equality on the hashed token / the target
-- (email or phone) the token relates to.
create index if not exists one_time_tokens_token_hash_hash_idx on auth.one_time_tokens using hash (token_hash);
create index if not exists one_time_tokens_relates_to_hash_idx on auth.one_time_tokens using hash (relates_to);

alter table auth.one_time_tokens enable row level security;

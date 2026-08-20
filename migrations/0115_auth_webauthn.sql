-- 0115_auth_webauthn.sql — auth.webauthn_credentials / auth.webauthn_challenges
-- (passkeys as a first-class login method, distinct from the WebAuthn MFA
-- factor columns on auth.mfa_factors which live in 0112).
--
-- Squashed from the upstream migration chain (github.com/supabase/auth,
-- master as of 2026-08):
--   * 20260302000000_add_passkeys.up.sql               (both tables + indexes)
--   * 20250925093508_add_last_webauthn_challenge_data.up.sql — this migration adds
--       auth.mfa_factors.last_webauthn_challenge_data ONLY; it touches neither of
--       the tables below and is therefore applied in 0112, not here.
-- Verified by applying the FULL upstream chain to Postgres 16 and diffing
-- `pg_dump --schema-only --schema=auth`.
--
-- NOTE: upstream does NOT enable row level security on these two tables (unlike
-- the pre-2024 auth.* tables) — matched deliberately.

-- ---------------------------------------------------------------------------
-- auth.webauthn_credentials
-- ---------------------------------------------------------------------------

create table if not exists auth.webauthn_credentials (
    id               uuid    not null default gen_random_uuid(),
    user_id          uuid    not null,
    credential_id    bytea   not null,
    public_key       bytea   not null,
    attestation_type text    not null default ''::text,
    aaguid           uuid,
    sign_count       bigint  not null default 0,
    transports       jsonb   not null default '[]'::jsonb,
    backup_eligible  boolean not null default false,
    backed_up        boolean not null default false,
    friendly_name    text    not null default ''::text,
    created_at       timestamptz not null default now(),
    updated_at       timestamptz not null default now(),
    last_used_at     timestamptz,
    constraint webauthn_credentials_pkey primary key (id),
    constraint webauthn_credentials_user_id_fkey foreign key (user_id) references auth.users (id) on delete cascade
);

-- credential_id uniqueness is a unique INDEX upstream, not a table constraint.
create unique index if not exists webauthn_credentials_credential_id_key on auth.webauthn_credentials using btree (credential_id);
create index        if not exists webauthn_credentials_user_id_idx       on auth.webauthn_credentials using btree (user_id);

-- ---------------------------------------------------------------------------
-- auth.webauthn_challenges
-- ---------------------------------------------------------------------------
-- user_id is NULLABLE: a discoverable-credential ("usernameless") authentication
-- challenge is issued before the user is known.

create table if not exists auth.webauthn_challenges (
    id             uuid  not null default gen_random_uuid(),
    user_id        uuid,
    challenge_type text  not null,
    session_data   jsonb not null,
    created_at     timestamptz not null default now(),
    expires_at     timestamptz not null,
    constraint webauthn_challenges_pkey primary key (id),
    constraint webauthn_challenges_challenge_type_check
        check (challenge_type = any (array['signup'::text, 'registration'::text, 'authentication'::text])),
    constraint webauthn_challenges_user_id_fkey foreign key (user_id) references auth.users (id) on delete cascade
);

create index if not exists webauthn_challenges_user_id_idx    on auth.webauthn_challenges using btree (user_id);
create index if not exists webauthn_challenges_expires_at_idx on auth.webauthn_challenges using btree (expires_at);

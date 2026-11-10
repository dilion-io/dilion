-- 0122_auth_mfa_recovery_codes.sql — MFA recovery codes.
--
-- Squashed from the upstream migration chain (github.com/supabase/auth @ bfbe078):
--   * 20260824000000_add_recovery_codes_factor_type.up.sql  ('recovery_code' factor_type)
--   * 20260824000001_add_recovery_codes_tables.up.sql       (mfa_recovery_code_sets, mfa_recovery_codes)
--
-- One set per user, tied 1:1 to the user's recovery_code factor. Deleting the
-- factor (DELETE /factors/recovery-codes, an admin factor delete, account
-- deletion or the privacy pipeline's delete from auth.mfa_factors) cascades to
-- the set and its codes. Codes are stored as argon2id PHC strings only.
--
-- NOTE: upstream does NOT enable row level security on these two tables.
--
-- ALTER TYPE ... ADD VALUE runs inside this file's transaction (PostgreSQL 12+);
-- the new value is not used until a later transaction.

alter type auth.factor_type add value if not exists 'recovery_code';

create table if not exists auth.mfa_recovery_code_sets (
    id uuid primary key,
    user_id uuid not null unique references auth.users (id) on delete cascade,
    mfa_factor_id uuid not null unique references auth.mfa_factors (id) on delete cascade,
    failed_verification_count integer not null default 0 check (failed_verification_count >= 0),
    verification_locked_until timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists auth.mfa_recovery_codes (
    id uuid primary key,
    mfa_recovery_code_set_id uuid not null references auth.mfa_recovery_code_sets (id) on delete cascade,
    code_hash text not null,
    consumed_at timestamptz,
    created_at timestamptz not null default now()
);

create index if not exists mfa_recovery_codes_set_id_idx
    on auth.mfa_recovery_codes (mfa_recovery_code_set_id);

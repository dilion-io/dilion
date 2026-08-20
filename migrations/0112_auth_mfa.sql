-- 0112_auth_mfa.sql — auth.mfa_factors / mfa_challenges / mfa_amr_claims.
--
-- Squashed from the upstream migration chain (github.com/supabase/auth,
-- master as of 2026-08):
--   * 20221003041349_add_mfa_schema.up.sql                          (3 tables, factor_type/factor_status enums)
--   * 20221011041400_add_mfa_indexes.up.sql                         (factor_id_created_at_idx, mfa_factors_user_friendly_name_unique)
--   * 20230523124323_add_mfa_challenge_cleanup_index.up.sql         (mfa_challenge_created_at_idx)
--   * 20230914180801_add_mfa_factors_user_id_idx.up.sql             (mfa_factors_user_id_idx)
--   * 20231117164230_add_id_pkey_identities.up.sql                  (amr_id_pk / mfa_amr_claims.id)
--   * 20240612123726_enable_rls_update_grants.up.sql                (RLS)
--   * 20240729123726_add_mfa_phone_config.up.sql                    (mfa_factors.phone, mfa_challenges.otp_code, 'phone' factor_type, unique_phone_factor_per_user)
--   * 20240802193726_add_mfa_factors_column_last_challenged_at.up.sql (last_challenged_at + unique key)
--   * 20241009103726_add_web_authn.up.sql                           (web_authn_credential, web_authn_aaguid, web_authn_session_data)
--   * 20250925093508_add_last_webauthn_challenge_data.up.sql        (mfa_factors.last_webauthn_challenge_data)
-- Verified by applying the FULL upstream chain to Postgres 16 and diffing
-- `pg_dump --schema-only --schema=auth`.
--
-- NOTE ON auth.sessions.factor_id: upstream has NO foreign key from
-- auth.sessions.factor_id to auth.mfa_factors(id) (the session must outlive a
-- deleted factor), so none is added here. Only sessions.oauth_client_id gets an
-- FK upstream, and that is added by 0116.

-- ---------------------------------------------------------------------------
-- enum types
-- ---------------------------------------------------------------------------

do $$
begin
    create type auth.factor_type as enum ('totp', 'webauthn', 'phone');
exception
    when duplicate_object then null;
end
$$;

do $$
begin
    create type auth.factor_status as enum ('unverified', 'verified');
exception
    when duplicate_object then null;
end
$$;

-- ---------------------------------------------------------------------------
-- auth.mfa_factors
-- ---------------------------------------------------------------------------

create table if not exists auth.mfa_factors (
    id                           uuid              not null,
    user_id                      uuid              not null,
    friendly_name                text,
    factor_type                  auth.factor_type  not null,
    status                       auth.factor_status not null,
    created_at                   timestamptz       not null,
    updated_at                   timestamptz       not null,
    secret                       text,
    phone                        text,
    last_challenged_at           timestamptz,
    web_authn_credential         jsonb,
    web_authn_aaguid             uuid,
    last_webauthn_challenge_data jsonb,
    constraint mfa_factors_pkey primary key (id),
    constraint mfa_factors_last_challenged_at_key unique (last_challenged_at),
    constraint mfa_factors_user_id_fkey foreign key (user_id) references auth.users (id) on delete cascade
);

comment on table auth.mfa_factors is 'auth: stores metadata about factors';
comment on column auth.mfa_factors.last_webauthn_challenge_data is 'Stores the latest WebAuthn challenge data including attestation/assertion for customer verification';

create index if not exists mfa_factors_user_id_idx on auth.mfa_factors using btree (user_id);
create index if not exists factor_id_created_at_idx on auth.mfa_factors using btree (user_id, created_at);
create unique index if not exists mfa_factors_user_friendly_name_unique on auth.mfa_factors using btree (friendly_name, user_id) where (trim(both from friendly_name) <> ''::text);
create unique index if not exists unique_phone_factor_per_user on auth.mfa_factors using btree (user_id, phone);

-- ---------------------------------------------------------------------------
-- auth.mfa_challenges
-- ---------------------------------------------------------------------------
-- NOTE: the FK is named mfa_challenges_auth_factor_id_fkey upstream (not
-- ..._factor_id_fkey) — preserved verbatim.

create table if not exists auth.mfa_challenges (
    id                     uuid        not null,
    factor_id              uuid        not null,
    created_at             timestamptz not null,
    verified_at            timestamptz,
    ip_address             inet        not null,
    otp_code               text,
    web_authn_session_data jsonb,
    constraint mfa_challenges_pkey primary key (id),
    constraint mfa_challenges_auth_factor_id_fkey foreign key (factor_id) references auth.mfa_factors (id) on delete cascade
);

comment on table auth.mfa_challenges is 'auth: stores metadata about challenge requests made';

create index if not exists mfa_challenge_created_at_idx on auth.mfa_challenges using btree (created_at desc);

-- ---------------------------------------------------------------------------
-- auth.mfa_amr_claims
-- ---------------------------------------------------------------------------
-- NOTE: the (session_id, authentication_method) constraint is a UNIQUE
-- constraint whose name still ends in `_pkey` upstream (it used to be the PK
-- before `id`/amr_id_pk were introduced) — preserved verbatim.

create table if not exists auth.mfa_amr_claims (
    session_id            uuid        not null,
    created_at            timestamptz not null,
    updated_at            timestamptz not null,
    authentication_method text        not null,
    id                    uuid        not null,
    constraint amr_id_pk primary key (id),
    constraint mfa_amr_claims_session_id_authentication_method_pkey unique (session_id, authentication_method),
    constraint mfa_amr_claims_session_id_fkey foreign key (session_id) references auth.sessions (id) on delete cascade
);

comment on table auth.mfa_amr_claims is 'auth: stores authenticator method reference claims for multi factor authentication';

alter table auth.mfa_factors    enable row level security;
alter table auth.mfa_challenges enable row level security;
alter table auth.mfa_amr_claims enable row level security;

-- 0119_dilion_auth_hooks.sql — per-instance auth hook settings (Dilion extension).
--
-- Upstream configures the auth hooks (send_email, before_user_created, ...)
-- per process through GOTRUE_HOOK_*. A Dilion server can serve many instances,
-- so an instance admin sets their own instance's hooks here, through
-- /auth/v1/admin/hooks. A row replaces the server-wide setting for its hook,
-- including disabling it; no row means the server-wide setting applies. A hook
-- the operator marked locked ignores its row. Every statement is idempotent so
-- the file can be re-applied.

create schema if not exists dilion_auth;

create table if not exists dilion_auth.hooks (
    name       text        primary key check (name in (
                   'custom_access_token', 'send_email', 'send_sms',
                   'before_user_created', 'after_user_created',
                   'mfa_verification_attempt', 'password_verification_attempt')),
    enabled    boolean     not null,
    uri        text        not null,
    -- v1,whsec_<base64> Standard Webhooks keys, all used to sign (rotation).
    -- Stored as-is and never returned, like auth.custom_oauth_providers'
    -- client_secret.
    secrets    text[]      not null default '{}',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- Dilion extension. Secrets are AEAD encrypted by an external master key.
create table if not exists auth.opaque_setup (
    scope text primary key,
    material bytea not null
);
create table if not exists auth.opaque_credentials (
    user_id uuid primary key references auth.users(id) on delete cascade,
    scope text not null,
    version uuid not null unique,
    identity text not null,
    record bytea not null,
    created_at timestamptz not null default now()
);
create table if not exists auth.opaque_handshakes (
    id uuid primary key,
    scope text not null,
    kind text not null check (kind in ('registration', 'login')),
    state bytea not null,
    expires_at timestamptz not null
);
create index if not exists opaque_handshakes_expiry on auth.opaque_handshakes(expires_at);
create index if not exists opaque_handshakes_scope_expiry on auth.opaque_handshakes(scope,expires_at);
create table if not exists auth.opaque_session_keys (
    id uuid primary key,
    scope text not null,
    session_id uuid not null references auth.sessions(id) on delete cascade,
    credential_version uuid not null references auth.opaque_credentials(version) on delete cascade,
    secret bytea not null,
    expires_at timestamptz not null
);
create index if not exists opaque_keys_session on auth.opaque_session_keys(session_id);
create index if not exists opaque_keys_expiry on auth.opaque_session_keys(expires_at);
create table if not exists auth.opaque_attempts (
    scope text not null,
    account text not null,
    window_start timestamptz not null,
    attempts integer not null,
    primary key(scope, account)
);
create index if not exists opaque_attempts_expiry on auth.opaque_attempts(window_start);
alter table auth.opaque_setup enable row level security;
alter table auth.opaque_credentials enable row level security;
alter table auth.opaque_handshakes enable row level security;
alter table auth.opaque_session_keys enable row level security;
alter table auth.opaque_attempts enable row level security;
revoke all on auth.opaque_setup, auth.opaque_credentials, auth.opaque_handshakes,
    auth.opaque_session_keys, auth.opaque_attempts from public;

-- Legacy password reset/change and soft deletion invalidate the independent
-- OPAQUE credential, outstanding logins (version check), and derived keys.
create or replace function auth.invalidate_opaque_credential() returns trigger
language plpgsql set search_path = '' as $$
begin
    if new.encrypted_password is distinct from old.encrypted_password
       or new.deleted_at is distinct from old.deleted_at then
        delete from auth.opaque_credentials where user_id = new.id;
    end if;
    return new;
end;
$$;
drop trigger if exists invalidate_opaque_credential on auth.users;
create trigger invalidate_opaque_credential after update on auth.users
for each row execute function auth.invalidate_opaque_credential();

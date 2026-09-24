-- 0120_dilion_auth_attempts.sql — failed credential attempts per account.
--
-- The per-IP rate limits cannot stop guessing spread over many addresses, so
-- password sign-in, typed OTPs, MFA factor codes and reauthentication nonces
-- also count failures per account (internal/auth attempts.go). account is a
-- SHA-256 of the kind and the identifier (address, phone, factor or user id),
-- not the identifier itself. Rows past their window are removed by the
-- cleanup worker. Every statement is idempotent so the file can be re-applied.

create schema if not exists dilion_auth;

create table if not exists dilion_auth.auth_attempts (
    account      text        primary key,
    window_start timestamptz not null,
    failures     integer     not null
);

create index if not exists auth_attempts_window on dilion_auth.auth_attempts (window_start);

-- 0114_auth_audit_log_entries.sql — auth.audit_log_entries.
--
-- Squashed from the upstream migration chain (github.com/supabase/auth,
-- master as of 2026-08):
--   * 00_init_auth_schema.up.sql                                  (table + audit_logs_instance_id_idx)
--   * 20220614074223_add_ip_address_to_audit_log.postgres.up.sql  (ip_address)
--   * 20240612123726_enable_rls_update_grants.up.sql              (RLS)
-- Verified by applying the FULL upstream chain to Postgres 16 and diffing
-- `pg_dump --schema-only --schema=auth`.
--
-- instance_id is retained for byte-level compatibility with existing Supabase
-- databases even though auth.instances is deliberately out of scope (same
-- precedent as auth.users.instance_id in 0100).

create table if not exists auth.audit_log_entries (
    instance_id uuid,
    id          uuid not null,
    payload     json,
    created_at  timestamptz,
    ip_address  varchar(64) not null default ''::character varying,
    constraint audit_log_entries_pkey primary key (id)
);

comment on table auth.audit_log_entries is 'Auth: Audit trail for user actions.';

-- NOTE: the index is named audit_logs_instance_id_idx (not audit_log_entries_*).
create index if not exists audit_logs_instance_id_idx on auth.audit_log_entries using btree (instance_id);

alter table auth.audit_log_entries enable row level security;

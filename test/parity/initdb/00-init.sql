-- Parity stack Postgres bootstrap. Runs once, on first cluster init, via the
-- official postgres image's /docker-entrypoint-initdb.d hook (executed as the
-- superuser against the maintenance database).
--
-- It provisions, in ONE cluster:
--   * the Supabase roles GoTrue's migrations depend on (postgres, anon,
--     authenticated, service_role, supabase_auth_admin, supabase_admin) — WITHOUT
--     these, upstream migration 20240612123726_enable_rls_update_grants FAILS with
--     `role "postgres" does not exist`. This was verified empirically during
--     harness bring-up.
--   * two SEPARATE logical databases so the two servers never share state:
--       - dilion_parity : Dilion migrates this itself on boot (srv.Migrate)
--       - gotrue_parity : `gotrue migrate` populates the `auth` schema here
--
-- Both databases live in a THROWAWAY container (compose volume is ephemeral);
-- neither is dilion_dev. Never point this at a real database.

-- ---- Supabase roles (cluster-global) --------------------------------------
CREATE ROLE postgres SUPERUSER LOGIN;
CREATE ROLE anon NOLOGIN NOINHERIT;
CREATE ROLE authenticated NOLOGIN NOINHERIT;
CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS;
CREATE ROLE supabase_auth_admin LOGIN NOINHERIT CREATEROLE PASSWORD 'root';
CREATE ROLE supabase_admin SUPERUSER LOGIN;

-- ---- databases -------------------------------------------------------------
CREATE DATABASE dilion_parity;
CREATE DATABASE gotrue_parity;

-- ---- gotrue schema + grants ------------------------------------------------
\connect gotrue_parity
CREATE SCHEMA IF NOT EXISTS auth AUTHORIZATION supabase_auth_admin;
GRANT ALL ON SCHEMA auth TO supabase_auth_admin;
GRANT USAGE ON SCHEMA auth TO postgres, anon, authenticated, service_role;
-- pgcrypto: several upstream migrations rely on gen_random_uuid()/crypt().
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---- dilion database extensions -------------------------------------------
\connect dilion_parity
-- Dilion's 0001_core migration also does this, but creating it here means the
-- connecting app role never needs the CREATE EXTENSION privilege.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 0001_core: extensions and schema layout (owner: agent A).
-- Every later migration assumes these schemas already exist.

create extension if not exists pgcrypto;

-- Supabase Auth compatible surface (owner: agent B).
create schema if not exists auth;

-- Compliance engine: policies, consent ledger, requests, outbox (owner: agent C).
create schema if not exists dilion_privacy;

-- PII vault: encrypted profiles + subject keys (owner: agent C).
create schema if not exists dilion_pii;

-- Management-plane RBAC (owner: agent D).
create schema if not exists dilion_authz;

-- Audit events + subject manifest (owner: agent D).
create schema if not exists dilion_audit;

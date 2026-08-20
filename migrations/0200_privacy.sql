-- 0200_privacy.sql — compliance engine schema (project.md §4, §2.7–§2.10).
-- Owner: agent C. Schemas are created by 0001_core.sql (agent A); the
-- "if not exists" guards below keep this file self-contained for tests.

create schema if not exists dilion_privacy;
create schema if not exists dilion_pii;

-- ---------------------------------------------------------------------------
-- Transactional outbox (§2.5) — written by auth (agent B), consumed by the
-- privacy dispatcher.
-- ---------------------------------------------------------------------------
create table if not exists dilion_privacy.outbox (
    id           uuid primary key default gen_random_uuid(),
    event_type   text        not null,
    aggregate_id text        not null,
    payload      jsonb       not null,
    created_at   timestamptz not null default now(),
    published_at timestamptz
);

create index if not exists outbox_unpublished_idx
    on dilion_privacy.outbox (created_at)
    where published_at is null;

-- ---------------------------------------------------------------------------
-- Compliance code per subject (§2.8). Changes are a "very high" audit event.
-- ---------------------------------------------------------------------------
create table if not exists dilion_privacy.subject_policies (
    user_id     uuid primary key,
    policy_id   text        not null,
    source      text        not null check (source in ('explicit', 'tenant-default')),
    assigned_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Data subject requests (§2.9). policy_snapshot freezes the resolved policy so
-- later policy edits cannot affect an in-flight pipeline.
-- ---------------------------------------------------------------------------
create table if not exists dilion_privacy.personal_data_requests (
    id                   text primary key,
    project_id           text        not null default 'default',
    user_id              uuid        not null,
    type                 text        not null,  -- DELETION | EXPORT | CONSENT_WITHDRAWAL
    status               text        not null,  -- REQUESTED | PROCESSING | DONE | MANUAL_REVIEW | CANCELED
    policy_id            text        not null,
    policy_snapshot      jsonb       not null,
    scheduled_at         timestamptz not null,
    requested_at         timestamptz not null default now(),
    completed_at         timestamptz,
    idempotency_key      text,
    requested_by         text,
    manual_review_reason text,                  -- LEGAL_HOLD | POLICY | TASK_FAILED | HOOK_REJECTED
    unique (idempotency_key)
);

-- At most one active DELETION per subject (§2.9 duplicate-request guard).
create unique index if not exists personal_data_requests_active_deletion_uniq
    on dilion_privacy.personal_data_requests (user_id)
    where type = 'DELETION' and status in ('REQUESTED', 'PROCESSING', 'MANUAL_REVIEW');

create index if not exists personal_data_requests_runnable_idx
    on dilion_privacy.personal_data_requests (scheduled_at)
    where type = 'DELETION' and status in ('REQUESTED', 'PROCESSING');

create index if not exists personal_data_requests_list_idx
    on dilion_privacy.personal_data_requests (project_id, requested_at desc, id desc);

-- ---------------------------------------------------------------------------
-- Destruction evidence. UNIQUE(request_id, domain) is the re-run dedup key.
-- ---------------------------------------------------------------------------
create table if not exists dilion_privacy.destruction_logs (
    id          bigserial primary key,
    request_id  text        not null,
    domain      text        not null,
    action      text        not null,
    basis       text,
    executed_at timestamptz not null default now(),
    unique (request_id, domain)
);

-- ---------------------------------------------------------------------------
-- Connector/webhook execution units for the external-system step (§3.1–3.2).
-- ---------------------------------------------------------------------------
create table if not exists dilion_privacy.tasks (
    id              text primary key,
    request_id      text        not null,
    user_id         uuid        not null,
    destination_id  text        not null,
    action          text        not null,  -- DELETE | ANONYMIZE | EXPORT | RECONFIRM_NOTICE
    status          text        not null,  -- pending | running | completed | failed | dead
    attempt_count   int         not null default 0,
    created_at      timestamptz not null default now(),
    started_at      timestamptz,
    completed_at    timestamptz,
    error_code      text,
    evidence        jsonb,
    next_attempt_at timestamptz not null default now(),
    payload         jsonb
);

-- One task per (request, destination): makes the fan-out step idempotent.
create unique index if not exists tasks_request_destination_uniq
    on dilion_privacy.tasks (request_id, destination_id);

create index if not exists tasks_runnable_idx
    on dilion_privacy.tasks (next_attempt_at)
    where status in ('pending', 'failed');

-- Crash recovery: tasks left 'running' by a dead worker are re-claimed.
create index if not exists tasks_running_idx
    on dilion_privacy.tasks (started_at)
    where status = 'running';

-- ---------------------------------------------------------------------------
-- Delivery destinations. The webhook secret is stored KMS-encrypted and is
-- never returned by the API.
-- ---------------------------------------------------------------------------
create table if not exists dilion_privacy.destinations (
    id         text primary key,
    project_id text not null default 'default',
    type       text not null,  -- WEBHOOK | CONNECTOR
    name       text not null,
    config     jsonb not null default '{}',
    secret_enc bytea,
    enabled    bool not null default true,
    created_at timestamptz default now()
);

create index if not exists destinations_project_idx
    on dilion_privacy.destinations (project_id, id);

-- ---------------------------------------------------------------------------
-- Legal holds (§2.9) — triple gate: pipeline, retention scanner, restore replay.
-- ---------------------------------------------------------------------------
create table if not exists dilion_privacy.legal_holds (
    id          text primary key,
    project_id  text        not null default 'default',
    user_id     uuid        not null,
    domain      text,                       -- null = whole subject
    reason      text        not null,
    basis       text,
    created_by  text,
    created_at  timestamptz not null default now(),
    released_by text,
    released_at timestamptz
);

create index if not exists legal_holds_active_idx
    on dilion_privacy.legal_holds (user_id)
    where released_at is null;

-- ---------------------------------------------------------------------------
-- Erasure registry (§2.10) — tombstone identifiers only, never raw ids.
-- ---------------------------------------------------------------------------
create table if not exists dilion_privacy.erasure_registry (
    tombstone_id text primary key,
    erased_at    timestamptz not null default now(),
    request_id   text        not null,
    reason       text
);

create index if not exists erasure_registry_erased_at_idx
    on dilion_privacy.erasure_registry (erased_at);

-- ---------------------------------------------------------------------------
-- Consent ledger (§4) — append-only.
-- ---------------------------------------------------------------------------
create table if not exists dilion_privacy.consent_events (
    id             bigserial primary key,
    project_id     text        not null default 'default',
    user_id        uuid        not null,
    purpose        text        not null,
    action         text        not null,  -- GRANT | WITHDRAW | RECONFIRM_NOTICE
    policy_version text,
    created_at     timestamptz not null default now(),
    source         text,
    region         text,
    evidence       jsonb
);

create index if not exists consent_events_subject_idx
    on dilion_privacy.consent_events (project_id, user_id, purpose, created_at desc, id desc);

-- Append-only enforcement: UPDATE/DELETE/TRUNCATE always raise.
create or replace function dilion_privacy.consent_events_append_only()
returns trigger language plpgsql as $$
begin
    raise exception 'dilion_privacy.consent_events is append-only (attempted %)', tg_op
        using errcode = 'insufficient_privilege';
end;
$$;

drop trigger if exists consent_events_no_update on dilion_privacy.consent_events;
create trigger consent_events_no_update
    before update on dilion_privacy.consent_events
    for each statement execute function dilion_privacy.consent_events_append_only();

drop trigger if exists consent_events_no_delete on dilion_privacy.consent_events;
create trigger consent_events_no_delete
    before delete on dilion_privacy.consent_events
    for each statement execute function dilion_privacy.consent_events_append_only();

drop trigger if exists consent_events_no_truncate on dilion_privacy.consent_events;
create trigger consent_events_no_truncate
    before truncate on dilion_privacy.consent_events
    for each statement execute function dilion_privacy.consent_events_append_only();

-- ---------------------------------------------------------------------------
-- PII Vault (§2.7). subject_keys shape is a contract with internal/kmslocal.
-- ---------------------------------------------------------------------------
create table if not exists dilion_pii.user_profiles (
    user_id     uuid primary key,
    enc_profile bytea,
    created_at  timestamptz default now(),
    updated_at  timestamptz
);

create table if not exists dilion_pii.subject_keys (
    user_id     uuid        not null,
    scope       text        not null check (scope in ('DEFAULT', 'CONSENT')),
    wrapped_dek bytea       not null,
    shred_after timestamptz,
    shredded_at timestamptz,
    created_at  timestamptz not null default now(),
    primary key (user_id, scope)
);

-- Retention sweep target: CONSENT keys whose shred_after has come.
create index if not exists subject_keys_shred_due_idx
    on dilion_pii.subject_keys (shred_after)
    where scope = 'CONSENT' and shredded_at is null;

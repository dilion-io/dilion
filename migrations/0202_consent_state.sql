-- Materialised current consent state. consent_events remains the append-only
-- source of truth; this table is the indexed projection used by reconfirm scans.

create table if not exists dilion_privacy.consent_state (
    user_id             uuid        not null,
    purpose             text        not null,
    granted             boolean     not null,
    policy_version      text        not null default '',
    updated_at          timestamptz not null,
    last_notice_at      timestamptz,
    next_reconfirm_at   timestamptz,
    scheduled_policy_id text,
    schedule_revision   text,
    schedule_computed   boolean     not null default false,
    primary key (user_id, purpose)
);

-- Existing installations are backfilled from the ledger. The application
-- computes policy-specific schedules in bounded batches because policy periods
-- live in validated YAML rather than SQL.
with latest as (
    select distinct on (user_id, purpose)
        user_id, purpose, action,
        coalesce(policy_version, '') as policy_version, created_at
    from dilion_privacy.consent_events
    where action in ('GRANT', 'WITHDRAW')
    order by user_id, purpose, created_at desc, id desc
), notices as (
    select user_id, purpose, max(created_at) as noticed_at
    from dilion_privacy.consent_events
    where action = 'RECONFIRM_NOTICE'
    group by user_id, purpose
)
insert into dilion_privacy.consent_state
    (user_id, purpose, granted, policy_version, updated_at, last_notice_at)
select l.user_id, l.purpose, l.action = 'GRANT',
       l.policy_version, l.created_at, n.noticed_at
from latest l
left join notices n using (user_id, purpose)
on conflict (user_id, purpose) do nothing;

create index if not exists consent_state_reconfirm_due_idx
    on dilion_privacy.consent_state (next_reconfirm_at, user_id, purpose)
    where granted and schedule_computed and next_reconfirm_at is not null;

-- The primary key also serves the bounded (user_id, purpose) reconciliation
-- cursor. Do not add a revision index: idle scans must not filter all rows.

-- 0301_audit_reason.sql — audit read path (project.md §5.1–§5.3).
-- Owner: agent D (platform API).
--
-- Adds the operator-supplied justification recorded with privileged reads
-- (PII_FULL_READ 사유 입력, §5.2) and makes the read path indexable:
--   * action + time  — "what happened, newest first"
--   * subject_id     — reverse lookup "who accessed subject X" (§5.3)
--
-- The table stays append-only (§5.4): this migration only adds a column and
-- indexes, it never rewrites recorded events.

alter table dilion_audit.events add column if not exists reason text;

-- 0300 already creates events_action_idx as (project_id, action, created_at
-- desc), which serves every project-scoped action filter this API issues; the
-- statement below is therefore a no-op there. It is kept so the file also
-- applies to installations whose 0300 predates that index.
create index if not exists events_action_idx on dilion_audit.events (action, created_at desc);

-- Reverse index (§5.3). 0300 already creates it; repeated here so the audit
-- read path never depends on which 0300 revision an installation applied.
create index if not exists subjects_subject_idx on dilion_audit.subjects (subject_id);

-- Keyset pagination of the event list orders by (created_at desc, event_id
-- desc) within a project.
create index if not exists events_project_created_idx
    on dilion_audit.events (project_id, created_at desc, event_id desc);

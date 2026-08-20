-- 0302_pii_write_permission.sql — builtin permission `pii.write` (project.md
-- §2.11 + §5.2 "개인정보 수정" = 강화 등급 이벤트).
-- Owner: agent D (platform API).
--
-- Writing a PII profile is a distinct authority from reading it: `pii.read`
-- (unmasked projection) and `pii.reveal` (원본 열람) say nothing about the right
-- to change a data subject's stored personal data. Every statement is
-- idempotent so the file can be re-applied.

insert into dilion_authz.permissions (project_id, name, builtin) values
    ('default', 'pii.write', true)
on conflict (project_id, name) do nothing;

-- Cumulative builtin bundles (§2.11): support (데이터 정정 처리), privacy-officer
-- (DSR 처리 중 정정), owner (전부). viewer and security-admin do not write PII —
-- security-admin is deliberately SoD-separated from subject data mutation.
update dilion_authz.roles
set permissions = permissions || array['pii.write']
where builtin
  and name in ('support', 'privacy-officer', 'owner')
  and not ('pii.write' = any (permissions));

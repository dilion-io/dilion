-- 0304_consents_write_permission.sql — builtin permission `consents.write`
-- (docs/use-cases.md 부수 개선: 동의 기록 권한 분리).
-- Owner: agent D (platform API).
--
-- Recording a consent change is a routine application-server operation (signup
-- flows, unsubscribe links), while `privacy.requests.manage` is the DSR
-- approval authority. Bundling both forced signup-flow keys to hold DSR
-- powers; `consents.write` separates them so a scoped API key can record
-- consent and nothing else. Every statement is idempotent so the file can be
-- re-applied.

insert into dilion_authz.permissions (project_id, name, builtin) values
    ('default', 'consents.write', true)
on conflict (project_id, name) do nothing;

-- Grant to every builtin role that could previously record consent via
-- privacy.requests.manage, so no existing operator loses the capability.
update dilion_authz.roles
set permissions = permissions || array['consents.write']
where builtin
  and name in ('privacy-officer', 'security-admin', 'owner')
  and not ('consents.write' = any (permissions));

-- 0303_users_admin_permission.sql — builtin permission `users.admin`
-- (project.md §2.11: 사용자 access token 으로 Supabase 호환 admin 표면 사용).
-- Owner: agent D (platform API).
--
-- `/auth/v1/admin/*` is gotrue's account-administration surface: it creates,
-- edits, bans and deletes accounts. Until now only a `service_role` JWT could
-- reach it. `users.admin` makes that authority grantable to a named human via
-- RBAC, so the all-powerful machine key stops being the only way in.
-- Every statement is idempotent so the file can be re-applied.

insert into dilion_authz.permissions (project_id, name, builtin) values
    ('default', 'users.admin', true)
on conflict (project_id, name) do nothing;

-- Only `owner` bundles it: account administration is the highest-blast-radius
-- authority on the compat plane, and support/privacy-officer/security-admin are
-- deliberately SoD-separated from it (§2.11).
update dilion_authz.roles
set permissions = permissions || array['users.admin']
where builtin
  and name = 'owner'
  and not ('users.admin' = any (permissions));

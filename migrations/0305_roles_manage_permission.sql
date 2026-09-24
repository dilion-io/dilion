-- 0305_roles_manage_permission.sql — builtin permission `roles.manage`.
--
-- Until now `keys.manage` guarded every IAM mutation: issuing API keys, but
-- also defining roles and permissions and granting or revoking role
-- assignments. Those are separate duties, so role administration moves to its
-- own permission. Either way a caller can only grant what it holds itself
-- (internal/api grantCeiling), so holding `roles.manage` is not a way to more
-- authority. Every statement is idempotent so the file can be re-applied.

insert into dilion_authz.permissions (name, builtin) values
    ('roles.manage', true)
on conflict (name) do nothing;

-- Both roles that held `keys.manage`, and with it role administration, keep
-- it: no existing deployment loses the capability.
update dilion_authz.roles
set permissions = permissions || array['roles.manage']
where builtin
  and name in ('owner', 'security-admin')
  and not ('roles.manage' = any (permissions));

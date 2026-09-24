-- 0306_auth_settings_permission.sql — builtin permission `auth.settings.manage`.
--
-- The instance's auth configuration kept in its database — auth hooks,
-- custom OAuth/OIDC providers, SSO providers and OAuth server clients — was
-- administered with `users.admin`. Each of them reaches every account: a
-- send_email hook receives every OTP and link, a provider signs in whoever
-- it names. It is now the owner's alone: this permission is bundled into the
-- builtin owner role and cannot be put in a custom role or an API key
-- (internal/iam OwnerOnlyPermissions). Every statement is idempotent so the
-- file can be re-applied.

insert into dilion_authz.permissions (name, builtin) values
    ('auth.settings.manage', true)
on conflict (name) do nothing;

update dilion_authz.roles
set permissions = permissions || array['auth.settings.manage']
where builtin
  and name = 'owner'
  and not ('auth.settings.manage' = any (permissions));

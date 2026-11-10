-- 0123_auth_saml_dedicated_scope.sql — saml_providers.dedicated_scope.
--
-- From upstream (github.com/supabase/auth @ bfbe078):
--   * 20261030120000_add_dedicated_scope_to_saml_providers.up.sql
--
-- NULL and false both mean the provider uses the SP URLs shared by every SAML
-- provider (/sso/saml/{metadata,acs}); true scopes them to the provider's own
-- id (/sso/{id}/saml/{metadata,acs}). Set on create only: changing it changes
-- the entity id the IdP was configured with.

alter table only auth.saml_providers
    add column if not exists dedicated_scope boolean null;

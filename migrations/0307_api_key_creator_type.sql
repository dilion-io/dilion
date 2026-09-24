-- 0307_api_key_creator_type.sql — which kind of actor issued an API key.
--
-- A key issued by a user must not outlive that user's own authority: once
-- the user loses a permission (a revoked role, a deleted account), the key
-- loses it too. The authorizer bounds such a key by its creator's current
-- grants, which needs to know the creator was a user and not service_role.
-- Keys issued before this column existed are left as they were (null).
-- Every statement is idempotent so the file can be re-applied.

alter table dilion_authz.api_keys add column if not exists created_by_type text;

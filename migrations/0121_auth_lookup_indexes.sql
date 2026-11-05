-- 0121_auth_lookup_indexes.sql — indexes for lookups that scanned whole tables.
--
--   * Every sign-in, OTP, sign-up and provider callback finds its user by
--     lower(email), and the management plane searches users the same way;
--     only the plain email was indexed, so each lookup read all of
--     auth.users. Upstream indexes (instance_id, lower(email)); the instance
--     id is the same nil UUID on every row, so lower(email) alone serves both
--     the auth lookups and the instance-less search.
--   * Revoking a user's refresh tokens (logout, ban, delete, erasure) filters
--     on user_id alone, which the (instance_id, user_id) index cannot serve.
--   * Deleting a factor cascades to its challenges by factor_id, and expired
--     factors are pruned through it; nothing indexed it.
--
-- Plain CREATE INDEX (each migration file runs in one transaction, so not
-- CONCURRENTLY): it blocks writes to the table while it builds. On a large
-- existing database, create these CONCURRENTLY by hand under the same names
-- first; IF NOT EXISTS then skips them here.

create index if not exists users_email_lower_idx on auth.users using btree (lower(email));
create index if not exists refresh_tokens_user_id_idx on auth.refresh_tokens using btree (user_id);
create index if not exists mfa_challenges_factor_id_idx on auth.mfa_challenges using btree (factor_id);

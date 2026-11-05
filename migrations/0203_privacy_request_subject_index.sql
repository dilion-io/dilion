-- 0203_privacy_request_subject_index.sql — find a subject's requests by index.
--
-- The outbox's duplicate check for user.deleted, request listing filtered by
-- user and the consent segment's "erased subjects" anti-join all look
-- requests up by user_id across every status; only active deletions were
-- indexed by it, so each of these read the whole table.
--
-- Plain CREATE INDEX: it blocks writes to the table while it builds (see
-- 0121 for creating it CONCURRENTLY by hand first).

create index if not exists personal_data_requests_user_idx
    on dilion_privacy.personal_data_requests (user_id, type, status);

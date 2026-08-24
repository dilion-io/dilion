-- 0201_pii_search_index.sql — blind index for exact-match user search over
-- vault profile fields (docs/use-cases.md 제안 P4).
-- Owner: agent C (privacy engine).
--
-- The vault document itself is envelope-encrypted (§2.7), so searching it
-- requires a keyed-hash side index: value_hmac = HMAC(search key, field_key
-- normalized value). The HMAC key is derived from the instance's tombstone key,
-- so the index reveals nothing without it and supports only exact matches.
--
-- Rows are maintained transactionally with every profile write and are removed
-- by the erasure pipeline's account step together with the profile row —
-- an index entry must never outlive the document it points into.
--
-- Rows written before this migration existed are indexed on their next profile
-- write; there is no backfill (the plaintext needed to compute the HMAC only
-- exists inside the sealed document).

create table if not exists dilion_pii.profile_search_index (
    user_id    uuid not null,
    field_key  text not null,
    value_hmac text not null,
    primary key (user_id, field_key)
);

create index if not exists profile_search_index_lookup_idx
    on dilion_pii.profile_search_index (field_key, value_hmac);

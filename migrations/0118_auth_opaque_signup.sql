-- Permit a separate single-use ceremony for unauthenticated account creation.
-- Existing enrollment/login state cannot be used on the signup finish route.
alter table auth.opaque_handshakes drop constraint if exists opaque_handshakes_kind_check;
alter table auth.opaque_handshakes add constraint opaque_handshakes_kind_check
    check (kind in ('registration', 'login', 'signup'));

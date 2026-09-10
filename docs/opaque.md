# OPAQUE authentication

Dilion implements RFC 9807 registration and login at
`/auth/v1/opaque/{signup,registration,login}/{start,finish}`. The JavaScript entry point
is `@dilion-io/auth-js`; see [SDK usage](../js/packages/auth-js/README.md).
The server uses `github.com/bytemare/opaque` v0.18.0 and the SDK uses
`@serenity-kit/opaque` 1.1.0. The suite is fixed to
`ristretto255-sha512-argon2id-v1`: Ristretto255, SHA-512, Argon2id with 64 MiB,
three iterations and four lanes on the client. The server never receives the
password or `export_key`; it cannot enforce password strength against plaintext.

## Enable

Apply migrations `0117_auth_opaque.sql` and `0118_auth_opaque_signup.sql` using
the normal migration runner. Set:

```sh
DILION_AUTH_OPAQUE_MASTER_KEY=<32 random bytes, unpadded base64url>
```

When this key is configured, OPAQUE is enabled by default; no
`DILION_AUTH_OPAQUE_ENABLED=true` setting is required. Without a key it remains
disabled. Set `DILION_AUTH_OPAQUE_ENABLED=false` to explicitly disable it even
when a key is present. When enabled (automatically or explicitly), a malformed or
missing key fails configuration validation rather than silently disabling OPAQUE.
The existing `GOTRUE_` environment-variable fallback is also supported.
Programmatic `WithAuthConfig` callers continue to set `Opaque.Enabled` explicitly.

Generate the master key using a cryptographic random source, provision it through
your secret manager, and keep it out of source control, logs and the database.
It is separate from the JWT signing key. All replicas must use the same key and
the same stable instance ID. Keep an independently protected backup: losing it
loses existing OPAQUE credentials. Changing this value is NOT a supported key
rotation procedure. An incorrect key fails closed; it never replaces the setup.

Use HTTPS at the trusted ingress. The Go handlers support TLS termination; they
do not infer security from client-supplied forwarding headers. Do not expose the
unencrypted backend port publicly. The SDK rejects non-loopback HTTP.

## Registration and account lifecycle

There are two distinct registration entry points:

- **New account:** `auth.opaque.signUp()` uses `signup/start` and `signup/finish`
  without a bearer session. Start creates only encrypted, two-minute, single-use
  state. Finish atomically creates the user, email identity and encrypted OPAQUE
  credential, with `encrypted_password = NULL`. It checks signup/email-provider
  flags at both steps, applies CAPTCHA and IP/shared account rate limits, and
  calls the existing before/after signup and user-created hooks. Hook metadata
  never contains the password. Email and metadata are bound to the handshake;
  finish cannot override them. Email rewrites by BeforeSignup are revalidated.
- **Existing account:** `auth.opaque.register()` uses `registration/start` and
  `registration/finish` with recent-authentication/MFA gates described below.

New-account signup respects `Mailer.Autoconfirm`. With confirmation required,
the normal confirmation mail and `/verify` flow are used; email delivery must be
configured. Delivery failure rolls back account and credential creation. No
OPAQUE login is allowed before email confirmation. Confirmation links use the
existing redirect allow-list and implicit flow; the extension does not initiate
PKCE. Registration returns `session: null` even with autoconfirm, since no KE3
proof has been verified. Explicitly perform OPAQUE login afterwards to establish
a session and shared key; do not reuse the signup CAPTCHA token for login.

Duplicate signup never replaces an existing account's credentials or metadata,
including unconfirmed accounts. With confirmation required, both new and
existing addresses return a sanitized placeholder user and no session; the
client's registration export key is not proof of creation and must not be used
until a successful OPAQUE login. Duplicates do not resend confirmation mail:
use `/resend` explicitly. With autoconfirm enabled, duplicates return 422
`user_already_exists`. An interrupted/failed signup may require a fresh signup
attempt or resend/login; retries never silently overwrite a credential.

Existing-account enrollment requires an email-confirmed, non-anonymous, non-SSO account.
SSO-managed users must continue through their identity provider. Create
or verify the account using the existing OTP/OAuth/password routes first. If the
password must never reach the server, bootstrap with OTP/OAuth instead of the
legacy password grant, or use the direct OPAQUE signup flow above.

Both existing-account registration steps require the SAME live session, created within five
minutes. An account with a verified MFA factor needs AAL2. Refreshing an old
session does not satisfy recent authentication. Concurrent/stale registration
finishes are rejected if the account or credential changed in between.
Successful re-enrollment replaces the old credential and revokes its stored
shared keys. Applications must rewrap any export-key-protected data before
changing the OPAQUE password; changing it may change `export_key`.

Legacy password change/reset and soft deletion invalidate OPAQUE credentials
through a database trigger. Hard deletion cascades. A pending login cannot
survive replacement/reset because its credential version is checked again under
an account lock at finish. Re-enroll after password recovery; the old export key
and data encrypted solely with it cannot be recovered by the server.
Enrollment does not remove an existing legacy password or disable other sign-in
methods. OPAQUE is additive; it does not retroactively erase previously stored
password hashes or make existing password-grant clients use OPAQUE.

OPAQUE login creates the ordinary Supabase-compatible access/refresh session,
with `amr=opaque` and **AAL1**, not AAL2. Existing refresh, logout, ban and
single-session policies remain in effect. Complete existing MFA verification
before using protected server-side key operations. The client mathematically
derives the key during OPAQUE, before MFA; this is not proof of MFA completion.

## Use the shared key on the server

Use the public `*dilion.Server` integration point (standalone auth embedders can
also use the `*auth.Mount` returned by `auth.Register`):

```go
err := server.WithOpaqueSessionKey(ctx, bearerToken, keyID, func(key []byte) error {
    // Derive a purpose-specific application key here; do not retain key.
    return useSharedKey(key)
})
```

This is an in-process integration point, NOT an HTTP endpoint exporting keys.
The caller supplies the actual request bearer and trusted instance context.
Every call checks JWT, account status, live session, single-session policy, MFA,
credential version and key expiry. The borrowed key slice is wiped on return.
The callback runs under account/session locks: keep it short, avoid network I/O,
and do not recursively call auth or update these locked rows. Callback external
side effects cannot be rolled back with the database transaction.

`session_key` is 64 bytes and shared by the client and server; `export_key` is
client-only. Neither belongs in JWTs, application logs or auth event payloads.
Derive separate keys using HKDF-SHA-512 with explicit instance, protocol,
purpose, direction and `key_id` binding. Do not use the raw 64-byte secret as an
AES key. Application message encryption, nonce/replay handling and export-key
backup/rewrapping are application responsibilities, not provided by this API.

Server shared-key handles expire after 15 minutes. Refresh does not extend or
restore them; perform a new OPAQUE login for a fresh shared key. Logout/session
deletion cascades the stored keys. The client owns its returned buffers and must
clear them on logout/use completion; the SDK does not persist or broadcast them.

## Storage and abuse controls

- Independent random long-term server setup per instance, encrypted using
  AES-256-GCM with domain-separated instance keys derived from the external
  master key. Setup, credential records, handshake state and shared keys are
  encrypted; ciphertext is bound to its purpose and row identifiers.
- Handshakes expire after two minutes. `DELETE ... RETURNING` consumes them
  atomically across replicas, before KE3 verification, including failed attempts.
- Existing per-IP login limiter plus a PostgreSQL-backed limit of ten login
  starts per normalized account/audience per minute. Missing accounts use fake
  records and the same response shape; this reduces enumeration signals but
  is not a constant-time network service.
- At most 10,000 live handshakes per instance. Admission uses a short database
  advisory lock. This is a safety cap, not a claim of unlimited scalability.
- Cleanup removes expired state, keys and rate buckets in batches. Run the
  existing cleanup worker for every instance. A distributed ingress/WAF limit
  is still needed against many-IP/many-account floods; per-account throttling
  can itself temporarily deny login to an account under targeted attack.
- New tables have RLS enabled without public policies and no PUBLIC privileges.
  Only trusted auth storage roles should access them. No raw key download route.

## Verification and limits

```sh
cd js
pnpm install --frozen-lockfile
pnpm build
cd ..
DILION_TEST_DB=postgres://.../dedicated_test_database \
DILION_OPAQUE_SDK_HTTP=1 go test -race ./internal/auth -run '^TestOpaque' -count=1
```

Tests reset auth tables: use a dedicated test database, never production.
Tests cover storage tampering/tenant isolation, native registration/login,
cross-mount finish, expiry/replay/concurrent consumption, account throttling,
credential reset and actual SDK/WASM → Dilion HTTP → PostgreSQL key agreement.
Signup tests also cover email confirmation, no legacy hash/session issuance,
duplicate and concurrent signup, hooks, policy changes, CAPTCHA, ceremony/audience
binding and mail-failure rollback. The real SDK HTTP test creates a fresh account
without a bootstrap session and verifies export-key recovery on later login.
The JS compatibility workflow runs the real-server test in its own daily job.

This implementation is not independently security-audited. The selected Go
cryptographic library also explicitly states that it has not been independently
audited. Review and load-test before production rollout; start with the feature
disabled using `DILION_AUTH_OPAQUE_ENABLED=false` during preparation if a master
key has already been provisioned. Master-key rotation tooling and encrypted-data
recovery/rewrapping are not included.

References: [RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html),
[bytemare security and operational notes](https://github.com/bytemare/opaque).

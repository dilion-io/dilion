# @dilion-io/auth-js

An additive Supabase client wrapper with OPAQUE authentication.

**Status:** SDK and Go server implementation. With environment configuration,
Dilion enables OPAQUE when its master key is configured, unless explicitly
disabled with `DILION_AUTH_OPAQUE_ENABLED=false`. See [server setup and security
limits](../../../docs/opaque.md) for the required migration, external master key,
recent-authentication/MFA enrollment gates and shared-key lifecycle. Actual SDK
HTTP tests use Dilion handlers and PostgreSQL; this is not a security audit.

## Supabase-compatible entry point

~~~ts
import { createClient } from '@dilion-io/auth-js'

const client = createClient<Database>('https://auth.example.com', publicAnonKey)

// Existing Supabase APIs and database inference are retained.
await client.auth.signInWithPassword({ email, password })
await client.from('profiles').select('id, name')

// Explicit OPAQUE opt-in. No automatic password-grant fallback.
const { data, error } = await client.auth.opaque.signInWithPassword({
  email,
  password,
})
if (error) throw error

const { session, user, key_id, session_key, export_key } = data
// session_key and export_key are separate 64-byte Uint8Array values.
// The server independently derives session_key; export_key stays client-only.
// Derive application-specific keys with HKDF; do not use this 64-byte root
// directly as an AES key. Bind derived keys to key_id, instance, and purpose.

// When the application is done with these buffers:
session_key.fill(0)
export_key.fill(0)
~~~

This root re-exports Supabase JS's exports. Existing behavior comes from
`@supabase/supabase-js` and `@supabase/auth-js` dependencies, not a fork.
The factory uses the SAME upstream auth instance/session manager, so refresh,
MFA, OAuth, storage and auth event behavior remain upstream's.
The upstream `accessToken` option still disables the entire auth surface,
including OPAQUE. This wrapper does not bypass that restriction.

## Standalone auth or an existing client

~~~ts
import { AuthClient } from '@dilion-io/auth-js/auth'
const auth = new AuthClient({
  url: 'https://auth.example.com/auth/v1',
  headers: { apikey: publicAnonKey },
})

import { withOpaque } from '@dilion-io/auth-js'
const extended = withOpaque(existingSupabaseClient, {
  url: 'https://auth.example.com/auth/v1',
  headers: { apikey: publicAnonKey },
  // Pass the same custom fetch and headers as the original client, if used.
})
~~~

Importing `SupabaseClient` and calling its constructor directly still creates
the unmodified upstream class. Use `withOpaque` to extend that instance.
The original constructor options and auth methods are not replaced.

## Registration

~~~ts
// Sign in to a verified account first, preferably using an email OTP or
// passkey if the password must never previously reach a server.
const result = await client.auth.opaque.register({ password })
if (result.error) throw result.error
// The registration export key is client-only. Authenticate the peer with a
// subsequent OPAQUE login before using recovered key material for application
// data. Server registration alone does not establish a shared session key.
result.data.export_key.fill(0)
~~~

This is account enrolment, not anonymous account creation or password reset.
Server-side recent reauthentication/MFA and verified-identity gates are mandatory.
Existing bcrypt/password accounts require an explicit migration policy; their
stored hashes cannot be converted into OPAQUE records.

## Wire contract

For CAPTCHA-enabled servers, pass `captchaToken` to
`auth.opaque.signInWithPassword({ email, password, captchaToken })`.

All routes are relative to the auth base URL and therefore resolve under
**`/auth/v1/opaque/...`**. JSON binary fields use unpadded base64url.

| POST route | Request | Successful response |
| --- | --- | --- |
| `registration/start` | `registration_request` + bearer session | common fields + `registration_response` |
| `registration/finish` | `handshake_id, registration_record` + bearer session | `{ "success": true }` |
| `login/start` | `email, ke1` | common fields + `ke2` |
| `login/finish` | `handshake_id, ke3` | `access_token, refresh_token, key_id` |

Common fields: `handshake_id, suite, client_identity, server_identity`.
The server must bind identities, instance, protocol configuration, and
credential version to single-use expiring handshake state. Never accept a
client-provided user ID as registration authorization. A login session and
shared-key handle may be activated only after server KE3 verification.
Unknown-user replies must use a fake record and avoid identity/metadata oracles.

The fixed profile `ristretto255-sha512-argon2id-v1` uses RFC 9807 OPAQUE-3DH,
Ristretto255/SHA-512 and Argon2id (64 MiB, 3 iterations, parallelism 4).
The same settings and identity bytes must be used during registration and login.
The client rejects an unknown profile instead of accepting weaker parameters.

## Key ownership and security boundaries

- The WASM dependency is loaded only when an OPAQUE operation is invoked.
- Passwords are supplied only to local cryptographic functions, never the HTTP
  request bodies. There is no silent fallback to `/token?grant_type=password`.
- Keys are returned ONLY by the OPAQUE result, not added to Session/User, JWTs,
  auth events, BroadcastChannel messages, or upstream session persistence.
- The caller owns the returned buffers. Clear them on logout/account switch and
  expiration, and never log or persist them. The SDK cannot erase caller-made
  copies; JavaScript strings and GC also prevent guaranteed memory zeroization.
- A page reload or another browser tab may restore a JWT but not these keys.
  JWT refresh is not a new OPAQUE key exchange. Reauthenticate when keys are needed.
- HTTPS is mandatory except on loopback. Redirects are rejected on OPAQUE
  requests. A caller-provided fetch must honor the RequestInit security options.
- Abort signals are honored before committing the result to upstream
  `setSession`; that public API's final session handoff is not cancellable.
- OPAQUE is not MFA, does not replace authorization/TLS, and does not defend
  against XSS or a compromised JavaScript delivery origin.
- The current WASM operations are synchronous after initialization. A Worker
  adapter and mobile performance measurements remain deployment work.
- Application encryption, server key storage/rotation, recovery of export-key
  protected data, and server-side key revocation are NOT provided by this SDK.

## Verification

From `js/`:

~~~sh
pnpm install --frozen-lockfile
pnpm build
pnpm typecheck
pnpm test
DILION_OPAQUE_GO_INTEROP=1 pnpm test
~~~

The last command runs a test-only `bytemare/opaque` Go peer. It proves
registration and login interoperability, equal shared keys, stable export keys,
and consumed-state replay rejection. It is deliberately not an HTTP auth server.
The separate `TestOpaqueSDKHTTP` Go test runs this SDK against actual Dilion
HTTP handlers and PostgreSQL; [server verification](../../../docs/opaque.md#verification-and-limits)
documents how to run it. The daily workflow runs both forms of interoperability.

References: [RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html),
[Supabase JS](https://github.com/supabase/supabase-js),
[Serenity OPAQUE](https://github.com/serenity-kit/opaque),
[Go OPAQUE](https://github.com/bytemare/opaque).
The Go implementation explicitly notes that it has not been independently
audited; passing tests is not a substitute for an integration security review.

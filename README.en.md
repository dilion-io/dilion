<!-- Generated from README.md by scripts/translate-readme.mjs; source-sha256: 4ea1d38470d573f21ba4201a2ed1054a98aa74fad4743c0c2eef44e1ee2f89e8. Do not edit directly. -->

# Dilion

[한국어](README.md) · [English](README.en.md)

Dilion is an authentication and personal information management server built with Go and PostgreSQL.
It handles sign-up and login through a Supabase Auth-compatible API, and manages personal information storage, consent history, and deletion tasks resulting from account withdrawal, all keyed on the same user ID.

Personal information is encrypted and stored in a Vault, and is either masked or provided in full depending on access permissions.
Consent and withdrawal are recorded as history, and deletion requests go through a grace period before being processed as asynchronous tasks.
Deletion processing on external systems can be connected via connectors.
API call examples and processing constraints are documented in [Use Cases](docs/use-cases.md).

The server can be run as a standalone process, or embedded into a Go application via `dilion.NewServer(...)`.
Mail/SMS, KMS, hooks, and deletion connectors can be swapped out via Go interfaces.

## Running Locally

Go 1.26.8 or later, Docker Compose, and GNU Make are required.

```bash
make dev
```

Start PostgreSQL at `localhost:55432`, apply migrations, then run the API server at `http://localhost:8787`.

```bash
curl http://localhost:8787/healthz
```

Run the sample admin screen in a different terminal. Node.js 22 or later is required.

```bash
make web-install
make dev-web
```

The screen address is `http://localhost:5173`. For setting up a development token for the admin API, refer to [web/README.md](web/README.md). The `service_role` token must not be exposed in a production browser.

The development PII encryption key is stored at `.dev/master.key`. If this file is lost, existing Vault data cannot be decrypted. To stop while preserving the DB, use `docker compose stop`. `make down` also deletes the DB volume.

## Authentication and SDK

The default path for the auth API is `/auth/v1`. It implements email/password, OTP, OAuth/OIDC, Passkey, MFA, and SAML SSO, and using external providers requires separate configuration.
The personal information API is provided at `/privacy/v1`, and role/permission/API key management at `/iam/v1`.

For general authentication, you can use `@supabase/supabase-js`.
To use OPAQUE, use the [`@dilion-io/auth-js`](js/packages/auth-js/README.md) in the repository.
This SDK brings in the Supabase library as a dependency and adds `auth.opaque` to an existing client.
It does not change the behavior of existing `auth.signUp()` or `auth.signInWithPassword()`.
Build instructions are in [js/README.md](js/README.md).

### OPAQUE Sign-up and Login

OPAQUE is an authentication method that allows sign-up and login without sending the password to the server.
It is activated by setting `DILION_AUTH_OPAQUE_MASTER_KEY` on the server.
The value must be a string of 32 random bytes encoded in unpadded base64url.
This key is separate from the PII encryption key, must be preserved across restarts, and must be identical across all server replicas.
To explicitly disable it, set `DILION_AUTH_OPAQUE_ENABLED=false`.

```ts
import { createClient } from '@dilion-io/auth-js'

const client = createClient('https://auth.example.com', 'your-anon-key')

const signup = await client.auth.opaque.signUp({
  email: 'user@example.com',
  password: 'user-supplied-password',
})
if (signup.error) throw signup.error
```

New sign-ups do not require an existing login session, and no plain password hash is created on the server.
The `session` in the sign-up response is `null`. If `confirmation_required` is `true`, log in after completing email verification.

```ts
const login = await client.auth.opaque.signInWithPassword({
  email: 'user@example.com',
  password: 'user-supplied-password',
})
if (login.error) throw login.error

const { session, key_id, session_key, export_key } = login.data
```

`session_key` is a shared key derived independently by the client and server.
On the server, it can be used as `Server.WithOpaqueSessionKey(...)`.
`export_key` is held only by the client, and neither key should be placed in a JWT or the SDK session storage.
The `export_key` received at sign-up must not be used for data encryption before login succeeds.

For OPAQUE registration on existing accounts, CAPTCHA, key derivation and expiration, and password recovery constraints, refer to the [OPAQUE documentation](docs/opaque.md). This implementation and its cryptographic libraries have not undergone an independent security audit.

## Compatibility Scope

It aims for compatibility with the Supabase Auth HTTP API and the `auth.*` schema, but not all APIs are fully compatible.

The [parity tests](test/parity/README.md) compare responses against the actual GoTrue.
The GitHub Actions run summary displays a support table generated from the test results, categorizing each item as **implemented, partially compatible, not implemented, or unverified**.
Intentional differences are recorded in [deviations.yaml](test/parity/deviations.yaml).
Compatibility of the SDK with the latest Supabase and TypeScript is checked daily via a separate workflow.

## Development

```bash
make test       # 빌드, 정적 검사, DB 없는 테스트
make test-db    # PostgreSQL 통합 테스트와 race 검사
make ci         # DB 테스트, OpenAPI 검사, 웹 빌드·검사
make parity     # GoTrue 비교 테스트
```

Tests reset data in a dedicated DB. Do not connect a production DB to tests.
CI also runs `govulncheck` as a separate job.

The Korean README is the source of truth. After making edits, the English README is generated with the following script.
Node.js 22 or later and an authenticated Claude Code CLI are required.

```bash
node scripts/translate-readme.mjs
```

The script calls `claude -p`. GitHub Actions uses the same script.
For CLI installation and workflow secret setup, refer to [README Translation Automation](docs/readme-translation.md).

## Documentation

- [Use Cases](docs/use-cases.md): API examples and constraints for consent collection, personal information lookup, and deletion requests
- [OPAQUE](docs/opaque.md): Server configuration, authentication flow, key management
- [SDK](js/packages/auth-js/README.md): Connecting the Supabase client and the OPAQUE API
- [API Conventions](docs/api-conventions.md): Procedures for API changes and OpenAPI generation
- [Design](project.md) · [Development Plan](PLAN.md): Design background and implementation plan

The fixed JWT secret and zero-day deletion grace period at `make dev` are for local development only.
In production environments, TLS, persistent keys, DB backups, mail/SMS providers, and access permissions must be configured separately.

## License

[Apache License 2.0](LICENSE)

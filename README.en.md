<!-- Generated from README.md by scripts/translate-readme.mjs; source-sha256: 5e3ffeb1a7c4099dc1dccd6b4a00143344782bcad33cd8381024690b4749d7e1. Do not edit directly. -->

# Dilion

[한국어](README.md) · [English](README.en.md)

Dilion is an authentication and personal data management server built with Go and PostgreSQL.
It handles sign-up and login via a Supabase Auth–compatible API, and manages personal data storage, consent history, and deletion operations resulting from account withdrawal, all keyed by the same user ID.

Personal data is encrypted and stored in Vault, and is either masked or provided in plaintext depending on the viewer's access permissions.
Consent and withdrawal are recorded as history, and deletion requests go through a grace period before being processed as asynchronous jobs.
Deletion handling in external systems can be connected via connectors.
API call examples and processing constraints are summarized in [Use Cases](docs/use-cases.md).

The server can run as an independent process, or be embedded into a Go application using `dilion.NewServer(...)`.
Mail/SMS, KMS, hooks, and deletion connectors can be swapped out via Go interfaces.

## Running Locally

Go 1.26.8 or higher, Docker Compose, and GNU Make are required.

```bash
make dev
```

Start PostgreSQL with `localhost:55432`, apply migrations, then run the API server with `http://localhost:8787`.

```bash
curl http://localhost:8787/healthz
```

Run the sample admin screen in a separate terminal. Node.js 22 or higher is required.

```bash
make web-install
make dev-web
```

The screen address is `http://localhost:5173`. For setting up a development token for the admin API, see [web/README.md](web/README.md). Never expose the `service_role` token in a production browser.

The development PII encryption key is stored in `.dev/master.key`. If you lose this file, you will not be able to decrypt existing Vault data.
To stop the server while preserving the DB, use `docker compose stop`.
`make down` also deletes the DB volume.

## Deployment Images and Packages

A release starts with a commit message. Bump the version in `js/packages/auth-js/package.json` and push a commit whose title exactly matches `chore(release): v<버전>` to the default branch; the workflow then creates a `v<버전>` tag and publishes the server image and JS SDK together at the same version.

```bash
# js/packages/auth-js/package.json 의 version 을 0.1.0-rc1 로 올린 뒤
git commit -am 'chore(release): v0.1.0-rc1'
git push
```

The tag is created by the release bot (`dilion-release[bot]`), and the push of that tag triggers the actual publish run. Thus a single release is split into two workflow runs — the commit push creates the tag, and the tag push performs the gate checks and publishing. Because publishing always runs from the tag, the tag (not the branch) is recorded in npm provenance and image attestations.

Pushing a `v*` tag directly also triggers the same release, except there is no tag-creation run in that case.
If the version stated in the commit does not match the version in package.json, it fails without creating the tag or publishing anything. A commit whose title does not exactly match the above format is not treated as a release, and a warning is only logged when it appears to resemble a release.

The server image is published to the GitHub Container Registry as `linux/amd64` and `linux/arm64`.

```bash
docker run --rm -p 8787:8787 \
  -e DILION_DSN='postgres://dilion:dilion@host:5432/dilion' \
  ghcr.io/dilion-io/dilion:latest
```

Migrations are applied automatically when the server starts, so no separate step is needed.
If `DILION_JWT_SECRET` and `DILION_MASTER_KEY` are not provided, a temporary key is generated on every boot, so they must be set in production. Restarting the server will invalidate issued tokens and make it impossible to decrypt stored personal data. The full list of environment variables is documented in comments in [cmd/dilion/main.go](cmd/dilion/main.go).

To build the same image locally, use `make docker-build`.

For Kubernetes, deploy using the Helm chart at [charts/dilion](charts/dilion/README.md).
If you provide `DILION_METRICS_ADDR` (e.g., `:9090`), Prometheus metrics are exposed on `/metrics` of a separate listener from the API; the chart enables this by default and can also create a ServiceMonitor.

The JS SDK is published to npm.

```bash
npm install @dilion-io/auth-js
```

Pre-releases (such as `v0.1.0-rc1`) are only published under the npm `next` tag and do not update the image's `latest` either.

## Authentication and SDK

The default base path for the authentication API is `/auth/v1`. It implements email/password, OTP, OAuth/OIDC, Passkey, MFA, and SAML SSO; using external providers requires separate configuration.
The personal data API is available at `/privacy/v1`, and role/permission/API key management is available at `/iam/v1`.

For general authentication, you can use `@supabase/supabase-js`.
To use OPAQUE, use the [`@dilion-io/auth-js`](js/packages/auth-js/README.md) in this repository.
This SDK pulls in the Supabase library as a dependency and adds `auth.opaque` to your existing client.
It does not change the behavior of existing `auth.signUp()` or `auth.signInWithPassword()`.
Build instructions are in [js/README.md](js/README.md).

### OPAQUE Sign-up and Login

OPAQUE is an authentication method that allows sign-up and login without ever sending the password to the server.
It is enabled by setting `DILION_AUTH_OPAQUE_MASTER_KEY` on the server.
The value must be a random 32-byte string encoded as unpadded base64url.
This key is separate from the PII encryption key, and must be preserved across restarts and kept identical across all server replicas.
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

A new sign-up does not require an existing login session, and no plain password hash is created on the server.
The `session` in the sign-up response is `null`. If `confirmation_required` is `true`, complete email verification before logging in.

```ts
const login = await client.auth.opaque.signInWithPassword({
  email: 'user@example.com',
  password: 'user-supplied-password',
})
if (login.error) throw login.error

const { session, key_id, session_key, export_key } = login.data
```

`session_key` is a shared key independently derived by the client and server, respectively.
On the server, it can be used as `Server.WithOpaqueSessionKey(...)`.
`export_key` is held only by the client; neither key should be placed into a JWT or the SDK's session storage.
The `export_key` received at sign-up must not be used for data encryption until login succeeds.

For OPAQUE registration on existing accounts, CAPTCHA, key derivation and expiration, and constraints on password recovery, see the [OPAQUE documentation](docs/opaque.md). This implementation and its cryptographic libraries have not undergone an independent security audit.

## Compatibility Scope

The goal is HTTP API and `auth.*` schema compatibility with Supabase Auth, but not every API is fully compatible.

The [Parity tests](test/parity/README.md) compare responses against the real GoTrue.
The GitHub Actions run summary displays a support table generated from the test results, categorizing each item as **Implemented, Partially Compatible, Not Implemented, or Unverified**.
Intentional differences are recorded in [deviations.yaml](test/parity/deviations.yaml).
SDK compatibility with the latest Supabase and TypeScript versions is checked daily via a separate workflow.

## Development

```bash
make test       # 빌드, 정적 검사, DB 없는 테스트
make test-db    # PostgreSQL 통합 테스트와 race 검사
make ci         # DB 테스트, OpenAPI 검사, 웹 빌드·검사
make parity     # GoTrue 비교 테스트
```

Tests reset the data in a dedicated database. Do not connect a production database to the tests.
CI also runs `govulncheck` as a separate job.

The Korean README is the source of truth. After making edits, generate the English README using the following script.
Node.js 22 or higher and an authenticated Claude Code CLI are required.

```bash
node scripts/translate-readme.mjs
```

The script calls `claude -p`. GitHub Actions uses the same script.
For CLI installation and workflow secret setup, see [README Translation Automation](docs/readme-translation.md).

## Documentation

- [Use Cases](docs/use-cases.md): API examples and constraints for consent collection, personal data lookup, and deletion requests
- [OPAQUE](docs/opaque.md): Server configuration, authentication flow, key management
- [SDK](js/packages/auth-js/README.md): Connecting the Supabase client and the OPAQUE API
- [API Conventions](docs/api-conventions.md): Procedures for API changes and OpenAPI generation
- [Design](project.md) · [Development Plan](PLAN.md): Design background and implementation plan

The fixed JWT secret and the zero-day deletion grace period in `make dev` are intended for local development only.
In production, TLS, persistent keys, DB backups, and mail/SMS providers and access permissions must be configured separately.

## License

[Apache License 2.0](LICENSE)

<!-- Generated from README.md by scripts/translate-readme.mjs; source-sha256: 2ffe2a80cdc4b9cf8e9eedf74ff73716936a70c5bbe3db94cc20f678bc4fe1b3. Do not edit directly. -->

# Dilion

[한국어](README.md) · [English](README.en.md)

Dilion is an authentication and personal information management server built with Go and PostgreSQL.
It handles sign-up and login through a Supabase Auth–compatible API, and manages personal information storage, consent history, and deletion tasks upon account withdrawal, all keyed to the same user ID.

Personal information is encrypted and stored in Vault, and is either masked or provided in plain text depending on access permissions.
Consent and withdrawal are recorded as history, and deletion requests are processed as asynchronous jobs after a grace period.
Deletion handling in external systems can be connected via connectors.
API call examples and processing constraints are documented in [Use Cases](docs/use-cases.md).

You can run the server as a standalone process, or embed it into a Go application using `dilion.NewServer(...)`.
Mail/SMS, KMS, hooks, and deletion connectors can be replaced via Go interfaces.

## Running Locally

Requires Go 1.26.8 or later, Docker Compose, and GNU Make.

```bash
make dev
```

Start PostgreSQL on `localhost:55432`, apply migrations, and then run the API server on `http://localhost:8787`.

```bash
curl http://localhost:8787/healthz
```

Run the sample admin screen in a separate terminal. Requires Node.js 22 or later.

```bash
make web-install
make dev-web
```

The screen address is `http://localhost:5173`. For setting up a development token for the admin API, see [web/README.md](web/README.md). Never expose the `service_role` token in a production browser.

The development PII encryption key is stored in `.dev/master.key`. If you lose this file, you will not be able to decrypt existing Vault data.
To stop the server while preserving the DB, use `docker compose stop`. `make down` also deletes the DB volume.

## Deployment Images and Packages

A release begins with a commit message. When you bump the version in `js/packages/auth-js/package.json` and push a commit whose title exactly matches `chore(release): v<버전>` to the default branch, the workflow creates a `v<버전>` tag and then publishes the server image and the JS SDK together at the same version.

```bash
# js/packages/auth-js/package.json 의 version 을 0.1.0-rc1 로 올린 뒤
git commit -am 'chore(release): v0.1.0-rc1'
git push
```

The tag is created by the release bot (`dilion-release[bot]`), and pushing that tag triggers the actual publish run. So a single release is split across two workflow runs — the commit push creates the tag, and the tag push performs the gating and publishing. Since publishing always runs from the tag, both the npm provenance and the image attestation record the tag rather than the branch.

Directly pushing a `v*` tag triggers the same release, except that the tag-creation run does not occur in this case.
If the version stated in the commit and the version in package.json don't match, the workflow fails without creating a tag or publishing anything. A commit whose title does not exactly match the format above is not treated as a release, and a warning is only logged if it looks like it was intended to be one.

The server image is published to the GitHub Container Registry as `linux/amd64` and `linux/arm64`.

```bash
docker run --rm -p 8787:8787 \
  -e DILION_DSN='postgres://dilion:dilion@host:5432/dilion' \
  ghcr.io/dilion-io/dilion:latest
```

Migrations are applied automatically when the server starts, so no separate step is required.
If `DILION_JWT_SECRET` and `DILION_MASTER_KEY` are not provided, a temporary key is generated on every boot, so these must be specified in production. Restarting will invalidate issued tokens and make it impossible to decrypt stored personal information. The full list of environment variables can be found in the comments of [cmd/dilion/main.go](cmd/dilion/main.go).

To build the same image locally, use `make docker-build`.

The JS SDK is published to npm.

```bash
npm install @dilion-io/auth-js
```

Pre-releases (such as `v0.1.0-rc1`) are only published to npm under the `next` tag, and do not update the image's `latest` either.

## Authentication and SDK

The base path for the authentication API is `/auth/v1`. It implements email/password, OTP, OAuth/OIDC, Passkey, MFA, and SAML SSO, though using external providers requires separate configuration.
The personal information API is provided at `/privacy/v1`, and role/permission/API key management is provided at `/iam/v1`.

For general authentication, you can use `@supabase/supabase-js`.
To use OPAQUE, use [`@dilion-io/auth-js`](js/packages/auth-js/README.md) from the repository.
This SDK brings in the Supabase library as a dependency and adds `auth.opaque` to an existing client.
It does not change the behavior of existing `auth.signUp()` or `auth.signInWithPassword()`.
For build instructions, see [js/README.md](js/README.md).

### OPAQUE Sign-Up and Login

OPAQUE is an authentication method that allows sign-up and login without sending the password to the server.
It is enabled by setting `DILION_AUTH_OPAQUE_MASTER_KEY` on the server.
The value must be a string encoding 32 random bytes in unpadded base64url.
This key is separate from the PII encryption key, and must be kept consistent across restarts and identical across all server replicas.
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

New sign-ups do not require an existing login session, and the server never creates a plain-text password hash.
The `session` in the sign-up response is `null`. If `confirmation_required` is `true`, log in after completing email verification.

```ts
const login = await client.auth.opaque.signInWithPassword({
  email: 'user@example.com',
  password: 'user-supplied-password',
})
if (login.error) throw login.error

const { session, key_id, session_key, export_key } = login.data
```

`session_key` is a shared key independently derived by both the client and the server.
On the server side, it can be used as `Server.WithOpaqueSessionKey(...)`.
`export_key` is held only by the client, and neither key should be placed in a JWT or the SDK's session storage.
The `export_key` received at sign-up must not be used for data encryption until login succeeds.

For OPAQUE registration on existing accounts, CAPTCHA, key derivation/expiration, and password recovery constraints, see the [OPAQUE documentation](docs/opaque.md). This implementation and its cryptographic library have not undergone an independent security audit.

## Compatibility Scope

We aim for compatibility with Supabase Auth's HTTP API and the `auth.*` schema, but not every API is fully compatible.

The [Parity tests](test/parity/README.md) compare responses against actual GoTrue.
The GitHub Actions run summary displays a support table generated from the test results, classifying each item as **Implemented, Partially Compatible, Not Implemented, or Unverified**.
Intentional differences are recorded in [deviations.yaml](test/parity/deviations.yaml).
SDK compatibility with the latest Supabase and TypeScript is checked daily via a separate workflow.

## Development

```bash
make test       # 빌드, 정적 검사, DB 없는 테스트
make test-db    # PostgreSQL 통합 테스트와 race 검사
make ci         # DB 테스트, OpenAPI 검사, 웹 빌드·검사
make parity     # GoTrue 비교 테스트
```

Tests reset the data in a dedicated database. Do not connect a production database to tests.
CI also runs `govulncheck` as a separate job.

The Korean README is the source of truth. After editing it, generate the English README using the following script.
Requires Node.js 22 or later and an authenticated Claude Code CLI.

```bash
node scripts/translate-readme.mjs
```

The script calls `claude -p`. GitHub Actions uses the same script.
For CLI installation and workflow secret setup, see [README Translation Automation](docs/readme-translation.md).

## Documentation

- [Use Cases](docs/use-cases.md): API examples and constraints for consent collection, personal information lookup, and deletion requests
- [OPAQUE](docs/opaque.md): Server configuration, authentication flow, key management
- [SDK](js/packages/auth-js/README.md): Supabase client integration and the OPAQUE API
- [API Contract](docs/api-conventions.md): API change and OpenAPI generation procedures
- [Design](project.md) · [Development Plan](PLAN.md): Design rationale and implementation plan

The fixed JWT secret and the zero-day deletion grace period in `make dev` are intended for local development only.
In production, you must separately configure TLS, persistent keys, DB backups, mail/SMS providers, and access permissions.

## License

[Apache License 2.0](LICENSE)

# Dilion ↔ GoTrue differential parity harness

Runs Dilion's Supabase-Auth-compatible `/auth/v1` surface **side-by-side against
the real upstream `github.com/supabase/auth` (GoTrue)** and asserts behavioural
equivalence, excluding the deliberate deviations Dilion documents.

Both servers run **identical config** (same HS256 secret, same `SITE_URL`, same
feature flags) against **separate throwaway databases**. Every request is issued
to both; responses are normalised (volatile ids/timestamps/tokens scrubbed) and
diffed structurally. A diff that matches an entry in [`deviations.yaml`](./deviations.yaml)
is downgraded from **FAIL** to **KNOWN**; anything else fails the test.

> Historical baseline against `supabase/auth:v2.196.0` (not a live support table), both profiles
> green (0 FAIL):
>
> | profile | how it runs | ops exercised | result |
> | --- | --- | --- | --- |
> | **default** (flags off) | `compose.parity.yml` | **36 / 69 (52.2%)** | PASS · 67 KNOWN |
> | **flagged** (`PARITY_FLAGS=1`) | `+ compose.parity.flags.yml` | **51 / 69 (73.9%)** | PASS · 76 KNOWN |
>
> The flagged run is a **superset** — 51 of the 69 curated operations are covered
> in all (up from the original 12 / 17.4%). Coverage grew via three mechanisms:
> single-request `scenario`s, multi-step `flow`s (flows_test.go — admin lifecycle,
> the full MFA/TOTP enrol→challenge→verify→aal2 chain, admin factors, and
> `generate_link`→`verify` OTP redemption without an inbox), and a matched
> feature-flag twin overlay (OAuth 2.1 server, passkeys, manual linking). The
> remaining 18 ops each need a capability the harness deliberately does not fake
> (software WebAuthn authenticator, signed SAML assertion, scriptable consent
> cookie, stubbed external IdP) — see the coverage section and the TODO scaffold
> in harness_test.go.

Every CI run also generates an operation-level **기능 지원표** in the GitHub
Actions summary. The table is derived from that run rather than maintained by
hand: `구현됨` means a successful response path was compared without differences
or assertion failures; `부분 호환` means a KNOWN/FAIL difference or assertion
failure; `미구현` means Dilion returned HTTP 501 on a tested path; and
`미검증` means comparison was missing/interrupted or only error paths were
compared. A passing error-only test is not proof that a feature works.
Only compared 2xx responses count as positive evidence; error redirects can
also return 3xx, so redirect-only operations remain unverified.
Statuses describe only the scenarios in that run, not complete protocol support.
CI runs both default and flagged profiles separately. Reproduce either summary
with `make parity-test PARITY_FLAGS=0 PARITY_SUMMARY_FILE=/tmp/parity-summary.md`
(use `1` for flagged, and start the matching stack with `make parity-up` first).

---

## Architecture

```
                    ┌───────────────────────── test runner (go test -tags parity) ─────────────────────────┐
                    │  harness_test.go: for each scenario → request BOTH → normalize → diff → allow-list     │
                    │  normalize.go   : scrub volatile fields · JWT claim compare · redirect compare         │
                    │  deviations.go  : consult deviations.yaml → FAIL | KNOWN                               │
                    │  coverage.go    : map scenarios → openapi-auth.yaml operationIds → coverage report      │
                    └───────────┬───────────────────────────────────────────────────────┬──────────────────┘
                                │ PARITY_DILION_URL                                       │ PARITY_GOTRUE_URL
                                │ http://localhost:8787/auth/v1                           │ http://localhost:9999
                                ▼                                                         ▼
                    ┌───────────────────────┐                             ┌───────────────────────────────┐
                    │  Dilion               │   identical twinned config  │  GoTrue  supabase/auth:v2.196.0│
                    │  (Dockerfile.dilion   │◄───────  same JWT secret ───►│  (published image)            │
                    │   or `go run`)        │          same SITE_URL       │  gotrue migrate → gotrue serve │
                    │  self-migrates on boot│          same feature flags  │  (migrate is a SEPARATE step)  │
                    └───────────┬───────────┘                             └───────────────┬───────────────┘
                                │ DILION_DSN                                               │ GOTRUE_DB_DATABASE_URL
                                ▼                                                         ▼
                    ┌───────────────────────┐                             ┌───────────────────────────────┐
                    │  database dilion_parity│                             │  database gotrue_parity        │
                    │  schemas: auth, dilion_*│   ONE postgres cluster,    │  schema: auth (Supabase roles) │
                    └───────────────────────┘   two logical databases     └───────────────────────────────┘
                              (postgres-parity, compose service — tmpfs, throwaway; NEVER dilion_dev)
```

The `/auth/v1` **path prefix** is the reason `PARITY_DILION_URL` includes
`/auth/v1` while `PARITY_GOTRUE_URL` is the bare host: GoTrue serves its routes at
the host root, Dilion mounts the compatible surface under `/auth/v1`. Scenario
paths are relative (`/health`, `/token?grant_type=password`) and joined onto each
base, which is what makes the two mounts comparable.

---

## How the two servers are launched

### GoTrue — published image (preferred)

The canonical image is Docker Hub **`supabase/gotrue`** (the repo kept the old
name after the project renamed to `auth`); `supabase/auth` mirrors it. Pin
**`v2.196.0`**.

Three hard-won facts, all **verified in this environment**:

1. **Migrations are a SEPARATE step.** The image does *not* auto-migrate
   (`GOTRUE_DB_AUTOMIGRATE` is dead code in current source). You must run
   `gotrue migrate` before `gotrue serve`, or every write path 500s with
   `relation "users" does not exist`.
2. **The runtime DSN needs `?search_path=auth`.** `gotrue migrate` writes the
   `auth` schema, but `gotrue serve` queries tables unqualified — without
   `search_path=auth` on the DSN it cannot find them.
3. **The Postgres cluster needs the Supabase roles.** Upstream migration
   `20240612123726_enable_rls_update_grants` runs `grant ... to postgres` and
   fails with `role "postgres" does not exist` on a vanilla cluster. The parity
   Postgres seeds `postgres, anon, authenticated, service_role,
   supabase_auth_admin, supabase_admin` (see [`initdb/00-init.sql`](./initdb/00-init.sql)).

Standalone (what the harness actually does under the hood):

```bash
# migrate (one-shot)
docker run --rm --network <net> \
  -e GOTRUE_DB_DRIVER=postgres \
  -e "GOTRUE_DB_DATABASE_URL=postgres://<u>:<p>@<pg>:5432/gotrue_parity?search_path=auth" \
  -e GOTRUE_DB_NAMESPACE=auth \
  -e API_EXTERNAL_URL=http://localhost:9999 \
  -e GOTRUE_SITE_URL=http://localhost:3000 \
  -e GOTRUE_JWT_SECRET=<shared-secret> \
  supabase/auth:v2.196.0 gotrue migrate

# serve
docker run -d --name gotrue --network <net> -p 9999:9999 \
  -e GOTRUE_DB_DRIVER=postgres \
  -e "GOTRUE_DB_DATABASE_URL=postgres://<u>:<p>@<pg>:5432/gotrue_parity?search_path=auth" \
  -e GOTRUE_DB_NAMESPACE=auth \
  -e API_EXTERNAL_URL=http://localhost:9999 -e GOTRUE_API_HOST=0.0.0.0 -e PORT=9999 \
  -e GOTRUE_SITE_URL=http://localhost:3000 \
  -e GOTRUE_JWT_SECRET=<shared-secret> \
  -e GOTRUE_JWT_DEFAULT_GROUP_NAME=authenticated \
  -e GOTRUE_MAILER_AUTOCONFIRM=true -e GOTRUE_EXTERNAL_EMAIL_ENABLED=true \
  supabase/auth:v2.196.0 gotrue serve
```

[`compose.parity.yml`](./compose.parity.yml) wires all of this — a one-shot
`gotrue-migrate` service (`depends_on: postgres healthy`), then `gotrue`
(`depends_on: gotrue-migrate completed_successfully`).

### GoTrue — from source (fallback if the image cannot be pulled)

`go.mod` requires **Go 1.26.8**. Migrations still run as a separate step.

```bash
git clone https://github.com/supabase/auth && cd auth
docker compose -f docker-compose-dev.yml up -d postgres   # or your own PG + the seed roles
make build                                                 # produces ./auth
GOTRUE_DB_DRIVER=postgres \
GOTRUE_DB_DATABASE_URL="postgres://parity:parity@localhost:5432/gotrue_parity?search_path=auth" \
API_EXTERNAL_URL=http://localhost:9999 GOTRUE_SITE_URL=http://localhost:3000 \
GOTRUE_JWT_SECRET=<shared-secret> ./auth migrate
# then serve with the same env (add GOTRUE_API_HOST/PORT/GOTRUE_JWT_DEFAULT_GROUP_NAME):
... ./auth serve
```

Point `PARITY_GOTRUE_URL` at the manually launched instance and the harness runs
unchanged.

### Dilion

Either containerised via [`Dockerfile.dilion`](./Dockerfile.dilion) (the `dilion`
compose service; builds from repo root, **self-migrates on boot** — no separate
migrate step), or run straight from source for a fast local loop:

```bash
go build -o /tmp/dilion ./cmd/dilion
DILION_DSN="postgres://parity:parity@localhost:55433/dilion_parity" \
DILION_ADDR=":8787" \
DILION_JWT_SECRET=<shared-secret> DILION_AUTH_JWT_SECRET=<shared-secret> \
DILION_MASTER_KEY="$(head -c32 /dev/zero | base64)" DILION_DEV_NO_ADMIN_MFA=1 \
DILION_AUTH_SITE_URL=http://localhost:3000 \
DILION_AUTH_MAILER_AUTOCONFIRM=true DILION_AUTH_EXTERNAL_EMAIL_ENABLED=true \
/tmp/dilion
```

---

## Env-twinning matrix (`DILION_AUTH_*` ⇄ `GOTRUE_*`)

Dilion's `auth.LoadConfig` reads **`DILION_AUTH_<NAME>` first and falls back to
`GOTRUE_<NAME>`** (`internal/auth/conf.go` `lookupEnv`). So **every config knob is
the same suffix on both** — twinning is literally "same `<NAME>`, swap the
prefix". These are the pairs the harness sets identically:

| Purpose | Dilion (`DILION_AUTH_*`) | GoTrue (`GOTRUE_*`) | Parity value |
| --- | --- | --- | --- |
| HS256 secret (signer) | `DILION_JWT_SECRET` **and** `DILION_AUTH_JWT_SECRET` | `GOTRUE_JWT_SECRET` | shared 40+ char secret |
| Site URL | `DILION_AUTH_SITE_URL` | `GOTRUE_SITE_URL` | `http://localhost:3000` |
| Access-token TTL | `DILION_AUTH_JWT_EXP` | `GOTRUE_JWT_EXP` | `3600` |
| Default audience | `DILION_AUTH_JWT_AUD` | `GOTRUE_JWT_AUD` | `authenticated` |
| Admin roles | `DILION_AUTH_JWT_ADMIN_ROLES` | `GOTRUE_JWT_ADMIN_ROLES` | `service_role,supabase_admin` |
| Default user role | *(implicit — Dilion defaults to `authenticated`)* | `GOTRUE_JWT_DEFAULT_GROUP_NAME` | `authenticated` **(GoTrue only — required, else the `role` claim diverges)** |
| Email autoconfirm | `DILION_AUTH_MAILER_AUTOCONFIRM` | `GOTRUE_MAILER_AUTOCONFIRM` | `true` |
| Email provider on | `DILION_AUTH_EXTERNAL_EMAIL_ENABLED` | `GOTRUE_EXTERNAL_EMAIL_ENABLED` | `true` |
| Signup disabled | `DILION_AUTH_DISABLE_SIGNUP` | `GOTRUE_DISABLE_SIGNUP` | `false` |
| Refresh rotation | `DILION_AUTH_SECURITY_REFRESH_TOKEN_ROTATION_ENABLED` | `GOTRUE_SECURITY_REFRESH_TOKEN_ROTATION_ENABLED` | `true` |
| Refresh reuse interval | `DILION_AUTH_SECURITY_REFRESH_TOKEN_REUSE_INTERVAL` | `GOTRUE_SECURITY_REFRESH_TOKEN_REUSE_INTERVAL` | `10` |
| JWT issuer *(optional)* | `DILION_AUTH_JWT_ISSUER` | `GOTRUE_JWT_ISSUER` | set to a shared value to make `iss` + OIDC discovery URLs match |

**Database (NOT twinned — deliberately separate):**

| | Dilion | GoTrue |
| --- | --- | --- |
| var | `DILION_DSN` | `GOTRUE_DB_DATABASE_URL` (+ `GOTRUE_DB_DRIVER=postgres`, `GOTRUE_DB_NAMESPACE=auth`) |
| database | `dilion_parity` | `gotrue_parity` |
| DSN tail | *(none)* | **`?search_path=auth`** (required) |
| migrations | self-migrates on boot | separate `gotrue migrate` step |

**GoTrue-only boot vars with no Dilion twin:** `API_EXTERNAL_URL`
(Dilion has no external-URL concept — it roots URLs at `SITE_URL + /auth/v1`;
this is the source of several deviations), `GOTRUE_API_HOST`, `PORT`.
**Dilion-only:** `DILION_MASTER_KEY` (built-in KMS), `DILION_DEV_NO_ADMIN_MFA`.

### Enabling the feature-flagged surfaces on BOTH

Flip a **matched pair** to compare a feature-flagged surface. Defaults are OFF on
both.

The parity stack ships the tested subset as a compose overlay,
[`compose.parity.flags.yml`](./compose.parity.flags.yml), which flips **OAuth 2.1
server + passkeys + manual identity linking** on for BOTH servers and supplies the
WebAuthn relying-party material. Layer it and run with `PARITY_FLAGS=1`:

```bash
docker-compose -f test/parity/compose.parity.yml \
               -f test/parity/compose.parity.flags.yml up -d gotrue dilion
PARITY_FLAGS=1 PARITY_DILION_URL=http://localhost:8787/auth/v1 \
  PARITY_GOTRUE_URL=http://localhost:9999 \
  PARITY_JWT_SECRET=parity-super-secret-shared-jwt-key-0123456789 \
  go test -tags parity ./test/parity/ -run TestParity -v
# restore the flags-off stack:
docker-compose -f test/parity/compose.parity.yml up -d gotrue dilion
```

`PARITY_FLAGS=1` tells the harness that the flagged twin is live, so scenarios and
flows tagged `profile:"on"` run and the flagged surfaces are asserted with their
enabled behaviour instead of the disabled 404s.

| Surface | Dilion | GoTrue |
| --- | --- | --- |
| Passkeys / WebAuthn | `DILION_AUTH_PASSKEY_ENABLED=true` (+ `DILION_AUTH_WEBAUTHN_RP_ID`, `_RP_NAME`, `_RP_ORIGINS`) | `GOTRUE_PASSKEY_ENABLED=true` (+ `GOTRUE_WEBAUTHN_RP_ID`, `GOTRUE_WEBAUTHN_RP_DISPLAY_NAME`, `GOTRUE_WEBAUTHN_RP_ORIGINS`) — **empirically confirmed**: passkeys are a SEPARATE `PASSKEY_ENABLED` block upstream, NOT the MFA-WebAuthn factor; RP config is required or GoTrue logs `WebAuthn configuration is invalid` |
| OAuth 2.1 server | `DILION_AUTH_OAUTH_SERVER_ENABLED=true` | `GOTRUE_OAUTH_SERVER_ENABLED=true` (+ `GOTRUE_OAUTH_SERVER_ALLOW_DYNAMIC_REGISTRATION=true` for DCR) |
| Manual identity linking | `DILION_AUTH_SECURITY_MANUAL_LINKING_ENABLED=true` | `GOTRUE_SECURITY_MANUAL_LINKING_ENABLED=true` |
| Phone / SMS | *(driven by SMS provider config)* `DILION_AUTH_SMS_PROVIDER=…` | `GOTRUE_EXTERNAL_PHONE_ENABLED=true` + `GOTRUE_SMS_PROVIDER=…` |
| SAML | `DILION_AUTH_SAML_ENABLED=true` (+ `DILION_AUTH_SAML_PRIVATE_KEY`) | `GOTRUE_SAML_ENABLED=true` |
| Anonymous users | `DILION_AUTH_EXTERNAL_ANONYMOUS_USERS_ENABLED=true` | `GOTRUE_EXTERNAL_ANONYMOUS_USERS_ENABLED=true` |
| MFA TOTP *(default ON both)* | `DILION_AUTH_MFA_TOTP_ENROLL_ENABLED` / `_VERIFY_ENABLED` | `GOTRUE_MFA_TOTP_ENROLL_ENABLED` / `_VERIFY_ENABLED` |
| Captcha | `DILION_AUTH_SECURITY_CAPTCHA_ENABLED` (+ provider/secret) | `GOTRUE_SECURITY_CAPTCHA_ENABLED` (+ provider/secret) |

MFA/TOTP is ON by default on both, so the full enrol→challenge→verify→aal2 chain
runs in the **default** profile (no overlay needed). For passkeys/SAML/OAuth-server
you must supply the matching key material to BOTH, or the surfaces answer
different setup errors — the overlay does this for OAuth + passkeys; SAML key
material is not supplied (SAML stays off in both profiles).

---

## How the deviation-exclusion list is encoded

[`deviations.yaml`](./deviations.yaml) is a machine-readable allow-list. Each
entry:

```yaml
- id: health-version          # stable slug shown in test output
  op: authHealth              # openapi-auth.yaml operationId, or "*"
  endpoint: GET /auth/v1/health
  aspect: body-field          # status | body-field | header | redirect | error-shape | jwt-claim
  field: version              # substring-matched against the differ's diff path ("" = whole response)
  dilion:   "0.1.0"
  upstream: "the GoTrue release string, e.g. v2.196.0"
  reason:   "volatile build identifier; scrubbed before diffing"
  source:   internal/auth/auth.go:34   # the in-code Deviation comment, or "empirical"
```

The differ (`deviations.go` `Match`) downgrades a diff to **KNOWN** when the op
matches (or the entry is `*`), the aspect is compatible with the diff kind, and
the field's last segment is a substring of the diff path. **A `body` diff always
requires a non-empty `field`** — a blanket empty-field entry can never silently
excuse an arbitrary body field.

Entries are harvested from the authoritative in-code notes (grep
`Deviation|DILION-ONLY|DILION DEVIATION` across `internal/auth/*.go`) plus
differences **observed empirically** during bring-up (e.g. `user_metadata` is not
mirrored by Dilion; upstream's `/settings` reports `saml_private_key_next_configured:true`).
Current catalogue: **38 entries.** (The six added during this expansion:
`admin-create-confirmed-at`, `admin-generate-link-action-link`, and the four
`oauth-as-*` entries mirroring the OIDC base-URL/alg deviations onto the
`/.well-known/oauth-authorization-server` document.)

Config-neutralisable differences (autoconfirm default, refresh reuse interval,
mailer URL paths) are **not** deviations — they are removed by the env matrix
above. Only what remains under identical config is catalogued.

---

## Running it

Prereqs: Docker + `docker-compose` (v2/v5); the harness also works against
manually launched servers. `make` targets below assume you run from the repo
root.

```bash
# 1. bring the stack up (postgres + gotrue-migrate + gotrue + dilion)
docker-compose -f test/parity/compose.parity.yml up -d --build
#    then wait for both /health endpoints (see make parity-up below)

# 2. run the differential + coverage suite
PARITY_DILION_URL=http://localhost:8787/auth/v1 \
PARITY_GOTRUE_URL=http://localhost:9999 \
PARITY_JWT_SECRET=parity-super-secret-shared-jwt-key-0123456789 \
go test -tags parity ./test/parity/ -run TestParity -v

# 3. tear down (‑v drops the throwaway volumes)
docker-compose -f test/parity/compose.parity.yml down -v
```

The suite is compiled **only** under `-tags parity`, so `go test ./...` never
runs it (the package builds to an empty target normally — see `doc.go`).

### Makefile target notes

The root `Makefile` is intentionally **not** modified. Add these targets to it (or
run the commands directly):

```makefile
PARITY := docker-compose -f test/parity/compose.parity.yml

parity-up:            ## bring up postgres + gotrue (migrate+serve) + dilion
	$(PARITY) up -d --build
	@echo "waiting for gotrue…"; until curl -fs http://localhost:9999/health >/dev/null; do sleep 1; done
	@echo "waiting for dilion…"; until curl -fs http://localhost:8787/auth/v1/health >/dev/null; do sleep 1; done
	@echo "parity stack up: dilion :8787  gotrue :9999"

parity-test:          ## run the differential + coverage suite against the stack
	PARITY_DILION_URL=http://localhost:8787/auth/v1 \
	PARITY_GOTRUE_URL=http://localhost:9999 \
	PARITY_JWT_SECRET=parity-super-secret-shared-jwt-key-0123456789 \
	go test -tags parity ./test/parity/ -run TestParity -v

parity-down:          ## tear the stack down and drop the throwaway volumes
	$(PARITY) down -v
```

---

## What is covered, and reaching full coverage

**Covered — 51/69 (73.9%), all green** (the `PARITY_FLAGS=1` flagged run; the
default flags-off run covers 36 of these). Grouped by how they are exercised:

- **Core / discovery:** `authHealth`, `authSettings`, `authJwks`,
  `authOpenIDConfiguration`, `authOAuthAuthorizationServerMetadata`.
- **Signup / token / user:** `authSignup`, `authToken` (password + refresh +
  bad-credential), `authGetUser`, `authUpdateUser`, `authLogout`.
- **Request-side email OTP (enumeration-safe 200 shapes):** `authOtp`,
  `authMagicLink`, `authRecover`, `authResend`, `authReauthenticate`.
- **Admin user surface (service_role):** `authAdminListUsers`,
  `authAdminCreateUser`, `authAdminGetUser`, `authAdminUpdateUser`,
  `authAdminDeleteUser`, `authInvite`, `authAdminGenerateLink`,
  `authAdminListSSOProviders`, `authAdminAuditLog`.
- **OTP-consuming email flows via `generate_link`** (flows_test.go — mint the
  hashed_token with admin `generate_link`, redeem it through `POST /verify` → a
  real session; no inbox): `authVerifyPost` (recovery + magiclink), `authVerifyGet`.
- **MFA / TOTP end-to-end** (flows_test.go — enrol, parse the secret, compute an
  RFC-6238 code in-test via `pquerna/otp`, challenge, verify → **aal2** asserted
  in the JWT on both): `authEnrollFactor`, `authChallengeFactor`,
  `authVerifyFactor`, `authUnenrollFactor`, plus admin factors
  `authAdminListFactors`, `authAdminUpdateFactor`, `authAdminDeleteFactor`.
- **External OAuth / identity (`PARITY_FLAGS=1` for linking):**
  `authExternalAuthorize`, `authLinkIdentity`, `authUnlinkIdentity`,
  `authSingleSignOn`, `authSamlMetadata`.
- **OAuth 2.1 server (`PARITY_FLAGS=1`):** `authOAuthDynamicRegisterClient`,
  `authAdminRegisterOAuthClient`, `authAdminGetOAuthClient`,
  `authAdminListOAuthClients`, `authAdminUpdateOAuthClient`,
  `authAdminDeleteOAuthClient`, `authAdminRegenerateOAuthClientSecret`,
  `authOAuthAuthorizeGet`, `authOAuthToken`, `authOAuthUserInfo`.
- **Passkeys (`PARITY_FLAGS=1`, options only):** `authPasskeyList`,
  `authPasskeyRegistrationOptions`, `authPasskeyAuthenticationOptions`.

**Remaining 18 (each blocked by a capability the harness does not fake)** — the
`harness_test.go` TODO scaffold and the coverage report list these live:

| group | ops | blocker |
| --- | --- | --- |
| Passkey ceremony | `authPasskeyRegistrationVerify`, `authPasskeyAuthenticationVerify`, `authPasskeyUpdate`, `authPasskeyDelete`, `authAdminPasskeyList`, `authAdminPasskeyDelete` | a software WebAuthn authenticator to sign the ceremony / enrol a credential |
| OAuth consent + grants | `authOAuthGetAuthorization`, `authOAuthConsent`, `authListOAuthGrants`, `authRevokeOAuthGrant` | a scriptable browser/consent session cookie to reach the consent screen and record a grant |
| OAuth authorize POST | `authOAuthAuthorizePost` | upstream v2.196.0 has no POST `/oauth/authorize` (405); Dilion-only capability — nothing to differentially test |
| External callback | `authExternalCallbackGet`, `authExternalCallbackPost` | a stubbed external OAuth provider returning a signed state+code |
| SSO provider CRUD | `authAdminCreateSSOProvider`, `authAdminGetSSOProvider`, `authAdminUpdateSSOProvider`, `authAdminDeleteSSOProvider` | valid SAML IdP metadata (a malformed doc diverges 400 vs 500); list IS covered |
| SAML ACS | `authSamlAcs` | a signed SAML assertion posted to the ACS URL |

Filling one in is mechanical: add a `scenario{}` (single request) or a `flow{}`
(stateful sequence with `capture`/substitution) — run it, the differ shows what
diverges, then add any genuinely-new intentional difference to `deviations.yaml`
(never loosen the differ). The goal is 69/69 with every non-green diff either
fixed in Dilion or catalogued as a deviation.

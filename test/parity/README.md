# Dilion ↔ GoTrue differential parity harness

Runs Dilion's Supabase-Auth-compatible `/auth/v1` surface **side-by-side against
the real upstream `github.com/supabase/auth` (GoTrue)** and asserts behavioural
equivalence, excluding the deliberate deviations Dilion documents.

Both servers run **identical config** (same HS256 secret, same `SITE_URL`, same
feature flags) against **separate throwaway databases**. Every request is issued
to both; responses are normalised (volatile ids/timestamps/tokens scrubbed) and
diffed structurally. A diff that matches an entry in [`deviations.yaml`](./deviations.yaml)
is downgraded from **FAIL** to **KNOWN**; anything else fails the test.

> Status: **working smoke slice verified end-to-end** against
> `supabase/auth:v2.196.0`. 14 scenarios spanning 12 of the 69 curated operations
> (17.4%) run **green** (0 FAIL, 34 known deviations tolerated). The remaining 57
> operations have a mechanical TODO scaffold (see below).

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

`go.mod` requires **Go 1.26.6**. Migrations still run as a separate step.

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
both. (`⚠` marks GoTrue env-name quirks found in upstream `configuration.go`.)

| Surface | Dilion | GoTrue |
| --- | --- | --- |
| Passkeys / WebAuthn | `DILION_AUTH_PASSKEY_ENABLED=true` (+ `DILION_AUTH_WEBAUTHN_RP_ID`, `DILION_AUTH_WEBAUTHN_RP_ORIGINS`) | `GOTRUE_MFA_WEB_AUTHN_ENROLL_ENABLED=true` + `GOTRUE_MFA_WEB_AUTHN_VERIFY_ENABLED=true` ⚠ `WEB_AUTHN` is split |
| OAuth 2.1 server | `DILION_AUTH_OAUTH_SERVER_ENABLED=true` | `GOTRUE_OAUTH_SERVER_ENABLED=true` |
| Phone / SMS | *(driven by SMS provider config)* `DILION_AUTH_SMS_PROVIDER=…` | `GOTRUE_EXTERNAL_PHONE_ENABLED=true` + `GOTRUE_SMS_PROVIDER=…` |
| SAML | `DILION_AUTH_SAML_ENABLED=true` (+ `DILION_AUTH_SAML_PRIVATE_KEY`) | `GOTRUE_SAML_ENABLED=true` ⚠ (example.env uses `GOTRUE_EXTERNAL_SAML_ENABLED`) |
| Anonymous users | `DILION_AUTH_EXTERNAL_ANONYMOUS_USERS_ENABLED=true` | `GOTRUE_EXTERNAL_ANONYMOUS_USERS_ENABLED=true` |
| MFA TOTP | `DILION_AUTH_MFA_TOTP_ENROLL_ENABLED` / `_VERIFY_ENABLED` | `GOTRUE_MFA_TOTP_ENROLL_ENABLED` / `_VERIFY_ENABLED` |
| Captcha | `DILION_AUTH_SECURITY_CAPTCHA_ENABLED` (+ provider/secret) | `GOTRUE_SECURITY_CAPTCHA_ENABLED` (+ provider/secret) |

For passkeys/SAML/OAuth-server you must supply the matching key material
(WebAuthn RP id/origins, SAML private key, an OAuth client) to BOTH, or the
surfaces answer different setup errors.

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
Current catalogue: **32 entries.**

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

**Working slice (12/69 ops, 17.4%, all green):** `authHealth`, `authSettings`,
`authJwks`, `authOpenIDConfiguration`, `authOAuthAuthorizationServerMetadata`,
`authSignup`, `authToken` (password + refresh + a bad-credential error case),
`authGetUser`, `authUpdateUser`, `authLogout`, `authAdminListUsers`
(service_role, cross-verifiable HS256 token), `authVerifyGet` (redirect).

The remaining **57 operations** each have a row in the **TODO table** in the
`harness_test.go` doc comment (also emitted by the coverage report), listing the
credential and prerequisite state each needs. Filling one in is mechanical:

1. add a `scenario{}` to `scenarios()` with the method/path/cred and the right
   `compare` mode;
2. run it — the differ shows what diverges;
3. add any genuinely-new intentional difference to `deviations.yaml`.

Priority order to reach full coverage:

1. **Admin user CRUD** (`authAdminCreateUser/GetUser/UpdateUser/DeleteUser`) and
   `authAdminGenerateLink` — all `service_role`, no feature flags. `generate_link`
   also unlocks the **OTP-consuming** flows (`authVerifyPost`, `authOtp`,
   `authMagicLink`, `authRecover`, `authResend`) by giving the harness a real
   token to redeem.
2. **MFA/TOTP** (`authEnrollFactor` → `authChallengeFactor` → `authVerifyFactor`,
   admin factor ops) — needs a TOTP code computed from the enrol secret.
3. **Feature-flagged surfaces** — enable the matched pairs and add scenarios:
   passkeys (7 ops), OAuth 2.1 server (12 ops), SAML/SSO (8 ops).
4. **External OAuth start/callback** (`authExternalAuthorize`, callbacks) — assert
   the redirect target with a stubbed provider.

Each newly-covered op raises the coverage % the report prints; the goal is 69/69
with every non-green diff either fixed in Dilion or catalogued as a deviation.

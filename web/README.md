# Dilion Sample Service (web)

A small sample app showing how a service integrates with **Dilion** from a browser, using both
supported client paths:

| Path | Library | Surface |
| --- | --- | --- |
| Auth | `@supabase/supabase-js` | `/auth/v1/*` — Supabase Auth compatible, so ordinary supabase-js code works unchanged |
| Management plane | `openapi-fetch` + types generated from `openapi.yaml` | `/privacy/v1/*`, `/iam/v1/*` — OpenAPI-first, fully typed |

Stack: Vite + React + TypeScript, no UI framework, no router dependency (hash routing).

---

## Run it

The Dilion dev server must be listening on `http://localhost:8787`.

```bash
npm install            # .npmrc sets legacy-peer-deps (see "Known wrinkles")
npm run gen:api        # openapi.yaml -> src/api/schema.d.ts
cp .env.example .env.local
#   ...then put a dev management token in .env.local (next section)
npm run dev            # http://localhost:5173
```

Other scripts: `npm run build` (`tsc -b && vite build`), `npm run lint` (oxlint), `npm run preview`.

`vite.config.ts` proxies `/auth`, `/privacy` and `/iam` to `http://localhost:8787`
(override with `DILION_ORIGIN=... npm run dev`). Everything the browser sees is same-origin, so
**no CORS configuration exists anywhere** — not in this app and not in the server.
`createClient(window.location.origin, ANON_KEY)` works because supabase-js appends `/auth/v1`
itself.

### Minting a dev `service_role` JWT

The management plane requires `Authorization: Bearer <service_role JWT | dk_ API key>`. The dev
server signs with **HS256** and the secret **`devsecret-e2e`**; claims are
`{ role: "service_role", sub, exp }`.

```bash
node -e "const c=require('crypto'),h=o=>Buffer.from(JSON.stringify(o)).toString('base64url'),\
p=h({alg:'HS256',typ:'JWT'})+'.'+h({role:'service_role',sub:'00000000-0000-0000-0000-000000000000',exp:Math.floor(Date.now()/1e3)+86400});\
console.log(p+'.'+c.createHmac('sha256','devsecret-e2e').update(p).digest('base64url'))"
```

Put the result in `.env.local` (gitignored via `*.local`) and restart the dev server:

```
VITE_DILION_SERVICE_TOKEN=eyJhbGciOi...
VITE_DILION_ANON_KEY=dev-anon-key
```

If the variable is unset the app still boots: the banner turns red and the Privacy Center renders
setup instructions instead of calling the API. The Admin console still works if you switch the
credential selector to `SESSION` (next section).

---

## Two credentials, one selector (`관리 API 자격증명`)

Dilion's management plane accepts **two different identities**, and this sample lets the operator
choose between them at runtime instead of hard-wiring one:

| Mode | Credential | How the server authorizes it |
| --- | --- | --- |
| `SERVICE` (default) | the dev `service_role` JWT from `VITE_DILION_SERVICE_TOKEN` | **bypasses RBAC** — a full-tenant credential |
| `SESSION` | the access token of the user signed in to this browser | **RBAC**: `role_assignments` must grant the permission the endpoint checks; deny by default (`403 permission_denied`, or `not_admin` on the auth surface) |

The option box lives in the **Admin console header** (visible on every admin screen), and a compact
badge under the dev banner mirrors it on every page, so the active identity is never in doubt.
Picking `SESSION` while signed out shows an inline warning ("로그인 필요 — 요청은 401이 됩니다") and
a link to `#/signin`; picking `SERVICE` without the env var warns the same way about the missing
token.

The choice is a tiny external store (`src/lib/credentialMode.ts`, `useSyncExternalStore` +
`localStorage`, no extra dependency) that every caller reads:

- `src/api/client.ts` — the openapi-fetch middleware is `async` and resolves the token per request:
  the service token, `supabase.auth.getSession().access_token`, or **no `Authorization` header at
  all** when neither exists (an empty bearer would read as a malformed credential, not as an
  anonymous call).
- `src/api/authAdmin.ts` — no longer a fixed `global.headers.Authorization`; see the Auth-admin
  section below.
- `src/pages/DocsPage.tsx` — the Swagger `requestInterceptor` injects the same credential, and an
  explicit *Authorize* in the UI still wins over it.
- The shared list hooks (`usePagedList`, `usePermissionCatalog`) and Admin → Users re-fetch when
  the mode changes, so a page never keeps a result fetched as the other identity.

**Bootstrapping a user into the admin console** (the deny-by-default path):

1. Sign in as the user (`#/signin`), then switch the selector to `SESSION` — admin lists answer
   `403 permission_denied`, and `<ProblemAlert />` appends the hint *"내 계정에 role이 필요합니다 —
   Admin → IAM → Roles에서 할당"* with a link to the Roles screen.
2. Switch back to `SERVICE`, go to **Admin → Roles → assignments**, and grant that user a role
   (`owner`, or a custom one holding the permissions you need — `users.admin` is what the
   **Auth admin** surface (`/auth/v1/admin/*`) checks).
3. Switch to `SESSION` again: the same calls now answer `200`, and the audit trail records them
   with `actor_type=user` and your user id (Admin → Audit, filter by `actor_id`) instead of the
   service actor.

---

## Production architecture note (read this)

This sample puts a management token in the browser **on purpose, for demonstration only**. A
`service_role` JWT or `dk_` API key is a full-tenant credential: anyone who opens devtools can
read every data subject's requests and mutate anyone's consent.

In production, the split is:

```
browser  ──(user JWT from supabase-js)──►  your backend  ──(service token)──►  Dilion /privacy/v1
   │                                             │
   └─ /auth/v1 direct to Dilion is fine          └─ authorizes "is this user allowed to act on this user_id?"
      (that's what the anon key is for)             then forwards, and never echoes the token back
```

- Keep the `/auth/v1` traffic in the browser — that surface is designed for public clients.
- Move every `/privacy/v1` and `/iam/v1` call behind your own endpoint (e.g.
  `POST /api/me/delete`), which validates the caller's user JWT, checks that `user_id` matches the
  caller, and only then calls Dilion with the service token held server-side.
- The typed client in `src/api/client.ts` moves to your backend unchanged — the generated schema
  is runtime-agnostic.

---

## What each page demonstrates

### Session (`#/signin`)

`supabase.auth.signUp`, `supabase.auth.signInWithPassword`, `supabase.auth.signOut`. Shows
session state (user id, email, access-token expiry) and surfaces gotrue errors with their
`code` (e.g. `invalid_credentials`). Sign-out lives in the header.

### My account (`#/account`)

`supabase.auth.getUser()` (`GET /auth/v1/user`) rendered as a summary plus the raw user JSON.
The `id` shown here is the canonical `user_id` that the whole privacy plane is keyed on.

This is also the **self-service** surface — everything an end user may do to their own account
without the management token:

- **Change email / Change password / Edit `user_metadata`** — all three are `PUT /auth/v1/user`
  (`supabase.auth.updateUser()`), split into three cards because their consequences differ:
  - *email*: with `MAILER_AUTOCONFIRM` on (the dev default) the address applies immediately and the
    **old** address is notified; with confirmation required it is parked in `new_email` until the
    mailed link is followed. A duplicate answers `422 email_exists`.
  - *password*: **변경 시 다른 세션이 폐기됩니다** — the server drops every *other* session and
    revokes its refresh tokens, and only the caller's own session survives. Reusing the current
    password answers `422 same_password`.
  - *metadata*: a JSON textarea validated client-side (must parse, and must be an *object*) before
    it is ever sent. The server **merges** the object and treats a `null` value as "delete this
    key", so this is a patch, not a replace. `app_metadata` is deliberately not editable here —
    a user may not escalate their own claims.
- **Session tools** — `supabase.auth.refreshSession()` (which mints a new access token and rotates
  the refresh token; the new expiry is the visible proof), `supabase.auth.signOut({ scope })` with
  gotrue's three scopes (`global` = every session, `local` = this browser only, `others` =
  everything except this one — the only scope that leaves you signed in), and the access token's
  own `sub` / `role` / `exp`, decoded from the JWT payload in the browser. That decode is for
  **display only**: `src/lib/jwt.ts` never verifies a signature, because a browser cannot.
- **Server info** — `GET /auth/v1/health` and `GET /auth/v1/.well-known/jwks.json`, the two public
  `/auth/v1` endpoints, fetched raw (supabase-js wraps neither). `keys: []` is the expected JWKS
  answer while the dev server signs with the HS256 shared secret: there is no public key to publish.

gotrue errors here go through `problemFromAuthError()` and render in the same `<ProblemAlert />`
as every management-plane failure.

### Privacy center (`#/privacy`)

All three sections go through the generated client:

- **Consents** — `GET /privacy/v1/users/{userId}/consents` lists the derived current state;
  toggling calls `PATCH` with `{ purpose, granted, policy_version, source: "UI" }`. The ledger is
  append-only, so each toggle is a new record, not an overwrite.
- **Delete my account** — `POST /privacy/v1/requests` with
  `{ user_id, type: "DELETION" }` and an `Idempotency-Key` header (the key is held in a ref, so a
  retry after a network error replays instead of opening a second request). The `202` response is
  then polled via `GET /privacy/v1/requests/{id}` every 2s and rendered as a
  `REQUESTED → PROCESSING → DONE` timeline, with `MANUAL_REVIEW` / `CANCELED` as terminal
  off-path states. The grace period is explained from `scheduled_at - requested_at`, and the
  request can be cancelled (`POST .../cancel`) while it is still within that window.
- **Privacy requests** — `GET /privacy/v1/requests` with cursor pagination
  (`{ items, next_cursor }`), `limit=10`, `sort=-requested_at` and a status filter. Previous/Next
  walk a cursor stack. This is the *management* view, so it lists every data subject; rows for
  the signed-in user are highlighted. The same `<RequestsList />` is reused by the admin console.

### API Docs (Swagger UI) (`#/docs`)

**Two** specs rendered by **Swagger UI**, bundled from `node_modules` (`swagger-ui-dist`) — **no
CDN**, so the docs work offline. A `<select>` in the page's own banner card picks between them and
re-initializes swagger-ui on the chosen URL (swagger-ui has no supported way to swap `url` on a
live instance); the app keeps its own header rather than swagger-ui's `StandaloneLayout` topbar.

| Spec | File | Surface | How it is maintained |
| --- | --- | --- | --- |
| **Platform API** (default) | `web/openapi.yaml` | `/privacy/v1`, `/iam/v1` — 38 operations | **Generated** by the server build (`cmd/openapi`) — never edit it here; re-run `npm run gen:api` after it changes |
| **Auth API (Supabase compatible)** | `web/openapi-auth.yaml` | `/auth/v1` — 69 operations | **Hand-curated in this repo.** Nothing generates it: it is written from the `internal/auth` handlers, so **update it by hand whenever `internal/auth` changes** |

`openapi-auth.yaml` is deliberately *not* upstream's gotrue spec — it documents **only what
`internal/auth` actually serves**, which is now the full 69-operation surface (see *Auth surface
coverage* below). Accuracy beats completeness: every field in it was read off a Go struct tag, and
the deviations from upstream are spelled out per operation.

Things the spec is careful about, because they are easy to get wrong from the outside:

- **Two error families.** Everything answers gotrue's `{code, error_code, msg}` envelope *except*
  `POST /oauth/token` (and the parameter errors of `grant_type=id_token`), which answer RFC 6749's
  `{error, error_description}` with HTTP 400 whatever the OAuth error code says.
- **Redirect semantics.** `/verify`, `/authorize`, `/callback`, `/sso`, `/sso/saml/acs` and
  `/oauth/authorize` answer with a `302`/`303`, never a body. The implicit flow puts the session in
  the URL **fragment**; a PKCE flow puts `?code=` in the **query string**; failures go into the
  fragment (and, for PKCE, the query string too).
- **Feature flags** are named in the description of every gated operation, together with the
  `error_code` the 404 carries.
- **Rate limits** — both the per-IP bucket (`DILION_AUTH_RATE_LIMIT_*`) and the per-user send
  throttle (`over_email_send_rate_limit` / `over_sms_send_rate_limit`) — are named per operation.

Its `securitySchemes` is a single `bearerAuth` covering three different credentials (user access
token, `service_role`/`users.admin`, and the OAuth **client** credentials of `/oauth/token`).
Validate edits with `npx @redocly/cli lint web/openapi-auth.yaml` — errors must be zero; the
handful of warnings are structural (redirect-only operations have no `2XX`, `/health` has no `4XX`,
the server URL is `localhost`).

Both specs reach the page as Vite asset URLs (`import specUrl from '../../openapi.yaml?url'`,
`import authSpecUrl from '../../openapi-auth.yaml?url'`); swagger-ui parses the YAML itself, so the
app carries no YAML parser. The page is `React.lazy`-loaded: swagger-ui is ~1.4 MB of vendor bundle
and nobody should pay for it just to sign in.

**Try it out actually works**, which takes two deliberate hacks — both dev-only:

- The spec's single server is `http://localhost:8787`, so a Try-it-out request would leave this
  origin and be blocked (Dilion configures no CORS, on purpose). A `requestInterceptor` rewrites
  any URL starting with `http://localhost:8787` to a **same-origin relative path**, which puts it
  back on the Vite proxy — the same route every other call in this app takes.
- The same interceptor injects `Authorization: Bearer <token>` **only when the request carries no
  `Authorization` of its own**, so an explicit *Authorize* in the UI (a `dk_` key, say) still wins.
  Which token that is follows the `관리 API 자격증명` selector — the dev service token or the
  signed-in user's — and the banner names the mode currently in effect. A banner above the UI says so, in the same tone as `<DevTokenBanner />`:
  the calls are real, they mutate the dev tenant, and that token must never ship to a browser in
  production.

On the **Auth API** the injected service token is usually the *wrong* credential, so the banner
grows a third paragraph. Which credential an operation wants now varies by tag:

- **Core / Email flows / Phone / External OAuth / SSO / Passkey login** — no credential at all
  (`/signup`, `/token`, `/verify`, `/otp`, `/magiclink`, `/recover`, `/resend`, `/authorize`,
  `/callback`, `/sso`, `/passkeys/authentication/*`, `/settings`, `/health`, `/.well-known/*`).
- **Self-service** — a **user access token** (`GET`/`PUT /auth/v1/user`, `/logout`,
  `/reauthenticate`, `/user/identities/*`, `/factors/*`, passkey management, `/oauth/userinfo`,
  `/oauth/authorizations/*`, `/user/oauth/grants`). Press *Authorize* and paste one — My account →
  Session tools shows the current session's, or run `POST /auth/v1/signup` right there and copy its
  `access_token`.
- **Admin** — `/auth/v1/admin/*` and `/auth/v1/invite` take the `service_role` JWT the interceptor
  already injects (or a user token holding `users.admin`).
- **`POST /auth/v1/oauth/token`** — authenticates the *client*, not a user: HTTP Basic, body
  credentials, or nothing for a public client. The bearer the interceptor injects is ignored here.

The redirect operations (`/verify`, `/authorize`, `/callback`, `/sso`, `/oauth/authorize`) are not
useful from *Try it out*: swagger-ui follows the redirect and shows you the landing page's body
rather than the `Location` header.

`deepLinking` is off: this app owns `window.location.hash` for its own router, and swagger-ui
would otherwise navigate away from `#/docs` on every expand.

`swagger-ui-dist` ships a UMD bundle and no types for it, so `src/types/swagger-ui-dist.d.ts`
declares exactly the config keys and the request shape this page uses — narrow enough that no `any`
reaches app code.

### Admin console (`#/admin-*`)

The **Admin** entry in the header opens the management plane itself. Every screen there talks to
Dilion with whichever credential the `관리 API 자격증명` selector in its header points at — the dev
`service_role` token (the default; there is deliberately no `requiresAuth` on these routes, because
the token *is* the credential) or the signed-in user's own access token, which the server authorizes
through RBAC. Each screen prints the
permission its endpoints check (`<PermissionHint />`), so a `403 permission_denied` is legible
before it happens; the `service_role` JWT bypasses RBAC, a scoped `dk_` key does not.

| Group | Screen | What it demonstrates |
| --- | --- | --- |
| Auth | **Users** | `supabase.auth.admin.*` against `/auth/v1/admin/users` — list (gotrue `page`/`per_page` + `Link`/`X-Total-Count`, *not* the cursor envelope), create, get, update, delete. Deleting warns that it starts the erasure pipeline and links to the request it produces. Reuses `<ConsentSection />` for the selected subject. |
| Privacy | **Requests** | Open a request for any subject (`202` + `Idempotency-Key`, optional `immediate`), inspect one by id with a polled timeline, cancel it, and browse the paginated management list. |
| Privacy | **Destinations** | Full CRUD: list, create (`type`, `name`, JSON `config`, write-only `secret`), open detail, enable/disable, edit `config`, delete behind a confirm that explains why *disable* is usually the right lever. |
| Privacy | **Legal holds** | Place a hold on a subject (optionally one `domain`), filter the list by `user_id`, release it. A hold is what turns a `DELETION` request into `MANUAL_REVIEW` instead of erasure. |
| IAM | **Roles** | Paginated role list (builtin vs custom) and role creation with a permission multi-select fed by `listPermissions`, so only registered names can be submitted. |
| IAM | **Assignments** | Per-role grant list with an `actor_id` filter and `include_revoked`, showing `granted_by`/`granted_at`/`revoked_by`/`revoked_at` — revoking preserves the row, it does not delete history. |
| IAM | **Permissions** | Catalog list, custom-permission registration with the namespace rule checked client-side *and* server-side (`422` rendered by `ProblemAlert`), plus the **recertification report**: who holds a permission today and through which role. |
| IAM | **API keys** | Issue a `dk_` key with a scope multi-select and optional `expires_at`. The plaintext token appears once, in a modal that can copy it and immediately prove it works by calling `GET /privacy/v1/requests` with it as the Bearer. Revoke from the list. |
| IAM | **Audit** | The append-only access log: filter by `actor_id`, `action` (grouped combobox over the §5.2 action taxonomy, widened by whatever the server returns) or `subject_id`, walk it with the cursor pager, and open one event to see its subject manifest. |

The flagship path is **Users → delete**: the account row and a `user.deleted` outbox event are
written in one transaction, the privacy engine turns that event into a `DELETION` request, and the
"Watch the DELETION request" button drops you into the request view to see it settle. Place a legal
hold on the subject first and the same request parks in `MANUAL_REVIEW` until the hold is released.

#### PII profile — masked by default, revealing is an event

`<ProfileSection />` renders a data subject's PII profile inside **Admin → Users → user detail**,
and standalone from a bare `user_id` in the *PII profile by user id* card (the audit trail links
there, and the audit log knows subjects the paginated gotrue list may not be showing).

Three permissions meet in that one card, and none of them implies the next:

- **`users.read` — the default.** `GET …/profile` answers `view: "MASKED"`: `홍길동` arrives as
  `홍**`, `gildong.hong@example.com` as `g**@example.com`. The projection happens on the server,
  from each field's masking hint — the browser never receives an original it then has to hide. A
  `404 not_found` is not an error state here but the **프로필 없음** empty state: Dilion deletes the
  row (and shreds its key) rather than storing an empty envelope, so "no fields" and "no profile"
  are the same thing.
- **`pii.reveal` — 원본 보기.** The button opens a modal that will not submit without a reason;
  `POST …/profile/reveal` then returns `view: "FULL"` and writes a `PII_FULL_READ` event carrying
  that reason and the subject's id. The card switches to a red **FULL — audited (PII_FULL_READ)**
  indicator, and **다시 마스킹** simply re-reads the masked projection.
- **`pii.write` — editing.** Field keys are arbitrary (the profile is an open key→field map, not a
  fixed schema), validated against `^[a-z][a-z0-9_.-]{0,63}$` client-side *and* server-side, with
  the masking hint chosen per field (`EMAIL | NAME | PHONE | ADDRESS | GENERIC`). Adds, replacements
  and removals are **staged locally** — the table marks them `NEW` / `EDIT` / `REMOVE` and every one
  is undoable — and *Save staged changes* sends them as a single
  `PATCH { set: {…}, remove: […] }`. The response is the masked projection, deliberately: a write
  never echoes personal data back, so saving also drops the card out of the FULL view.

#### Audit — the reverse lookup

**Admin → Audit** is `GET /iam/v1/audit/events`: newest first, cursor paged through the same
`usePagedList` as every other list, showing `created_at`, `action`, actor, `access_level`, `reason`
and `result_count`. `actor_id` and `action` answer *what did this operator do*; `action` is a
combobox — a `<datalist>` mirroring the action constants of `internal/audit/audit.go`, each option
carrying its group as a hint label (*Accounts*, *PII*, *Privacy requests*, *Consent*, *Holds &
destinations*, *IAM*, *Security*) and widened with anything the server returns that this build has
never heard of (*Seen in results*) — but the filter itself is free text, so an action added after
this build is still typeable.

Read actions name the **record kind** that was read, not the screen: `USER_LIST_READ` /
`USER_DETAIL_READ` are the account directory only, while subject-scoped reads under `/privacy/v1`
have their own actions (`PII_MASKED_READ`, `PRIVACY_REQUEST_LIST_READ`, `CONSENT_READ`,
`LEGAL_HOLD_LIST_READ`, `DESTINATION_READ`, `IAM_READ`, …), which is what makes filtering by action
worth doing. Actions graded **매우 민감** in §5.2 — the ones that disclose unmasked personal data or
change who may access it — carry a small `매우 민감` tag next to the action name in the table and in
the event detail; `PERMISSION_DENIED` instead gets a red `denied` tag, since a refusal is an
outcome rather than a sensitivity grade.

`subject_id` is the interesting one: it matches against each event's **subject manifest**, so it
answers **이 사용자를 누가 봤는가** rather than what one operator did. That is the direction the
Users screen and the profile card link in — *View audit trail* parks the subject id in
`src/lib/handoff.ts` and the audit page consumes it once on mount.

List rows always report `subject_ids: []`; the manifest is only returned by
`GET /iam/v1/audit/events/{eventId}`, so clicking a row is a second, deliberate request for
evidence the list withholds. Each id in the manifest links back to that subject's PII profile, or
pivots the list onto that subject. There is no write wrapper for any of this because there is no
write endpoint: the log is append-only, and reading it is deliberately *not* itself audited —
an access event per audit read would recurse without adding evidence.

### Errors

Every management-plane failure is parsed as RFC 9457 problem+json and rendered by
`ProblemAlert`: the machine-readable `code`, the HTTP status, `detail`, and per-field `errors[]`
from 422 validation responses. gotrue errors from `/auth/v1/admin/*` are not problem+json, so
`problemFromAuthError()` maps them onto the same shape — one error renderer for the whole app.

---

## API coverage

30 of the 38 operations in `openapi.yaml` have a typed wrapper in `src/api/client.ts` and a
trigger in the UI. No API payload is typed `any`; the wrappers derive everything from generated
`paths` / `components["schemas"]`. The 8 operations added on 2026-08-24 (consent segment/audience:
`listConsentStates`, `exportConsentAudience`; user search: `searchUsers`; self-service:
`createMePrivacyRequest`, `listMePrivacyRequests`, `cancelMePrivacyRequest`, `listMeConsents`,
`updateMeConsent`) are in the generated schema and exercisable from `#/docs`, but have no UI or
wrapper yet.

| # | Operation | Endpoint | Permission | UI location |
| --- | --- | --- | --- | --- |
| 1 | `listUserConsents` | `GET /privacy/v1/users/{id}/consents` | `users.read` | Privacy center → Consents; Admin → Users → user detail |
| 2 | `updateUserConsent` | `PATCH /privacy/v1/users/{id}/consents` | `consents.write` | Same — the consent toggles |
| 3 | `getUserProfile` | `GET /privacy/v1/users/{id}/profile` | `users.read` | Admin → Users → user detail → PII profile (masked view, and the `404` empty state) |
| 4 | `revealUserProfile` | `POST /privacy/v1/users/{id}/profile/reveal` | `pii.reveal` | Admin → PII profile → **원본 보기** (reason modal) |
| 5 | `updateUserProfile` | `PATCH /privacy/v1/users/{id}/profile` | `pii.write` | Admin → PII profile → Save staged changes (one call for every add/edit/remove) |
| 6 | `createPrivacyRequest` | `POST /privacy/v1/requests` | `privacy.requests.manage` | Privacy center → Delete my account; Admin → Requests → Open a request |
| 7 | `getPrivacyRequest` | `GET /privacy/v1/requests/{id}` | `privacy.requests.manage` | Polled by both the deletion timeline and Admin → Requests → Request inspector |
| 8 | `cancelPrivacyRequest` | `POST /privacy/v1/requests/{id}/cancel` | `privacy.requests.manage` | Privacy center → Cancel request; Admin → Request inspector → Cancel request |
| 9 | `listPrivacyRequests` | `GET /privacy/v1/requests` | `privacy.requests.manage` | Privacy center → Privacy requests; Admin → Requests (same component) |
| 10 | `listDestinations` | `GET /privacy/v1/destinations` | `destinations.manage` | Admin → Destinations |
| 11 | `createDestination` | `POST /privacy/v1/destinations` | `destinations.manage` | Admin → Destinations → Register a destination |
| 12 | `getDestination` | `GET /privacy/v1/destinations/{id}` | `destinations.manage` | Admin → Destinations → Open |
| 13 | `updateDestination` | `PATCH /privacy/v1/destinations/{id}` | `destinations.manage` | Admin → Destination detail → Save config / Enable / Disable |
| 14 | `deleteDestination` | `DELETE /privacy/v1/destinations/{id}` | `destinations.manage` | Admin → Destination detail → Delete (confirm) |
| 15 | `listLegalHolds` | `GET /privacy/v1/holds` | `holds.manage` | Admin → Legal holds (with `user_id` filter) |
| 16 | `createLegalHold` | `POST /privacy/v1/holds` | `holds.manage` | Admin → Legal holds → Place a legal hold |
| 17 | `releaseLegalHold` | `POST /privacy/v1/holds/{id}/release` | `holds.manage` | Admin → Legal holds → Release |
| 18 | `listRoles` | `GET /iam/v1/roles` | `audit.read` | Admin → Roles; also the role picker on Assignments |
| 19 | `createRole` | `POST /iam/v1/roles` | `keys.manage` | Admin → Roles → Create a role |
| 20 | `listRoleAssignments` | `GET /iam/v1/roles/{id}/assignments` | `audit.read` | Admin → Assignments |
| 21 | `createRoleAssignment` | `POST /iam/v1/roles/{id}/assignments` | `keys.manage` | Admin → Assignments → Grant this role |
| 22 | `revokeRoleAssignment` | `DELETE /iam/v1/assignments/{id}` | `keys.manage` | Admin → Assignments → Revoke |
| 23 | `listPermissions` | `GET /iam/v1/permissions` | `audit.read` | Admin → Permissions; feeds the role/scope multi-selects |
| 24 | `createPermission` | `POST /iam/v1/permissions` | `keys.manage` | Admin → Permissions → Register a custom permission |
| 25 | `listPermissionHolders` | `GET /iam/v1/permissions/{name}/holders` | `audit.read` | Admin → Permissions → Recertification report |
| 26 | `listApiKeys` | `GET /iam/v1/api-keys` | `audit.read` | Admin → API keys |
| 27 | `createApiKey` | `POST /iam/v1/api-keys` | `keys.manage` | Admin → API keys → Issue an API key (one-time token modal) |
| 28 | `revokeApiKey` | `DELETE /iam/v1/api-keys/{id}` | `keys.manage` | Admin → API keys → Revoke |
| 29 | `listAuditEvents` | `GET /iam/v1/audit/events` | `audit.read` | Admin → Audit (filters `actor_id` / `action` / `subject_id`, cursor paged) |
| 30 | `getAuditEvent` | `GET /iam/v1/audit/events/{id}` | `audit.read` | Admin → Audit → row click → Event detail (the only read that carries the subject manifest) |

## Auth surface coverage (`/auth/v1`)

`/auth/v1` is outside `openapi.yaml` (it follows the upstream Supabase contract, not
`docs/api-conventions.md`); it is documented by the hand-curated **`openapi-auth.yaml`**, which
now covers **all 69 operations** `internal/auth` serves. The sample app itself only drives the 16
of them supabase-js wraps — the rest are documented and exercisable from `#/docs`.

### The groups

| Tag | Ops | Endpoints | Credential |
| --- | ---: | --- | --- |
| **Core** | 7 | `/health`, `/settings`, `/signup`, `/token` (4 grants), `GET`/`PUT /user`, `/logout` | none / user token |
| **Email flows** | 9 | `GET`+`POST /verify`, `/otp`, `/magiclink`, `/recover`, `/resend`, `/reauthenticate`, `/invite`, `/admin/generate_link` | none (admin for the last two) |
| **Phone** | 8 | no paths of its own — the phone branch of `/signup`, `/otp`, `/verify`, `/resend`, `PUT /user`, `/reauthenticate`, `/token?grant_type=password` | none / user token |
| **PKCE** | 14 | `code_challenge` on the flow starters, `?code=` on the redirects, `/token?grant_type=pkce` to redeem | none |
| **External OAuth** | 6 | `/authorize`, `GET`+`POST /callback`, `/user/identities/authorize`, `DELETE /user/identities/{id}`, `/token?grant_type=id_token` | none / user token |
| **MFA** | 7 | `/factors`, `/factors/{id}` (+`/challenge`, `/verify`), `/admin/users/{id}/factors[/{id}]` | user token / admin |
| **Passkeys** | 9 | `/passkeys/{authentication,registration}/{options,verify}`, `GET /passkeys`, `PATCH`/`DELETE /passkeys/{id}`, `/admin/users/{id}/passkeys[/{id}]` | none (login) / user token / admin |
| **SSO/SAML** | 8 | `/sso`, `/sso/saml/metadata`, `/sso/saml/acs`, `/admin/sso/providers[/{idp_id}]` | none / admin |
| **OAuth2 Server** | 16 | `/oauth/clients/register`, `/oauth/token`, `GET`+`POST /oauth/authorize`, `/oauth/userinfo`, `/oauth/authorizations/{id}[/consent]`, `GET`+`DELETE /user/oauth/grants`, `/admin/oauth/clients[/{id}[/regenerate_secret]]` | client creds / user token / admin |
| **Admin** | 24 | the five `/admin/users` operations, `/admin/audit`, and the admin halves of MFA, passkeys, SSO and the OAuth server | `service_role` or `users.admin` |
| **Well-known** | 3 | `/.well-known/jwks.json`, `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server` | none |

Operations carry more than one tag where that is the truth (`POST /signup` is Core + Phone + PKCE,
for instance), so the counts add up to more than 69.

### Feature flags

Whole groups are compiled in but gated at request time. Config is read from `DILION_AUTH_<NAME>`
first, falling back to upstream's `GOTRUE_<NAME>` spelling.

| Env var | Gates | Answer when off |
| --- | --- | --- |
| `DILION_AUTH_PASSKEY_ENABLED` | `/passkeys/**` (the admin routes stay open) | `404 passkey_disabled` |
| `DILION_AUTH_OAUTH_SERVER_ENABLED` | `/oauth/**`, `/user/oauth/grants`, `/admin/oauth/**`, `/.well-known/oauth-authorization-server` | `404 feature_disabled` |
| `DILION_AUTH_SAML_ENABLED` | `/sso/**` (`/admin/sso/**` stays open) | `404 saml_provider_disabled` |
| `DILION_AUTH_EXTERNAL_PHONE_ENABLED` | every phone/SMS path | `400`/`422 phone_provider_disabled` |
| `DILION_AUTH_EXTERNAL_EMAIL_ENABLED` | `/magiclink`, `/otp` (email), `/resend` | `422 email_provider_disabled` |
| `DILION_AUTH_EXTERNAL_<PROVIDER>_ENABLED` | that provider at `/authorize` and `/callback` | `400 validation_failed` |
| `DILION_AUTH_EXTERNAL_ANONYMOUS_USERS_ENABLED` | `POST /signup` with no identifier | `422 anonymous_provider_disabled` |
| `DILION_AUTH_MFA_TOTP_ENROLL_ENABLED` / `..._VERIFY_ENABLED` | TOTP enroll / challenge+verify | `422 mfa_totp_*_not_enabled` |
| `DILION_AUTH_SECURITY_MANUAL_LINKING_ENABLED` | `GET /user/identities/authorize` | `422 manual_linking_disabled` |
| `DILION_AUTH_SECURITY_CAPTCHA_ENABLED` | adds `gotrue_meta_security.captcha_token` to the unauthenticated surfaces | `422 captcha_failed` |

Supporting knobs the spec references: `WEBAUTHN_RP_ID` / `WEBAUTHN_RP_ORIGINS` (passkeys),
`SAML_PRIVATE_KEY` (SSO), `MAILER_AUTOCONFIRM` / `SMS_AUTOCONFIRM` (whether `/signup` returns a
session or a bare user), `MAILER_MAX_FREQUENCY` / `SMS_MAX_FREQUENCY` (per-user send throttles),
`SECURITY_UPDATE_PASSWORD_REQUIRE_REAUTHENTICATION` (the `nonce` on `PUT /user`) and the
`RATE_LIMIT_*` family.

The dev server this sample talks to runs with **passkeys, the OAuth server and the phone provider
enabled**, so those groups answer for real from `#/docs`.

### What is still missing versus upstream

Checked against `internal/auth` before writing this list:

- **SCIM** — no provisioning surface at all (`/admin/scim/**` does not exist).
- **`grant_type=web3`** — the Solana/Ethereum sign-in grant is unimplemented. The rate-limit knob
  (`RATE_LIMIT_WEB3`) and its limiter exist, but no grant is registered, so it answers
  `400 invalid_credentials` / `unsupported_grant_type`.
- **SMS providers other than Twilio** — `twilio_verify`, `messagebird`, `vonage` and `textlocal`
  have no driver. `SMS_PROVIDER` is reported verbatim by `GET /settings`, but only `twilio` (or an
  embedder-injected sender) actually delivers.
- **Encrypted SAML assertions** — deliberately not implemented; the SP metadata publishes only the
  signing key, because advertising an encryption key the server cannot use would make IdPs send
  assertions it cannot decrypt. Upstream gates this behind `SAML_ALLOW_ENCRYPTED_ASSERTIONS`.
- **Most external providers** — drivers exist for **apple, github, google and kakao** only.
  `GET /settings` still reports the `ENABLED` flag of all 25 provider slots (it reflects
  configuration, not drivers), so a slot can read `true` while `/authorize` answers
  `400 validation_failed`. There is no admin surface for registering a custom OAuth provider;
  custom **OIDC** issuers are reachable only through `POST /token?grant_type=id_token` with
  `client_id` + `issuer`.
- **MFA factor types other than TOTP** — `phone` and `webauthn` factors are recognised and refused
  (`422 mfa_phone_*_not_enabled` / `mfa_webauthn_*_not_enabled`). Passkeys exist as their own
  first-class surface instead of as a WebAuthn MFA factor.
- **Phone users via the admin API** — `POST /admin/users` has no phone branch
  (`422 validation_failed`), even though `POST /signup` creates them.
- **`SESSIONS_SINGLE_PER_USER`** — the config field is parsed but not enforced.

### What the sample app drives

`@supabase/supabase-js` through `src/api/authAdmin.ts`:

| Endpoint | supabase-js call | UI location |
| --- | --- | --- |
| `POST /auth/v1/signup` | `supabase.auth.signUp` | Session → Sign up |
| `POST /auth/v1/token?grant_type=password` | `supabase.auth.signInWithPassword` | Session → Sign in |
| `POST /auth/v1/token?grant_type=refresh_token` | `supabase.auth.refreshSession` | My account → Session tools → Refresh session |
| `POST /auth/v1/logout` | `supabase.auth.signOut` | Header → Sign out |
| `POST /auth/v1/logout?scope=global\|local\|others` | `supabase.auth.signOut({ scope })` | My account → Session tools → Sign out (scope selector) |
| `GET /auth/v1/user` | `supabase.auth.getUser` | My account |
| `PUT /auth/v1/user` (email) | `supabase.auth.updateUser({ email })` | My account → Change email |
| `PUT /auth/v1/user` (password) | `supabase.auth.updateUser({ password })` | My account → Change password |
| `PUT /auth/v1/user` (metadata) | `supabase.auth.updateUser({ data })` | My account → Edit user_metadata |
| `GET /auth/v1/health` | raw `fetch` (no supabase-js wrapper) | My account → Server info |
| `GET /auth/v1/.well-known/jwks.json` | raw `fetch` (no supabase-js wrapper) | My account → Server info |
| `GET /auth/v1/admin/users` | `auth.admin.listUsers` | Admin → Users |
| `POST /auth/v1/admin/users` | `auth.admin.createUser` | Admin → Users → Create a user |
| `GET /auth/v1/admin/users/{id}` | `auth.admin.getUserById` | Admin → Users → Open |
| `PUT /auth/v1/admin/users/{id}` | `auth.admin.updateUserById` | Admin → User detail → Save changes |
| `DELETE /auth/v1/admin/users/{id}` | `auth.admin.deleteUser` | Admin → User detail → Danger zone |

Everything else — the email/phone flows, PKCE, external OAuth, MFA, passkeys, SSO and the OAuth
server — is documented in `openapi-auth.yaml` and callable from **API Docs → Auth API**, but has no
dedicated screen in this sample.

The admin surface needs a privileged credential — a `service_role` JWT, or a user token whose actor
holds `users.admin` — so `authAdmin.ts` builds a **second** supabase client with
`persistSession: false` and its own `storageKey`; the end-user client keeps the anon key and the
browser session, and the two never share storage.

Its credential is **not** a fixed `global.headers.Authorization` any more: that would freeze one
token into the client at module load, while the selector can change between two calls of the same
page. Instead the client is created once with a `global.fetch` wrapper that resolves the active
credential per request and rewrites `Authorization` on the way out (dropping it entirely when there
is none), leaving gotrue's own headers untouched. Recreating the client per mode would have worked
too, but it would invalidate the `authAdmin` handle every page imports.

One deviation from gotrue's published OpenAPI worth repeating: `DELETE /admin/users/{id}` answers
`200 {}` rather than a user object (which is what upstream's *implementation* does, and what
supabase-js is written against), so `deleteAuthUser()` returns `void`.

---

## Code map

```
src/api/schema.d.ts        generated — do not edit (npm run gen:api)
src/api/client.ts          openapi-fetch client typed by `paths`, auth middleware,
                           problem+json -> ApiError, one function per operation (all 30)
src/api/authAdmin.ts       admin supabase client (mode-aware global.fetch) +
                           /auth/v1/admin wrappers, gotrue error -> Problem
src/lib/supabase.ts        supabase-js client pointed at window.location.origin
src/lib/credentialMode.ts  SERVICE | SESSION store (localStorage + useSyncExternalStore),
                           resolveManagementToken() used by every management caller
src/lib/useSession.ts      session state via getSession + onAuthStateChange
src/lib/router.ts          hash router: user routes + admin routes
src/lib/jwt.ts             JWT payload decode for display only (never verifies)
src/lib/usePagedList.ts    the cursor-stack pagination shared by every list
src/lib/usePermissionCatalog.ts  full permission catalog for the pickers
src/lib/handoff.ts         one-shot values passed between admin screens
src/pages/                 AuthPage, AccountPage, PrivacyCenterPage, DocsPage
                           (lazy-loaded Swagger UI), AdminConsole (shell + sub-nav)
                           and one page per admin screen
src/components/            ConsentSection, ProfileSection (masked/FULL PII + staged
                           edits), DeleteAccountSection, UpdateUserSection (self-service
                           PUT /auth/v1/user), SessionToolsCard, ServerInfoCard,
                           RequestTimeline, RequestsList, RequestInspector, ProblemAlert,
                           DevTokenBanner, CredentialModeSelect (option box + badge),
                           Pager, PermissionHint, MultiSelect, ApiKeySecretModal
src/types/                 ambient declarations for untyped deps (swagger-ui-dist)
```

`openapi.yaml` is generated by the server build — never edit it here. After the server's API
changes, re-run `npm run gen:api`; type errors then point at every call site that needs updating.

`openapi-auth.yaml` is the opposite: nothing generates it, so it is edited here by hand and must be
re-checked against `internal/auth` whenever that package changes. It feeds the docs page only — no
types are generated from it (the `/auth/v1` calls go through supabase-js's own types).

## Known wrinkles

- `openapi-typescript@7` declares a peer dependency on `typescript@^5` while this project uses
  TypeScript 6. The generator works fine, so `.npmrc` sets `legacy-peer-deps=true`; remove it once
  the peer range widens.
- The dev server issues short-lived tokens. A sudden wall of `unauthenticated` problem alerts
  usually just means the JWT in `.env.local` expired — mint a new one and restart `npm run dev`.

/**
 * Typed client for the Dilion management plane (/privacy/v1, /iam/v1).
 *
 * Every type in this file flows from `schema.d.ts`, which is generated from
 * `web/openapi.yaml` by `npm run gen:api`. Nothing here hand-writes a request or
 * response shape — regenerate the schema and the compiler points at whatever
 * broke.
 *
 * DEV ONLY: the browser sends a management token (service_role JWT or `dk_` API
 * key) directly. In production these calls belong behind your own backend — see
 * the banner rendered by <DevTokenBanner /> and web/README.md.
 */
import createClient, { type Middleware } from 'openapi-fetch'
import { resolveManagementToken } from '../lib/credentialMode'
import type { components, paths } from './schema'

export type Problem = components['schemas']['Problem']
export type ErrorDetail = components['schemas']['ErrorDetail']
export type PrivacyRequest = components['schemas']['PrivacyRequest']
export type PrivacyRequestPage = components['schemas']['PrivacyRequestPage']
export type PrivacyRequestStatus = PrivacyRequest['status']
export type PrivacyRequestType = PrivacyRequest['type']
export type ConsentState = components['schemas']['ConsentState']
export type UpdateConsentBody = components['schemas']['UpdateConsentBody']
export type CreatePrivacyRequestBody = components['schemas']['CreatePrivacyRequestBody']

// PII profile --------------------------------------------------------------
export type Profile = components['schemas']['Profile']
export type ProfileField = components['schemas']['ProfileField']
/** MASKED = hint-based projection, FULL = the original values. */
export type ProfileView = Profile['view']
/** Masking hint: decides how a value is projected in the MASKED view. */
export type ProfileFieldHint = ProfileField['hint']
export type ProfileBatch = components['schemas']['ProfileBatch']
export type RevealUserProfileBody = components['schemas']['RevealUserProfileBody']
export type UpdateUserProfileBody = components['schemas']['UpdateUserProfileBody']

// Privacy admin ------------------------------------------------------------
export type Destination = components['schemas']['Destination']
export type DestinationPage = components['schemas']['DestinationPage']
export type DestinationType = Destination['type']
export type CreateDestinationBody = components['schemas']['CreateDestinationBody']
export type UpdateDestinationBody = components['schemas']['UpdateDestinationBody']
export type LegalHold = components['schemas']['LegalHold']
export type LegalHoldPage = components['schemas']['LegalHoldPage']
export type CreateLegalHoldBody = components['schemas']['CreateLegalHoldBody']

// IAM ----------------------------------------------------------------------
export type Role = components['schemas']['Role']
export type RolePage = components['schemas']['RolePage']
export type CreateRoleBody = components['schemas']['CreateRoleBody']
export type RoleAssignment = components['schemas']['RoleAssignment']
export type RoleAssignmentPage = components['schemas']['RoleAssignmentPage']
export type CreateRoleAssignmentBody = components['schemas']['CreateRoleAssignmentBody']
export type Permission = components['schemas']['Permission']
export type PermissionPage = components['schemas']['PermissionPage']
export type CreatePermissionBody = components['schemas']['CreatePermissionBody']
export type PermissionHolder = components['schemas']['PermissionHolder']
export type PermissionHolderPage = components['schemas']['PermissionHolderPage']
/**
 * The operational view of an actor, attached to a grant by `expand=actor`. It
 * says whether the grant is still usable; it deliberately carries no personal
 * data, so labelling an operator means a separate {@link listUserProfiles}.
 */
export type Actor = components['schemas']['Actor']
export type ActorType = Actor['actor_type']
export type AuditEvent = components['schemas']['AuditEvent']
export type AuditEventPage = components['schemas']['AuditEventPage']
export type ApiKey = components['schemas']['APIKey']
export type ApiKeyPage = components['schemas']['APIKeyPage']
export type ApiKeyWithToken = components['schemas']['APIKeyWithToken']
export type CreateApiKeyBody = components['schemas']['CreateAPIKeyBody']

// Query envelopes ----------------------------------------------------------
export type ListRequestsQuery = NonNullable<
  paths['/privacy/v1/requests']['get']['parameters']['query']
>
export type ListDestinationsQuery = NonNullable<
  paths['/privacy/v1/destinations']['get']['parameters']['query']
>
export type ListHoldsQuery = NonNullable<paths['/privacy/v1/holds']['get']['parameters']['query']>
export type ListRolesQuery = NonNullable<paths['/iam/v1/roles']['get']['parameters']['query']>
export type ListAssignmentsQuery = NonNullable<
  paths['/iam/v1/roles/{roleId}/assignments']['get']['parameters']['query']
>
export type ListPermissionsQuery = NonNullable<
  paths['/iam/v1/permissions']['get']['parameters']['query']
>
export type ListHoldersQuery = NonNullable<
  paths['/iam/v1/permissions/{permissionName}/holders']['get']['parameters']['query']
>
export type ListApiKeysQuery = NonNullable<paths['/iam/v1/api-keys']['get']['parameters']['query']>
export type ListAuditEventsQuery = NonNullable<
  paths['/iam/v1/audit/events']['get']['parameters']['query']
>

/**
 * Mirror of `maxBatchProfiles` (internal/api/profiles_batch.go). The server is
 * the authority and answers 422 beyond it; this keeps callers from building a
 * request that cannot succeed.
 */
export const MAX_BATCH_PROFILES = 100

/** Every list endpoint answers with this envelope (docs/api-conventions.md). */
export type CursorPage<T> = { items: T[]; next_cursor: string | null }

/**
 * The management credential lives in `src/lib/credentialMode.ts`, which also
 * owns the SERVICE/SESSION switch. Re-exported here because this module is what
 * the rest of the app imports its API surface from.
 */
export {
  SERVICE_TOKEN,
  hasServiceToken,
  type CredentialMode,
  useCredentialMode,
} from '../lib/credentialMode'

/**
 * Signs every management call with whatever the active credential mode
 * prescribes: the dev `service_role` token (SERVICE) or the signed-in user's
 * access token (SESSION). With no credential available the request goes out
 * unauthenticated and the server answers `401 unauthenticated` — which is the
 * honest outcome, and what the selector warns about.
 */
const authMiddleware: Middleware = {
  async onRequest({ request }) {
    const token = await resolveManagementToken()
    if (token) request.headers.set('Authorization', `Bearer ${token}`)
    else request.headers.delete('Authorization')
    return request
  },
}

/**
 * baseUrl is empty on purpose: requests go to the app's own origin and the Vite
 * dev proxy (see vite.config.ts) forwards /privacy and /iam to the Dilion server.
 */
export const api = createClient<paths>({ baseUrl: '' })
api.use(authMiddleware)

/** A problem+json response surfaced as a throwable. */
export class ApiError extends Error {
  readonly problem: Problem

  constructor(problem: Problem) {
    super(problem.detail ?? problem.title ?? problem.code)
    this.name = 'ApiError'
    this.problem = problem
  }

  get code(): Problem['code'] {
    return this.problem.code
  }
}

const PROBLEM_CODES: ReadonlyArray<Problem['code']> = [
  'validation_failed',
  'unauthenticated',
  'permission_denied',
  'not_found',
  'conflict',
  'idempotency_conflict',
  'legal_hold_active',
  'policy_violation',
  'rate_limited',
  'reauthentication_needed',
  'insufficient_aal',
  'internal',
]

function isProblem(value: unknown): value is Problem {
  if (typeof value !== 'object' || value === null || !('code' in value)) return false
  const code = (value as { code: unknown }).code
  return PROBLEM_CODES.some((known) => known === code)
}

/** Coerce anything a failed call produced into a Problem we can render. */
export function toProblem(error: unknown, response?: Response): Problem {
  if (error instanceof ApiError) return error.problem
  if (isProblem(error)) return error
  const status = response?.status
  return {
    code: status === 401 ? 'unauthenticated' : 'internal',
    title: response?.statusText || 'Request failed',
    status,
    detail:
      error instanceof Error
        ? error.message
        : typeof error === 'string' && error.length > 0
          ? error
          : 'The request could not be completed.',
  }
}

type ApiResult<T> = { data?: T; error?: unknown; response: Response }

/** Unwrap an openapi-fetch result, throwing ApiError on problem+json. */
export function unwrap<T>(result: ApiResult<T>): T {
  if (result.data === undefined) {
    throw new ApiError(toProblem(result.error, result.response))
  }
  return result.data
}

/**
 * Same, for `204 No Content`. openapi-fetch resolves those with `data:
 * undefined`, so success has to be read off the response instead.
 */
export function unwrapEmpty(result: { error?: unknown; response: Response }): void {
  if (!result.response.ok) {
    throw new ApiError(toProblem(result.error, result.response))
  }
}

// ---------------------------------------------------------------------------
// Privacy API — every call goes through the generated `paths` type.
// ---------------------------------------------------------------------------

export async function listUserConsents(userId: string): Promise<ConsentState[]> {
  const result = await api.GET('/privacy/v1/users/{userId}/consents', {
    params: { path: { userId } },
  })
  return unwrap(result).items
}

export async function updateUserConsent(
  userId: string,
  body: UpdateConsentBody,
): Promise<ConsentState> {
  const result = await api.PATCH('/privacy/v1/users/{userId}/consents', {
    params: { path: { userId } },
    body,
  })
  return unwrap(result)
}

/**
 * Masked by default (§2.6): the plain GET never returns an original value, only
 * the projection its masking hint prescribes. `404 not_found` means the subject
 * has no profile row at all — not that the caller may not see it.
 * Recorded as `PII_MASKED_READ`.
 */
export async function getUserProfile(userId: string): Promise<Profile> {
  const result = await api.GET('/privacy/v1/users/{userId}/profile', {
    params: { path: { userId } },
  })
  return unwrap(result)
}

/**
 * The plural form of {@link getUserProfile}: the masked profiles of up to
 * {@link MAX_BATCH_PROFILES} subjects in one request, for a screen that lists
 * subjects and needs to label them. Same permission and same masking; the
 * server records ONE `PII_MASKED_READ` naming the subjects it returned.
 *
 * Ids with no stored profile come back in `missing` rather than being dropped,
 * so "no profile" stays distinguishable from "id you did not ask about".
 * Revealing has no batch form on purpose — every reveal needs its own reason.
 *
 * The ids travel as one comma-separated value, which is how the parameter is
 * declared in the spec and therefore how openapi-fetch serialises the array.
 * The server reads only the first `user_ids=` occurrence, so do not hand-build
 * a repeated form of this query.
 */
export async function listUserProfiles(userIds: readonly string[]): Promise<ProfileBatch> {
  const result = await api.GET('/privacy/v1/profiles', {
    params: { query: { user_ids: [...userIds] } },
  })
  return unwrap(result)
}

/**
 * The privileged unmasking (§5.2): a separate permission (`pii.reveal`) and a
 * mandatory `reason`, which is stored on the `PII_FULL_READ` audit event
 * together with the subject manifest. Answers `view: "FULL"`.
 */
export async function revealUserProfile(
  userId: string,
  body: RevealUserProfileBody,
): Promise<Profile> {
  const result = await api.POST('/privacy/v1/users/{userId}/profile/reveal', {
    params: { path: { userId } },
    body,
  })
  return unwrap(result)
}

/**
 * Partial write: `set` upserts fields, `remove` deletes them, and at least one
 * of the two is required. Recorded as `PII_UPDATE`; the response is the
 * **masked** projection — writing personal data never reveals it.
 */
export async function updateUserProfile(
  userId: string,
  body: UpdateUserProfileBody,
): Promise<Profile> {
  const result = await api.PATCH('/privacy/v1/users/{userId}/profile', {
    params: { path: { userId } },
    body,
  })
  return unwrap(result)
}

export async function createPrivacyRequest(
  body: CreatePrivacyRequestBody,
  idempotencyKey: string,
): Promise<PrivacyRequest> {
  const result = await api.POST('/privacy/v1/requests', {
    params: { header: { 'Idempotency-Key': idempotencyKey } },
    body,
  })
  return unwrap(result)
}

/**
 * `POST /privacy/v1/me/requests` — the self-service surface, sent with the
 * signed-in user's own access token rather than the management credential.
 * Deleting one's account there needs a recent sign-in: an older one answers
 * `403 reauthentication_needed`.
 */
export async function createMyPrivacyRequest(
  accessToken: string,
  body: components['schemas']['CreateMeRequestBody'],
  idempotencyKey: string,
): Promise<PrivacyRequest> {
  // Not the shared client: its middleware would put the management
  // credential back in place of the user's token.
  const asUser = createClient<paths>({ baseUrl: '' })
  asUser.use({
    onRequest({ request }) {
      request.headers.set('Authorization', `Bearer ${accessToken}`)
      return request
    },
  })
  const result = await asUser.POST('/privacy/v1/me/requests', {
    params: { header: { 'Idempotency-Key': idempotencyKey } },
    body,
  })
  return unwrap(result)
}

export async function getPrivacyRequest(requestId: string): Promise<PrivacyRequest> {
  const result = await api.GET('/privacy/v1/requests/{requestId}', {
    params: { path: { requestId } },
  })
  return unwrap(result)
}

export async function cancelPrivacyRequest(requestId: string): Promise<PrivacyRequest> {
  const result = await api.POST('/privacy/v1/requests/{requestId}/cancel', {
    params: { path: { requestId } },
  })
  return unwrap(result)
}

export async function listPrivacyRequests(
  query: ListRequestsQuery,
): Promise<PrivacyRequestPage> {
  const result = await api.GET('/privacy/v1/requests', { params: { query } })
  return unwrap(result)
}

// ---------------------------------------------------------------------------
// Privacy admin — destinations (destinations.manage) and legal holds
// (holds.manage). Same generated `paths` type, management-plane permissions.
// ---------------------------------------------------------------------------

export async function listDestinations(
  query: ListDestinationsQuery,
): Promise<DestinationPage> {
  const result = await api.GET('/privacy/v1/destinations', { params: { query } })
  return unwrap(result)
}

export async function createDestination(body: CreateDestinationBody): Promise<Destination> {
  const result = await api.POST('/privacy/v1/destinations', { body })
  return unwrap(result)
}

export async function getDestination(destinationId: string): Promise<Destination> {
  const result = await api.GET('/privacy/v1/destinations/{destinationId}', {
    params: { path: { destinationId } },
  })
  return unwrap(result)
}

export async function updateDestination(
  destinationId: string,
  body: UpdateDestinationBody,
): Promise<Destination> {
  const result = await api.PATCH('/privacy/v1/destinations/{destinationId}', {
    params: { path: { destinationId } },
    body,
  })
  return unwrap(result)
}

/** 204 No Content on success. */
export async function deleteDestination(destinationId: string): Promise<void> {
  const result = await api.DELETE('/privacy/v1/destinations/{destinationId}', {
    params: { path: { destinationId } },
  })
  unwrapEmpty(result)
}

export async function listLegalHolds(query: ListHoldsQuery): Promise<LegalHoldPage> {
  const result = await api.GET('/privacy/v1/holds', { params: { query } })
  return unwrap(result)
}

export async function createLegalHold(body: CreateLegalHoldBody): Promise<LegalHold> {
  const result = await api.POST('/privacy/v1/holds', { body })
  return unwrap(result)
}

export async function releaseLegalHold(holdId: string): Promise<LegalHold> {
  const result = await api.POST('/privacy/v1/holds/{holdId}/release', {
    params: { path: { holdId } },
  })
  return unwrap(result)
}

// ---------------------------------------------------------------------------
// IAM — roles, assignments, permissions, API keys.
// Reads require `audit.read`; writes require `keys.manage`.
// ---------------------------------------------------------------------------

export async function listRoles(query: ListRolesQuery): Promise<RolePage> {
  const result = await api.GET('/iam/v1/roles', { params: { query } })
  return unwrap(result)
}

export async function createRole(body: CreateRoleBody): Promise<Role> {
  const result = await api.POST('/iam/v1/roles', { body })
  return unwrap(result)
}

/** `PATCH /iam/v1/roles/{roleId}` — replace a custom role's permissions. */
export async function updateRole(roleId: string, permissions: string[]): Promise<Role> {
  const result = await api.PATCH('/iam/v1/roles/{roleId}', {
    params: { path: { roleId } },
    body: { permissions },
  })
  return unwrap(result)
}

export async function listRoleAssignments(
  roleId: string,
  query: ListAssignmentsQuery,
): Promise<RoleAssignmentPage> {
  const result = await api.GET('/iam/v1/roles/{roleId}/assignments', {
    params: { path: { roleId }, query },
  })
  return unwrap(result)
}

export async function createRoleAssignment(
  roleId: string,
  body: CreateRoleAssignmentBody,
): Promise<RoleAssignment> {
  const result = await api.POST('/iam/v1/roles/{roleId}/assignments', {
    params: { path: { roleId } },
    body,
  })
  return unwrap(result)
}

/** 204 No Content on success; the row survives with `revoked_at` set. */
export async function revokeRoleAssignment(assignmentId: number): Promise<void> {
  const result = await api.DELETE('/iam/v1/assignments/{assignmentId}', {
    params: { path: { assignmentId } },
  })
  unwrapEmpty(result)
}

export async function listPermissions(query: ListPermissionsQuery): Promise<PermissionPage> {
  const result = await api.GET('/iam/v1/permissions', { params: { query } })
  return unwrap(result)
}

export async function createPermission(body: CreatePermissionBody): Promise<Permission> {
  const result = await api.POST('/iam/v1/permissions', { body })
  return unwrap(result)
}

/** Recertification report: who currently holds `permissionName`, and via which role. */
export async function listPermissionHolders(
  permissionName: string,
  query: ListHoldersQuery = {},
): Promise<PermissionHolderPage> {
  const result = await api.GET('/iam/v1/permissions/{permissionName}/holders', {
    params: { path: { permissionName }, query },
  })
  return unwrap(result)
}

export async function listApiKeys(query: ListApiKeysQuery): Promise<ApiKeyPage> {
  const result = await api.GET('/iam/v1/api-keys', { params: { query } })
  return unwrap(result)
}

/** The only response that ever carries the plaintext `dk_` token. */
export async function createApiKey(body: CreateApiKeyBody): Promise<ApiKeyWithToken> {
  const result = await api.POST('/iam/v1/api-keys', { body })
  return unwrap(result)
}

/** 204 No Content on success. */
export async function revokeApiKey(keyId: string): Promise<void> {
  const result = await api.DELETE('/iam/v1/api-keys/{keyId}', {
    params: { path: { keyId } },
  })
  unwrapEmpty(result)
}

// ---------------------------------------------------------------------------
// Audit — append-only (§5.4), so there is no write wrapper here and none to
// write against. Both reads require `audit.read` and are themselves not
// audited: recording an access event for every audit read would recurse.
// ---------------------------------------------------------------------------

/** `subject_id` answers the reverse question "who accessed subject X" (§5.3). */
export async function listAuditEvents(query: ListAuditEventsQuery): Promise<AuditEventPage> {
  const result = await api.GET('/iam/v1/audit/events', { params: { query } })
  return unwrap(result)
}

/** The only response carrying the full `subject_ids` manifest — list rows omit it. */
export async function getAuditEvent(eventId: string): Promise<AuditEvent> {
  const result = await api.GET('/iam/v1/audit/events/{eventId}', {
    params: { path: { eventId } },
  })
  return unwrap(result)
}

/** Idempotency-Key for a retry-safe create. Stable per (user, type, attempt). */
export function newIdempotencyKey(): string {
  return crypto.randomUUID()
}

/**
 * One-off call with an alternate credential — used by the API keys screen to
 * prove a freshly minted `dk_` key actually authenticates. It deliberately
 * bypasses the shared client so the ambient service token is not sent.
 */
export async function listPrivacyRequestsAs(
  token: string,
  query: ListRequestsQuery,
): Promise<PrivacyRequestPage> {
  const oneOff = createClient<paths>({ baseUrl: '' })
  oneOff.use({
    onRequest({ request }) {
      request.headers.set('Authorization', `Bearer ${token}`)
      return request
    },
  })
  return unwrap(await oneOff.GET('/privacy/v1/requests', { params: { query } }))
}

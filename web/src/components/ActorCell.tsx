/**
 * Renders the `expand=actor` view of a grant: what the actor id names and
 * whether the grant is still usable.
 *
 * It shows no personal data, because the server sends none. A grant ledger is
 * not the surface personal data belongs on, so labelling an operator by name is
 * a separate, separately audited read — <SubjectProfiles /> does that.
 */
import type { Actor } from '../api/client'
import { formatDateTime } from '../lib/format'

const KIND_LABEL: Record<Actor['actor_type'], string> = {
  user: 'user',
  api_key: 'API key',
  unknown: 'gone',
}

/**
 * Why an expanded actor cannot use its grant, or null while it still can. An
 * `unknown` actor is one the ledger still names but neither auth.users nor the
 * key table knows — exactly what an access review is looking for.
 */
function inactiveReason(actor: Actor): string | null {
  if (actor.active) return null
  if (actor.actor_type === 'unknown') return 'no such user or API key'
  if (actor.deleted_at) return `deleted ${formatDateTime(actor.deleted_at)}`
  if (actor.banned_until) return `banned until ${formatDateTime(actor.banned_until)}`
  if (actor.revoked_at) return `revoked ${formatDateTime(actor.revoked_at)}`
  return 'not usable'
}

export function ActorCell({ actor }: { actor: Actor | undefined }) {
  if (!actor) return <span className="muted small">—</span>

  const reason = inactiveReason(actor)
  const last = actor.actor_type === 'user' ? actor.last_sign_in_at : null
  return (
    <div className="actor-cell">
      <span className={`badge ${actor.active ? 'badge-done' : 'badge-canceled'}`}>
        {KIND_LABEL[actor.actor_type]}
      </span>
      {reason ? (
        <span className="small muted">{reason}</span>
      ) : (
        <span className="small muted">
          {actor.actor_type === 'user'
            ? last
              ? `last sign-in ${formatDateTime(last)}`
              : 'never signed in'
            : `created ${formatDateTime(actor.created_at)}`}
        </span>
      )}
    </div>
  )
}

/**
 * The toggle both grant reports carry. Expanding needs `users.read` on top of
 * the report's own permission, and the label says so rather than leaving the
 * 403 to explain it.
 */
export function ExpandActorToggle({
  expanded,
  onChange,
}: {
  expanded: boolean
  onChange: (next: boolean) => void
}) {
  return (
    <label className="switch" title="Adds users.read to this request">
      <input type="checkbox" checked={expanded} onChange={(e) => onChange(e.target.checked)} />
      <span>
        expand actor <span className="muted">(needs users.read)</span>
      </span>
    </label>
  )
}

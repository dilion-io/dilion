import { useCallback, useEffect, useState } from 'react'
import {
  createDestination,
  deleteDestination,
  getDestination,
  listDestinations,
  toProblem,
  updateDestination,
  type CreateDestinationBody,
  type Destination,
  type DestinationPage,
  type DestinationType,
  type Problem,
} from '../api/client'
import { PAGE_SIZE, usePagedList } from '../lib/usePagedList'
import { ProblemAlert } from '../components/ProblemAlert'
import { PermissionHint } from '../components/PermissionHint'
import { Pager } from '../components/Pager'

const TYPES: DestinationType[] = ['WEBHOOK', 'CONNECTOR']

const SAMPLE_CONFIG = `{
  "url": "https://example.test/dilion/erasure",
  "identity_field": "email"
}`

type JsonObject = { [key: string]: unknown }

/** Parse a config textarea into the `{ [key: string]: unknown }` the API takes. */
function parseConfig(raw: string): { config?: JsonObject; error?: string } {
  try {
    const value: unknown = JSON.parse(raw)
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      return { error: 'config must be a JSON object.' }
    }
    return { config: value as JsonObject }
  } catch (err) {
    return { error: err instanceof Error ? err.message : 'Invalid JSON.' }
  }
}

export function AdminDestinationsPage() {
  const load = useCallback(
    (cursor?: string): Promise<DestinationPage> =>
      listDestinations({ limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) }),
    [],
  )
  const destinations = usePagedList<Destination>(load)
  const [selectedId, setSelectedId] = useState<string | null>(null)

  return (
    <>
      <section className="card">
        <h2>Destinations</h2>
        <p className="muted">
          <code>GET /privacy/v1/destinations</code> — the systems the erasure pipeline fans out to.
          Each request in <code>PROCESSING</code> waits on one task per <em>enabled</em>{' '}
          destination, which is why disabling one is an operational lever, not a cosmetic flag.
        </p>
        <PermissionHint permission="destinations.manage" />

        {destinations.problem && <ProblemAlert problem={destinations.problem} />}

        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Destination</th>
                <th>Name</th>
                <th>Type</th>
                <th>Enabled</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {destinations.items.map((d) => (
                <tr key={d.id} className={d.id === selectedId ? 'is-mine' : ''}>
                  <td>
                    <code className="small">{d.id}</code>
                  </td>
                  <td>{d.name}</td>
                  <td>{d.type}</td>
                  <td>
                    <span className={`badge ${d.enabled ? 'badge-done' : 'badge-canceled'}`}>
                      {d.enabled ? 'ENABLED' : 'DISABLED'}
                    </span>
                  </td>
                  <td>
                    <button
                      className="btn btn-ghost btn-sm"
                      type="button"
                      onClick={() => setSelectedId(d.id === selectedId ? null : d.id)}
                    >
                      {d.id === selectedId ? 'Close' : 'Open'}
                    </button>
                  </td>
                </tr>
              ))}
              {destinations.items.length === 0 && !destinations.loading && (
                <tr>
                  <td colSpan={5} className="muted">
                    No destinations. Erasure requests will complete immediately with nothing to fan
                    out to.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <Pager list={destinations} unit="destination" />
      </section>

      {selectedId && (
        <DestinationDetail
          key={selectedId}
          destinationId={selectedId}
          onChanged={destinations.reload}
          onDeleted={() => {
            setSelectedId(null)
            destinations.reload()
          }}
        />
      )}

      <CreateDestinationForm onCreated={destinations.reload} />
    </>
  )
}

function DestinationDetail({
  destinationId,
  onChanged,
  onDeleted,
}: {
  destinationId: string
  onChanged: () => void
  onDeleted: () => void
}) {
  const [destination, setDestination] = useState<Destination | null>(null)
  const [configDraft, setConfigDraft] = useState('')
  const [problem, setProblem] = useState<Problem | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [confirming, setConfirming] = useState(false)

  useEffect(() => {
    let active = true
    getDestination(destinationId)
      .then((d) => {
        if (!active) return
        setDestination(d)
        setConfigDraft(JSON.stringify(d.config, null, 2))
        setProblem(null)
      })
      .catch((err: unknown) => {
        if (active) setProblem(toProblem(err))
      })
    return () => {
      active = false
    }
  }, [destinationId])

  const parsed = parseConfig(configDraft)

  async function patch(body: { enabled?: boolean; config?: JsonObject }, message: string) {
    setBusy(true)
    setProblem(null)
    setNotice(null)
    try {
      const updated = await updateDestination(destinationId, body)
      setDestination(updated)
      setConfigDraft(JSON.stringify(updated.config, null, 2))
      setNotice(message)
      onChanged()
    } catch (err) {
      setProblem(toProblem(err))
    } finally {
      setBusy(false)
    }
  }

  async function remove() {
    setBusy(true)
    setProblem(null)
    try {
      await deleteDestination(destinationId)
      onDeleted()
    } catch (err) {
      setProblem(toProblem(err))
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <h3>Destination detail</h3>
      <p className="muted">
        <code>GET</code> / <code>PATCH</code> / <code>DELETE /privacy/v1/destinations/{'{id}'}</code>
        . <code>PATCH</code> takes only <code>enabled</code> and <code>config</code>; the webhook{' '}
        <code>secret</code> is write-only and never comes back in a response.
      </p>
      <PermissionHint permission="destinations.manage" />

      {problem && <ProblemAlert problem={problem} />}
      {notice && <div className="alert alert-info">{notice}</div>}

      {!destination ? (
        <p className="muted">Loading…</p>
      ) : (
        <>
          <dl className="kv">
            <dt>Id</dt>
            <dd>
              <code>{destination.id}</code>
            </dd>
            <dt>Name</dt>
            <dd>{destination.name}</dd>
            <dt>Type</dt>
            <dd>{destination.type}</dd>
            <dt>Enabled</dt>
            <dd>
              <span className={`badge ${destination.enabled ? 'badge-done' : 'badge-canceled'}`}>
                {destination.enabled ? 'ENABLED' : 'DISABLED'}
              </span>
            </dd>
          </dl>

          <label className="form">
            config (JSON)
            <textarea
              rows={8}
              className="mono"
              value={configDraft}
              onChange={(e) => setConfigDraft(e.target.value)}
              spellCheck={false}
            />
          </label>
          {parsed.error && (
            <p className="field-error small" role="alert">
              {parsed.error}
            </p>
          )}

          <div className="row">
            <button
              className="btn"
              type="button"
              disabled={busy || parsed.config === undefined}
              onClick={() => {
                if (parsed.config) void patch({ config: parsed.config }, 'config updated.')
              }}
            >
              Save config
            </button>
            <button
              className="btn btn-ghost"
              type="button"
              disabled={busy}
              onClick={() =>
                void patch(
                  { enabled: !destination.enabled },
                  destination.enabled
                    ? 'Disabled — the erasure pipeline will skip this destination.'
                    : 'Enabled — new requests will fan out here again.',
                )
              }
            >
              {destination.enabled ? 'Disable' : 'Enable'}
            </button>
            {!confirming ? (
              <button
                className="btn btn-danger"
                type="button"
                disabled={busy}
                onClick={() => setConfirming(true)}
              >
                Delete
              </button>
            ) : (
              <>
                <button
                  className="btn btn-danger"
                  type="button"
                  disabled={busy}
                  onClick={() => void remove()}
                >
                  {busy ? 'Deleting…' : `Yes, delete ${destination.name}`}
                </button>
                <button
                  className="btn btn-ghost"
                  type="button"
                  disabled={busy}
                  onClick={() => setConfirming(false)}
                >
                  Keep it
                </button>
              </>
            )}
          </div>
          {confirming && (
            <div className="confirm">
              <p>
                Deleting a destination removes it from every <em>future</em> fan-out (
                <code>204 No Content</code>). Erasure tasks already recorded against it are part of
                the compliance record and are not rewritten — prefer <strong>Disable</strong> when
                you only want to pause it.
              </p>
            </div>
          )}
        </>
      )}
    </section>
  )
}

function CreateDestinationForm({ onCreated }: { onCreated: () => void }) {
  const [type, setType] = useState<DestinationType>('WEBHOOK')
  const [name, setName] = useState('')
  const [secret, setSecret] = useState('')
  const [configDraft, setConfigDraft] = useState(SAMPLE_CONFIG)
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState<Problem | null>(null)
  const [created, setCreated] = useState<Destination | null>(null)

  const parsed = parseConfig(configDraft)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    if (!parsed.config) return
    setBusy(true)
    setProblem(null)
    try {
      const body: CreateDestinationBody = {
        type,
        name: name.trim(),
        config: parsed.config,
        ...(secret ? { secret } : {}),
      }
      setCreated(await createDestination(body))
      setName('')
      setSecret('')
      onCreated()
    } catch (err) {
      setProblem(toProblem(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <h3>Register a destination</h3>
      <p className="muted">
        <code>POST /privacy/v1/destinations</code> with{' '}
        <code>{'{ type, name, config, secret? }'}</code>. For a <code>WEBHOOK</code> the config is{' '}
        <code>{'{ url, identity_field }'}</code>; <code>secret</code> is the HMAC key Dilion signs
        the callout with and is write-only.
      </p>
      <PermissionHint permission="destinations.manage" />

      {problem && <ProblemAlert problem={problem} />}
      {created && (
        <div className="alert alert-info">
          Created <code>{created.id}</code> — {created.name} ({created.type}).
        </div>
      )}

      <form className="form" onSubmit={(e) => void submit(e)}>
        <label>
          Type
          <select value={type} onChange={(e) => setType(e.target.value as DestinationType)}>
            {TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>
        <label>
          Name
          <input
            required
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="billing-webhook"
          />
        </label>
        <label>
          config (JSON)
          <textarea
            rows={6}
            className="mono"
            value={configDraft}
            onChange={(e) => setConfigDraft(e.target.value)}
            spellCheck={false}
          />
        </label>
        {parsed.error && (
          <p className="field-error small" role="alert">
            {parsed.error}
          </p>
        )}
        <label>
          secret (optional, write-only)
          <input
            type="password"
            value={secret}
            onChange={(e) => setSecret(e.target.value)}
            placeholder="hmac shared secret"
          />
        </label>
        <div className="row">
          <button
            className="btn"
            type="submit"
            disabled={busy || !parsed.config || name.trim().length === 0}
          >
            {busy ? 'Creating…' : 'Create destination'}
          </button>
        </div>
      </form>
    </section>
  )
}

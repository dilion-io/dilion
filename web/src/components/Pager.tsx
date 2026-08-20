import type { PagedList } from '../lib/usePagedList'

/**
 * Footer for a cursor-paginated list: row count on the left, Previous/Next on
 * the right. `Previous` is enabled from the cursor stack, `Next` from
 * `next_cursor` — the API never reports a total.
 */
export function Pager<T>({ list, unit = 'row' }: { list: PagedList<T>; unit?: string }) {
  const n = list.items.length
  return (
    <div className="row row-between">
      <span className="muted small">
        {list.loading ? 'Loading…' : `${n} ${unit}${n === 1 ? '' : 's'}`}
        {list.hasNext ? ' · more available' : ''}
      </span>
      <div className="row">
        <button
          className="btn btn-ghost btn-sm"
          onClick={list.reload}
          disabled={list.loading}
          type="button"
        >
          Refresh
        </button>
        <button
          className="btn btn-ghost btn-sm"
          onClick={list.prev}
          disabled={!list.hasPrev || list.loading}
          type="button"
        >
          Previous
        </button>
        <button
          className="btn btn-ghost btn-sm"
          onClick={list.next}
          disabled={!list.hasNext || list.loading}
          type="button"
        >
          Next
        </button>
      </div>
    </div>
  )
}

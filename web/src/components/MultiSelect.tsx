/**
 * Checkbox group for the `string[]` fields the IAM API takes — role
 * `permissions` and API key `scopes`. Options come from `listPermissions`, so
 * the UI can only offer names the server already knows.
 */
export function MultiSelect({
  label,
  options,
  selected,
  onChange,
  disabled,
  hint,
}: {
  label: string
  options: ReadonlyArray<{ value: string; note?: string }>
  selected: readonly string[]
  onChange: (next: string[]) => void
  disabled?: boolean
  hint?: string
}) {
  function toggle(value: string, on: boolean) {
    onChange(on ? [...selected, value] : selected.filter((v) => v !== value))
  }

  return (
    <fieldset className="multiselect" disabled={disabled}>
      <legend>
        {label} <span className="muted small">({selected.length} selected)</span>
      </legend>
      {hint && <p className="muted small multiselect-hint">{hint}</p>}
      <div className="multiselect-grid">
        {options.map((option) => (
          <label key={option.value} className="multiselect-item">
            <input
              type="checkbox"
              checked={selected.includes(option.value)}
              onChange={(e) => toggle(option.value, e.target.checked)}
            />
            <span>
              <code>{option.value}</code>
              {option.note && <span className="muted small"> {option.note}</span>}
            </span>
          </label>
        ))}
        {options.length === 0 && <p className="muted small">No permissions registered yet.</p>}
      </div>
    </fieldset>
  )
}

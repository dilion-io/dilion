/**
 * Every admin screen states the permission its endpoints check, so a 403
 * `permission_denied` is legible before it happens. The dev `service_role` JWT
 * bypasses the check entirely — a scoped `dk_` key does not.
 */
export function PermissionHint({ permission }: { permission: string | string[] }) {
  const names = Array.isArray(permission) ? permission : [permission]
  return (
    <p className="perm-hint small">
      <span className="perm-hint-tag">requires</span>
      {names.map((name) => (
        <code key={name}>{name}</code>
      ))}
    </p>
  )
}

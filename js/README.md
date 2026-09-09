# Dilion JavaScript SDK

pnpm workspace. The SDK delegates existing behavior to upstream dependencies;
it does not vendor or fork Supabase's auth implementation.

~~~sh
pnpm install --frozen-lockfile
pnpm build
pnpm typecheck
DILION_OPAQUE_GO_INTEROP=1 pnpm test
~~~

Node 22+, pnpm 10.27.0 and Go 1.26.8+ (for the optional interoperability test).
Run build before typecheck: compatibility fixtures also consume the package's
published ESM and CommonJS declaration entry points.

The package is [@dilion-io/auth-js](packages/auth-js/README.md).
No npm publication or license grant has been made by this change.

## Daily compatibility monitoring

`.github/workflows/js-compat.yml` runs on relevant pushes/PRs, manually, and
daily at 07:17 Korea time (22:17 UTC). Scheduled runs require the workflow to be
on the repository's default branch; creating this file locally does not activate
GitHub Actions.

Each run checks:

1. Frozen lockfile: the supported build/test combination.
2. Latest Supabase Auth + Supabase JS with the supported TypeScript compiler.
3. Latest Supabase Auth + Supabase JS + TypeScript.
4. A separate Go/PostgreSQL job runs the SDK against real Dilion HTTP handlers,
   including shared-key agreement and session revocation.

The TypeScript checks keep `skipLibCheck: false`. A separate upstream-only
control distinguishes errors already present in Supabase from Dilion errors.
The suite tests public API assignability, typed database query inference,
expected compile errors, ESM/CJS exports, runtime delegation, and real OPAQUE
cryptography. An unsuccessful or skipped gate fails the job; it is not silently
marked compatible. Results and resolved versions appear in the Actions summary.
No automated package update, commit, issue creation, or publication is performed.

### Observed baseline (2026-09-09)

- Supabase Auth/JS 2.116.0 + TypeScript 5.9.3: build and strict type checks pass.
- TypeScript 7.0.2: the upstream-only control fails in Supabase's WebAuthn DOM
  declarations (`PublicKeyCredentialFuture.toJSON` / largeBlob types).
  The latest-compiler monitoring job is expected to remain red until resolved.
  This is not suppressed by a declaration shim or by skipping library checks.

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

The package is [@dilion-io/auth-js](packages/auth-js/README.md), published to npm
under Apache-2.0 by `.github/workflows/release.yml` when a `v*` tag is pushed.
One tag releases both the SDK and the server image, so the tag and
`packages/auth-js/package.json` must carry the same version -- bump the package
version in the commit you tag, or the release fails before publishing anything.
Prereleases (`v0.1.0-rc1`) go to the npm `next` tag and never move `latest`.

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

The TypeScript checks keep `skipLibCheck: false`. Two checks separate the
question "is Dilion wrong?" from "is someone else's `.d.ts` wrong?":
an upstream-only control isolates errors already present in Supabase, and
`tsconfig.sources.json` checks Dilion's own sources with third-party declaration
files left unchecked. Nothing this repository asserts is lost under the latter --
the `Equal<>` parity checks and the expected compile errors are written in our
own files, not in declarations.

The suite tests public API assignability, typed database query inference,
expected compile errors, ESM/CJS exports, runtime delegation, and real OPAQUE
cryptography. An unsuccessful or skipped gate fails the job; it is not silently
marked compatible. Results and resolved versions appear in the Actions summary.
No automated package update, commit, issue creation, or publication is performed.

Which checks gate depends on the profile. Under the frozen lockfile every version
is pinned, so all four must pass. The latest-* profiles resolve `@latest` of
packages and of the compiler itself, so strict declaration checking there fails on
other projects' release schedules; those two results are reported as warnings,
and the Dilion-sources and runtime checks are what fail the job. Strict checking
is not weakened anywhere -- it still runs, and it is still published in the
summary; only its authority to fail a canary profile is withdrawn, so that a red
run continues to mean "Dilion has a problem".

### Observed baseline (2026-09-18)

- Supabase Auth/JS 2.116.0 + TypeScript 5.9.3: build and strict type checks pass.
- TypeScript 7.0.2: two strict declaration failures, both third-party. Dilion's
  own sources typecheck clean under 7.0.2, and no reported error resolves to a
  file outside `node_modules/`.
  - The upstream-only control fails in Supabase's WebAuthn DOM declarations
    (`PublicKeyCredentialFuture.toJSON` / largeBlob types). 7.0 added WebAuthn
    Level 3 types to `lib.dom` that Supabase's forward-compatibility interface
    contradicts; 5.9.3 did not declare them, so the conflict could not arise.
  - `@types/chai` 5.2.3 and vitest 3.2.7 both declare `Chai.Assert#containSubset`,
    one as a method and one as a function-typed property. 7.0 rejects that merge
    where 5.x accepted it in this order (microsoft/typescript-go#1192).
  Neither is fixable from this repository, and neither is suppressed by a
  declaration shim: both are still checked, and both are still published in the
  run summary. The latest-compiler job reports them as warnings rather than
  holding itself red indefinitely on another project's release schedule, and goes
  red as soon as Dilion's own sources or the runtime checks break.

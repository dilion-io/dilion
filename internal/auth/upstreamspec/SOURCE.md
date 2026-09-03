# Provenance of `openapi.yaml`

| | |
|---|---|
| Source URL | https://raw.githubusercontent.com/supabase/auth/master/openapi.yaml |
| Upstream commit | [`2d4680ef054bedc898da1dbac1b6a7cb9cf5b5af`](https://github.com/supabase/auth/commit/2d4680ef054bedc898da1dbac1b6a7cb9cf5b5af) — "feat(auditlogs): introduce identity linked action", authored 2026-08-12 |
| Commit lookup | `curl -s 'https://api.github.com/repos/supabase/auth/commits?path=openapi.yaml&per_page=1'` |
| Fetched | 2026-09-03 |
| sha256 | `2e2a74a7459f377dd37e1c0e4c926e39a5be9e6a140fcf6dc1fd0c3ec8a0e621` |
| Size | 136129 bytes, 3929 lines |

The file is vendored **verbatim** — byte-for-byte as served. Do not edit it.
`make upstream-spec-check` diffs it against upstream master and is the signal
to review upstream changes; editing it locally would silence that signal.

## Surface

43 paths, 59 operations, 15 named schemas under `components.schemas`:

```
AccessTokenResponseSchema     ErrorSchema                  PublicKeyCredentialDescriptor
CredentialCreationOptions     GoTrueSecurity               SAMLAttributeMappingSchema
CredentialRequestOptions      IdentitySchema               SSOProviderSchema
CustomOAuthProviderSchema     MFAFactorSchema              TOTPPhoneChallengeResponse
                              OAuthClientSchema            UserSchema
                                                           WebAuthnChallengeResponse
```

For comparison, Dilion implements 69 operations; the passkeys routes have no
entry in this document at all.

## Known spec bugs

Two classes of construct (three occurrences) make the document fail to load in
kin-openapi, and are worked around in-memory by `gen.go` (never by editing this file):

1. `GET /user` 401 and 403 put `$ref: "#/components/responses/UnauthorizedResponse"`
   (a *response* object) where a *schema* object is required.
2. `WebAuthnChallengeResponse.webauthn` carries a `discriminator` on a `oneOf`
   of inline (non-`$ref`) alternatives with no `mapping`.

Further semantic bugs — properties the document declares that upstream's own Go
code never emits, and properties it omits that upstream does emit — are
catalogued as `knownSpecGaps` in `internal/auth/upstream_conformance_test.go`.

## Regenerating

```sh
make upstream-spec-sync    # re-fetch + regenerate + refresh this file's hash by hand
go generate ./internal/auth/upstreamspec/   # regenerate types.gen.go only
```

`go generate` is idempotent: running it twice produces a byte-identical
`types.gen.go`.

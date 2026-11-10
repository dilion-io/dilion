# Provenance of `openapi.yaml`

| | |
|---|---|
| Source URL | https://raw.githubusercontent.com/supabase/auth/master/openapi.yaml |
| Upstream commit | [`bfbe078ce0061e18bb4716beab63316d06efe119`](https://github.com/supabase/auth/commit/bfbe078ce0061e18bb4716beab63316d06efe119) — "feat(saml): add dedicated_scope option for SAML providers (#2893)", authored 2026-11-06 |
| Commit lookup | `curl -s 'https://api.github.com/repos/supabase/auth/commits?path=openapi.yaml&per_page=1'` |
| Fetched | 2026-11-10 |
| sha256 | `7bea0702c9dca759a2dfe693b0253e093478833de4ab0846eaf25a1c5b324db8` |
| Size | 152877 bytes, 4327 lines |

The file is vendored **verbatim** — byte-for-byte as served. Do not edit it.
`make upstream-spec-check` diffs it against upstream master and is the signal
to review upstream changes; editing it locally would silence that signal.

## Surface

46 paths, 64 operations, 17 named schemas under `components.schemas`:

```
AccessTokenResponseSchema     GoTrueSecurity                 PublicKeyCredentialDescriptor
CredentialCreationOptions     IdentitySchema                 SAMLAttributeMappingSchema
CredentialRequestOptions      MFAFactorSchema                SSOProviderSchema
CustomOAuthProviderSchema     MFARecoveryCodesSchema         TOTPPhoneChallengeResponse
ErrorSchema                   MFARecoveryCodesStatusSchema   UserSchema
                              OAuthClientSchema              WebAuthnChallengeResponse
```

For comparison, Dilion implements 80 operations (web/openapi-auth.yaml); the passkeys routes have no
entry in this document at all.

### Synced at bfbe078

What this sync brought in, and where Dilion serves it:

- MFA recovery codes — `/factors/recovery-codes*` and the two
  `MFARecoveryCodes*Schema` bodies: `internal/auth/recovery_codes.go`,
  migration 0122. Both schemas are conformance pairs of
  `RecoveryCodesResponse`.
- SAML `dedicated_scope` — `saml.dedicated_scope` on SSO providers and the
  `/sso/{id}/saml/{metadata,acs}` routes: migration 0123, `saml_sp.go`,
  `saml_acs.go`. The conformance test compares top-level properties only, so
  this nested property is held by `sso_dedicated_scope_db_test.go` instead.
- `DELETE /admin/users/{id}` now documents the `{}` it has always returned.

## Known spec bugs

One construct makes the document fail to load in kin-openapi, and is worked
around in-memory by `gen.go` (never by editing this file):

- `WebAuthnChallengeResponse.webauthn` carries a `discriminator` on a `oneOf`
  of inline (non-`$ref`) alternatives with no `mapping`.

`gen.go` also still carries `fixupResponseRefInSchema` for a second bug: in
`GET /user`, the 401 and 403 responses put
`$ref: "#/components/responses/UnauthorizedResponse"` (a *response* object)
where a *schema* object is required. Upstream fixed it by bfbe078, so that
fixup now matches 0 nodes. It is kept in case the construct comes back.

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

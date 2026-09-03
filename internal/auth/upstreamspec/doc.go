// Package upstreamspec holds Go types generated from the OpenAPI document that
// github.com/supabase/auth (GoTrue) publishes for its own REST API.
//
// # This package is a CONFORMANCE ORACLE. It is never imported by runtime code.
//
// Nothing under internal/auth (or anywhere else in the module) may import it
// outside of _test.go files. The only consumer is
// internal/auth/upstream_conformance_test.go, which reflects over these types
// and asserts that Dilion's hand-written structs are JSON-compatible supersets
// of what upstream documents. If you find yourself wanting to import
// upstreamspec from a handler, stop: the answer is to change the hand-written
// struct in internal/auth and let the conformance test confirm it.
//
// # Why the generated types are not the runtime types
//
// The obvious move — delete our structs and serve these instead — is wrong,
// because upstream's openapi.yaml lags upstream's own Go implementation:
//
//   - UserSchema omits invited_at, which models.User has and returns.
//   - AccessTokenResponseSchema omits provider_token / provider_refresh_token
//     and id_token, all of which tokens.AccessTokenResponse has and returns.
//   - MFAFactorSchema declares webauthn_credential, which models.Factor tags
//     `json:"-"` and therefore never returns; it omits web_authn_aaguid and
//     last_webauthn_challenge_data, which models.Factor does return.
//   - SSOProviderSchema calls the domain list sso_domains; models.SSOProvider
//     serializes it as domains.
//   - OAuthClientSchema declares scope, which OAuthServerClientResponse has no
//     field for.
//   - The passkeys routes are absent entirely: 43 paths / 59 operations / 15
//     named schemas here, against the 69-operation surface Dilion implements.
//
// Dilion's structs were derived from upstream's Go source and are verified
// against a live upstream server by the differential harness in test/parity
// (51/69 operations, 0 FAIL). Swapping in spec-derived types would regress
// behavior that is known-good in favour of a document that is known-stale.
// So: generate the spec types, and use them only to prove that every property
// upstream DOCUMENTS is one we also serve.
//
// # Regenerating
//
// openapi.yaml is vendored verbatim; see SOURCE.md for its provenance and
// gen.go for the load-blocking spec bugs the generator works around.
// `make upstream-spec-sync` re-fetches and regenerates;
// `make upstream-spec-check` reports drift against upstream master.
//
//go:generate go run gen.go
package upstreamspec

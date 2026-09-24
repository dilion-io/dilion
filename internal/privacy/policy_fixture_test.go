package privacy

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// testPolicyYAML stands in for builtin_policies.yaml in tests. The built-in
// file is legal knowledge that changes with the law (see
// .github/workflows/compliance-policy-review.yml), so tests of merge, grace,
// retention and consent logic pin their own values here instead. Every policy
// carries all three sections, so nothing leaks in from the real built-in file.
// The built-in file itself is checked by TestBuiltinPoliciesAreValid.
const testPolicyYAML = `
compliance:
  default-policy: gdpr
  retention-batch-size: 1000
  policies:
    kr:
      erasure:
        grace-period-days: 30
        manual-review: false
        domains:
          audit-log: KEEP
      retention:
        - domain: consent-evidence
          period: P3Y
          from: erasure
          action: CRYPTO_SHRED
          basis: "test basis: kr consent evidence"
        - domain: audit-log
          period: P3Y
          from: created
          action: DELETE
          basis: "test basis: kr audit log"
      consent:
        required-keys: [terms, privacy]
        reconfirm:
          "marketing.*": P2Y

    gdpr:
      erasure:
        grace-period-days: 30
        manual-review: false
        domains: {}
      retention:
        - domain: consent-evidence
          period: P3Y
          from: erasure
          action: CRYPTO_SHRED
          basis: "test basis: gdpr consent evidence"
      consent:
        required-keys: [terms, privacy]
        reconfirm: {}

    hipaa:
      erasure:
        grace-period-days: 0
        manual-review: true
        domains:
          external-system: KEEP
          audit-log: KEEP
          account: KEEP
          oauth-identity: KEEP
      retention:
        - domain: audit-log
          period: P6Y
          from: created
          action: DELETE
          basis: "test basis: hipaa audit log"
        - domain: consent-evidence
          period: P6Y
          from: created
          action: CRYPTO_SHRED
          basis: "test basis: hipaa consent evidence"
      consent:
        required-keys: [terms, privacy]
        reconfirm: {}
`

// testPolicies layers user over testPolicyYAML with the loader's own
// SECTION-REPLACE rules and returns one document for LoadPolicies or
// EngineDeps.PolicyYAML. Because every fixture section is spelled out, that
// document replaces the matching built-in sections entirely.
func testPolicies(t testing.TB, user string) []byte {
	t.Helper()
	var base, over policyFile
	if err := yaml.Unmarshal([]byte(testPolicyYAML), &base); err != nil {
		t.Fatalf("test policy fixture: %v", err)
	}
	if err := yaml.Unmarshal([]byte(user), &over); err != nil {
		t.Fatalf("test policy yaml: %v", err)
	}
	if over.Compliance.DefaultPolicy != "" {
		base.Compliance.DefaultPolicy = over.Compliance.DefaultPolicy
	}
	if over.Compliance.RetentionBatchSize != 0 {
		base.Compliance.RetentionBatchSize = over.Compliance.RetentionBatchSize
	}
	for id, p := range over.Compliance.Policies {
		if b, ok := base.Compliance.Policies[id]; ok {
			p = mergePolicy(b, p)
		}
		base.Compliance.Policies[id] = p
	}
	out, err := yaml.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

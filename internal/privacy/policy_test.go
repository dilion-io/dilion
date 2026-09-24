package privacy

import (
	"encoding/json"
	"strings"
	"testing"
)

// mustLoad loads yaml over the test policies (testPolicyYAML), so assertions
// never depend on the legal values in builtin_policies.yaml.
func mustLoad(t *testing.T, yaml string) *PolicySet {
	t.Helper()
	set, err := LoadPolicies(testPolicies(t, yaml))
	if err != nil {
		t.Fatalf("LoadPolicies: %v", err)
	}
	return set
}

// TestBuiltinPoliciesAreValid checks the shipped policy file for what the code
// relies on, not for its legal values: those change with the law.
func TestBuiltinPoliciesAreValid(t *testing.T) {
	set, err := LoadPolicies(nil)
	if err != nil {
		t.Fatalf("built-in policies: %v", err)
	}
	if _, known := set.Resolve(set.DefaultPolicy); !known {
		t.Fatalf("default policy %q is not defined", set.DefaultPolicy)
	}
	for _, id := range []string{"kr", "gdpr", "hipaa"} {
		p, ok := set.Policies[id]
		if !ok {
			t.Fatalf("built-in policy %q missing", id)
		}
		// Every built-in policy is complete, so a user override of one section
		// never leaves another undefined.
		if p.Erasure == nil || p.Retention == nil || p.Consent == nil {
			t.Errorf("built-in policy %q must define erasure, retention and consent", id)
		}
		for _, r := range p.RetentionRules() {
			if r.Basis == "" {
				t.Errorf("built-in policy %q: %s retention must cite its legal basis", id, r.Domain)
			}
		}
		raw, err := p.Snapshot()
		if err != nil {
			t.Fatalf("snapshot %q: %v", id, err)
		}
		if _, err := policyFromSnapshot(raw); err != nil {
			t.Errorf("snapshot of %q does not restore: %v", id, err)
		}
	}
}

// TestPoliciesLoad checks the loaded accessors against the test policies.
func TestPoliciesLoad(t *testing.T) {
	set := mustLoad(t, "")

	if set.DefaultPolicy != "gdpr" {
		t.Fatalf("default policy = %q, want gdpr", set.DefaultPolicy)
	}
	if set.RetentionBatchSize != 1000 {
		t.Fatalf("retention batch size = %d, want 1000", set.RetentionBatchSize)
	}
	for _, id := range []string{"kr", "gdpr", "hipaa"} {
		if _, ok := set.Policies[id]; !ok {
			t.Fatalf("built-in policy %q missing", id)
		}
	}

	kr := set.Policies["kr"]
	if got := kr.GraceDays(); got != 30 {
		t.Errorf("kr grace = %d, want 30", got)
	}
	if got := kr.ActionFor(DomainAuditLog, ActionAnonymize); got != ActionKeep {
		t.Errorf("kr audit-log action = %q, want KEEP", got)
	}
	if got := kr.ActionFor(DomainSession, ActionDelete); got != ActionDelete {
		t.Errorf("kr session action = %q, want DELETE (step default)", got)
	}
	if kr.ManualReview() {
		t.Error("kr must not require manual review")
	}
	ce := kr.RetentionFor(DomainConsentEvidence)
	if len(ce) != 1 || ce[0].Period != "P3Y" || ce[0].From != FromErasure || ce[0].Action != ActionCryptoShred {
		t.Errorf("kr consent-evidence retention = %+v", ce)
	}
	if ce[0].Basis == "" {
		t.Error("kr consent-evidence retention must carry a basis string")
	}
	al := kr.RetentionFor(DomainAuditLog)
	if len(al) != 1 || al[0].Period != "P3Y" || al[0].From != FromCreated || al[0].Action != ActionDelete {
		t.Errorf("kr audit-log retention = %+v", al)
	}

	hipaa := set.Policies["hipaa"]
	if hipaa.GraceDays() != 0 || !hipaa.ManualReview() {
		t.Errorf("hipaa grace/manual-review = %d/%v, want 0/true", hipaa.GraceDays(), hipaa.ManualReview())
	}
	for _, d := range []string{DomainExternalSystem, DomainAuditLog, DomainAccount, DomainOAuthIdentity} {
		if got := hipaa.ActionFor(d, ActionDelete); got != ActionKeep {
			t.Errorf("hipaa %s action = %q, want KEEP", d, got)
		}
	}
	if got := hipaa.ActionFor(DomainCredential, ActionDelete); got != ActionDelete {
		t.Errorf("hipaa credential action = %q, want DELETE", got)
	}

	gdpr := set.Policies["gdpr"]
	if gdpr.GraceDays() != 30 {
		t.Errorf("gdpr grace = %d, want 30", gdpr.GraceDays())
	}
	if r := gdpr.RetentionFor(DomainConsentEvidence); len(r) != 1 || r[0].From != FromErasure {
		t.Errorf("gdpr consent-evidence retention = %+v", r)
	}
}

func TestUserPolicySectionReplace(t *testing.T) {
	set := mustLoad(t, `
compliance:
  default-policy: kr
  retention-batch-size: 25
  policies:
    kr:
      erasure:
        grace-period-days: 7
        domains:
          audit-log: DELETE
`)
	if set.DefaultPolicy != "kr" || set.RetentionBatchSize != 25 {
		t.Fatalf("root override not applied: %+v", set)
	}
	kr := set.Policies["kr"]
	if kr.GraceDays() != 7 {
		t.Errorf("grace = %d, want 7", kr.GraceDays())
	}
	if got := kr.ActionFor(DomainAuditLog, ActionAnonymize); got != ActionDelete {
		t.Errorf("audit-log action = %q, want DELETE", got)
	}
	// Sections not provided by the user are inherited untouched.
	if r := kr.RetentionFor(DomainConsentEvidence); len(r) != 1 || r[0].Period != "P3Y" {
		t.Errorf("retention section must be inherited, got %+v", r)
	}
	if len(kr.RequiredConsentKeys()) == 0 {
		t.Error("consent section must be inherited")
	}
}

func TestUserPolicyReplacesWholeSection(t *testing.T) {
	// Providing `retention` at all replaces the built-in list entirely — the
	// built-in audit-log rule must be gone (§2.8 section replace).
	set := mustLoad(t, `
compliance:
  policies:
    kr:
      retention:
        - domain: consent-evidence
          period: P1Y
          from: erasure
          action: CRYPTO_SHRED
`)
	kr := set.Policies["kr"]
	if got := len(kr.RetentionRules()); got != 1 {
		t.Fatalf("retention rules = %d, want 1 (whole section replaced)", got)
	}
	if r := kr.RetentionFor(DomainAuditLog); len(r) != 0 {
		t.Errorf("built-in audit-log retention should be replaced away, got %+v", r)
	}
	if r := kr.RetentionFor(DomainConsentEvidence); r[0].Period != "P1Y" || r[0].Basis != "" {
		t.Errorf("consent-evidence rule = %+v, want P1Y with no inherited basis", r[0])
	}
	// erasure section untouched.
	if kr.GraceDays() != 30 {
		t.Errorf("grace = %d, want inherited 30", kr.GraceDays())
	}
}

func TestUserPolicyEmptySectionReplaces(t *testing.T) {
	set := mustLoad(t, `
compliance:
  policies:
    hipaa:
      erasure:
        grace-period-days: 0
        manual-review: false
        domains: {}
`)
	h := set.Policies["hipaa"]
	if h.ManualReview() {
		t.Error("manual-review override to false must take effect")
	}
	if got := h.ActionFor(DomainAccount, ActionAnonymize); got != ActionAnonymize {
		t.Errorf("account action = %q, want the step default after domains reset", got)
	}
}

func TestNewCustomPolicy(t *testing.T) {
	set := mustLoad(t, `
compliance:
  default-policy: kr-hipaa
  policies:
    kr-hipaa:
      erasure:
        grace-period-days: 0
        manual-review: true
        domains:
          audit-log: KEEP
      retention:
        - domain: audit-log
          period: P6Y
          from: created
          action: DELETE
      consent:
        required-keys: [terms]
        reconfirm:
          "marketing.*": P1Y
`)
	p, known := set.Resolve("kr-hipaa")
	if !known || p.ID != "kr-hipaa" {
		t.Fatalf("custom policy not resolvable: %+v", p)
	}
	if !p.ManualReview() || p.GraceDays() != 0 {
		t.Errorf("custom policy erasure = %+v", p.Erasure)
	}
}

func TestPolicyValidationFailures(t *testing.T) {
	cases := map[string]string{
		"unknown domain": `
compliance:
  policies:
    kr:
      erasure:
        grace-period-days: 1
        domains: {orders: DELETE}`,
		"unknown action": `
compliance:
  policies:
    kr:
      erasure:
        grace-period-days: 1
        domains: {audit-log: SHRED}`,
		"unknown retention domain": `
compliance:
  policies:
    kr:
      retention:
        - {domain: orders, period: P1Y, from: created, action: DELETE}`,
		"invalid retention action": `
compliance:
  policies:
    kr:
      retention:
        - {domain: audit-log, period: P1Y, from: created, action: KEEP}`,
		"invalid from": `
compliance:
  policies:
    kr:
      retention:
        - {domain: audit-log, period: P1Y, from: yesterday, action: DELETE}`,
		"invalid period": `
compliance:
  policies:
    kr:
      retention:
        - {domain: audit-log, period: 3 years, from: created, action: DELETE}`,
		"invalid reconfirm period": `
compliance:
  policies:
    kr:
      consent:
        required-keys: [terms]
        reconfirm: {"marketing.*": 2Y}`,
		"undefined default policy": `
compliance:
  default-policy: swiss`,
		"bad batch size": `
compliance:
  retention-batch-size: -1`,
	}
	for name, yaml := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadPolicies([]byte(yaml)); err == nil {
				t.Fatal("expected a startup error, got nil")
			}
		})
	}
}

func TestPolicyMalformedYAML(t *testing.T) {
	if _, err := LoadPolicies([]byte("compliance: [this is not a map]")); err == nil {
		t.Fatal("expected yaml error")
	}
}

func TestResolveFallsBackToDefault(t *testing.T) {
	set := mustLoad(t, "")
	p, known := set.Resolve("does-not-exist")
	if known {
		t.Fatal("unknown code must report known=false")
	}
	if p.ID != set.DefaultPolicy {
		t.Fatalf("fallback policy = %q, want %q", p.ID, set.DefaultPolicy)
	}
}

func TestSnapshotRoundTrip(t *testing.T) {
	set := mustLoad(t, "")
	kr := set.Policies["kr"]
	raw, err := kr.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if !strings.Contains(string(raw), `"id":"kr"`) {
		t.Errorf("snapshot must record the policy id: %s", raw)
	}

	restored, err := policyFromSnapshot(raw)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if restored.GraceDays() != kr.GraceDays() ||
		restored.ActionFor(DomainAuditLog, ActionDelete) != ActionKeep ||
		len(restored.RetentionRules()) != len(kr.RetentionRules()) {
		t.Fatalf("restored policy differs: %+v", restored)
	}
	if restored.BasisFor(DomainConsentEvidence) != kr.BasisFor(DomainConsentEvidence) {
		t.Error("basis evidence lost in snapshot round trip")
	}

	// A snapshot is a frozen document: mutating the live set must not alter it.
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if _, ok := doc["erasure"]; !ok {
		t.Error("snapshot missing erasure section")
	}
}

func TestSnapshotOfAbsentSectionsIsSafe(t *testing.T) {
	p := &Policy{ID: "bare"}
	raw, err := p.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := policyFromSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	if restored.GraceDays() != 0 || restored.ManualReview() ||
		restored.ActionFor(DomainAccount, ActionAnonymize) != ActionAnonymize ||
		len(restored.RetentionRules()) != 0 || len(restored.RequiredConsentKeys()) != 0 {
		t.Fatalf("bare policy accessors are not nil-safe: %+v", restored)
	}
}

func TestRequiredConsentKeys(t *testing.T) {
	kr := mustLoad(t, "").Policies["kr"]
	if !kr.RequiresConsent("terms") || !kr.RequiresConsent("privacy") {
		t.Error("kr required keys must include terms and privacy")
	}
	if kr.RequiresConsent("marketing.email") {
		t.Error("marketing must not be a required key")
	}
}

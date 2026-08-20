package privacy

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed builtin_policies.yaml
var builtinPolicyYAML []byte

// ---- Domains / actions (project.md §2.9 step table) -------------------------

// Erasure domains, in pipeline order. The order values match §2.9.
const (
	DomainCredential      = "credential"
	DomainRefreshToken    = "refresh-token"
	DomainSession         = "session"
	DomainMFAFactor       = "mfa-factor"
	DomainPasskey         = "passkey"
	DomainOAuthIdentity   = "oauth-identity"
	DomainExternalSystem  = "external-system"
	DomainAuditLog        = "audit-log"
	DomainSubjectKey      = "subject-key"
	DomainAccount         = "account"
	DomainConsentEvidence = "consent-evidence" // retention-only domain (no erasure step)
)

// actionExecute is the external-system fan-out action. It is not part of the
// ErasureAction enum in service.go (which describes data-at-rest outcomes) but
// is a legal value for the `external-system` domain in policy data.
const actionExecute ErasureAction = "EXECUTE"

var erasureDomains = []string{
	DomainCredential, DomainRefreshToken, DomainSession, DomainMFAFactor,
	DomainPasskey, DomainOAuthIdentity, DomainExternalSystem, DomainAuditLog,
	DomainSubjectKey, DomainAccount,
}

func isErasureDomain(d string) bool {
	for _, x := range erasureDomains {
		if x == d {
			return true
		}
	}
	return false
}

func isRetentionDomain(d string) bool { return d == DomainConsentEvidence || isErasureDomain(d) }

func isErasureAction(a ErasureAction) bool {
	switch a {
	case ActionDelete, ActionAnonymize, ActionCryptoShred, ActionKeep, actionExecute:
		return true
	}
	return false
}

// §2.8: retention action is DELETE (row) or CRYPTO_SHRED (scope DEK).
func isRetentionAction(a ErasureAction) bool {
	return a == ActionDelete || a == ActionCryptoShred
}

// RetentionFrom is the clock the retention period is measured from.
const (
	FromCreated = "created"
	FromErasure = "erasure"
)

// ---- Policy model ----------------------------------------------------------

// ErasureSection overrides pipeline behaviour for a policy.
type ErasureSection struct {
	GracePeriodDays int                      `yaml:"grace-period-days" json:"grace_period_days"`
	ManualReview    bool                     `yaml:"manual-review"     json:"manual_review"`
	Domains         map[string]ErasureAction `yaml:"domains"           json:"domains,omitempty"`
}

// RetentionRule is one row of the policy's retention table.
type RetentionRule struct {
	Domain string        `yaml:"domain" json:"domain"`
	Period string        `yaml:"period" json:"period"` // ISO-8601 duration
	From   string        `yaml:"from"   json:"from"`   // created | erasure
	Action ErasureAction `yaml:"action" json:"action"`
	Basis  string        `yaml:"basis"  json:"basis,omitempty"` // evidence string, never used in logic
}

// ConsentSection carries the consent knowledge of a policy.
type ConsentSection struct {
	RequiredKeys []string          `yaml:"required-keys" json:"required_keys,omitempty"`
	Reconfirm    map[string]string `yaml:"reconfirm"     json:"reconfirm,omitempty"` // glob pattern -> ISO-8601
}

// Policy is one compliance code (kr, gdpr, hipaa, custom...). Sections are
// pointers so "absent" (inherit built-in) is distinguishable from "provided
// but empty" (replace built-in with nothing) — see SECTION-REPLACE in §2.8.
type Policy struct {
	ID        string           `yaml:"-"         json:"id"`
	Erasure   *ErasureSection  `yaml:"erasure"   json:"erasure,omitempty"`
	Retention *[]RetentionRule `yaml:"retention" json:"retention,omitempty"`
	Consent   *ConsentSection  `yaml:"consent"   json:"consent,omitempty"`
}

// PolicySet is the loaded, validated and merged policy data.
type PolicySet struct {
	DefaultPolicy      string
	RetentionBatchSize int
	Policies           map[string]*Policy
}

type policyFile struct {
	Compliance struct {
		DefaultPolicy      string            `yaml:"default-policy"`
		RetentionBatchSize int               `yaml:"retention-batch-size"`
		Policies           map[string]Policy `yaml:"policies"`
	} `yaml:"compliance"`
}

// LoadPolicies parses the built-in policies, merges userYAML over them and
// validates the result. Unknown domains/actions are a startup error (§2.8:
// "런타임에 조용히 무시 금지").
func LoadPolicies(userYAML []byte) (*PolicySet, error) {
	var builtin policyFile
	if err := yaml.Unmarshal(builtinPolicyYAML, &builtin); err != nil {
		return nil, fmt.Errorf("privacy: built-in policies are corrupt: %w", err)
	}

	set := &PolicySet{
		DefaultPolicy:      builtin.Compliance.DefaultPolicy,
		RetentionBatchSize: builtin.Compliance.RetentionBatchSize,
		Policies:           map[string]*Policy{},
	}
	for id, p := range builtin.Compliance.Policies {
		p.ID = id
		cp := p
		set.Policies[id] = &cp
	}

	if len(strings.TrimSpace(string(userYAML))) > 0 {
		var user policyFile
		if err := yaml.Unmarshal(userYAML, &user); err != nil {
			return nil, fmt.Errorf("privacy: policy yaml: %w", err)
		}
		if user.Compliance.DefaultPolicy != "" {
			set.DefaultPolicy = user.Compliance.DefaultPolicy
		}
		if user.Compliance.RetentionBatchSize != 0 {
			set.RetentionBatchSize = user.Compliance.RetentionBatchSize
		}
		for id, over := range user.Compliance.Policies {
			over.ID = id
			base, ok := set.Policies[id]
			if !ok {
				cp := over
				set.Policies[id] = &cp
				continue
			}
			merged := mergePolicy(*base, over)
			set.Policies[id] = &merged
		}
	}

	if err := set.validate(); err != nil {
		return nil, err
	}
	return set, nil
}

// mergePolicy applies SECTION-REPLACE semantics: any section present in `over`
// replaces the whole corresponding section of `base`.
func mergePolicy(base, over Policy) Policy {
	out := base
	out.ID = base.ID
	if over.Erasure != nil {
		out.Erasure = over.Erasure
	}
	if over.Retention != nil {
		out.Retention = over.Retention
	}
	if over.Consent != nil {
		out.Consent = over.Consent
	}
	return out
}

func (s *PolicySet) validate() error {
	if s.RetentionBatchSize <= 0 {
		return fmt.Errorf("privacy: compliance.retention-batch-size must be > 0")
	}
	if s.DefaultPolicy == "" {
		return fmt.Errorf("privacy: compliance.default-policy is required")
	}
	if _, ok := s.Policies[s.DefaultPolicy]; !ok {
		return fmt.Errorf("privacy: compliance.default-policy %q is not defined", s.DefaultPolicy)
	}
	ids := make([]string, 0, len(s.Policies))
	for id := range s.Policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := s.Policies[id].validate(); err != nil {
			return err
		}
	}
	return nil
}

func (p *Policy) validate() error {
	if p.Erasure != nil {
		if p.Erasure.GracePeriodDays < 0 {
			return fmt.Errorf("privacy: policy %q: grace-period-days must be >= 0", p.ID)
		}
		domains := make([]string, 0, len(p.Erasure.Domains))
		for d := range p.Erasure.Domains {
			domains = append(domains, d)
		}
		sort.Strings(domains)
		for _, d := range domains {
			if !isErasureDomain(d) {
				return fmt.Errorf("privacy: policy %q: unknown erasure domain %q", p.ID, d)
			}
			a := p.Erasure.Domains[d]
			if !isErasureAction(a) {
				return fmt.Errorf("privacy: policy %q: unknown action %q for domain %q", p.ID, a, d)
			}
		}
	}
	if p.Retention != nil {
		for i, r := range *p.Retention {
			if !isRetentionDomain(r.Domain) {
				return fmt.Errorf("privacy: policy %q: retention[%d]: unknown domain %q", p.ID, i, r.Domain)
			}
			if !isRetentionAction(r.Action) {
				return fmt.Errorf("privacy: policy %q: retention[%d]: unknown action %q", p.ID, i, r.Action)
			}
			if r.From != FromCreated && r.From != FromErasure {
				return fmt.Errorf("privacy: policy %q: retention[%d]: `from` must be %q or %q, got %q",
					p.ID, i, FromCreated, FromErasure, r.From)
			}
			if _, err := ParseISODuration(r.Period); err != nil {
				return fmt.Errorf("privacy: policy %q: retention[%d]: %w", p.ID, i, err)
			}
		}
	}
	if p.Consent != nil {
		pats := make([]string, 0, len(p.Consent.Reconfirm))
		for pat := range p.Consent.Reconfirm {
			pats = append(pats, pat)
		}
		sort.Strings(pats)
		for _, pat := range pats {
			if _, err := path.Match(pat, ""); err != nil {
				return fmt.Errorf("privacy: policy %q: consent.reconfirm: bad pattern %q: %w", p.ID, pat, err)
			}
			if _, err := ParseISODuration(p.Consent.Reconfirm[pat]); err != nil {
				return fmt.Errorf("privacy: policy %q: consent.reconfirm[%q]: %w", p.ID, pat, err)
			}
		}
	}
	return nil
}

// Resolve returns the policy for a compliance code, falling back to the
// configured default policy when the code is empty or unknown.
func (s *PolicySet) Resolve(policyID string) (*Policy, bool) {
	if p, ok := s.Policies[policyID]; ok {
		return p, true
	}
	return s.Policies[s.DefaultPolicy], false
}

// ---- Policy accessors (nil-safe: an absent section means "no knowledge") ----

func (p *Policy) GraceDays() int {
	if p == nil || p.Erasure == nil {
		return 0
	}
	return p.Erasure.GracePeriodDays
}

func (p *Policy) ManualReview() bool {
	return p != nil && p.Erasure != nil && p.Erasure.ManualReview
}

// ActionFor returns the effective action for an erasure domain: the policy
// override if present, otherwise the step's default action.
func (p *Policy) ActionFor(domain string, def ErasureAction) ErasureAction {
	if p == nil || p.Erasure == nil {
		return def
	}
	if a, ok := p.Erasure.Domains[domain]; ok && a != "" {
		return a
	}
	return def
}

// RetentionFor returns the retention rules that apply to a domain.
func (p *Policy) RetentionFor(domain string) []RetentionRule {
	if p == nil || p.Retention == nil {
		return nil
	}
	var out []RetentionRule
	for _, r := range *p.Retention {
		if r.Domain == domain {
			out = append(out, r)
		}
	}
	return out
}

// RetentionRules returns every retention rule of the policy.
func (p *Policy) RetentionRules() []RetentionRule {
	if p == nil || p.Retention == nil {
		return nil
	}
	return *p.Retention
}

// BasisFor returns the evidence string recorded in destruction_logs for a
// domain (retention basis of the same domain, if the policy declares one).
func (p *Policy) BasisFor(domain string) string {
	for _, r := range p.RetentionFor(domain) {
		if r.Basis != "" {
			return r.Basis
		}
	}
	return ""
}

func (p *Policy) RequiredConsentKeys() []string {
	if p == nil || p.Consent == nil {
		return nil
	}
	return p.Consent.RequiredKeys
}

func (p *Policy) RequiresConsent(purpose string) bool {
	for _, k := range p.RequiredConsentKeys() {
		if k == purpose {
			return true
		}
	}
	return false
}

// ReconfirmFor returns the reconfirmation period for a purpose. Patterns are
// globs ("marketing.*"); the most specific (longest) matching pattern wins.
func (p *Policy) ReconfirmFor(purpose string) (Duration, bool) {
	if p == nil || p.Consent == nil || len(p.Consent.Reconfirm) == 0 {
		return Duration{}, false
	}
	best, bestLen := "", -1
	for pat := range p.Consent.Reconfirm {
		if matchPurpose(pat, purpose) && len(pat) > bestLen {
			best, bestLen = pat, len(pat)
		}
	}
	if bestLen < 0 {
		return Duration{}, false
	}
	d, err := ParseISODuration(p.Consent.Reconfirm[best])
	if err != nil { // unreachable: validated at load
		return Duration{}, false
	}
	return d, true
}

// matchPurpose does glob matching on consent purposes ("marketing.*").
func matchPurpose(pattern, purpose string) bool {
	if pattern == purpose {
		return true
	}
	ok, err := path.Match(pattern, purpose)
	return err == nil && ok
}

// Snapshot serialises the resolved policy for personal_data_requests.policy_snapshot.
func (p *Policy) Snapshot() ([]byte, error) {
	if p == nil {
		return []byte(`{}`), nil
	}
	return json.Marshal(p)
}

// policyFromSnapshot restores a snapshotted policy. In-flight pipelines always
// run against the snapshot, never against the current policy file (§2.8).
func policyFromSnapshot(raw []byte) (*Policy, error) {
	var p Policy
	if len(raw) == 0 {
		return &p, nil
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("privacy: policy snapshot: %w", err)
	}
	return &p, nil
}

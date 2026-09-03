//go:build parity

package parity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SummaryInput is everything the markdown run-summary renders. It is the same
// data the harness already prints with t.Logf — the markdown file is an
// ADDITIONAL sink (for CI's $GITHUB_STEP_SUMMARY), never a replacement.
type SummaryInput struct {
	Coverage CoverageReport
	Known    int    // deviations.yaml 로 허용된 차이 수
	Fail     int    // 허용되지 않은 차이 수
	Profile  string // "flagged (PARITY_FLAGS=1)" / "default (flags off)"
	Failed   bool   // t.Failed() — 스위트 전체의 성패
}

// maxUncoveredList caps the collapsible list so a pathological run cannot blow
// GitHub's 1 MiB step-summary budget.
const maxUncoveredList = 120

// WriteMarkdownSummary renders the parity result as GitHub-flavoured markdown at
// path (creating parent directories). It is written from a defer in TestParity,
// so it must be robust to being called on a half-finished run: every field is
// optional and a zero CoverageReport still produces a sensible document.
func WriteMarkdownSummary(path string, in SummaryInput) error {
	if path == "" {
		return nil
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir for parity summary: %w", err)
		}
	}
	if err := os.WriteFile(path, []byte(renderSummary(in)), 0o644); err != nil {
		return fmt.Errorf("write parity summary: %w", err)
	}
	return nil
}

func renderSummary(in SummaryInput) string {
	covered, total := len(in.Coverage.Covered), in.Coverage.Total
	pct := 0.0
	if total > 0 {
		pct = 100 * float64(covered) / float64(total)
	}

	var b strings.Builder
	b.WriteString("## Parity vs upstream supabase/auth\n\n")

	if in.Failed {
		fmt.Fprintf(&b, "**❌ FAIL** — %d unexpected diff(s) against upstream.\n\n", in.Fail)
	} else {
		b.WriteString("**✅ PASS** — no unexpected diffs against upstream.\n\n")
	}

	b.WriteString("| Metric | Value |\n| --- | --- |\n")
	fmt.Fprintf(&b, "| Operations covered | **%d / %d** (%.1f%%) |\n", covered, total, pct)
	fmt.Fprintf(&b, "| KNOWN deviations tolerated | %d |\n", in.Known)
	fmt.Fprintf(&b, "| Unexpected FAIL diffs | %d |\n", in.Fail)
	if in.Profile != "" {
		fmt.Fprintf(&b, "| Profile | %s |\n", in.Profile)
	}
	b.WriteString("\n")

	if n := len(in.Coverage.Uncovered); n > 0 {
		fmt.Fprintf(&b, "<details>\n<summary>%d uncovered operationId(s)</summary>\n\n", n)
		shown := in.Coverage.Uncovered
		if len(shown) > maxUncoveredList {
			shown = shown[:maxUncoveredList]
		}
		for _, id := range shown {
			fmt.Fprintf(&b, "- `%s`\n", id)
		}
		if len(shown) < n {
			fmt.Fprintf(&b, "- … %d more (see the step log)\n", n-len(shown))
		}
		b.WriteString("\nEach uncovered op needs a capability the harness deliberately does not fake ")
		b.WriteString("(software WebAuthn authenticator, external IdP stub, signed SAML assertion, …) — ")
		b.WriteString("see the `TODOScaffold` doc comment in `test/parity/harness_test.go`.\n")
		b.WriteString("\n</details>\n")
	}

	return b.String()
}

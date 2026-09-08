//go:build parity

package parity

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// SummaryInput is everything the markdown run-summary renders. It is the same
// data the harness already prints with t.Logf — the markdown file is an
// ADDITIONAL sink (for CI's $GITHUB_STEP_SUMMARY), never a replacement.
type SummaryInput struct {
	Coverage   CoverageReport
	Operations map[string]OperationResult
	Known      int    // deviations.yaml 로 허용된 차이 수
	Fail       int    // 허용되지 않은 차이 수
	Profile    string // "flagged (PARITY_FLAGS=1)" / "default (flags off)"
	Failed     bool   // t.Failed() — 스위트 전체의 성패
}

// OperationResult is accumulated directly while a scenario/flow runs. Summary
// status is therefore evidence-based rather than a hand-maintained capability
// claim in documentation.
type OperationResult struct {
	Exercised       bool
	Compared        bool
	Positive        bool // A 2xx response path was compared on both servers.
	Incomplete      bool // At least one attempted scenario did not finish.
	AssertionFailed bool // Includes status/capture failures outside the diff engine.
	Known           int
	Fail            int
	Unimplemented   bool // Dilion returned HTTP 501 during an exercised operation.
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
		fmt.Fprintf(&b, "**❌ FAIL** — %d unexpected diff(s); see the test log for assertion or setup failures.\n\n", in.Fail)
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

	b.WriteString("### 기능 지원표\n\n")
	b.WriteString("| operationId | 상태 | 실행 근거 |\n| --- | --- | --- |\n")
	all := append(append([]string(nil), in.Coverage.Covered...), in.Coverage.Uncovered...)
	slices.Sort(all)
	for _, id := range all {
		result := in.Operations[id]
		status, evidence := operationStatus(result)
		fmt.Fprintf(&b, "| `%s` | %s | %s |\n", id, status, evidence)
	}
	b.WriteString("\n")
	b.WriteString("> 이 실행의 테스트 범위에 한정한 결과이며 전체 기능 지원 보증이 아닙니다. 구현됨=성공 경로 비교 완료 및 차이 없음, ")
	b.WriteString("부분 호환=KNOWN/FAIL 또는 검증 실패, 미구현=테스트 경로에서 Dilion이 501 응답, 미검증=비교 미완료 또는 오류 경로만 검증.\n\n")

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

func operationStatus(r OperationResult) (status, evidence string) {
	switch {
	case r.Unimplemented:
		return "미구현", "Dilion HTTP 501"
	case r.Incomplete:
		return "미검증", "테스트 중단 · 비교 미완료"
	case !r.Exercised || !r.Compared:
		return "미검증", "parity 비교 미실행"
	case r.Known > 0 || r.Fail > 0:
		return "부분 호환", fmt.Sprintf("KNOWN %d · FAIL %d", r.Known, r.Fail)
	case r.AssertionFailed:
		return "부분 호환", "응답 상태 또는 시나리오 검증 실패"
	case !r.Positive:
		return "미검증", "오류/리디렉션 경로만 비교 · 성공 경로 미검증"
	default:
		return "구현됨", "비교 실행 · diff 0"
	}
}

// Start before HTTP execution and finish in a defer, so Fatal/Skip cannot leave
// a prior successful scenario falsely representing an interrupted operation.
func trackOperation(results map[string]OperationResult, op string) func(bool, bool, bool, bool) {
	if op != "" {
		r := results[op]
		r.Exercised = true
		results[op] = r
	}
	return func(completed, compared, positive, failed bool) {
		if op == "" {
			return
		}
		r := results[op]
		r.Incomplete = r.Incomplete || !completed
		r.Compared = r.Compared || compared
		r.Positive = r.Positive || (compared && positive)
		r.AssertionFailed = r.AssertionFailed || failed
		results[op] = r
	}
}

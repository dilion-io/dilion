//go:build parity

package parity

import (
	"strings"
	"testing"
)

func TestRenderSummaryBuildsCapabilityTableFromRunResults(t *testing.T) {
	got := renderSummary(SummaryInput{
		Coverage: CoverageReport{
			Total:     4,
			Covered:   []string{"implemented", "partial", "unimplemented"},
			Uncovered: []string{"unverified"},
		},
		Operations: map[string]OperationResult{
			"implemented":   {Exercised: true, Compared: true, Positive: true},
			"partial":       {Exercised: true, Compared: true, Known: 2},
			"unimplemented": {Exercised: true, Compared: true, Unimplemented: true},
		},
	})
	for _, row := range []string{
		"| `implemented` | 구현됨 | 비교 실행 · diff 0 |",
		"| `partial` | 부분 호환 | KNOWN 2 · FAIL 0 |",
		"| `unimplemented` | 미구현 | Dilion HTTP 501 |",
		"| `unverified` | 미검증 | parity 비교 미실행 |",
	} {
		if !strings.Contains(got, row) {
			t.Errorf("summary missing row %q:\n%s", row, got)
		}
	}
}

func TestOperationStatusRequiresCompletedPositiveEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result OperationResult
		want   string
	}{
		{"transport interrupted", OperationResult{Exercised: true, Incomplete: true}, "미검증"},
		{"earlier success cannot hide interruption", OperationResult{Exercised: true, Compared: true, Positive: true, Incomplete: true}, "미검증"},
		{"error only", OperationResult{Exercised: true, Compared: true}, "미검증"},
		{"expected status failed", OperationResult{Exercised: true, Compared: true, Positive: true, AssertionFailed: true}, "부분 호환"},
		{"unexpected diff", OperationResult{Exercised: true, Compared: true, Fail: 1}, "부분 호환"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := operationStatus(tc.result)
			if got != tc.want {
				t.Fatalf("status = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestOperationTrackingAccumulatesFailures(t *testing.T) {
	results := map[string]OperationResult{}
	trackOperation(results, "op")(true, true, true, false)
	trackOperation(results, "op")(false, false, false, true)
	r := results["op"]
	if !r.Positive || !r.Compared || !r.Incomplete || !r.AssertionFailed {
		t.Fatalf("lost evidence: %+v", r)
	}
}

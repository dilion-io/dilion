package privacy

import (
	"testing"
	"time"
)

func TestMatchPurposeGlob(t *testing.T) {
	cases := []struct {
		pattern, purpose string
		want             bool
	}{
		{"marketing.*", "marketing.email", true},
		{"marketing.*", "marketing.push.daily", true},
		{"marketing.*", "marketing", false},
		{"marketing.*", "transactional.email", false},
		{"marketing", "marketing", true},
		{"*", "anything", true},
		{"terms", "privacy", false},
		{"analytics.?", "analytics.a", true},
		{"analytics.?", "analytics.ab", false},
	}
	for _, c := range cases {
		if got := matchPurpose(c.pattern, c.purpose); got != c.want {
			t.Errorf("matchPurpose(%q, %q) = %v, want %v", c.pattern, c.purpose, got, c.want)
		}
	}
}

func TestReconfirmForLongestPatternWins(t *testing.T) {
	set := mustLoad(t, `
compliance:
  policies:
    kr:
      consent:
        required-keys: [terms]
        reconfirm:
          "marketing.*": P2Y
          "marketing.push": P1Y
`)
	kr := set.Policies["kr"]

	d, ok := kr.ReconfirmFor("marketing.email")
	if !ok || d.Years != 2 {
		t.Errorf("marketing.email -> %+v (ok=%v), want P2Y", d, ok)
	}
	d, ok = kr.ReconfirmFor("marketing.push")
	if !ok || d.Years != 1 {
		t.Errorf("marketing.push -> %+v (ok=%v), want the more specific P1Y", d, ok)
	}
	if _, ok := kr.ReconfirmFor("terms"); ok {
		t.Error("terms must have no reconfirm period")
	}
}

func TestReconfirmDue(t *testing.T) {
	kr := mustLoad(t, "").Policies["kr"] // marketing.* : P2Y
	granted := time.Date(2024, 1, 10, 0, 0, 0, 0, time.UTC)

	due, ok := reconfirmDue(kr, "marketing.email", true, granted, nil)
	if !ok {
		t.Fatal("expected a due date for marketing.email")
	}
	if want := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC); !due.Equal(want) {
		t.Errorf("due = %s, want %s", due, want)
	}

	// A notice resets the clock.
	notice := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	due, _ = reconfirmDue(kr, "marketing.email", true, granted, &notice)
	if want := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC); !due.Equal(want) {
		t.Errorf("due after notice = %s, want %s", due, want)
	}

	// Withdrawn consent is never reconfirmed, and unmatched purposes have no due date.
	if _, ok := reconfirmDue(kr, "marketing.email", false, granted, nil); ok {
		t.Error("withdrawn purpose must not have a reconfirm due date")
	}
	if _, ok := reconfirmDue(kr, "terms", true, granted, nil); ok {
		t.Error("purpose without a reconfirm pattern must not have a due date")
	}
	if _, ok := reconfirmDue(&Policy{ID: "bare"}, "marketing.email", true, granted, nil); ok {
		t.Error("policy without a consent section must not produce a due date")
	}
}

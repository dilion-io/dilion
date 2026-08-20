package privacy

import (
	"testing"
	"time"
)

func TestParseISODuration(t *testing.T) {
	ok := map[string]Duration{
		"P3Y":      {Years: 3},
		"P6M":      {Months: 6},
		"P30D":     {Days: 30},
		"P2W":      {Days: 14},
		"P1Y6M15D": {Years: 1, Months: 6, Days: 15},
		"PT12H":    {Hours: 12},
		"PT1M30S":  {Mins: 1, Secs: 30},
		"P1DT2H3M": {Days: 1, Hours: 2, Mins: 3},
	}
	for in, want := range ok {
		got, err := ParseISODuration(in)
		if err != nil {
			t.Errorf("%s: unexpected error %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%s: got %+v, want %+v", in, got, want)
		}
	}

	// Surrounding whitespace is tolerated (YAML scalars); everything else is not.
	if d, err := ParseISODuration("  P1Y "); err != nil || d.Years != 1 {
		t.Errorf("padded duration: %+v, %v", d, err)
	}
	bad := []string{"", "3Y", "P", "PT", "P3", "P1.5Y", "P-1Y", "3 years", "P 1Y", "PY", "p3y"}
	for _, in := range bad {
		if d, err := ParseISODuration(in); err == nil {
			t.Errorf("%q: expected error, got %+v", in, d)
		}
	}
}

func TestDurationCalendarArithmetic(t *testing.T) {
	base := time.Date(2024, 2, 29, 12, 0, 0, 0, time.UTC) // leap day
	d, err := ParseISODuration("P1Y")
	if err != nil {
		t.Fatal(err)
	}
	got := d.AddTo(base)
	want := time.Date(2025, 3, 1, 12, 0, 0, 0, time.UTC) // Go normalises Feb 29 -> Mar 1
	if !got.Equal(want) {
		t.Errorf("P1Y from leap day = %s, want %s", got, want)
	}

	// P3Y is three calendar years, not 3*365 days.
	d3, _ := ParseISODuration("P3Y")
	from := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	if got := d3.AddTo(from); got.Year() != 2029 || got.Month() != 8 || got.Day() != 12 {
		t.Errorf("P3Y from %s = %s", from, got)
	}
	if got := d3.SubFrom(from); got.Year() != 2023 || got.Month() != 8 || got.Day() != 12 {
		t.Errorf("SubFrom P3Y = %s", got)
	}
}

func TestDurationString(t *testing.T) {
	for _, in := range []string{"P3Y", "P30D", "PT12H", "P1Y6M15D"} {
		d, err := ParseISODuration(in)
		if err != nil {
			t.Fatal(err)
		}
		if got := d.String(); got != in {
			t.Errorf("round trip %s -> %s", in, got)
		}
	}
}

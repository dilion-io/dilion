package privacy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Duration is an ISO-8601 duration (P3Y, P30D, PT12H...). Calendar components
// are kept separate from clock components so that "P3Y" means three calendar
// years rather than 3*365 days (§2.8 retention periods are legal periods).
type Duration struct {
	Years  int
	Months int
	Days   int
	Hours  int
	Mins   int
	Secs   int
}

var isoDurationRe = regexp.MustCompile(
	`^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$`)

// ParseISODuration parses an ISO-8601 duration. Fractional and negative values
// are rejected: retention periods must be unambiguous.
func ParseISODuration(s string) (Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Duration{}, fmt.Errorf("empty duration")
	}
	m := isoDurationRe.FindStringSubmatch(s)
	if m == nil {
		return Duration{}, fmt.Errorf("invalid ISO-8601 duration %q", s)
	}
	atoi := func(v string) int {
		if v == "" {
			return 0
		}
		n, _ := strconv.Atoi(v)
		return n
	}
	d := Duration{
		Years:  atoi(m[1]),
		Months: atoi(m[2]),
		Days:   atoi(m[3])*7 + atoi(m[4]),
		Hours:  atoi(m[5]),
		Mins:   atoi(m[6]),
		Secs:   atoi(m[7]),
	}
	if d.IsZero() {
		return Duration{}, fmt.Errorf("invalid ISO-8601 duration %q: no components", s)
	}
	return d, nil
}

func (d Duration) IsZero() bool { return d == Duration{} }

// AddTo applies the duration to t using calendar arithmetic.
func (d Duration) AddTo(t time.Time) time.Time {
	return t.AddDate(d.Years, d.Months, d.Days).
		Add(time.Duration(d.Hours)*time.Hour +
			time.Duration(d.Mins)*time.Minute +
			time.Duration(d.Secs)*time.Second)
}

// SubFrom subtracts the duration from t (used to compute expiry cut-offs).
func (d Duration) SubFrom(t time.Time) time.Time {
	return t.AddDate(-d.Years, -d.Months, -d.Days).
		Add(-(time.Duration(d.Hours)*time.Hour +
			time.Duration(d.Mins)*time.Minute +
			time.Duration(d.Secs)*time.Second))
}

func (d Duration) String() string {
	var b strings.Builder
	b.WriteByte('P')
	if d.Years > 0 {
		fmt.Fprintf(&b, "%dY", d.Years)
	}
	if d.Months > 0 {
		fmt.Fprintf(&b, "%dM", d.Months)
	}
	if d.Days > 0 {
		fmt.Fprintf(&b, "%dD", d.Days)
	}
	if d.Hours > 0 || d.Mins > 0 || d.Secs > 0 {
		b.WriteByte('T')
		if d.Hours > 0 {
			fmt.Fprintf(&b, "%dH", d.Hours)
		}
		if d.Mins > 0 {
			fmt.Fprintf(&b, "%dM", d.Mins)
		}
		if d.Secs > 0 {
			fmt.Fprintf(&b, "%dS", d.Secs)
		}
	}
	if b.Len() == 1 {
		return "P0D"
	}
	return b.String()
}

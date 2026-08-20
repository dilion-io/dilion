//go:build parity

package parity

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Deviation is one entry of deviations.yaml — an intentional, documented
// difference the differ downgrades from FAIL to KNOWN.
type Deviation struct {
	ID       string `yaml:"id"`
	Op       string `yaml:"op"`
	Endpoint string `yaml:"endpoint"`
	Aspect   string `yaml:"aspect"`
	Field    string `yaml:"field"`
	Dilion   string `yaml:"dilion"`
	Upstream string `yaml:"upstream"`
	Reason   string `yaml:"reason"`
	Source   string `yaml:"source"`
}

type deviationFile struct {
	Deviations []Deviation `yaml:"deviations"`
}

// LoadDeviations reads and parses the allow-list.
func LoadDeviations(path string) ([]Deviation, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read deviations: %w", err)
	}
	var f deviationFile
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parse deviations: %w", err)
	}
	return f.Deviations, nil
}

// aspectMatches maps a Diff.Kind to the deviation `aspect` vocabulary. A single
// Diff.Kind can satisfy several aspects (a body-field diff also covers an
// error-shape deviation on an error response).
func aspectMatches(diffKind, aspect string) bool {
	switch aspect {
	case "status":
		return diffKind == "status"
	case "header":
		return diffKind == "header"
	case "redirect":
		return diffKind == "redirect"
	case "jwt-claim":
		return diffKind == "jwt-claim"
	case "body-field":
		return diffKind == "body"
	case "error-shape":
		// an error-shape deviation forgives body/status differences on the route
		return diffKind == "body" || diffKind == "status"
	}
	return false
}

// Match reports the first deviation that excuses diff for operation op, or nil.
//
// A deviation matches when ALL hold:
//   - op matches exactly, or the deviation op is "*";
//   - the aspect is compatible with the diff kind;
//   - the field matches. To keep the allow-list from over-forgiving, a BODY
//     diff (which always has a specific dotted path) requires the deviation to
//     name a non-empty field whose last segment is a substring of that path — a
//     blanket empty-field entry can NEVER silently excuse an arbitrary body
//     field. An empty field is only honoured for whole-response aspects
//     (status/header/redirect/jwt-claim, or a diff whose path is empty).
func Match(devs []Deviation, op string, diff Diff) *Deviation {
	for i := range devs {
		d := &devs[i]
		if d.Op != "*" && d.Op != op {
			continue
		}
		if !aspectMatches(diff.Kind, d.Aspect) {
			continue
		}
		if d.Field == "" {
			// Empty field: only whole-response / non-body diffs may be excused.
			if diff.Kind == "body" && diff.Path != "" {
				continue
			}
			return d
		}
		if !strings.Contains(strings.ToLower(diff.Path), strings.ToLower(lastSegment(d.Field))) {
			continue
		}
		return d
	}
	return nil
}

// lastSegment lets a deviation field like "Location.path" or
// "user.app_metadata.provider" match the differ's dotted path robustly.
func lastSegment(field string) string {
	field = strings.TrimSpace(field)
	if i := strings.LastIndex(field, "."); i >= 0 && i < len(field)-1 {
		return field[i+1:]
	}
	return field
}

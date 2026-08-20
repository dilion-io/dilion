//go:build parity

package parity

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Operation is one curated-contract operation from web/openapi-auth.yaml.
type Operation struct {
	ID     string
	Method string // upper-case HTTP method
	Path   string // with the /auth/v1 prefix stripped, e.g. "/token"
}

// Contract is the parsed set of the 69 operations the harness measures coverage
// against.
type Contract struct {
	Ops []Operation
	// byRoute resolves "METHOD /normalised/path" to an operationId.
	byRoute map[string]string
}

// openapiDoc is the sliver of the OpenAPI document we need. Path-item values are
// decoded loosely: a path item mixes HTTP-method operation objects with
// non-method keys (a shared `parameters` sequence, `$ref`, `summary`), so each
// value is an untyped node we inspect selectively.
type openapiDoc struct {
	Paths map[string]map[string]any `yaml:"paths"`
}

// httpMethods is the set of path-item keys that denote an operation.
var httpMethods = map[string]bool{
	"get": true, "put": true, "post": true, "delete": true,
	"patch": true, "head": true, "options": true, "trace": true,
}

// LoadContract parses the curated auth OpenAPI file and indexes its operations.
func LoadContract(path string) (*Contract, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read openapi: %w", err)
	}
	var doc openapiDoc
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("parse openapi: %w", err)
	}
	c := &Contract{byRoute: map[string]string{}}
	for rawPath, item := range doc.Paths {
		p := normalizePath(strings.TrimPrefix(rawPath, "/auth/v1"))
		for method, opNode := range item {
			method = strings.ToLower(method)
			if !httpMethods[method] {
				continue // parameters, $ref, summary, ...
			}
			opMap, ok := opNode.(map[string]any)
			if !ok {
				continue
			}
			id, _ := opMap["operationId"].(string)
			if id == "" {
				continue
			}
			m := strings.ToUpper(method)
			c.Ops = append(c.Ops, Operation{ID: id, Method: m, Path: p})
			c.byRoute[m+" "+p] = id
		}
	}
	sort.Slice(c.Ops, func(i, j int) bool { return c.Ops[i].ID < c.Ops[j].ID })
	return c, nil
}

// normalizePath collapses templated path params ({user_id}) to a fixed token so
// a concrete scenario path resolves to its templated operation.
func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			segs[i] = "{}"
		}
	}
	return strings.Join(segs, "/")
}

// Resolve maps a concrete scenario (method + relative path, query stripped) to
// an operationId, or "" when no contract operation matches.
func (c *Contract) Resolve(method, relPath string) string {
	if i := strings.IndexAny(relPath, "?#"); i >= 0 {
		relPath = relPath[:i]
	}
	return c.byRoute[strings.ToUpper(method)+" "+normalizeConcrete(relPath)]
}

// normalizeConcrete turns a concrete path's identifier-looking segments into the
// {} token so it lines up with normalizePath. A segment is treated as a param
// when it looks like a UUID, a numeric id, or a dk_/pr_-style prefixed id.
func normalizeConcrete(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if looksLikeID(s) {
			segs[i] = "{}"
		}
	}
	return strings.Join(segs, "/")
}

func looksLikeID(s string) bool {
	if s == "" {
		return false
	}
	// UUID
	if len(s) == 36 && strings.Count(s, "-") == 4 {
		return true
	}
	// all-hex or all-digit or prefixed opaque id
	hexish := true
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || r == '-' || r == '_') {
			hexish = false
			break
		}
	}
	return hexish && len(s) >= 16
}

// CoverageReport summarises which contract operations the scenario set touched.
type CoverageReport struct {
	Total     int
	Covered   []string
	Uncovered []string
}

// Coverage compares the set of operationIds the scenarios exercised against the
// full contract.
func (c *Contract) Coverage(hit map[string]bool) CoverageReport {
	all := map[string]bool{}
	for _, op := range c.Ops {
		all[op.ID] = true
	}
	var covered, uncovered []string
	for id := range all {
		if hit[id] {
			covered = append(covered, id)
		} else {
			uncovered = append(uncovered, id)
		}
	}
	sort.Strings(covered)
	sort.Strings(uncovered)
	return CoverageReport{Total: len(all), Covered: covered, Uncovered: uncovered}
}

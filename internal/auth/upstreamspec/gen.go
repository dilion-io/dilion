//go:build ignore

// Command gen regenerates types.gen.go from the vendored upstream openapi.yaml.
//
// Run it with `go generate ./internal/auth/upstreamspec/` (see doc.go). It is
// NOT part of the upstreamspec package — the `ignore` build tag keeps it out of
// every normal build.
//
// # Why a wrapper instead of a bare oapi-codegen invocation
//
// openapi.yaml is vendored VERBATIM from upstream (see SOURCE.md), and upstream
// master currently ships two classes of construct (three occurrences in all)
// that kin-openapi (oapi-codegen's loader) rejects outright, so
// `oapi-codegen -config cfg.yaml openapi.yaml`
// fails before it emits a single line. Rather than hand-patch the vendored spec
// — which would destroy the drift check in `make upstream-spec-check` — or
// hand-patch the generated file — which the codegen would clobber — this
// wrapper applies a small, closed, documented set of fixups to an IN-MEMORY
// copy and feeds that to the generator.
//
// The fixups are deliberately narrow. Each one is a spec-side bug, not a
// modelling choice, and none of them touches a property name, type or
// required-ness of any schema this repo asserts against:
//
//	fixupResponseRefInSchema
//	  `schema: {$ref: "#/components/responses/UnauthorizedResponse"}` under
//	  GET /user's 401/403 — a response object where a schema object belongs.
//	  kin-openapi: `bad data in "#/components/responses/UnauthorizedResponse"
//	  (expecting ref to schema object)`. Rewritten to the schema that the
//	  named response itself wraps (ErrorSchema), which is what the author
//	  plainly meant.
//
//	fixupInlineOneOfDiscriminator
//	  WebAuthnChallengeResponse.webauthn is a `oneOf` of two INLINE schemas
//	  carrying a `discriminator`. OAS 3.0 only permits a discriminator when
//	  every alternative is a $ref (or an explicit mapping is given), so the
//	  generator fails with `discriminator: not all schemas were mapped`. The
//	  discriminator is dropped; the oneOf itself is generated unchanged.
//
// If upstream fixes any of these, the corresponding fixup simply matches zero
// nodes and the counts printed below go to 0 — nothing breaks.
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	specFile   = "openapi.yaml"
	configFile = "cfg.yaml"
	outputFile = "types.gen.go"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("upstreamspec/gen: ")

	raw, err := os.ReadFile(specFile)
	if err != nil {
		log.Fatal(err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		log.Fatalf("parsing %s: %v", specFile, err)
	}
	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}

	nRefs := fixupResponseRefInSchema(root)
	nDisc := fixupInlineOneOfDiscriminator(root)
	log.Printf("fixups applied: response-ref-in-schema=%d inline-oneof-discriminator=%d", nRefs, nDisc)

	tmp, err := os.MkdirTemp("", "upstreamspec-gen-")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	normalized := filepath.Join(tmp, "openapi.normalized.yaml")
	f, err := os.Create(normalized)
	if err != nil {
		log.Fatal(err)
	}
	enc := yaml.NewEncoder(f)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		log.Fatal(err)
	}
	if err := enc.Close(); err != nil {
		log.Fatal(err)
	}
	if err := f.Close(); err != nil {
		log.Fatal(err)
	}

	bin, err := exec.LookPath("oapi-codegen")
	if err != nil {
		log.Fatalf("oapi-codegen not found on PATH — install it with\n"+
			"    go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0\n"+
			"and make sure $(go env GOPATH)/bin is on PATH (%v)", err)
	}

	cmd := exec.Command(bin, "-config", configFile, normalized)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("oapi-codegen: %v", err)
	}

	// The generator stamps the source file name it was handed into nothing, but
	// be defensive: make sure the temp path never leaks into the committed file.
	out, err := os.ReadFile(outputFile)
	if err != nil {
		log.Fatal(err)
	}
	if strings.Contains(string(out), tmp) {
		log.Fatalf("%s leaked the temporary spec path %s", outputFile, tmp)
	}
	fmt.Printf("wrote %s (%d bytes)\n", outputFile, len(out))
}

// fixupResponseRefInSchema rewrites `schema: {$ref: "#/components/responses/X"}`
// to the schema that response X wraps. Returns the number of rewrites.
func fixupResponseRefInSchema(root *yaml.Node) int {
	responses := lookup(root, "components", "responses")
	if responses == nil {
		return 0
	}

	// name -> the $ref of components.responses.<name>.content.*/schema
	target := map[string]string{}
	for i := 0; i+1 < len(responses.Content); i += 2 {
		name := responses.Content[i].Value
		content := lookup(responses.Content[i+1], "content")
		if content == nil {
			continue
		}
		for j := 0; j+1 < len(content.Content); j += 2 {
			if ref := lookup(content.Content[j+1], "schema", "$ref"); ref != nil {
				target[name] = ref.Value
				break
			}
		}
	}

	n := 0
	walk(root, func(m *yaml.Node) {
		for i := 0; i+1 < len(m.Content); i += 2 {
			if m.Content[i].Value != "schema" {
				continue
			}
			ref := lookup(m.Content[i+1], "$ref")
			if ref == nil {
				continue
			}
			name, ok := strings.CutPrefix(ref.Value, "#/components/responses/")
			if !ok {
				continue
			}
			replacement, ok := target[name]
			if !ok {
				continue
			}
			ref.Value = replacement
			n++
		}
	})
	return n
}

// fixupInlineOneOfDiscriminator deletes a `discriminator` sibling of a `oneOf`
// whose alternatives are not all $refs. Returns the number of deletions.
func fixupInlineOneOfDiscriminator(root *yaml.Node) int {
	n := 0
	walk(root, func(m *yaml.Node) {
		oneOf := lookup(m, "oneOf")
		if oneOf == nil || lookup(m, "discriminator") == nil {
			return
		}
		allRefs := true
		for _, alt := range oneOf.Content {
			if lookup(alt, "$ref") == nil {
				allRefs = false
				break
			}
		}
		if allRefs {
			return
		}
		for i := 0; i+1 < len(m.Content); i += 2 {
			if m.Content[i].Value == "discriminator" {
				m.Content = append(m.Content[:i], m.Content[i+2:]...)
				n++
				return
			}
		}
	})
	return n
}

// lookup follows a chain of mapping keys, returning nil if any hop is missing.
func lookup(n *yaml.Node, keys ...string) *yaml.Node {
	for _, key := range keys {
		if n == nil || n.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == key {
				next = n.Content[i+1]
				break
			}
		}
		n = next
	}
	return n
}

// walk calls fn for every mapping node reachable from n, depth-first.
func walk(n *yaml.Node, fn func(*yaml.Node)) {
	if n == nil {
		return
	}
	if n.Kind == yaml.MappingNode {
		fn(n)
	}
	for _, c := range n.Content {
		walk(c, fn)
	}
}

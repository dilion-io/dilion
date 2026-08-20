// Command openapi generates web/openapi.yaml from the huma route definitions.
// The spec is derived from the same registration code the server runs, so the
// contract cannot drift from the implementation. It needs no database: the
// handlers are registered with a zero Deps and no privacy engine.
//
//	go run ./cmd/openapi            # writes web/openapi.yaml
//	go run ./cmd/openapi -o out.yml
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"net/http"

	"github.com/dilion-project/dilion/internal/api"
)

func main() {
	out := flag.String("o", filepath.Join("web", "openapi.yaml"), "output path for the OpenAPI document")
	flag.Parse()

	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "openapi:", err)
		os.Exit(1)
	}
}

func run(out string) error {
	doc, err := Document()
	if err != nil {
		return err
	}
	if dir := filepath.Dir(out); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(out, doc, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	fmt.Printf("wrote %s (%d bytes)\n", out, len(doc))
	return nil
}

// Document builds the API in memory and returns the OpenAPI 3.1 YAML.
func Document() ([]byte, error) {
	humaAPI := humago.New(http.NewServeMux(), api.NewConfig())
	// Registration performs no I/O: a nil privacy engine and a zero Deps are
	// enough to describe every route.
	api.RegisterPrivacyAPI(humaAPI, nil, api.Deps{})
	api.RegisterIAMAPI(humaAPI, api.Deps{})

	doc, err := humaAPI.OpenAPI().YAML()
	if err != nil {
		return nil, fmt.Errorf("render OpenAPI: %w", err)
	}
	var _ huma.API = humaAPI
	return doc, nil
}

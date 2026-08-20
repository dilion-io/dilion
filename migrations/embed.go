// Package migrations holds Dilion's forward-only SQL migrations as an embedded
// filesystem. Files are named NNNN_name.sql and applied in lexicographic order
// by internal/store.Migrate.
//
// Number ranges are owned per domain (see PLAN.md §2):
//
//	0001      core (extensions, schemas)
//	01xx      auth.*            (Supabase Auth compatible surface)
//	02xx      dilion_privacy.*, dilion_pii.*
//	03xx      dilion_authz.*, dilion_audit.*
package migrations

import "embed"

// FS contains every *.sql migration file in this directory.
//
//go:embed *.sql
var FS embed.FS

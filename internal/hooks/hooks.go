// Package hooks implements the hook registry (project.md §2.4). CONTRACT file —
// agents consume, do not modify.
package hooks

import (
	"context"
	"fmt"
	"sync"

	"github.com/dilion-project/dilion/ports"
)

type Registry struct {
	mu    sync.RWMutex
	funcs map[ports.HookPoint][]ports.HookFunc
}

func NewRegistry() *Registry {
	return &Registry{funcs: map[ports.HookPoint][]ports.HookFunc{}}
}

func (r *Registry) Register(p ports.HookPoint, fn ports.HookFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.funcs[p] = append(r.funcs[p], fn)
}

// Run executes hooks in registration order. A returned error aborts the chain
// (fail-closed; validating hook points rely on this). A non-nil returned map
// replaces the payload for subsequent hooks and the caller (mutating hooks).
func (r *Registry) Run(ctx context.Context, p ports.HookPoint, payload map[string]any) (map[string]any, error) {
	r.mu.RLock()
	fns := r.funcs[p]
	r.mu.RUnlock()
	for i, fn := range fns {
		out, err := fn(ctx, payload)
		if err != nil {
			return nil, fmt.Errorf("hook %s[%d]: %w", p, i, err)
		}
		if out != nil {
			payload = out
		}
	}
	return payload, nil
}

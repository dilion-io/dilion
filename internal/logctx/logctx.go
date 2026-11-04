// Package logctx tags log records with the instance selected on their context.
//
// Dilion serves many instances from one process, so a log line is only useful
// with the instance it came from. Rather than every call site adding the
// attribute, each package wraps its logger once with Wrap and logs with the
// *Context methods; the handler reads ports.LookupInstance from the record's
// context and adds "instance" when one was selected.
package logctx

import (
	"context"
	"log/slog"

	"github.com/dilion-io/dilion/ports"
)

// Key is the attribute that names the instance.
const Key = "instance"

// Wrap returns l with its handler wrapped to tag records with the instance
// selected on their context. A nil l means slog.Default(). Wrapping an already
// wrapped logger returns it unchanged, so every package can wrap what it is
// given without stacking handlers.
func Wrap(l *slog.Logger) *slog.Logger {
	if l == nil {
		l = slog.Default()
	}
	if _, ok := l.Handler().(*handler); ok {
		return l
	}
	return slog.New(&handler{next: l.Handler()})
}

// handler adds Key from the context unless the logger (With) or the record
// already carries it: a per-instance component such as a privacy engine
// names its instance up front, and a server-level line may name one
// explicitly. Records whose context selects no instance (startup, shutdown)
// pass through untagged. Under WithGroup the attribute lands inside the open
// group, as any attribute added at Handle time does.
type handler struct {
	next  slog.Handler
	named bool // Key was added with WithAttrs
}

func (h *handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	if !h.named && ctx != nil {
		if id, ok := ports.LookupInstance(ctx); ok && !hasKey(r) {
			r = r.Clone()
			r.AddAttrs(slog.String(Key, id))
		}
	}
	return h.next.Handle(ctx, r)
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	named := h.named
	for _, a := range attrs {
		if a.Key == Key {
			named = true
		}
	}
	return &handler{next: h.next.WithAttrs(attrs), named: named}
}

func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{next: h.next.WithGroup(name), named: h.named}
}

func hasKey(r slog.Record) bool {
	found := false
	r.Attrs(func(a slog.Attr) bool {
		found = a.Key == Key
		return !found
	})
	return found
}

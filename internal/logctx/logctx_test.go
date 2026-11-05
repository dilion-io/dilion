package logctx

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/dilion-io/dilion/ports"
)

func newLogger(buf *bytes.Buffer) *slog.Logger {
	return Wrap(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
}

func TestTagsTheSelectedInstance(t *testing.T) {
	var buf bytes.Buffer
	log := newLogger(&buf)
	ctx := ports.ContextWithInstance(context.Background(), "tenant-a")
	log.InfoContext(ctx, "one")
	log.With("k", "v").WithGroup("g").InfoContext(ctx, "two", "x", 1)
	if got := strings.Count(buf.String(), `"instance":"tenant-a"`); got != 2 {
		t.Fatalf("instance tagged on %d of 2 records: %s", got, buf.String())
	}
}

func TestLeavesUnselectedContextsUntagged(t *testing.T) {
	var buf bytes.Buffer
	newLogger(&buf).Info("startup")
	if strings.Contains(buf.String(), `"instance"`) {
		t.Fatalf("a record with no selected instance was tagged: %s", buf.String())
	}
}

// A logger or record that already names its instance is not tagged twice.
func TestDoesNotDuplicateAnExplicitInstance(t *testing.T) {
	var buf bytes.Buffer
	log := newLogger(&buf)
	ctx := ports.ContextWithInstance(context.Background(), "tenant-a")
	log.With(Key, "tenant-b").InfoContext(ctx, "fixed")
	log.InfoContext(ctx, "explicit", Key, "tenant-c")
	if strings.Contains(buf.String(), "tenant-a") {
		t.Fatalf("an explicit instance was overridden or duplicated: %s", buf.String())
	}
}

func TestWrapIsIdempotent(t *testing.T) {
	l := Wrap(nil)
	if Wrap(l) != l {
		t.Fatal("wrapping a wrapped logger stacked another handler")
	}
}

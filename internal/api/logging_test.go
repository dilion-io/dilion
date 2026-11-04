package api

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/dilion-io/dilion/ports"
)

func TestPrivacyErrorLogIncludesInstance(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	ctx := ports.ContextWithInstance(context.Background(), "tenant-a")
	_ = mapPrivacyError(ctx, errors.New("test failure"))
	if !strings.Contains(buf.String(), `"instance":"tenant-a"`) {
		t.Fatalf("privacy error log missing instance: %s", buf.String())
	}
}

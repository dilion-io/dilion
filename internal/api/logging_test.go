package api

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2/humatest"

	"github.com/dilion-io/dilion/ports"
)

// The logger passed in Deps receives the management plane's error logs,
// tagged with the request's instance.
func TestPrivacyErrorLogIncludesInstance(t *testing.T) {
	var buf bytes.Buffer
	_, humaAPI := humatest.New(t)
	r := newRegistrar(humaAPI, Deps{Logger: slog.New(slog.NewJSONHandler(&buf, nil))}, nil)
	ctx := ports.ContextWithInstance(context.Background(), "tenant-a")
	_ = r.d.mapPrivacyError(ctx, errors.New("test failure"))
	if !strings.Contains(buf.String(), `"instance":"tenant-a"`) {
		t.Fatalf("privacy error log missing instance: %s", buf.String())
	}
}

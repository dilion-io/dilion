package auth

import (
	"bytes"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dilion-io/dilion/ports"
)

func TestRequestErrorLogIncludesInstance(t *testing.T) {
	var buf bytes.Buffer
	a := &api{log: slog.New(slog.NewJSONHandler(&buf, nil))}
	req := httptest.NewRequest("GET", "/auth/v1/user", nil)
	req = req.WithContext(ports.ContextWithInstance(req.Context(), "tenant-a"))
	a.writeError(req, httptest.NewRecorder(), internalServerError("test failure"))
	if !strings.Contains(buf.String(), `"instance":"tenant-a"`) {
		t.Fatalf("request log missing instance: %s", buf.String())
	}
}

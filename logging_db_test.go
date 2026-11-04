package dilion

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/dilion-io/dilion/ports"
)

// syncBuffer is a bytes.Buffer safe for the server's concurrent writers.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// The logger an embedder passes with WithLogger receives the /auth/v1 request
// logs, each tagged with the instance the request selected.
func TestWithLoggerReceivesInstanceTaggedAuthLogs(t *testing.T) {
	var out syncBuffer
	srv, _, _ := twoInstanceServer(t,
		WithLogger(slog.New(slog.NewJSONHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug}))))

	req := httptest.NewRequest(http.MethodGet, "/auth/v1/user", nil)
	req = req.WithContext(ports.ContextWithInstance(req.Context(), "h2"))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code < 400 {
		t.Fatalf("unauthenticated /user = %d, want an error", rec.Code)
	}

	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, `"auth: request failed"`) {
			if !strings.Contains(line, `"instance":"h2"`) {
				t.Fatalf("auth request log not tagged with h2: %s", line)
			}
			return
		}
	}
	t.Fatalf("WithLogger received no auth request log: %s", out.String())
}

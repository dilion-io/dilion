package privacy

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The logger passed in EngineDeps receives the engine's logs, each naming the
// engine's instance once.
func TestEngineLogsIncludeInstance(t *testing.T) {
	var buf bytes.Buffer
	e, err := NewEngine(EngineDeps{
		Pool: &pgxpool.Pool{}, KMS: &fakeKMS{},
		TombstoneKey: []byte("test-key"), InstanceID: "tenant-a",
		Logger: slog.New(slog.NewJSONHandler(&buf, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	e.log.Info("test engine log")
	if got := strings.Count(buf.String(), `"instance":"tenant-a"`); got != 1 {
		t.Fatalf("instance named %d times, want 1: %s", got, buf.String())
	}
}

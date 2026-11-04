package privacy

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestEngineLogsIncludeInstance(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	e, err := NewEngine(EngineDeps{
		Pool: &pgxpool.Pool{}, KMS: &fakeKMS{},
		TombstoneKey: []byte("test-key"), InstanceID: "tenant-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	e.log.Info("test engine log")
	if !strings.Contains(buf.String(), `"instance":"tenant-a"`) {
		t.Fatalf("engine log missing instance: %s", buf.String())
	}
}

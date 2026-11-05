package privacy

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Without intervals the workers poll at the production defaults, not the
// few seconds that suit development; set ones are kept.
func TestWorkerIntervals(t *testing.T) {
	deps := EngineDeps{Pool: &pgxpool.Pool{}, KMS: &fakeKMS{}, TombstoneKey: []byte("test-key")}
	e, err := NewEngine(deps)
	if err != nil {
		t.Fatal(err)
	}
	if e.pollInterval != DefaultPollInterval || e.retentionInterval != DefaultRetentionInterval {
		t.Errorf("defaults = %v / %v", e.pollInterval, e.retentionInterval)
	}
	deps.PollInterval, deps.RetentionInterval = 2*time.Second, time.Minute
	if e, _ = NewEngine(deps); e.pollInterval != 2*time.Second || e.retentionInterval != time.Minute {
		t.Errorf("set intervals = %v / %v", e.pollInterval, e.retentionInterval)
	}
	for range 100 {
		if d := jitter(10 * time.Second); d < 10*time.Second || d > 15*time.Second {
			t.Fatalf("jitter(10s) = %v, want within [10s, 15s]", d)
		}
	}
}

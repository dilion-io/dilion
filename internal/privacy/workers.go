package privacy

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"
)

// Dev-friendly poll intervals. Every worker ticks at base + jitter so that
// several engine instances spread their load (§2.9 scheduler SLA is measured
// in days; seconds here are for responsiveness in development).
const (
	pollMin = 2 * time.Second
	pollMax = 5 * time.Second
)

type worker struct {
	name string
	run  func(context.Context) error
}

// RunWorkers starts the background pollers and blocks until ctx is done:
//
//	outbox dispatcher  — account deletions and reconfirm notices (§2.5)
//	pipeline runner    — erasure steps 100–1000 (§2.9)
//	task sender        — webhook/connector delivery with retry + DLQ (§3.2)
//	reconfirm scanner  — consent reconfirmation notices (§2.8)
//	retention scanner  — retention periods / crypto-shred (§2.8)
func (e *Engine) RunWorkers(ctx context.Context) {
	workers := []worker{
		{"outbox", e.dispatchOutboxOnce},
		{"pipeline", e.runPipelineOnce},
		{"tasks", e.runTasksOnce},
		{"reconfirm", e.scanReconfirmDue},
		{"retention", e.runRetentionOnce},
	}

	var wg sync.WaitGroup
	for _, w := range workers {
		wg.Add(1)
		go func(w worker) {
			defer wg.Done()
			e.loop(ctx, w)
		}(w)
	}
	e.log.Info("privacy workers started", "count", len(workers),
		"poll_min", pollMin.String(), "poll_max", pollMax.String())
	<-ctx.Done()
	wg.Wait()
	e.log.Info("privacy workers stopped")
}

func (e *Engine) loop(ctx context.Context, w worker) {
	timer := time.NewTimer(jitter())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := w.run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			e.log.Error("privacy worker tick failed", "worker", w.name, "err", err)
		}
		timer.Reset(jitter())
	}
}

func jitter() time.Duration {
	return pollMin + time.Duration(rand.Int64N(int64(pollMax-pollMin)+1))
}

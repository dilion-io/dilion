package privacy

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"
)

// Default worker intervals. Every engine (one per instance) in every process
// polls on its own, so the idle query rate is the number of workers times
// instances times replicas over the interval: a few seconds is responsive in
// development but thousands of queries a second for a large deployment. The
// §2.9 scheduler SLA is measured in days, and retention periods in years.
const (
	// DefaultPollInterval is how often the outbox, pipeline, task and
	// reconfirm workers poll (EngineDeps.PollInterval).
	DefaultPollInterval = 30 * time.Second
	// DefaultRetentionInterval is how often the retention scanner runs
	// (EngineDeps.RetentionInterval).
	DefaultRetentionInterval = time.Hour
)

type worker struct {
	name     string
	run      func(context.Context) error
	interval time.Duration
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
		{"outbox", e.dispatchOutboxOnce, e.pollInterval},
		{"pipeline", e.runPipelineOnce, e.pollInterval},
		{"tasks", e.runTasksOnce, e.pollInterval},
		{"reconfirm", e.scanReconfirmDue, e.pollInterval},
		{"retention", e.runRetentionOnce, e.retentionInterval},
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
		"poll_interval", e.pollInterval.String(), "retention_interval", e.retentionInterval.String())
	<-ctx.Done()
	wg.Wait()
	e.log.Info("privacy workers stopped")
}

func (e *Engine) loop(ctx context.Context, w worker) {
	timer := time.NewTimer(jitter(w.interval))
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		start := time.Now()
		err := w.run(ctx)
		// A cancelled tick is shutdown, not a failure worth counting.
		if !errors.Is(err, context.Canceled) {
			e.metrics.WorkerTick(w.name, time.Since(start), err)
			if err != nil {
				e.log.Error("privacy worker tick failed", "worker", w.name, "err", err)
			}
		}
		timer.Reset(jitter(w.interval))
	}
}

// jitter is interval plus up to half of it again, so the engines of many
// instances started together drift apart instead of polling in step.
func jitter(interval time.Duration) time.Duration {
	return interval + time.Duration(rand.Int64N(int64(interval/2)+1))
}

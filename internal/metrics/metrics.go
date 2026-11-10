// Package metrics holds Dilion's Prometheus instruments: the HTTP surface, the
// database pools and the privacy workers.
//
// Label cardinality is kept independent of the number of instances everywhere
// except the pool gauges. A multi-tenant deployment may serve thousands of
// instances (one per workspace), and an instance label on the request
// histograms would multiply every route by that number; a pool, on the other
// hand, is a per-instance resource whose exhaustion has to be traced to its
// instance. That label is `instance_id`, because Prometheus reserves
// `instance` for the scraped target and would rename ours.
//
// Every method is safe on a nil *Metrics, so components built without metrics
// (tests, tools) need no guard.
package metrics

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "dilion"

// unmatchedRoute labels requests no route matched, so probes for random paths
// cannot create a series each.
const unmatchedRoute = "unmatched"

// PoolSource lists the pools to report, keyed by instance id. It is called on
// every scrape with a bounded context.
type PoolSource func(ctx context.Context) (map[string]*pgxpool.Pool, error)

// Options configure New.
type Options struct {
	// Registry receives every collector. nil creates a private registry that
	// also carries the Go runtime and process collectors; a caller-supplied
	// registry is assumed to have those already.
	Registry *prometheus.Registry
	// Version is reported by dilion_build_info.
	Version string
	// Pools feeds the dilion_db_pool_* gauges; nil reports none.
	Pools PoolSource
}

// Metrics is the set of instruments one Server records into.
type Metrics struct {
	reg *prometheus.Registry

	httpRequests *prometheus.CounterVec
	httpDuration *prometheus.HistogramVec
	httpInFlight prometheus.Gauge

	workerRuns     *prometheus.CounterVec
	workerDuration *prometheus.HistogramVec
	deliveries     *prometheus.CounterVec
}

// New registers the instruments. It fails only when the registry already holds
// collectors of the same names (two Servers sharing one registry).
func New(o Options) (*Metrics, error) {
	reg := o.Registry
	var runtime []prometheus.Collector
	if reg == nil {
		reg = prometheus.NewRegistry()
		runtime = []prometheus.Collector{
			collectors.NewGoCollector(),
			collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		}
	}
	version := o.Version
	if version == "" {
		version = "unknown"
	}

	m := &Metrics{
		reg: reg,
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "http", Name: "requests_total",
			Help: "HTTP requests served, by route pattern, method and status code.",
		}, []string{"route", "method", "code"}),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "http", Name: "request_duration_seconds",
			Help: "Time to serve an HTTP request, by route pattern and method.",
			// Sign-in hashes a password (bcrypt/argon2, ~50-300ms), so the
			// buckets reach well past the default 10s ceiling's middle.
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30},
		}, []string{"route", "method"}),
		httpInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace, Subsystem: "http", Name: "requests_in_flight",
			Help: "HTTP requests currently being served.",
		}),
		workerRuns: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "privacy", Name: "worker_runs_total",
			Help: "Privacy worker ticks across all instances, by worker and result (ok or error).",
		}, []string{"worker", "result"}),
		workerDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace, Subsystem: "privacy", Name: "worker_run_duration_seconds",
			Help:    "Duration of one privacy worker tick, by worker.",
			Buckets: []float64{.01, .05, .1, .5, 1, 5, 15, 60, 300},
		}, []string{"worker"}),
		deliveries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace, Subsystem: "privacy", Name: "deliveries_total",
			Help: "Webhook/connector delivery attempts across all instances, by outcome " +
				"(completed, retry, dead). Any increase of outcome=\"dead\" needs an operator.",
		}, []string{"outcome"}),
	}
	buildInfo := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: namespace, Name: "build_info",
		Help:        "Always 1; the version label names the running Dilion.",
		ConstLabels: prometheus.Labels{"version": version},
	}, func() float64 { return 1 })

	cs := append(runtime, m.httpRequests, m.httpDuration, m.httpInFlight,
		m.workerRuns, m.workerDuration, m.deliveries, buildInfo)
	if o.Pools != nil {
		cs = append(cs, newPoolCollector(o.Pools))
	}
	for _, c := range cs {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	// Pre-create the series alerts compare against, so a rate() over
	// deliveries{outcome="dead"} exists before the first dead letter.
	for _, outcome := range []string{"completed", "retry", "dead"} {
		m.deliveries.WithLabelValues(outcome)
	}
	return m, nil
}

// Registry is the registry the instruments live in.
func (m *Metrics) Registry() *prometheus.Registry {
	if m == nil {
		return nil
	}
	return m.reg
}

// Handler serves the registry in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		return http.NotFoundHandler()
	}
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{Registry: m.reg})
}

// Middleware records every request. Install it on the chi router itself
// (r.Use), so the matched route pattern is known once next returns — the
// pattern, not the URL path, is the label, so user ids and tokens in paths
// never become series — and ahead of middleware.Recoverer, so a panic is
// counted as the 500 the recoverer writes.
func (m *Metrics) Middleware(next http.Handler) http.Handler {
	if m == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.httpInFlight.Inc()
		defer m.httpInFlight.Dec()

		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		code := ww.Status()
		if code == 0 { // nothing written: net/http sends 200
			code = http.StatusOK
		}
		route := unmatchedRoute
		if rc := chi.RouteContext(r.Context()); rc != nil {
			if p := rc.RoutePattern(); p != "" {
				route = p
			}
		}
		m.httpRequests.WithLabelValues(route, r.Method, strconv.Itoa(code)).Inc()
		m.httpDuration.WithLabelValues(route, r.Method).Observe(time.Since(start).Seconds())
	})
}

// WorkerTick records one privacy worker tick.
func (m *Metrics) WorkerTick(worker string, d time.Duration, err error) {
	if m == nil {
		return
	}
	result := "ok"
	if err != nil {
		result = "error"
	}
	m.workerRuns.WithLabelValues(worker, result).Inc()
	m.workerDuration.WithLabelValues(worker).Observe(d.Seconds())
}

// Delivery records the outcome of one delivery attempt: completed, retry or
// dead.
func (m *Metrics) Delivery(outcome string) {
	if m == nil {
		return
	}
	m.deliveries.WithLabelValues(outcome).Inc()
}

// ---- pools ----

// poolScrapeTimeout bounds the resolver calls a scrape makes; Prometheus'
// default scrape timeout is 10s.
const poolScrapeTimeout = 5 * time.Second

var (
	poolLabels = []string{"instance_id"}

	poolMaxConns = prometheus.NewDesc(namespace+"_db_pool_max_connections",
		"Maximum size of the instance's connection pool.", poolLabels, nil)
	poolTotalConns = prometheus.NewDesc(namespace+"_db_pool_connections",
		"Connections currently open in the pool, by state.", append(poolLabels, "state"), nil)
	poolAcquires = prometheus.NewDesc(namespace+"_db_pool_acquires_total",
		"Successful connection acquisitions from the pool.", poolLabels, nil)
	poolEmptyAcquires = prometheus.NewDesc(namespace+"_db_pool_empty_acquires_total",
		"Acquisitions that had to wait because the pool had no idle connection.", poolLabels, nil)
	poolCanceledAcquires = prometheus.NewDesc(namespace+"_db_pool_canceled_acquires_total",
		"Acquisitions abandoned because their context ended while waiting.", poolLabels, nil)
	poolAcquireWait = prometheus.NewDesc(namespace+"_db_pool_acquire_wait_seconds_total",
		"Total time spent waiting for a connection from the pool.", poolLabels, nil)
	poolScrapeErrors = prometheus.NewDesc(namespace+"_db_pool_scrape_error",
		"1 when the instance list or a pool could not be resolved during this scrape.", nil, nil)
)

type poolCollector struct{ src PoolSource }

func newPoolCollector(src PoolSource) *poolCollector { return &poolCollector{src: src} }

func (c *poolCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{poolMaxConns, poolTotalConns, poolAcquires,
		poolEmptyAcquires, poolCanceledAcquires, poolAcquireWait, poolScrapeErrors} {
		ch <- d
	}
}

func (c *poolCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), poolScrapeTimeout)
	defer cancel()
	pools, err := c.src(ctx)
	failed := 0.0
	if err != nil {
		failed = 1
	}
	ch <- prometheus.MustNewConstMetric(poolScrapeErrors, prometheus.GaugeValue, failed)

	// A resolver may hand the same pool to several instances; report each pool
	// once so sums across instances stay true.
	seen := make(map[*pgxpool.Pool]bool, len(pools))
	for id, p := range pools {
		if p == nil || seen[p] {
			continue
		}
		seen[p] = true
		s := p.Stat()
		gauge := func(d *prometheus.Desc, v float64, extra ...string) {
			ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, append([]string{id}, extra...)...)
		}
		counter := func(d *prometheus.Desc, v float64) {
			ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, v, id)
		}
		gauge(poolMaxConns, float64(s.MaxConns()))
		gauge(poolTotalConns, float64(s.AcquiredConns()), "acquired")
		gauge(poolTotalConns, float64(s.IdleConns()), "idle")
		gauge(poolTotalConns, float64(s.ConstructingConns()), "constructing")
		counter(poolAcquires, float64(s.AcquireCount()))
		counter(poolEmptyAcquires, float64(s.EmptyAcquireCount()))
		counter(poolCanceledAcquires, float64(s.CanceledAcquireCount()))
		counter(poolAcquireWait, s.AcquireDuration().Seconds())
	}
}

package metrics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func newTestRouter(t *testing.T, m *Metrics) http.Handler {
	t.Helper()
	r := chi.NewRouter()
	r.Use(m.Middleware)
	r.Use(middleware.Recoverer)
	r.Route("/auth/v1", func(r chi.Router) {
		r.Get("/admin/users/{user_id}", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		})
		r.Get("/boom", func(http.ResponseWriter, *http.Request) { panic("boom") })
	})
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	return r
}

func serve(h http.Handler, method, path string) {
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, path, nil))
}

// The route pattern, not the path, is the label: ids in paths must not become
// series, and unrouted probes must collapse into one.
func TestMiddlewareLabelsByRoutePattern(t *testing.T) {
	m, err := New(Options{Registry: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	h := newTestRouter(t, m)

	serve(h, http.MethodGet, "/auth/v1/admin/users/11111111-1111-1111-1111-111111111111")
	serve(h, http.MethodGet, "/auth/v1/admin/users/22222222-2222-2222-2222-222222222222")
	serve(h, http.MethodGet, "/healthz")
	serve(h, http.MethodGet, "/wp-login.php")
	serve(h, http.MethodGet, "/.env")

	for _, tc := range []struct {
		route, code string
		want        float64
	}{
		{"/auth/v1/admin/users/{user_id}", "404", 2},
		{"/healthz", "200", 1},
		{unmatchedRoute, "404", 2},
	} {
		got := testutil.ToFloat64(m.httpRequests.WithLabelValues(tc.route, http.MethodGet, tc.code))
		if got != tc.want {
			t.Errorf("requests{route=%q,code=%s} = %v, want %v", tc.route, tc.code, got, tc.want)
		}
	}
	if n := testutil.CollectAndCount(m.httpRequests); n != 3 {
		t.Errorf("request series = %d, want 3 (one per route and code)", n)
	}
	if v := testutil.ToFloat64(m.httpInFlight); v != 0 {
		t.Errorf("in flight after all requests returned = %v, want 0", v)
	}
}

// A panic reaches the client as the recoverer's 500 and must be counted as one.
func TestMiddlewareCountsPanicsAsServerErrors(t *testing.T) {
	m, err := New(Options{Registry: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	serve(newTestRouter(t, m), http.MethodGet, "/auth/v1/boom")
	if got := testutil.ToFloat64(m.httpRequests.WithLabelValues("/auth/v1/boom", http.MethodGet, "500")); got != 1 {
		t.Fatalf("requests{route=/auth/v1/boom,code=500} = %v, want 1", got)
	}
}

func TestWorkerAndDeliveryCounters(t *testing.T) {
	m, err := New(Options{Registry: prometheus.NewRegistry()})
	if err != nil {
		t.Fatal(err)
	}
	m.WorkerTick("tasks", 10*time.Millisecond, nil)
	m.WorkerTick("tasks", 10*time.Millisecond, errors.New("db down"))
	m.Delivery("dead")

	if got := testutil.ToFloat64(m.workerRuns.WithLabelValues("tasks", "error")); got != 1 {
		t.Errorf("worker_runs{tasks,error} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.workerRuns.WithLabelValues("tasks", "ok")); got != 1 {
		t.Errorf("worker_runs{tasks,ok} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.deliveries.WithLabelValues("dead")); got != 1 {
		t.Errorf("deliveries{dead} = %v, want 1", got)
	}
	// Alert expressions over the other outcomes need the series to exist
	// before the first event.
	if n := testutil.CollectAndCount(m.deliveries); n != 3 {
		t.Errorf("delivery series = %d, want 3 pre-created outcomes", n)
	}
}

// Components built without metrics hold a nil *Metrics and must not need a
// guard at every call site.
func TestNilMetricsIsInert(t *testing.T) {
	var m *Metrics
	m.WorkerTick("tasks", time.Second, nil)
	m.Delivery("completed")
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if h := m.Middleware(next); h == nil {
		t.Fatal("nil Middleware returned nil")
	}
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("nil Handler status = %d, want 404", rec.Code)
	}
}

// pgxpool.New does not connect while MinConns is 0, so pools pointing nowhere
// are enough to exercise the collector.
func lazyPool(t *testing.T, maxConns string) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(context.Background(), "postgres://x@127.0.0.1:1/x?pool_max_conns="+maxConns)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestPoolCollector(t *testing.T) {
	a, b := lazyPool(t, "7"), lazyPool(t, "3")
	shared := lazyPool(t, "5")
	m, err := New(Options{
		Registry: prometheus.NewRegistry(),
		Pools: func(context.Context) (map[string]*pgxpool.Pool, error) {
			// Two instances on one pool: reported once, or sums double.
			return map[string]*pgxpool.Pool{"a": a, "b": b, "s1": shared, "s2": shared}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	maxConns := map[string]float64{}
	for _, f := range families {
		if f.GetName() != "dilion_db_pool_max_connections" {
			continue
		}
		for _, mm := range f.GetMetric() {
			maxConns[mm.GetLabel()[0].GetValue()] = mm.GetGauge().GetValue()
		}
	}
	if maxConns["a"] != 7 || maxConns["b"] != 3 {
		t.Errorf("max_connections = %v, want a=7 b=3", maxConns)
	}
	sharedSeen := 0
	for id := range maxConns {
		if id == "s1" || id == "s2" {
			sharedSeen++
		}
	}
	if sharedSeen != 1 || len(maxConns) != 3 {
		t.Errorf("max_connections = %v, want the shared pool reported once", maxConns)
	}
}

func TestPoolCollectorReportsResolverErrors(t *testing.T) {
	m, err := New(Options{
		Registry: prometheus.NewRegistry(),
		Pools: func(context.Context) (map[string]*pgxpool.Pool, error) {
			return nil, errors.New("control plane down")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = `
# HELP dilion_db_pool_scrape_error 1 when the instance list or a pool could not be resolved during this scrape.
# TYPE dilion_db_pool_scrape_error gauge
dilion_db_pool_scrape_error 1
`
	if err := testutil.GatherAndCompare(m.Registry(), strings.NewReader(want), "dilion_db_pool_scrape_error"); err != nil {
		t.Fatal(err)
	}
}

// The private registry carries the runtime collectors; an embedder's registry
// is assumed to have its own, so registering them again would fail.
func TestRuntimeCollectorsOnlyOnPrivateRegistry(t *testing.T) {
	own, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasFamily(t, own.Registry(), "go_goroutines") {
		t.Error("private registry lacks go_goroutines")
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	if _, err := New(Options{Registry: reg}); err != nil {
		t.Fatalf("New on a registry that already has the Go collector: %v", err)
	}
	if _, err := New(Options{Registry: reg}); err == nil {
		t.Fatal("registering a second Metrics into one registry succeeded, want a duplicate error")
	}
}

func TestHandlerExposesBuildInfo(t *testing.T) {
	m, err := New(Options{Registry: prometheus.NewRegistry(), Version: "v1.2.3"})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(rec.Body.String(), `dilion_build_info{version="v1.2.3"} 1`) {
		t.Fatalf("exposition lacks build_info:\n%s", rec.Body.String())
	}
}

func hasFamily(t *testing.T, g prometheus.Gatherer, name string) bool {
	t.Helper()
	fs, err := g.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.GetName() == name {
			return true
		}
	}
	return false
}

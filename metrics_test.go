package dilion

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/dilion-io/dilion/ports"
)

// lazyResolver serves instances whose pools never connect (pgxpool.New with
// MinConns 0 dials on first use), enough to wire a Server without a database.
// Engines cannot be built — there is no KMS — which only stops the workers.
type lazyResolver struct{ pools map[string]*pgxpool.Pool }

func (r lazyResolver) Pool(_ context.Context, id string) (*pgxpool.Pool, error) {
	if p, ok := r.pools[id]; ok {
		return p, nil
	}
	return nil, errors.New("unknown instance " + id)
}
func (lazyResolver) KMS(context.Context, string) (ports.KMS, error)     { return nil, errors.New("no kms") }
func (lazyResolver) PolicyYAML(context.Context, string) ([]byte, error) { return nil, nil }
func (lazyResolver) PIIFields(context.Context, string) ([]byte, error)  { return nil, nil }
func (lazyResolver) JWT(_ context.Context, id string) (ports.JWTKeys, error) {
	return ports.JWTKeys{Secret: "metrics-test-secret-for-" + id + "-0123456789"}, nil
}
func (r lazyResolver) List(context.Context) ([]string, error) {
	ids := make([]string, 0, len(r.pools))
	for id := range r.pools {
		ids = append(ids, id)
	}
	return ids, nil
}

func newMetricsTestServer(t *testing.T, opts ...Option) *Server {
	t.Helper()
	pools := map[string]*pgxpool.Pool{}
	for _, id := range []string{"ws-a", "ws-b"} {
		p, err := pgxpool.New(context.Background(), "postgres://x@127.0.0.1:1/x")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		pools[id] = p
	}
	base := []Option{
		WithInstanceResolver(lazyResolver{pools}),
		WithMasterKey(make([]byte, 32)),
		WithJWTSecret([]byte("metrics-test-secret-0123456789abcdef")),
	}
	srv, err := NewServer(append(base, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func scrape(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape status = %d", rec.Code)
	}
	return rec.Body.String()
}

// Requests through Handler land in MetricsHandler's exposition, and every
// instance's pool is reported under its own label.
func TestServerMetrics(t *testing.T) {
	srv := newMetricsTestServer(t)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz = %d", rec.Code)
	}

	body := scrape(t, srv.MetricsHandler())
	for _, want := range []string{
		`dilion_http_requests_total{code="200",method="GET",route="/healthz"} 1`,
		`dilion_db_pool_max_connections{instance_id="ws-a"}`,
		`dilion_db_pool_max_connections{instance_id="ws-b"}`,
		`dilion_db_pool_scrape_error 0`,
		`dilion_build_info{version=`,
		`go_goroutines `,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition lacks %q", want)
		}
	}
	// /metrics is not on the API surface: it describes the deployment.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("API handler /metrics = %d, want 404", rec.Code)
	}
}

// An embedder's registry receives Dilion's collectors and keeps its own.
func TestServerMetricsIntoEmbedderRegistry(t *testing.T) {
	reg := prometheus.NewRegistry()
	mine := prometheus.NewCounter(prometheus.CounterOpts{Name: "embedder_things_total", Help: "x"})
	reg.MustRegister(mine)
	srv := newMetricsTestServer(t, WithMetricsRegistry(reg))

	body := scrape(t, srv.MetricsHandler())
	if !strings.Contains(body, "embedder_things_total 0") || !strings.Contains(body, "dilion_http_requests_in_flight 0") {
		t.Fatalf("shared registry exposition lacks one side:\n%s", body)
	}
	if strings.Contains(body, "go_goroutines") {
		t.Error("Dilion added runtime collectors to the embedder's registry")
	}

	// A second Server in the same registry would report its numbers under the
	// same series; it is refused instead.
	if _, err := NewServer(WithInstanceResolver(lazyResolver{}), WithMasterKey(make([]byte, 32)),
		WithJWTSecret([]byte("metrics-test-secret-0123456789abcdef")), WithMetricsRegistry(reg)); err == nil {
		t.Fatal("second Server on one registry: NewServer succeeded, want an error")
	}
}

// WithMetricsAddr opens a second listener that serves only /metrics.
func TestStartServesMetricsListener(t *testing.T) {
	apiAddr, metricsAddr := freeAddr(t), freeAddr(t)
	srv := newMetricsTestServer(t, WithAddr(apiAddr), WithMetricsAddr(metricsAddr))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Start = %v", err)
		}
	})

	body := get(t, "http://"+metricsAddr+"/metrics", http.StatusOK)
	if !strings.Contains(body, "dilion_build_info") {
		t.Fatalf("metrics listener body lacks dilion_build_info:\n%s", body)
	}
	get(t, "http://"+metricsAddr+"/healthz", http.StatusNotFound)
	get(t, "http://"+apiAddr+"/metrics", http.StatusNotFound)
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// get retries until the listener is up.
func get(t *testing.T, url string, want int) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err := http.Get(url)
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != want {
				t.Fatalf("GET %s = %d, want %d", url, resp.StatusCode, want)
			}
			return string(b)
		}
		if time.Now().After(deadline) {
			t.Fatalf("GET %s: %v", url, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

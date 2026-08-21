package auth

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testHookAPI is a minimal api for driver-level tests (no DB, no tokens).
func testHookAPI(cfg *Config) *api {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &api{cfg: cfg, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

// TestHookSignatureVector pins the exact Standard Webhooks signature bytes for a
// known secret / id / timestamp / body, so a regression in the signing string or
// the base64 encoding is caught immediately.
func TestHookSignatureVector(t *testing.T) {
	// key = "0123456789abcdef"; secret = v1,whsec_<base64(key)>.
	secret := "v1,whsec_MDEyMzQ1Njc4OWFiY2RlZg=="
	msgID := "msg-id-123"
	ts := time.Unix(1700000000, 0)
	body := []byte(`{"hello":"world"}`)

	sigs, err := signHookPayload([]string{secret}, msgID, ts, body)
	if err != nil {
		t.Fatalf("signHookPayload: %v", err)
	}
	const want = "v1,9ok+Y07IiCznWM6gDY9UfUiTXtHIpfJhpjIt8iXQQt4="
	if len(sigs) != 1 || sigs[0] != want {
		t.Fatalf("signature = %v, want [%s]", sigs, want)
	}
}

// TestHookSignatureRotation asserts one signature per configured secret, signed
// with each, so a receiver mid-rotation can verify against whichever it holds.
func TestHookSignatureRotation(t *testing.T) {
	secrets := []string{
		"v1,whsec_MDEyMzQ1Njc4OWFiY2RlZg==", // "0123456789abcdef"
		"v1,whsec_ZmVkY2JhOTg3NjU0MzIxMA==", // "fedcba9876543210"
	}
	msgID := "id-rot"
	ts := time.Unix(1700000123, 0)
	body := []byte(`{"a":1}`)

	sigs, err := signHookPayload(secrets, msgID, ts, body)
	if err != nil {
		t.Fatalf("signHookPayload: %v", err)
	}
	if len(sigs) != 2 {
		t.Fatalf("got %d signatures, want 2", len(sigs))
	}
	if sigs[0] == sigs[1] {
		t.Fatalf("rotated signatures must differ: %v", sigs)
	}
	for _, s := range sigs {
		if !strings.HasPrefix(s, "v1,") {
			t.Fatalf("signature %q missing v1, prefix", s)
		}
	}
	// The header joins them with ", " (upstream), so both are presented.
	header := strings.Join(sigs, ", ")
	if !strings.Contains(header, sigs[0]) || !strings.Contains(header, sigs[1]) {
		t.Fatalf("header %q must carry both signatures", header)
	}
}

func TestHTTPHookDispatchSignsAndDecodes(t *testing.T) {
	secret := "v1,whsec_MDEyMzQ1Njc4OWFiY2RlZg=="
	var gotHeaders http.Header
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"claims":{"role":"authenticated","added":"yes"}}`))
	}))
	defer srv.Close()

	cfg := HookEndpointConfig{Enabled: true, URI: srv.URL, Secrets: []string{secret}}
	in := map[string]any{"hello": "world"}
	out := &CustomAccessTokenOutput{}
	if err := testHookAPI(nil).runExtHook(context.Background(), cfg, nil, in, out); err != nil {
		t.Fatalf("runExtHook: %v", err)
	}

	// The response was decoded.
	if out.Claims["added"] != "yes" {
		t.Fatalf("out.Claims = %v, want added=yes", out.Claims)
	}

	// The request carried a valid Standard Webhooks signature over its own
	// id/timestamp/body.
	if gotHeaders.Get("Content-Type") != "application/json" {
		t.Fatalf("content-type = %q", gotHeaders.Get("Content-Type"))
	}
	id := gotHeaders.Get("webhook-id")
	tsStr := gotHeaders.Get("webhook-timestamp")
	sig := gotHeaders.Get("webhook-signature")
	if id == "" || tsStr == "" || sig == "" {
		t.Fatalf("missing webhook headers: id=%q ts=%q sig=%q", id, tsStr, sig)
	}
	tsInt, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		t.Fatalf("bad timestamp header %q: %v", tsStr, err)
	}
	want, err := signHookPayload([]string{secret}, id, time.Unix(tsInt, 0), gotBody)
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	if sig != want[0] {
		t.Fatalf("signature header = %q, want %q", sig, want[0])
	}
}

func TestHTTPHookTimeout(t *testing.T) {
	defer restoreHTTPHookDefaults(swapHTTPHookDefaults(50*time.Millisecond, 1, 0))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	cfg := HookEndpointConfig{Enabled: true, URI: srv.URL, Secrets: []string{"v1,whsec_MDEyMzQ1Njc4OWFiY2RlZg=="}}
	err := testHookAPI(nil).runExtHook(context.Background(), cfg, nil, map[string]any{}, &SendEmailOutput{})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	he, ok := err.(*HTTPError)
	if !ok {
		t.Fatalf("error type = %T, want *HTTPError", err)
	}
	if he.ErrorCode != ErrorCodeHookTimeout && he.ErrorCode != ErrorCodeHookTimeoutAfterRetry {
		t.Fatalf("error code = %q, want a hook timeout code", he.ErrorCode)
	}
}

func TestHTTPHookErrorEnvelopeRejects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"error":{"http_code":403,"message":"nope"}}`))
	}))
	defer srv.Close()

	cfg := HookEndpointConfig{Enabled: true, URI: srv.URL, Secrets: []string{"v1,whsec_MDEyMzQ1Njc4OWFiY2RlZg=="}}
	err := testHookAPI(nil).runExtHook(context.Background(), cfg, nil, map[string]any{}, &BeforeUserCreatedOutput{})
	if err == nil {
		t.Fatal("expected a rejection error")
	}
	he, ok := err.(*HTTPError)
	if !ok {
		t.Fatalf("error type = %T, want *HTTPError", err)
	}
	if he.HTTPStatus != 403 || he.Message != "nope" {
		t.Fatalf("error = %d %q, want 403 nope", he.HTTPStatus, he.Message)
	}
}

func TestHTTPHook4xxStatusRejects(t *testing.T) {
	defer restoreHTTPHookDefaults(swapHTTPHookDefaults(2*time.Second, 1, 0))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad", http.StatusBadRequest)
	}))
	defer srv.Close()

	cfg := HookEndpointConfig{Enabled: true, URI: srv.URL, Secrets: []string{"v1,whsec_MDEyMzQ1Njc4OWFiY2RlZg=="}}
	err := testHookAPI(nil).runExtHook(context.Background(), cfg, nil, map[string]any{}, &SendSMSOutput{})
	if err == nil {
		t.Fatal("expected an error for HTTP 400")
	}
	he, ok := err.(*HTTPError)
	if !ok {
		t.Fatalf("error type = %T, want *HTTPError", err)
	}
	if he.HTTPStatus != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (invalid payload sent to hook)", he.HTTPStatus)
	}
}

func TestHTTPHookDisabledIsNoop(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("disabled hook must not be called")
	}))
	defer srv.Close()
	cfg := HookEndpointConfig{Enabled: false, URI: srv.URL}
	out := &CustomAccessTokenOutput{Claims: map[string]any{"untouched": true}}
	if err := testHookAPI(nil).runExtHook(context.Background(), cfg, nil, map[string]any{}, out); err != nil {
		t.Fatalf("disabled hook returned error: %v", err)
	}
	if out.Claims["untouched"] != true {
		t.Fatalf("disabled hook must leave out untouched, got %v", out.Claims)
	}
}

// TestCustomAccessTokenOutputMissingClaims pins upstream's contract: a response
// without a `claims` field is a hard error.
func TestCustomAccessTokenOutputMissingClaims(t *testing.T) {
	var out CustomAccessTokenOutput
	if err := json.Unmarshal([]byte(`{}`), &out); err == nil {
		t.Fatal("expected an error for missing claims field")
	}
	if err := json.Unmarshal([]byte(`{"claims":{"a":1}}`), &out); err != nil {
		t.Fatalf("valid claims should decode: %v", err)
	}
	if out.Claims["a"] != float64(1) {
		t.Fatalf("claims = %v", out.Claims)
	}
}

// ---- helpers for swapping the tunable HTTP hook defaults -------------------

type httpHookDefaults struct {
	timeout time.Duration
	retries int
	backoff time.Duration
}

func swapHTTPHookDefaults(timeout time.Duration, retries int, backoff time.Duration) httpHookDefaults {
	prev := httpHookDefaults{httpHookTimeout, httpHookRetries, httpHookBackoff}
	httpHookTimeout, httpHookRetries, httpHookBackoff = timeout, retries, backoff
	return prev
}

func restoreHTTPHookDefaults(prev httpHookDefaults) {
	httpHookTimeout, httpHookRetries, httpHookBackoff = prev.timeout, prev.retries, prev.backoff
}

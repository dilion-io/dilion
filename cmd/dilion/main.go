// Command dilion runs the Dilion server: Supabase Auth compatible auth plus the
// privacy/compliance plane.
//
// Configuration (environment):
//
//	DILION_DSN            Postgres connection string (required)
//	DILION_JWT_SECRET     HS256 secret for the /auth/v1 surface
//	DILION_MASTER_KEY     base64-encoded 32-byte KEK for the built-in KMS
//	DILION_ADDR           listen address (default :8787)
//	DILION_METRICS_ADDR   Prometheus /metrics listener, e.g. :9090 (default off)
//	DILION_POLICY_FILE    optional compliance policy YAML (merged onto built-ins)
//	DILION_PII_FIELDS_FILE   optional PII vault field definitions YAML
//	                         (pii-fields: {<key>: {hint: EMAIL|NAME|PHONE|ADDRESS|GENERIC}});
//	                         omit for free-form PII fields
//	DILION_LOG_LEVEL      debug | info | warn | error (default info)
//	DILION_DEV_NO_ADMIN_MFA  set to 1/true to disable admin MFA (development only)
//
// Missing secrets are generated per boot, which is only useful for local
// development: tokens stop verifying and stored PII becomes unreadable after a
// restart. The server logs a warning in that case.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	dilion "github.com/dilion-io/dilion"
)

func main() {
	if err := run(); err != nil {
		slog.Error("dilion: fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	setupLogging()

	dsn := os.Getenv("DILION_DSN")
	if dsn == "" {
		return errors.New("DILION_DSN is required")
	}

	opts := []dilion.Option{dilion.WithDSN(dsn)}
	if addr := os.Getenv("DILION_ADDR"); addr != "" {
		opts = append(opts, dilion.WithAddr(addr))
	}
	if addr := os.Getenv("DILION_METRICS_ADDR"); addr != "" {
		opts = append(opts, dilion.WithMetricsAddr(addr))
	}
	if secret := os.Getenv("DILION_JWT_SECRET"); secret != "" {
		opts = append(opts, dilion.WithJWTSecret([]byte(secret)))
	}
	if raw := os.Getenv("DILION_MASTER_KEY"); raw != "" {
		key, err := decodeBase64(raw)
		if err != nil {
			return fmt.Errorf("DILION_MASTER_KEY: %w", err)
		}
		opts = append(opts, dilion.WithMasterKey(key))
	}
	if path := os.Getenv("DILION_POLICY_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("DILION_POLICY_FILE: %w", err)
		}
		opts = append(opts, dilion.WithPolicyYAML(b))
	}
	if path := os.Getenv("DILION_PII_FIELDS_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("DILION_PII_FIELDS_FILE: %w", err)
		}
		opts = append(opts, dilion.WithPIIFieldsYAML(b))
	}
	// Comma-separated IPs/CIDRs, or "*": see dilion.WithTrustedProxies and
	// dilion.WithOutboundNetworks.
	if v := os.Getenv("DILION_TRUSTED_PROXIES"); v != "" {
		opts = append(opts, dilion.WithTrustedProxies(v))
	}
	if v := os.Getenv("DILION_OUTBOUND_ALLOWED_NETWORKS"); v != "" {
		opts = append(opts, dilion.WithOutboundNetworks(v))
	}
	// Go durations ("30s", "1h"): see dilion.WithPrivacyWorkerIntervals.
	var poll, retention time.Duration
	for name, d := range map[string]*time.Duration{
		"DILION_PRIVACY_POLL_INTERVAL":      &poll,
		"DILION_PRIVACY_RETENTION_INTERVAL": &retention,
	} {
		if v := os.Getenv(name); v != "" {
			parsed, err := time.ParseDuration(v)
			if err != nil || parsed <= 0 {
				return fmt.Errorf("%s: want a positive duration such as 30s, got %q", name, v)
			}
			*d = parsed
		}
	}
	if poll > 0 || retention > 0 {
		opts = append(opts, dilion.WithPrivacyWorkerIntervals(poll, retention))
	}
	if truthy(os.Getenv("DILION_DEV_NO_ADMIN_MFA")) {
		opts = append(opts, dilion.WithoutAdminMFA())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Go's profiler (CPU, heap, goroutines), on a listener of its own and only
	// when asked for: it reveals internals and costs CPU, so bind it to
	// loopback ("127.0.0.1:6060") and never expose it. The load test
	// (test/perf) profiles the server through it.
	if addr := os.Getenv("DILION_PPROF_ADDR"); addr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		go func() {
			srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
			if err := srv.ListenAndServe(); err != nil {
				slog.Error("dilion: pprof listener stopped", "addr", addr, "error", err)
			}
		}()
		slog.Warn("dilion: profiler enabled; keep it off public interfaces", "addr", addr)
	}

	srv, err := dilion.NewServer(opts...)
	if err != nil {
		return err
	}
	defer func() { _ = srv.Close() }()

	if err := srv.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return srv.Start(ctx)
}

func setupLogging() {
	level := slog.LevelInfo
	if v := os.Getenv("DILION_LOG_LEVEL"); v != "" {
		if err := level.UnmarshalText([]byte(v)); err != nil {
			slog.Warn("dilion: unknown DILION_LOG_LEVEL, using info", "value", v)
		}
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})))
}

// decodeBase64 accepts standard and URL alphabets, padded or not.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	encodings := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not valid base64")
}

func truthy(s string) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(s))
	return err == nil && b
}

// Command dilion runs the Dilion server: Supabase Auth compatible auth plus the
// privacy/compliance plane.
//
// Configuration (environment):
//
//	DILION_DSN            Postgres connection string (required)
//	DILION_JWT_SECRET     HS256 secret for the /auth/v1 surface
//	DILION_MASTER_KEY     base64-encoded 32-byte KEK for the built-in KMS
//	DILION_ADDR           listen address (default :8787)
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
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

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
	if truthy(os.Getenv("DILION_DEV_NO_ADMIN_MFA")) {
		opts = append(opts, dilion.WithoutAdminMFA())
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

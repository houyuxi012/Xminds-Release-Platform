package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"xminds-release-platform/internal/platform/buildinfo"
	"xminds-release-platform/internal/platform/config"
	"xminds-release-platform/internal/platform/database"
)

var errHandlersNotConfigured = errors.New("worker job handlers are not configured")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, config.CurrentEnvironment()); err != nil {
		logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
		logger.Error("release-worker terminated", "error", err, "version", buildinfo.Current().Version)
		os.Exit(1)
	}
}

func run(ctx context.Context, environ map[string]string) error {
	configuration, err := config.Load(environ)
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	if configuration.DatabaseURL == "" {
		return config.ErrDatabaseURLRequired
	}
	pool, err := database.Open(ctx, configuration.DatabaseURL)
	if err != nil {
		return err
	}
	pool.Close()
	return errHandlersNotConfigured
}

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"xminds-release-platform/internal/platform/buildinfo"
	"xminds-release-platform/internal/platform/config"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/internal/platform/httpserver"
	"xminds-release-platform/migrations"
)

var errUsage = errors.New("usage: release-api <serve|migrate>")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], config.CurrentEnvironment()); err != nil {
		logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
		logger.Error("release-api terminated", "error", err, "version", buildinfo.Current().Version)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, environ map[string]string) error {
	if len(arguments) != 1 || (arguments[0] != "serve" && arguments[0] != "migrate") {
		return errUsage
	}

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
	defer pool.Close()

	if arguments[0] == "migrate" {
		if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
			return fmt.Errorf("apply database migrations: %w", err)
		}
		return nil
	}

	server := &http.Server{
		Addr:              configuration.APIListen,
		Handler:           httpserver.NewHandler(pool, buildinfo.Current()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve management API: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown management API: %w", err)
		}
		return nil
	}
}

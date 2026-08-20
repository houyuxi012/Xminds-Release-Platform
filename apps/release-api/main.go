package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"xminds-release-platform/internal/artifact"
	"xminds-release-platform/internal/catalog"
	"xminds-release-platform/internal/platform/buildinfo"
	"xminds-release-platform/internal/platform/config"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/internal/platform/httpserver"
	"xminds-release-platform/internal/platform/objectstore"
	"xminds-release-platform/migrations"
)

var errUsage = errors.New("usage: release-api <serve|migrate>")
var errAPIRuntimeConfiguration = errors.New("API runtime configuration is invalid")

type apiRuntimeConfig struct {
	ObjectStoreAccessKey string
	ObjectStoreSecretKey string
	Region               string
	SessionToken         string
	DefaultProductID     string
	DefaultChannel       string
}

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
	runtimeConfig, err := loadAPIRuntimeConfig(environ)
	if err != nil {
		return err
	}
	if configuration.APIListen == configuration.PublicListen {
		return fmt.Errorf("management and public listen addresses must differ: %w", errAPIRuntimeConfiguration)
	}
	store, err := objectstore.NewMinIOStore(objectstore.MinIOConfig{
		EndpointURL:  configuration.ObjectStoreURL,
		Bucket:       configuration.ObjectBucket,
		Region:       runtimeConfig.Region,
		AccessKey:    runtimeConfig.ObjectStoreAccessKey,
		SecretKey:    runtimeConfig.ObjectStoreSecretKey,
		SessionToken: runtimeConfig.SessionToken,
	})
	if err != nil {
		return fmt.Errorf("configure API object store: %w", err)
	}
	publicHandler, err := catalog.NewPublicHTTPHandler(catalog.PublicHTTPConfig{
		DefaultProductID: runtimeConfig.DefaultProductID,
		DefaultChannel:   runtimeConfig.DefaultChannel,
		Catalogs:         catalog.NewPostgresRepository(pool),
		Artifacts:        artifact.NewPostgresRepository(pool),
		Store:            store,
	})
	if err != nil {
		return fmt.Errorf("configure public distribution API: %w", err)
	}

	managementServer := &http.Server{
		Addr:              configuration.APIListen,
		Handler:           httpserver.NewHandler(pool, buildinfo.Current()),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	publicServer := &http.Server{
		Addr:              configuration.PublicListen,
		Handler:           publicHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	return serveAPIServers(ctx, managementServer, publicServer)
}

func loadAPIRuntimeConfig(environ map[string]string) (apiRuntimeConfig, error) {
	result := apiRuntimeConfig{
		ObjectStoreAccessKey: strings.TrimSpace(environ["XMINDS_RELEASE_OBJECT_STORE_ACCESS_KEY"]),
		ObjectStoreSecretKey: strings.TrimSpace(environ["XMINDS_RELEASE_OBJECT_STORE_SECRET_KEY"]),
		Region:               strings.TrimSpace(environ["XMINDS_RELEASE_OBJECT_STORE_REGION"]),
		SessionToken:         strings.TrimSpace(environ["XMINDS_RELEASE_OBJECT_STORE_SESSION_TOKEN"]),
		DefaultProductID:     strings.TrimSpace(environ["XMINDS_RELEASE_DEFAULT_PRODUCT_ID"]),
		DefaultChannel:       strings.TrimSpace(environ["XMINDS_RELEASE_DEFAULT_CHANNEL"]),
	}
	if result.ObjectStoreAccessKey == "" || result.ObjectStoreSecretKey == "" || result.DefaultProductID == "" || result.DefaultChannel == "" {
		return apiRuntimeConfig{}, errAPIRuntimeConfiguration
	}
	return result, nil
}

type apiServerResult struct {
	name string
	err  error
}

func serveAPIServers(ctx context.Context, management, public *http.Server) error {
	results := make(chan apiServerResult, 2)
	go func() { results <- apiServerResult{name: "management", err: management.ListenAndServe()} }()
	go func() { results <- apiServerResult{name: "public", err: public.ListenAndServe()} }()

	select {
	case result := <-results:
		shutdownErr := shutdownAPIServers(context.Background(), management, public)
		if !errors.Is(result.err, http.ErrServerClosed) {
			return errors.Join(fmt.Errorf("serve %s API: %w", result.name, result.err), shutdownErr)
		}
		return shutdownErr
	case <-ctx.Done():
		return shutdownAPIServers(context.WithoutCancel(ctx), management, public)
	}
}

func shutdownAPIServers(parent context.Context, servers ...*http.Server) error {
	shutdownCtx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	var result error
	for _, server := range servers {
		if err := server.Shutdown(shutdownCtx); err != nil {
			result = errors.Join(result, fmt.Errorf("shutdown %s: %w", server.Addr, err))
		}
	}
	return result
}

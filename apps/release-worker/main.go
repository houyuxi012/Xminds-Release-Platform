package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/catalog"
	"xminds-release-platform/internal/iam"
	"xminds-release-platform/internal/platform/buildinfo"
	"xminds-release-platform/internal/platform/config"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/platform/objectstore"
	"xminds-release-platform/internal/product"
	"xminds-release-platform/internal/release"
	"xminds-release-platform/internal/signing"
)

const (
	defaultWorkerPollInterval = time.Second
	minimumWorkerPollInterval = 100 * time.Millisecond
	maximumWorkerPollInterval = time.Minute
	maximumCatalogRootBytes   = 4 * 1024 * 1024
)

var errWorkerRuntimeConfiguration = errors.New("worker runtime configuration is invalid")

type workerRuntimeConfig struct {
	ObjectStoreAccessKey string
	ObjectStoreSecretKey string
	Region               string
	SessionToken         string
	SigningKeyDirectory  string
	SigningMasterKeyPath string
	CatalogRootPath      string
	KeyRefs              catalog.RoleKeyRefs
	AuditExportTempDir   string
	PollInterval         time.Duration
	Directory            iam.DirectoryRuntimeConfig
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, config.CurrentEnvironment()); err != nil && !errors.Is(err, context.Canceled) {
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
	runtimeConfig, err := loadWorkerRuntimeConfig(environ)
	if err != nil {
		return err
	}
	pool, err := database.Open(ctx, configuration.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	store, err := objectstore.NewMinIOStore(objectstore.MinIOConfig{
		EndpointURL: configuration.ObjectStoreURL,
		Bucket:      configuration.ObjectBucket, Region: runtimeConfig.Region,
		AccessKey: runtimeConfig.ObjectStoreAccessKey, SecretKey: runtimeConfig.ObjectStoreSecretKey,
		SessionToken: runtimeConfig.SessionToken,
	})
	if err != nil {
		return fmt.Errorf("configure worker object store: %w", err)
	}
	if err := store.EnsureBucket(ctx); err != nil {
		return fmt.Errorf("prepare worker object bucket: %w", err)
	}

	provider, err := signing.NewLocalEncryptedProvider(runtimeConfig.SigningKeyDirectory, runtimeConfig.SigningMasterKeyPath)
	if err != nil {
		return fmt.Errorf("configure catalog signing provider: %w", err)
	}
	root, err := readCatalogRoot(runtimeConfig.CatalogRootPath)
	if err != nil {
		return err
	}
	products := product.NewPostgresRepository(pool)
	targets, err := catalog.NewRepositoryTargetResolver(products)
	if err != nil {
		return fmt.Errorf("configure catalog target resolver: %w", err)
	}
	builder, err := catalog.NewBuilder(catalog.BuilderConfig{
		Root: root, Provider: provider, KeyRefs: runtimeConfig.KeyRefs, Resolver: targets, Clock: time.Now,
	})
	if err != nil {
		return fmt.Errorf("configure catalog builder: %w", err)
	}

	transactor := release.PoolTransactor{Pool: pool}
	auditRepository := audit.NewPostgresRepository(pool)
	auditor := audit.NewService(auditRepository)
	publication, err := catalog.NewPublicationService(catalog.PublicationConfig{
		Catalogs: catalog.NewPostgresRepository(pool), Releases: release.NewPostgresRepository(pool),
		Transactor: transactor, Builder: builder, Store: store, Auditor: auditor, Clock: time.Now,
	})
	if err != nil {
		return fmt.Errorf("configure catalog publication handler: %w", err)
	}
	exportHandler, err := audit.NewExportHandler(audit.ExportHandlerConfig{
		Repository: auditRepository, Transactor: transactor, Store: store, Auditor: auditor,
		Clock: time.Now, TempDir: runtimeConfig.AuditExportTempDir,
	})
	if err != nil {
		return fmt.Errorf("configure audit export handler: %w", err)
	}
	directorySecrets, err := iam.NewDirectorySecretResolver(runtimeConfig.Directory.SecretDirectory)
	if err != nil {
		return fmt.Errorf("configure IAM directory secret resolver: %w", err)
	}
	defer directorySecrets.Close()
	directoryAdapter, err := iam.NewSecretBackedDirectoryAdapter(iam.SecretBackedDirectoryAdapterConfig{
		Secrets: directorySecrets, RequestTimeout: runtimeConfig.Directory.RequestTimeout,
		MaximumPages: runtimeConfig.Directory.MaximumPages, MaximumObjects: runtimeConfig.Directory.MaximumObjects,
		AllowLoopbackHTTP: runtimeConfig.Directory.AllowLoopbackHTTP, AllowPrivateNetworks: runtimeConfig.Directory.AllowPrivateNetworks,
	})
	if err != nil {
		return fmt.Errorf("configure IAM directory adapter: %w", err)
	}
	iamRepository := iam.NewPostgresRepository(pool)
	directoryExecutor, err := iam.NewPostgresDirectorySyncExecutor(iam.PostgresDirectorySyncExecutorConfig{
		Pool: pool, Auditor: auditor, Sessions: iamRepository, Clock: time.Now,
	})
	if err != nil {
		return fmt.Errorf("configure IAM directory sync executor: %w", err)
	}
	directoryHandler, err := iam.NewDirectorySyncHandler(iam.DirectorySyncHandlerConfig{
		Executor: directoryExecutor, Directory: directoryAdapter,
	})
	if err != nil {
		return fmt.Errorf("configure IAM directory sync handler: %w", err)
	}

	handlers := jobs.NewHandlerRegistry(map[string]jobs.Handler{
		catalog.JobKindCatalogPublish: publication,
		catalog.JobKindCatalogRevoke:  publication,
		audit.JobKindAuditExport:      exportHandler,
		iam.JobKindDirectorySync:      directoryHandler,
	})
	deadLetters := jobs.NewDeadLetterRegistry(map[string]jobs.DeadLetterHandler{
		catalog.JobKindCatalogPublish: publication,
		catalog.JobKindCatalogRevoke:  publication,
		audit.JobKindAuditExport:      exportHandler,
		iam.JobKindDirectorySync:      directoryHandler,
	})
	renewInterval := configuration.JobLease / 3
	if renewInterval > 10*time.Second {
		renewInterval = 10 * time.Second
	}
	worker, err := jobs.NewWorker(jobs.WorkerConfig{
		Owner: configuration.WorkerID, Repository: jobs.NewPostgresRepository(pool), Handlers: handlers,
		DeadLetters: deadLetters, LeaseDuration: configuration.JobLease, RenewInterval: renewInterval,
	})
	if err != nil {
		return fmt.Errorf("configure durable worker: %w", err)
	}
	return worker.Run(ctx, runtimeConfig.PollInterval)
}

func loadWorkerRuntimeConfig(environ map[string]string) (workerRuntimeConfig, error) {
	result := workerRuntimeConfig{
		ObjectStoreAccessKey: strings.TrimSpace(environ["XMINDS_RELEASE_OBJECT_STORE_ACCESS_KEY"]),
		ObjectStoreSecretKey: strings.TrimSpace(environ["XMINDS_RELEASE_OBJECT_STORE_SECRET_KEY"]),
		Region:               strings.TrimSpace(environ["XMINDS_RELEASE_OBJECT_STORE_REGION"]),
		SessionToken:         strings.TrimSpace(environ["XMINDS_RELEASE_OBJECT_STORE_SESSION_TOKEN"]),
		SigningKeyDirectory:  filepath.Clean(strings.TrimSpace(environ["XMINDS_RELEASE_SIGNING_KEY_DIRECTORY"])),
		SigningMasterKeyPath: filepath.Clean(strings.TrimSpace(environ["XMINDS_RELEASE_SIGNING_MASTER_KEY_PATH"])),
		CatalogRootPath:      filepath.Clean(strings.TrimSpace(environ["XMINDS_RELEASE_CATALOG_ROOT_PATH"])),
		AuditExportTempDir:   strings.TrimSpace(environ["XMINDS_RELEASE_AUDIT_EXPORT_TEMP_DIR"]),
		PollInterval:         defaultWorkerPollInterval,
	}
	if result.ObjectStoreAccessKey == "" || result.ObjectStoreSecretKey == "" ||
		!absoluteConfiguredPath(environ["XMINDS_RELEASE_SIGNING_KEY_DIRECTORY"]) ||
		!absoluteConfiguredPath(environ["XMINDS_RELEASE_SIGNING_MASTER_KEY_PATH"]) ||
		!absoluteConfiguredPath(environ["XMINDS_RELEASE_CATALOG_ROOT_PATH"]) {
		return workerRuntimeConfig{}, errWorkerRuntimeConfiguration
	}
	if result.AuditExportTempDir != "" {
		if !filepath.IsAbs(result.AuditExportTempDir) {
			return workerRuntimeConfig{}, errWorkerRuntimeConfiguration
		}
		result.AuditExportTempDir = filepath.Clean(result.AuditExportTempDir)
	}
	var err error
	result.KeyRefs.Targets, err = parseKeyRefs(environ["XMINDS_RELEASE_CATALOG_TARGETS_KEY_REFS"])
	if err != nil {
		return workerRuntimeConfig{}, err
	}
	result.KeyRefs.Snapshot, err = parseKeyRefs(environ["XMINDS_RELEASE_CATALOG_SNAPSHOT_KEY_REFS"])
	if err != nil {
		return workerRuntimeConfig{}, err
	}
	result.KeyRefs.Timestamp, err = parseKeyRefs(environ["XMINDS_RELEASE_CATALOG_TIMESTAMP_KEY_REFS"])
	if err != nil {
		return workerRuntimeConfig{}, err
	}
	result.KeyRefs.Revocation, err = parseKeyRefs(environ["XMINDS_RELEASE_CATALOG_REVOCATION_KEY_REFS"])
	if err != nil {
		return workerRuntimeConfig{}, err
	}
	if raw := strings.TrimSpace(environ["XMINDS_RELEASE_WORKER_POLL_INTERVAL"]); raw != "" {
		result.PollInterval, err = time.ParseDuration(raw)
		if err != nil || result.PollInterval < minimumWorkerPollInterval || result.PollInterval > maximumWorkerPollInterval {
			return workerRuntimeConfig{}, errWorkerRuntimeConfiguration
		}
	}
	result.Directory, err = iam.LoadDirectoryRuntimeConfig(environ, environ["XMINDS_RELEASE_ENVIRONMENT"])
	if err != nil {
		return workerRuntimeConfig{}, errWorkerRuntimeConfiguration
	}
	return result, nil
}

func absoluteConfiguredPath(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	return trimmed != "" && filepath.IsAbs(trimmed)
}

func parseKeyRefs(raw string) ([]string, error) {
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, errWorkerRuntimeConfiguration
		}
		if _, duplicate := seen[part]; duplicate {
			return nil, errWorkerRuntimeConfiguration
		}
		seen[part] = struct{}{}
		result = append(result, part)
	}
	return result, nil
}

func readCatalogRoot(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open catalog root: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximumCatalogRootBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read catalog root: %w", err)
	}
	if len(raw) == 0 || len(raw) > maximumCatalogRootBytes {
		return nil, errWorkerRuntimeConfiguration
	}
	return raw, nil
}

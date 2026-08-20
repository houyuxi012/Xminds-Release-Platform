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

	"github.com/go-chi/chi/v5"

	"xminds-release-platform/internal/artifact"
	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/catalog"
	"xminds-release-platform/internal/endpoint"
	"xminds-release-platform/internal/iam"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/buildinfo"
	"xminds-release-platform/internal/platform/config"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/internal/platform/httpserver"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/platform/objectstore"
	"xminds-release-platform/internal/product"
	"xminds-release-platform/internal/release"
	"xminds-release-platform/migrations"
)

var errUsage = errors.New("usage: release-api <serve|migrate>")
var errAPIRuntimeConfiguration = errors.New("API runtime configuration is invalid")

type apiRuntimeConfig struct {
	ObjectStoreAccessKey string
	ObjectStoreSecretKey string
	Region               string
	SessionToken         string
	EndpointCADirectory  string
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
	humanVerifier, err := identity.NewOIDCVerifier(ctx, identity.OIDCVerifierConfig{
		Issuer: configuration.OIDCIssuer, Audience: configuration.OIDCAudience,
	})
	if err != nil {
		return fmt.Errorf("configure human OIDC identity: %w", err)
	}
	workloadVerifier, err := identity.NewWorkloadVerifier(ctx, identity.OIDCVerifierConfig{
		Issuer: configuration.OIDCIssuer, Audience: configuration.OIDCAudience,
	})
	if err != nil {
		return fmt.Errorf("configure workload OIDC identity: %w", err)
	}
	managementVerifier, err := identity.NewManagementVerifier(
		humanVerifier,
		workloadVerifier,
		identity.NewAPITokenVerifier(identity.NewPostgresAPITokenStore(pool)),
	)
	if err != nil {
		return fmt.Errorf("configure management identity: %w", err)
	}

	jobRepository := jobs.NewPostgresRepository(pool)
	auditRepository := audit.NewPostgresRepository(pool)
	auditor := audit.NewService(auditRepository, jobRepository)
	productRepository := product.NewPostgresRepository(pool)
	productService := product.NewService(productRepository, product.PoolTransactor{Pool: pool}, auditor)
	artifactRepository := artifact.NewPostgresRepository(pool)
	artifactService := artifact.NewService(
		artifactRepository,
		artifact.PoolTransactor{Pool: pool},
		productRepository,
		store,
		auditor,
		jobRepository,
	)
	releaseRepository := release.NewPostgresRepository(pool)
	releaseService := release.NewService(
		releaseRepository,
		release.PoolTransactor{Pool: pool},
		productRepository,
		artifactService,
		auditor,
		jobRepository,
	)
	var endpointCABundles endpoint.CABundleLoader
	if runtimeConfig.EndpointCADirectory != "" {
		endpointCABundles, err = endpoint.NewDirectoryCABundleLoader(runtimeConfig.EndpointCADirectory)
		if err != nil {
			return fmt.Errorf("configure distribution endpoint CA bundles: %w", err)
		}
	}
	endpointProbe, err := endpoint.NewHTTPProbe(endpoint.HTTPProbeConfig{
		CABundles: endpointCABundles, AllowLoopback: configuration.Environment == "development",
	})
	if err != nil {
		return fmt.Errorf("configure distribution endpoint probe: %w", err)
	}
	endpointRepository := endpoint.NewPostgresRepository(pool)
	endpointService, err := endpoint.NewService(endpoint.ServiceConfig{
		Repository: endpointRepository, Transactor: endpointRepository, Catalogs: catalog.NewPostgresRepository(pool),
		Probe: endpointProbe, Auditor: auditor, DefaultChannel: runtimeConfig.DefaultChannel, Clock: time.Now,
	})
	if err != nil {
		return fmt.Errorf("configure distribution endpoint service: %w", err)
	}
	iamPasswords, err := iam.NewActivationCredentialManager()
	if err != nil {
		return fmt.Errorf("configure IAM activation credentials: %w", err)
	}
	iamService, err := iam.NewService(iam.ServiceConfig{
		Repository: iam.NewPostgresRepository(pool), Auditor: auditor, Passwords: iamPasswords, Clock: time.Now,
	})
	if err != nil {
		return fmt.Errorf("configure IAM service: %w", err)
	}

	managementServer := &http.Server{
		Addr: configuration.APIListen,
		Handler: httpserver.NewManagementHandler(
			pool,
			buildinfo.Current(),
			identity.AuthenticationMiddleware(managementVerifier),
			managementRoutes(managementApplications{
				Products:  productService,
				Artifacts: artifactService,
				Releases:  releaseService,
				Endpoints: endpointService,
				Audits: auditManagementApplication{
					Application: auditor,
					Transactor:  audit.PoolTransactor{Pool: pool},
				},
				IAM: iamService,
			}),
		),
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

type managementApplications struct {
	Products  product.ProductApplication
	Artifacts artifact.ArtifactApplication
	Releases  release.ReleaseApplication
	Endpoints endpoint.EndpointApplication
	Audits    auditManagementApplication
	IAM       iam.IAMApplication
}

type auditManagementApplication struct {
	Application audit.HTTPApplication
	Transactor  audit.HTTPTransactor
}

func managementRoutes(applications managementApplications) httpserver.RouteRegistrar {
	return func(router chi.Router) {
		if applications.Products != nil {
			product.RegisterRoutes(router, applications.Products)
		}
		if applications.Artifacts != nil {
			artifact.RegisterRoutes(router, applications.Artifacts)
		}
		if applications.Releases != nil {
			release.RegisterRoutes(router, applications.Releases)
		}
		if applications.Endpoints != nil {
			endpoint.RegisterRoutes(router, applications.Endpoints)
		}
		if applications.Audits.Application != nil && applications.Audits.Transactor != nil {
			audit.RegisterRoutes(router, applications.Audits.Application, applications.Audits.Transactor)
		}
		if applications.IAM != nil {
			iam.RegisterRoutes(router, applications.IAM)
		}
	}
}

func loadAPIRuntimeConfig(environ map[string]string) (apiRuntimeConfig, error) {
	result := apiRuntimeConfig{
		ObjectStoreAccessKey: strings.TrimSpace(environ["XMINDS_RELEASE_OBJECT_STORE_ACCESS_KEY"]),
		ObjectStoreSecretKey: strings.TrimSpace(environ["XMINDS_RELEASE_OBJECT_STORE_SECRET_KEY"]),
		Region:               strings.TrimSpace(environ["XMINDS_RELEASE_OBJECT_STORE_REGION"]),
		SessionToken:         strings.TrimSpace(environ["XMINDS_RELEASE_OBJECT_STORE_SESSION_TOKEN"]),
		EndpointCADirectory:  strings.TrimSpace(environ["XMINDS_RELEASE_ENDPOINT_CA_DIRECTORY"]),
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

package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// CurrentEnvironment returns a snapshot of the process environment for Load.
func CurrentEnvironment() map[string]string {
	result := make(map[string]string)
	for _, entry := range os.Environ() {
		key, value, found := strings.Cut(entry, "=")
		if found {
			result[key] = value
		}
	}
	return result
}

const (
	defaultEnvironment  = "development"
	defaultAPIListen    = "127.0.0.1:8080"
	defaultPublicListen = "127.0.0.1:8081"
	defaultWorkerID     = "release-worker-development"
	defaultJobLease     = 30 * time.Second
	maximumJobLease     = 24 * time.Hour
)

var (
	ErrEnvironmentInvalid        = errors.New("environment is invalid")
	ErrDatabaseURLRequired       = errors.New("database URL is required")
	ErrObjectStoreURLRequired    = errors.New("object store URL is required")
	ErrObjectBucketRequired      = errors.New("object bucket is required")
	ErrOIDCIssuerRequired        = errors.New("OIDC issuer is required")
	ErrOIDCAudienceRequired      = errors.New("OIDC audience is required")
	ErrWorkerIDRequired          = errors.New("worker ID is required")
	ErrLocalAdminDevelopmentOnly = errors.New("local admin is allowed only in development")
	ErrLocalAdminInvalid         = errors.New("local admin flag is invalid")
	ErrJobLeaseInvalid           = errors.New("job lease is invalid")
	ErrListenAddressInvalid      = errors.New("listen address is invalid")
	ErrServiceURLInvalid         = errors.New("service URL is invalid")
)

type Config struct {
	Environment          string
	APIListen            string
	PublicListen         string
	DatabaseURL          string
	ObjectStoreURL       string
	ObjectBucket         string
	WorkloadOIDCIssuer   string
	WorkloadOIDCAudience string
	LocalAdmin           bool
	WorkerID             string
	JobLease             time.Duration
}

func Load(environ map[string]string) (Config, error) {
	configuration := Config{
		Environment:          valueOrDefault(environ, "XMINDS_RELEASE_ENVIRONMENT", defaultEnvironment),
		APIListen:            valueOrDefault(environ, "XMINDS_RELEASE_API_LISTEN", defaultAPIListen),
		PublicListen:         valueOrDefault(environ, "XMINDS_RELEASE_PUBLIC_LISTEN", defaultPublicListen),
		DatabaseURL:          value(environ, "XMINDS_RELEASE_DATABASE_URL"),
		ObjectStoreURL:       value(environ, "XMINDS_RELEASE_OBJECT_STORE_URL"),
		ObjectBucket:         value(environ, "XMINDS_RELEASE_OBJECT_BUCKET"),
		WorkloadOIDCIssuer:   value(environ, "XMINDS_RELEASE_OIDC_ISSUER"),
		WorkloadOIDCAudience: value(environ, "XMINDS_RELEASE_OIDC_AUDIENCE"),
		WorkerID:             valueOrDefault(environ, "XMINDS_RELEASE_WORKER_ID", defaultWorkerID),
		JobLease:             defaultJobLease,
	}
	configuration.Environment = strings.ToLower(configuration.Environment)

	if !validEnvironment(configuration.Environment) {
		return Config{}, ErrEnvironmentInvalid
	}
	if err := validateListenAddress(configuration.APIListen); err != nil {
		return Config{}, fmt.Errorf("API listen: %w", err)
	}
	if err := validateListenAddress(configuration.PublicListen); err != nil {
		return Config{}, fmt.Errorf("public listen: %w", err)
	}

	localAdmin, err := parseOptionalBool(environ, "XMINDS_RELEASE_LOCAL_ADMIN_ENABLED")
	if err != nil {
		return Config{}, err
	}
	configuration.LocalAdmin = localAdmin
	if configuration.LocalAdmin && configuration.Environment != defaultEnvironment {
		return Config{}, ErrLocalAdminDevelopmentOnly
	}

	if rawLease := value(environ, "XMINDS_RELEASE_JOB_LEASE"); rawLease != "" {
		lease, parseErr := time.ParseDuration(rawLease)
		if parseErr != nil || lease <= 0 || lease > maximumJobLease {
			return Config{}, ErrJobLeaseInvalid
		}
		configuration.JobLease = lease
	}

	if configuration.Environment != defaultEnvironment {
		if configuration.DatabaseURL == "" {
			return Config{}, ErrDatabaseURLRequired
		}
		if configuration.ObjectStoreURL == "" {
			return Config{}, ErrObjectStoreURLRequired
		}
		if configuration.ObjectBucket == "" {
			return Config{}, ErrObjectBucketRequired
		}
		if configuration.WorkloadOIDCIssuer == "" {
			return Config{}, ErrOIDCIssuerRequired
		}
		if configuration.WorkloadOIDCAudience == "" {
			return Config{}, ErrOIDCAudienceRequired
		}
		if value(environ, "XMINDS_RELEASE_WORKER_ID") == "" {
			return Config{}, ErrWorkerIDRequired
		}
	}

	if err := validateServiceURL(configuration.ObjectStoreURL); err != nil {
		return Config{}, fmt.Errorf("object store URL: %w", err)
	}
	if err := validateServiceURL(configuration.WorkloadOIDCIssuer); err != nil {
		return Config{}, fmt.Errorf("workload OIDC issuer: %w", err)
	}

	return configuration, nil
}

func value(environ map[string]string, key string) string {
	return strings.TrimSpace(environ[key])
}

func valueOrDefault(environ map[string]string, key string, fallback string) string {
	if result := value(environ, key); result != "" {
		return result
	}
	return fallback
}

func validEnvironment(environment string) bool {
	switch environment {
	case "development", "test", "staging", "production":
		return true
	default:
		return false
	}
}

func validateListenAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return ErrListenAddressInvalid
	}
	return nil
}

func validateServiceURL(rawURL string) error {
	if rawURL == "" {
		return nil
	}
	parsed, err := url.ParseRequestURI(rawURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ErrServiceURLInvalid
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ErrServiceURLInvalid
	}
	return nil
}

func parseOptionalBool(environ map[string]string, key string) (bool, error) {
	raw := value(environ, key)
	if raw == "" {
		return false, nil
	}
	result, err := strconv.ParseBool(raw)
	if err != nil {
		return false, ErrLocalAdminInvalid
	}
	return result, nil
}

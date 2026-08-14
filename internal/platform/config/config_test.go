package config

import (
	"errors"
	"testing"
	"time"
)

func TestLoadRejectsMissingDatabaseURL(t *testing.T) {
	t.Parallel()

	_, err := Load(map[string]string{
		"XMINDS_RELEASE_ENVIRONMENT": "test",
	})
	if !errors.Is(err, ErrDatabaseURLRequired) {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadRejectsEveryRequiredNonDevelopmentSetting(t *testing.T) {
	t.Parallel()

	for _, testCase := range []struct {
		key       string
		wantedErr error
	}{
		{key: "XMINDS_RELEASE_DATABASE_URL", wantedErr: ErrDatabaseURLRequired},
		{key: "XMINDS_RELEASE_OBJECT_STORE_URL", wantedErr: ErrObjectStoreURLRequired},
		{key: "XMINDS_RELEASE_OBJECT_BUCKET", wantedErr: ErrObjectBucketRequired},
		{key: "XMINDS_RELEASE_OIDC_ISSUER", wantedErr: ErrOIDCIssuerRequired},
		{key: "XMINDS_RELEASE_OIDC_AUDIENCE", wantedErr: ErrOIDCAudienceRequired},
		{key: "XMINDS_RELEASE_WORKER_ID", wantedErr: ErrWorkerIDRequired},
	} {
		testCase := testCase
		t.Run(testCase.key, func(t *testing.T) {
			environ := validTestEnvironment()
			delete(environ, testCase.key)

			_, err := Load(environ)
			if !errors.Is(err, testCase.wantedErr) {
				t.Fatalf("Load() error = %v, want %v", err, testCase.wantedErr)
			}
		})
	}
}

func TestLoadIgnoresGenericDatabaseURL(t *testing.T) {
	t.Parallel()

	_, err := Load(map[string]string{
		"XMINDS_RELEASE_ENVIRONMENT": "test",
		"DATABASE_URL":               "postgres://must-not-be-used",
	})
	if !errors.Is(err, ErrDatabaseURLRequired) {
		t.Fatalf("generic DATABASE_URL must be ignored, error = %v", err)
	}
}

func TestLoadRejectsLocalAdminOutsideDevelopment(t *testing.T) {
	t.Parallel()

	environ := validTestEnvironment()
	environ["XMINDS_RELEASE_LOCAL_ADMIN_ENABLED"] = "true"

	_, err := Load(environ)
	if !errors.Is(err, ErrLocalAdminDevelopmentOnly) {
		t.Fatalf("error = %v", err)
	}
}

func TestLoadParsesValidatedConfiguration(t *testing.T) {
	t.Parallel()

	environ := validTestEnvironment()
	environ["XMINDS_RELEASE_JOB_LEASE"] = "45s"

	got, err := Load(environ)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Environment != "test" {
		t.Fatalf("Environment = %q", got.Environment)
	}
	if got.JobLease != 45*time.Second {
		t.Fatalf("JobLease = %s", got.JobLease)
	}
	if got.APIListen != "127.0.0.1:8080" {
		t.Fatalf("APIListen = %q", got.APIListen)
	}
}

func validTestEnvironment() map[string]string {
	return map[string]string{
		"XMINDS_RELEASE_ENVIRONMENT":      "test",
		"XMINDS_RELEASE_DATABASE_URL":     "postgres://release:test@127.0.0.1:55432/release?sslmode=disable",
		"XMINDS_RELEASE_OBJECT_STORE_URL": "https://objects.example.test",
		"XMINDS_RELEASE_OBJECT_BUCKET":    "xminds-release",
		"XMINDS_RELEASE_OIDC_ISSUER":      "https://identity.example.test",
		"XMINDS_RELEASE_OIDC_AUDIENCE":    "xminds-release-platform",
		"XMINDS_RELEASE_WORKER_ID":        "worker-test-1",
	}
}

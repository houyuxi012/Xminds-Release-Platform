package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/platform/database"
)

func TestRunRejectsExistingCredentialsOutputBeforeConnectingToDatabase(t *testing.T) {
	t.Parallel()

	repositoryRoot := t.TempDir()
	path := filepath.Join(privateTempDir(t), "credentials.json")
	if err := os.WriteFile(path, []byte("do-not-overwrite"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	err := run(ctx, runtimeFixtureConfig{
		DatabaseURL:    "postgres://user:password@127.0.0.1:1/xminds_release_runtime_test?sslmode=disable",
		APIURL:         "http://127.0.0.1:18080",
		OutputPath:     path,
		RepositoryRoot: repositoryRoot,
		Username:       "runtime.admin",
		DisplayName:    "Runtime Administrator",
		Password:       "Strong-Test-Password!",
	})
	if err == nil || !strings.Contains(err.Error(), "credentials output") {
		t.Fatalf("run() error = %v, want existing credentials output rejection", err)
	}
	content, readErr := os.ReadFile(path)
	if readErr != nil || string(content) != "do-not-overwrite" {
		t.Fatalf("existing output changed: content=%q error=%v", content, readErr)
	}
}

func TestRunCleansSeededAdministratorWhenActivationAPIIsUnavailable(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("XMINDS_RELEASE_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("XMINDS_RELEASE_TEST_DATABASE_URL is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	username := "runtime." + uuid.NewString()
	outputPath := filepath.Join(privateTempDir(t), "credentials.json")
	err := run(ctx, runtimeFixtureConfig{
		DatabaseURL:    databaseURL,
		APIURL:         "http://127.0.0.1:1",
		OutputPath:     outputPath,
		RepositoryRoot: t.TempDir(),
		Username:       username,
		DisplayName:    "Runtime Cleanup Test",
		Password:       "Strong-Test-Password!",
	})
	if err == nil {
		t.Fatal("run() error = nil, want activation API failure")
	}

	pool, openErr := database.Open(ctx, databaseURL)
	if openErr != nil {
		t.Fatal(openErr)
	}
	defer pool.Close()
	var count int
	if queryErr := pool.QueryRow(ctx, `SELECT count(*) FROM user_principals WHERE lower(username)=lower($1)`, username).Scan(&count); queryErr != nil {
		t.Fatal(queryErr)
	}
	if count != 0 {
		t.Fatalf("fixture administrator count = %d, want cleanup; run error=%v", count, err)
	}
	if _, statErr := os.Stat(outputPath); !os.IsNotExist(statErr) {
		t.Fatalf("credentials reservation remains after failure: %v", statErr)
	}
}

func TestValidateRuntimeConfigRejectsUnsafeTargets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		databaseURL string
		apiURL      string
	}{
		{
			name:        "remote database",
			databaseURL: "postgres://user:password@db.example.test:5432/xminds_release_test?sslmode=disable",
			apiURL:      "http://127.0.0.1:18080",
		},
		{
			name:        "non test database",
			databaseURL: "postgres://user:password@127.0.0.1:5432/xminds_release?sslmode=disable",
			apiURL:      "http://127.0.0.1:18080",
		},
		{
			name:        "remote api",
			databaseURL: "postgres://user:password@127.0.0.1:5432/xminds_release_test?sslmode=disable",
			apiURL:      "https://release.example.test",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := validateRuntimeConfig(test.databaseURL, test.apiURL, filepath.Join(t.TempDir(), "credentials.json"), t.TempDir()); err == nil {
				t.Fatal("validateRuntimeConfig() error = nil, want unsafe target rejection")
			}
		})
	}
}

func TestValidateRuntimeConfigRejectsCredentialsInsideRepository(t *testing.T) {
	t.Parallel()

	repositoryRoot := t.TempDir()
	if err := os.Chmod(repositoryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	err := validateRuntimeConfig(
		"postgres://user:password@127.0.0.1:55432/xminds_release_runtime_test?sslmode=disable",
		"http://127.0.0.1:18080",
		filepath.Join(repositoryRoot, "runtime-credentials.json"),
		repositoryRoot,
	)
	if err == nil || !strings.Contains(err.Error(), "outside repository") {
		t.Fatalf("validateRuntimeConfig() error = %v, want repository-contained output rejection", err)
	}
}

func TestValidateRuntimeConfigRejectsPublicCredentialsDirectory(t *testing.T) {
	t.Parallel()

	repositoryRoot := t.TempDir()
	credentialsDirectory := t.TempDir()
	if err := os.Chmod(credentialsDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	err := validateRuntimeConfig(
		"postgres://user:password@127.0.0.1:55432/xminds_release_runtime_test?sslmode=disable",
		"http://127.0.0.1:18080",
		filepath.Join(credentialsDirectory, "runtime-credentials.json"),
		repositoryRoot,
	)
	if err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("validateRuntimeConfig() error = %v, want public directory rejection", err)
	}
}

func TestValidateRuntimeConfigRejectsCredentialsSymlink(t *testing.T) {
	t.Parallel()

	repositoryRoot := t.TempDir()
	credentialsDirectory := privateTempDir(t)
	target := filepath.Join(credentialsDirectory, "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(credentialsDirectory, "credentials.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	err := validateRuntimeConfig(
		"postgres://user:password@127.0.0.1:55432/xminds_release_runtime_test?sslmode=disable",
		"http://127.0.0.1:18080",
		link,
		repositoryRoot,
	)
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("validateRuntimeConfig() error = %v, want symbolic-link rejection", err)
	}
}

func TestValidateRuntimeConfigAcceptsLoopbackTestRuntime(t *testing.T) {
	t.Parallel()

	err := validateRuntimeConfig(
		"postgres://user:password@127.0.0.1:55432/xminds_release_runtime_test?sslmode=disable",
		"http://localhost:18080",
		filepath.Join(privateTempDir(t), "credentials.json"),
		t.TempDir(),
	)
	if err != nil {
		t.Fatalf("validateRuntimeConfig() error = %v", err)
	}
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestGenerateTOTPRFC6238SHA1Vector(t *testing.T) {
	t.Parallel()

	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	proof, err := generateTOTP(secret, time.Unix(59, 0), 8)
	if err != nil {
		t.Fatal(err)
	}
	if proof != "94287082" {
		t.Fatalf("generateTOTP() = %q, want RFC 6238 vector", proof)
	}
}

func TestWriteCredentialsCreatesPrivateFileOnce(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "credentials.json")
	credentials := runtimeCredentials{
		Username:        "runtime.admin",
		Password:        "test-password",
		TOTPSecret:      "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		DisplayName:     "Runtime Administrator",
		TOTPAvailableAt: time.Date(2026, 8, 30, 5, 45, 30, 0, time.UTC),
	}
	if err := writeCredentials(path, credentials); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("credentials mode = %o, want 600", got)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), `"display_name":"Runtime Administrator"`) {
		t.Fatalf("credentials output missing stable display_name field: %s", content)
	}
	if !strings.Contains(string(content), `"totp_available_at":"2026-08-30T05:45:30Z"`) {
		t.Fatalf("credentials output missing TOTP replay boundary: %s", content)
	}
	if err := writeCredentials(path, credentials); err == nil {
		t.Fatal("second writeCredentials() error = nil, want no overwrite")
	}
}

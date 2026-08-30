package main

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"xminds-release-platform/internal/platform/config"
)

func TestRunValidatesConfigurationBeforeConnecting(t *testing.T) {
	t.Parallel()

	err := run(context.Background(), map[string]string{
		"XMINDS_RELEASE_ENVIRONMENT": "test",
	})
	if !errors.Is(err, config.ErrDatabaseURLRequired) {
		t.Fatalf("run() error = %v, want %v", err, config.ErrDatabaseURLRequired)
	}
}

func TestLoadWorkerRuntimeConfigRequiresEverySecretAndSigningSetting(t *testing.T) {
	t.Parallel()

	for _, key := range []string{
		"XMINDS_RELEASE_OBJECT_STORE_ACCESS_KEY",
		"XMINDS_RELEASE_OBJECT_STORE_SECRET_KEY",
		"XMINDS_RELEASE_LOG_ARCHIVE_OBJECT_STORE_URL",
		"XMINDS_RELEASE_LOG_ARCHIVE_OBJECT_BUCKET",
		"XMINDS_RELEASE_LOG_ARCHIVE_OBJECT_STORE_ACCESS_KEY",
		"XMINDS_RELEASE_LOG_ARCHIVE_OBJECT_STORE_SECRET_KEY",
		"XMINDS_RELEASE_SIGNING_KEY_DIRECTORY",
		"XMINDS_RELEASE_SIGNING_MASTER_KEY_PATH",
		"XMINDS_RELEASE_LOG_EXPORT_SIGNING_KEY_DIRECTORY",
		"XMINDS_RELEASE_LOG_EXPORT_SIGNING_MASTER_KEY_PATH",
		"XMINDS_RELEASE_CATALOG_ROOT_PATH",
		"XMINDS_RELEASE_CATALOG_TARGETS_KEY_REFS",
		"XMINDS_RELEASE_CATALOG_SNAPSHOT_KEY_REFS",
		"XMINDS_RELEASE_CATALOG_TIMESTAMP_KEY_REFS",
		"XMINDS_RELEASE_CATALOG_REVOCATION_KEY_REFS",
		"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY",
	} {
		key := key
		t.Run(key, func(t *testing.T) {
			environ := validWorkerRuntimeEnvironment()
			delete(environ, key)

			_, err := loadWorkerRuntimeConfig(environ)
			if !errors.Is(err, errWorkerRuntimeConfiguration) {
				t.Fatalf("loadWorkerRuntimeConfig() error = %v", err)
			}
		})
	}
}

func TestLoadWorkerRuntimeConfigParsesValidatedSettings(t *testing.T) {
	t.Parallel()

	environ := validWorkerRuntimeEnvironment()
	environ["XMINDS_RELEASE_OBJECT_STORE_REGION"] = "cn-east-1"
	environ["XMINDS_RELEASE_OBJECT_STORE_SESSION_TOKEN"] = "temporary-session-token"
	environ["XMINDS_RELEASE_AUDIT_EXPORT_TEMP_DIR"] = "/var/tmp/xminds-audit"
	environ["XMINDS_RELEASE_WORKER_POLL_INTERVAL"] = "750ms"
	environ["XMINDS_RELEASE_LOG_ARCHIVE_RETENTION_DAYS"] = "730"
	environ["XMINDS_RELEASE_CATALOG_TARGETS_KEY_REFS"] = "targets-1, targets-2"

	got, err := loadWorkerRuntimeConfig(environ)
	if err != nil {
		t.Fatalf("loadWorkerRuntimeConfig() error = %v", err)
	}
	if got.PollInterval != 750*time.Millisecond || got.Region != "cn-east-1" || got.SessionToken != "temporary-session-token" || got.AuditExportTempDir != "/var/tmp/xminds-audit" || got.Directory.SecretDirectory != "/run/secrets/iam" || got.LogCursorKeyReference != "secret://iam/log-center-cursor-key" || got.LogCursorTTL != 15*time.Minute || got.LogExportSigningKeyRef != "log-export-archive" || got.LogArchiveRetentionDays != 730 {
		t.Fatalf("parsed runtime config = %+v", got)
	}
	if !reflect.DeepEqual(got.KeyRefs.Targets, []string{"targets-1", "targets-2"}) {
		t.Fatalf("targets key refs = %#v", got.KeyRefs.Targets)
	}
}

func TestLoadWorkerRuntimeConfigKeepsLogExportSecretsIndependent(t *testing.T) {
	t.Parallel()

	environ := validWorkerRuntimeEnvironment()
	environ["XMINDS_RELEASE_LOG_CURSOR_KEY_REFERENCE"] = "secret://iam/worker-log-cursor-key"
	environ["XMINDS_RELEASE_LOG_CURSOR_TTL"] = "30m"
	environ["XMINDS_RELEASE_LOG_EXPORT_SIGNING_KEY_REF"] = "worker-log-export-2026"

	got, err := loadWorkerRuntimeConfig(environ)
	if err != nil {
		t.Fatalf("loadWorkerRuntimeConfig() error = %v", err)
	}
	if got.LogCursorKeyReference != "secret://iam/worker-log-cursor-key" || got.LogCursorTTL != 30*time.Minute || got.LogExportSigningKeyRef != "worker-log-export-2026" {
		t.Fatalf("log export settings = %+v", got)
	}
	if got.LogCursorKeyReference == "secret://iam/directory-conflict-cursor-key" {
		t.Fatal("log cursor reference reused directory cursor reference")
	}
}

func TestLoadWorkerRuntimeConfigRejectsInvalidPollingAndDuplicateKeyRefs(t *testing.T) {
	t.Parallel()

	for name, mutate := range map[string]func(map[string]string){
		"polling too short": func(environ map[string]string) {
			environ["XMINDS_RELEASE_WORKER_POLL_INTERVAL"] = "25ms"
		},
		"duplicate key ref": func(environ map[string]string) {
			environ["XMINDS_RELEASE_CATALOG_TARGETS_KEY_REFS"] = "targets-1,targets-1"
		},
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			environ := validWorkerRuntimeEnvironment()
			mutate(environ)
			if _, err := loadWorkerRuntimeConfig(environ); !errors.Is(err, errWorkerRuntimeConfiguration) {
				t.Fatalf("loadWorkerRuntimeConfig() error = %v", err)
			}
		})
	}
}

func validWorkerRuntimeEnvironment() map[string]string {
	return map[string]string{
		"XMINDS_RELEASE_OBJECT_STORE_ACCESS_KEY":             "worker-access",
		"XMINDS_RELEASE_OBJECT_STORE_SECRET_KEY":             "worker-secret",
		"XMINDS_RELEASE_LOG_ARCHIVE_OBJECT_STORE_URL":        "https://minio-archive.example.invalid",
		"XMINDS_RELEASE_LOG_ARCHIVE_OBJECT_BUCKET":           "xminds-log-archive",
		"XMINDS_RELEASE_LOG_ARCHIVE_OBJECT_STORE_ACCESS_KEY": "archive-access",
		"XMINDS_RELEASE_LOG_ARCHIVE_OBJECT_STORE_SECRET_KEY": "archive-secret",
		"XMINDS_RELEASE_SIGNING_KEY_DIRECTORY":               "/run/secrets/catalog-keys",
		"XMINDS_RELEASE_SIGNING_MASTER_KEY_PATH":             "/run/secrets/catalog-master-key",
		"XMINDS_RELEASE_LOG_EXPORT_SIGNING_KEY_DIRECTORY":    "/run/secrets/log-export-keys",
		"XMINDS_RELEASE_LOG_EXPORT_SIGNING_MASTER_KEY_PATH":  "/run/secrets/log-export-master-key",
		"XMINDS_RELEASE_CATALOG_ROOT_PATH":                   "/etc/xminds/catalog/root.json",
		"XMINDS_RELEASE_CATALOG_TARGETS_KEY_REFS":            "targets-1",
		"XMINDS_RELEASE_CATALOG_SNAPSHOT_KEY_REFS":           "snapshot-1",
		"XMINDS_RELEASE_CATALOG_TIMESTAMP_KEY_REFS":          "timestamp-1",
		"XMINDS_RELEASE_CATALOG_REVOCATION_KEY_REFS":         "revocation-1",
		"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY":            "/run/secrets/iam",
	}
}

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
		"XMINDS_RELEASE_SIGNING_KEY_DIRECTORY",
		"XMINDS_RELEASE_SIGNING_MASTER_KEY_PATH",
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
	environ["XMINDS_RELEASE_CATALOG_TARGETS_KEY_REFS"] = "targets-1, targets-2"

	got, err := loadWorkerRuntimeConfig(environ)
	if err != nil {
		t.Fatalf("loadWorkerRuntimeConfig() error = %v", err)
	}
	if got.PollInterval != 750*time.Millisecond || got.Region != "cn-east-1" || got.SessionToken != "temporary-session-token" || got.AuditExportTempDir != "/var/tmp/xminds-audit" || got.Directory.SecretDirectory != "/run/secrets/iam" {
		t.Fatalf("parsed runtime config = %+v", got)
	}
	if !reflect.DeepEqual(got.KeyRefs.Targets, []string{"targets-1", "targets-2"}) {
		t.Fatalf("targets key refs = %#v", got.KeyRefs.Targets)
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
		"XMINDS_RELEASE_OBJECT_STORE_ACCESS_KEY":     "worker-access",
		"XMINDS_RELEASE_OBJECT_STORE_SECRET_KEY":     "worker-secret",
		"XMINDS_RELEASE_SIGNING_KEY_DIRECTORY":       "/run/secrets/catalog-keys",
		"XMINDS_RELEASE_SIGNING_MASTER_KEY_PATH":     "/run/secrets/catalog-master-key",
		"XMINDS_RELEASE_CATALOG_ROOT_PATH":           "/etc/xminds/catalog/root.json",
		"XMINDS_RELEASE_CATALOG_TARGETS_KEY_REFS":    "targets-1",
		"XMINDS_RELEASE_CATALOG_SNAPSHOT_KEY_REFS":   "snapshot-1",
		"XMINDS_RELEASE_CATALOG_TIMESTAMP_KEY_REFS":  "timestamp-1",
		"XMINDS_RELEASE_CATALOG_REVOCATION_KEY_REFS": "revocation-1",
		"XMINDS_RELEASE_IAM_MFA_SECRET_DIRECTORY":    "/run/secrets/iam",
	}
}

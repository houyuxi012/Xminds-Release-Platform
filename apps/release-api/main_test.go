package main

import (
	"context"
	"errors"
	"testing"

	"xminds-release-platform/internal/platform/config"
)

func TestRunRequiresExplicitCommand(t *testing.T) {
	t.Parallel()

	err := run(context.Background(), nil, map[string]string{})
	if !errors.Is(err, errUsage) {
		t.Fatalf("run() error = %v, want %v", err, errUsage)
	}
}

func TestRunMigrationValidatesConfigurationBeforeConnecting(t *testing.T) {
	t.Parallel()

	err := run(context.Background(), []string{"migrate"}, map[string]string{
		"XMINDS_RELEASE_ENVIRONMENT": "test",
	})
	if !errors.Is(err, config.ErrDatabaseURLRequired) {
		t.Fatalf("run() error = %v, want %v", err, config.ErrDatabaseURLRequired)
	}
}

func TestLoadAPIRuntimeConfigRejectsMissingPublicDistributionSettings(t *testing.T) {
	t.Parallel()

	base := map[string]string{
		"XMINDS_RELEASE_OBJECT_STORE_ACCESS_KEY": "access-key",
		"XMINDS_RELEASE_OBJECT_STORE_SECRET_KEY": "secret-key",
		"XMINDS_RELEASE_DEFAULT_PRODUCT_ID":      "ngep",
		"XMINDS_RELEASE_DEFAULT_CHANNEL":         "stable",
	}
	for _, key := range []string{
		"XMINDS_RELEASE_OBJECT_STORE_ACCESS_KEY",
		"XMINDS_RELEASE_OBJECT_STORE_SECRET_KEY",
		"XMINDS_RELEASE_DEFAULT_PRODUCT_ID",
		"XMINDS_RELEASE_DEFAULT_CHANNEL",
	} {
		t.Run(key, func(t *testing.T) {
			environ := make(map[string]string, len(base))
			for name, value := range base {
				environ[name] = value
			}
			delete(environ, key)
			if _, err := loadAPIRuntimeConfig(environ); !errors.Is(err, errAPIRuntimeConfiguration) {
				t.Fatalf("loadAPIRuntimeConfig() error = %v", err)
			}
		})
	}
}

func TestLoadAPIRuntimeConfigParsesValidatedSettings(t *testing.T) {
	t.Parallel()

	configuration, err := loadAPIRuntimeConfig(map[string]string{
		"XMINDS_RELEASE_OBJECT_STORE_ACCESS_KEY":    " access-key ",
		"XMINDS_RELEASE_OBJECT_STORE_SECRET_KEY":    " secret-key ",
		"XMINDS_RELEASE_OBJECT_STORE_REGION":        " cn-east-1 ",
		"XMINDS_RELEASE_OBJECT_STORE_SESSION_TOKEN": " session-token ",
		"XMINDS_RELEASE_DEFAULT_PRODUCT_ID":         " ngep ",
		"XMINDS_RELEASE_DEFAULT_CHANNEL":            " stable ",
	})
	if err != nil {
		t.Fatalf("loadAPIRuntimeConfig() error = %v", err)
	}
	if configuration.DefaultProductID != "ngep" || configuration.DefaultChannel != "stable" || configuration.Region != "cn-east-1" {
		t.Fatalf("configuration = %+v", configuration)
	}
}

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

package main

import (
	"context"
	"errors"
	"testing"

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

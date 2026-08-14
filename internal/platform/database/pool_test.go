package database

import (
	"context"
	"strings"
	"testing"
)

func TestOpenDoesNotExposePasswordFromInvalidConfiguration(t *testing.T) {
	t.Parallel()

	_, err := Open(context.Background(), "postgres://release:must-not-leak@%zz/release")
	if err == nil {
		t.Fatal("Open() error = nil, want invalid configuration error")
	}
	if strings.Contains(err.Error(), "must-not-leak") {
		t.Fatalf("database password leaked in error: %v", err)
	}
}

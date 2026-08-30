package logcenter

import (
	"errors"
	"testing"
)

func TestRedactMetadataKeepsOnlyAllowlistedScalarSummary(t *testing.T) {
	input := map[string]any{
		"correlation_id": "corr-1",
		"changed_fields": []any{"status"},
	}
	got, err := RedactMetadata(input)
	if err != nil {
		t.Fatalf("RedactMetadata() error = %v", err)
	}
	if got["correlation_id"] != "corr-1" {
		t.Fatalf("correlation_id = %#v", got["correlation_id"])
	}
}

func TestRedactMetadataRejectsSensitiveKeysRecursivelyCaseInsensitively(t *testing.T) {
	_, err := RedactMetadata(map[string]any{
		"trace_id": "trace-1",
		"nested":   map[string]any{"AUTHORIZATION": "secret"},
	})
	if !errors.Is(err, ErrSensitiveMetadata) {
		t.Fatalf("RedactMetadata() error = %v, want ErrSensitiveMetadata", err)
	}
}

func TestRedactMetadataRejectsSensitiveValueAndUnknownKey(t *testing.T) {
	if _, err := RedactMetadata(map[string]any{"reason_summary": "token=secret"}); !errors.Is(err, ErrSensitiveMetadata) {
		t.Fatalf("sensitive value error = %v", err)
	}
	if _, err := RedactMetadata(map[string]any{"unknown": "value"}); !errors.Is(err, ErrMetadataNotAllowlisted) {
		t.Fatalf("unknown key error = %v", err)
	}
}

func TestRedactMetadataRejectsSensitiveAnyStringLeaf(t *testing.T) {
	_, err := RedactMetadata(map[string]any{"changed_fields": []any{"status", "PASSWORD=secret"}})
	if !errors.Is(err, ErrSensitiveMetadata) {
		t.Fatalf("sensitive []any error = %v", err)
	}
}

package logcenter

import (
	"errors"
	"strings"
)

var ErrMetadataNotAllowlisted = errors.New("metadata key is not allowlisted")
var ErrSensitiveMetadata = errors.New("sensitive metadata is not allowed")

var sensitiveMetadataTerms = []string{"authorization", "cookie", "token", "password", "secret", "private_key", "license_key", "query", "body", "recovery_code", "signed_context", "webhook_secret"}

var metadataAllowlist = map[string]bool{
	"correlation_id": true,
	"trace_id":       true,
	"changed_fields": true,
	"version_before": true,
	"version_after":  true,
	"reason_summary": true,
}

func RedactMetadata(input map[string]any) (map[string]any, error) {
	if containsSensitiveMetadata(input) {
		return nil, ErrSensitiveMetadata
	}
	result := make(map[string]any, len(input))
	for key, value := range input {
		if !metadataAllowlist[key] {
			return nil, ErrMetadataNotAllowlisted
		}
		clean, err := allowlistedMetadataValue(key, value)
		if err != nil {
			return nil, err
		}
		result[key] = clean
	}
	return result, nil
}

func containsSensitiveMetadata(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			lower := strings.ToLower(key)
			for _, term := range sensitiveMetadataTerms {
				if strings.Contains(lower, term) {
					return true
				}
			}
			if stringValueContainsSensitive(child) {
				return true
			}
			if containsSensitiveMetadata(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if stringValueContainsSensitive(child) || containsSensitiveMetadata(child) {
				return true
			}
		}
	case []string:
		for _, child := range typed {
			if stringValueContainsSensitive(child) {
				return true
			}
		}
	}
	return false
}

func stringValueContainsSensitive(value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	lower := strings.ToLower(text)
	for _, term := range sensitiveMetadataTerms {
		if strings.Contains(lower, term) {
			return true
		}
	}
	return false
}

func allowlistedMetadataValue(key string, value any) (any, error) {
	switch typed := value.(type) {
	case string:
		if strings.TrimSpace(typed) == "" || len([]rune(typed)) > 256 {
			return nil, ErrMetadataNotAllowlisted
		}
		return typed, nil
	case []string:
		if len(typed) > 64 {
			return nil, ErrMetadataNotAllowlisted
		}
		clean := make([]string, len(typed))
		for index, item := range typed {
			if strings.TrimSpace(item) == "" || len([]rune(item)) > 128 {
				return nil, ErrMetadataNotAllowlisted
			}
			clean[index] = item
		}
		return clean, nil
	case []any:
		items := make([]string, len(typed))
		for index, item := range typed {
			stringItem, ok := item.(string)
			if !ok {
				return nil, ErrMetadataNotAllowlisted
			}
			items[index] = stringItem
		}
		return allowlistedMetadataValue(key, items)
	default:
		return nil, ErrMetadataNotAllowlisted
	}
}

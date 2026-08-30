// Package strictjson provides bounded, duplicate-safe JSON object decoding for
// security-sensitive configuration, HTTP requests, and worker payloads.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

var (
	ErrInvalidInput = errors.New("strict JSON input is invalid")
	ErrTooLarge     = errors.New("strict JSON input exceeds its byte limit")
)

func Decode(reader io.Reader, maximumBytes int, target any) error {
	if reader == nil || maximumBytes < 1 || target == nil {
		return ErrInvalidInput
	}
	contents, err := io.ReadAll(io.LimitReader(reader, int64(maximumBytes)+1))
	if err != nil {
		return fmt.Errorf("%w: read input", ErrInvalidInput)
	}
	return DecodeBytes(contents, maximumBytes, target)
}

func DecodeBytes(contents []byte, maximumBytes int, target any) error {
	if maximumBytes < 1 || target == nil || len(contents) == 0 {
		return ErrInvalidInput
	}
	if len(contents) > maximumBytes {
		return ErrTooLarge
	}
	if err := ValidateObject(contents, maximumBytes); err != nil {
		return err
	}
	if err := validateTargetSchema(contents, target, false); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return ErrInvalidInput
	}
	return nil
}

// DecodeKnownBytes decodes an extensible JSON object while requiring every
// member that case-folds to a known target field to use that field's exact JSON
// name. Unknown extension members remain available to upstream protocols.
func DecodeKnownBytes(contents []byte, maximumBytes int, target any) error {
	if maximumBytes < 1 || target == nil || len(contents) == 0 {
		return ErrInvalidInput
	}
	if len(contents) > maximumBytes {
		return ErrTooLarge
	}
	if err := ValidateObject(contents, maximumBytes); err != nil {
		return err
	}
	if err := validateTargetSchema(contents, target, true); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return ErrInvalidInput
	}
	return nil
}

func validateTargetSchema(contents []byte, target any, allowUnknown bool) error {
	targetType := reflect.TypeOf(target)
	if targetType == nil || targetType.Kind() != reflect.Pointer || reflect.ValueOf(target).IsNil() {
		return ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return ErrInvalidInput
	}
	if err := validateJSONValueSchema(value, targetType.Elem(), allowUnknown); err != nil {
		return err
	}
	return nil
}

func validateJSONValueSchema(value any, targetType reflect.Type, allowUnknown bool) error {
	for targetType.Kind() == reflect.Pointer {
		targetType = targetType.Elem()
	}
	if targetType == reflect.TypeFor[json.RawMessage]() {
		return nil
	}
	switch typed := value.(type) {
	case map[string]any:
		switch targetType.Kind() {
		case reflect.Struct:
			fields := make(map[string]reflect.Type)
			collectJSONFields(targetType, fields)
			for name, child := range typed {
				fieldType, exact := fields[name]
				if exact {
					if err := validateJSONValueSchema(child, fieldType, allowUnknown); err != nil {
						return err
					}
					continue
				}
				for known := range fields {
					if strings.EqualFold(name, known) {
						return ErrInvalidInput
					}
				}
				if !allowUnknown {
					return ErrInvalidInput
				}
			}
		case reflect.Map:
			for _, child := range typed {
				if err := validateJSONValueSchema(child, targetType.Elem(), allowUnknown); err != nil {
					return err
				}
			}
		}
	case []any:
		if targetType.Kind() == reflect.Slice || targetType.Kind() == reflect.Array {
			for _, child := range typed {
				if err := validateJSONValueSchema(child, targetType.Elem(), allowUnknown); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func collectJSONFields(targetType reflect.Type, fields map[string]reflect.Type) {
	for index := 0; index < targetType.NumField(); index++ {
		field := targetType.Field(index)
		if field.PkgPath != "" {
			continue
		}
		tag := field.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		if field.Anonymous && name == "" {
			embedded := field.Type
			for embedded.Kind() == reflect.Pointer {
				embedded = embedded.Elem()
			}
			if embedded.Kind() == reflect.Struct {
				collectJSONFields(embedded, fields)
				continue
			}
		}
		if name == "" {
			name = field.Name
		}
		fields[name] = field.Type
	}
}

// ValidateObject enforces the byte bound, a single top-level object, and unique
// member names recursively without imposing a target schema.
func ValidateObject(contents []byte, maximumBytes int) error {
	if maximumBytes < 1 || len(contents) == 0 {
		return ErrInvalidInput
	}
	if len(contents) > maximumBytes {
		return ErrTooLarge
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return ErrInvalidInput
	}
	if err := consumeJSONObject(decoder); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return ErrInvalidInput
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalidInput
	}
	switch token {
	case json.Delim('{'):
		return consumeJSONObject(decoder)
	case json.Delim('['):
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidInput
		}
		return nil
	default:
		return nil
	}
}

func consumeJSONObject(decoder *json.Decoder) error {
	seen := map[string]struct{}{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return ErrInvalidInput
		}
		key, ok := token.(string)
		if !ok {
			return ErrInvalidInput
		}
		if _, duplicate := seen[key]; duplicate {
			return ErrInvalidInput
		}
		seen[key] = struct{}{}
		if err := consumeJSONValue(decoder); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return ErrInvalidInput
	}
	return nil
}

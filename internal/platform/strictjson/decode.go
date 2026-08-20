// Package strictjson provides bounded, duplicate-safe JSON object decoding for
// security-sensitive configuration, HTTP requests, and worker payloads.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

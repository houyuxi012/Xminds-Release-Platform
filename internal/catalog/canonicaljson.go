package catalog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

var integerJSONPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

func CanonicalJSON(value any) ([]byte, error) {
	var raw []byte
	switch item := value.(type) {
	case json.RawMessage:
		raw = append([]byte(nil), item...)
	case []byte:
		raw = append([]byte(nil), item...)
	default:
		if err := validateCanonicalInput(reflect.ValueOf(value)); err != nil {
			return nil, err
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCanonicalJSON, err)
		}
		raw = encoded
	}
	parsed, err := strictJSONValue(raw)
	if err != nil {
		return nil, err
	}
	var builder strings.Builder
	if err := encodeCanonicalValue(&builder, parsed); err != nil {
		return nil, err
	}
	return []byte(builder.String()), nil
}

func strictJSONValue(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, ErrCanonicalJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := strictJSONToken(decoder)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCanonicalJSON, err)
	}
	if token, err := decoder.Token(); err != io.EOF || token != nil {
		return nil, ErrCanonicalJSON
	}
	return value, nil
}

func strictJSONToken(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			result := map[string]any{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok || !utf8.ValidString(key) {
					return nil, ErrCanonicalJSON
				}
				if _, duplicate := result[key]; duplicate {
					return nil, ErrCanonicalJSON
				}
				child, err := strictJSONToken(decoder)
				if err != nil {
					return nil, err
				}
				result[key] = child
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return nil, ErrCanonicalJSON
			}
			return result, nil
		case '[':
			result := []any{}
			for decoder.More() {
				child, err := strictJSONToken(decoder)
				if err != nil {
					return nil, err
				}
				result = append(result, child)
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return nil, ErrCanonicalJSON
			}
			return result, nil
		default:
			return nil, ErrCanonicalJSON
		}
	case json.Number:
		text := value.String()
		if text == "-0" || !integerJSONPattern.MatchString(text) {
			return nil, ErrCanonicalJSON
		}
		return value, nil
	case string:
		if !utf8.ValidString(value) {
			return nil, ErrCanonicalJSON
		}
		return value, nil
	case bool, nil:
		return value, nil
	default:
		return nil, ErrCanonicalJSON
	}
}

func encodeCanonicalValue(builder *strings.Builder, value any) error {
	switch item := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(item))
		for key := range item {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		builder.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				builder.WriteByte(',')
			}
			encodeJSONString(builder, key)
			builder.WriteByte(':')
			if err := encodeCanonicalValue(builder, item[key]); err != nil {
				return err
			}
		}
		builder.WriteByte('}')
	case []any:
		builder.WriteByte('[')
		for index, child := range item {
			if index > 0 {
				builder.WriteByte(',')
			}
			if err := encodeCanonicalValue(builder, child); err != nil {
				return err
			}
		}
		builder.WriteByte(']')
	case string:
		encodeJSONString(builder, item)
	case bool:
		if item {
			builder.WriteString("true")
		} else {
			builder.WriteString("false")
		}
	case nil:
		builder.WriteString("null")
	case json.Number:
		builder.WriteString(item.String())
	default:
		return fmt.Errorf("%w: unsupported value %T", ErrCanonicalJSON, item)
	}
	return nil
}

func encodeJSONString(builder *strings.Builder, value string) {
	const hexadecimal = "0123456789abcdef"
	builder.WriteByte('"')
	for _, character := range value {
		switch character {
		case '"', '\\':
			builder.WriteByte('\\')
			builder.WriteRune(character)
		case '\b':
			builder.WriteString(`\b`)
		case '\f':
			builder.WriteString(`\f`)
		case '\n':
			builder.WriteString(`\n`)
		case '\r':
			builder.WriteString(`\r`)
		case '\t':
			builder.WriteString(`\t`)
		default:
			if character < 0x20 {
				builder.WriteString(`\u00`)
				builder.WriteByte(hexadecimal[byte(character)>>4])
				builder.WriteByte(hexadecimal[byte(character)&0x0f])
				continue
			}
			builder.WriteRune(character)
		}
	}
	builder.WriteByte('"')
}

func validateCanonicalInput(value reflect.Value) error {
	if !value.IsValid() {
		return nil
	}
	if value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return nil
		}
		return validateCanonicalInput(value.Elem())
	}
	switch value.Kind() {
	case reflect.Float32, reflect.Float64:
		return ErrCanonicalJSON
	case reflect.String:
		if !utf8.ValidString(value.String()) {
			return ErrCanonicalJSON
		}
	case reflect.Map:
		iterator := value.MapRange()
		for iterator.Next() {
			if iterator.Key().Kind() != reflect.String || !utf8.ValidString(iterator.Key().String()) {
				return ErrCanonicalJSON
			}
			if err := validateCanonicalInput(iterator.Value()); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			return nil
		}
		for index := 0; index < value.Len(); index++ {
			if err := validateCanonicalInput(value.Index(index)); err != nil {
				return err
			}
		}
	case reflect.Struct:
		if value.Type() == reflect.TypeOf(json.Number("")) {
			return nil
		}
	}
	return nil
}

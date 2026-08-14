package product

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	ManifestSchemaVersion = "xminds-product-manifest/v1"
	ManifestCatalogFormat = "xminds-tuf-v1"
	maximumManifestBytes  = 256 * 1024
)

var (
	ErrManifestInvalid           = errors.New("product manifest is invalid")
	ErrManifestTooLarge          = errors.New("product manifest exceeds size limit")
	ErrManifestDuplicateField    = errors.New("product manifest contains a duplicate JSON field")
	ErrSchemaVersionUnsupported  = errors.New("product manifest schema version is unsupported")
	ErrProductIDInvalid          = errors.New("product ID is invalid")
	ErrDisplayNameInvalid        = errors.New("product display name is invalid")
	ErrArtifactTypeInvalid       = errors.New("artifact type is invalid")
	ErrArtifactTypeDuplicate     = errors.New("artifact type is duplicated")
	ErrVersionSchemeUnsupported  = errors.New("version scheme is unsupported")
	ErrCompatibilityKeyInvalid   = errors.New("compatibility key is invalid")
	ErrCompatibilityKeyDuplicate = errors.New("compatibility key is duplicated")
	ErrCatalogFormatUnsupported  = errors.New("catalog format is unsupported")
	ErrChannelInvalid            = errors.New("default channel is invalid")
	ErrChannelDuplicate          = errors.New("default channel is duplicated")
)

var (
	productIDPattern  = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	identifierPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
)

type Manifest struct {
	SchemaVersion     string            `json:"schema_version"`
	ProductID         string            `json:"product_id"`
	DisplayName       string            `json:"display_name"`
	ArtifactTypes     []string          `json:"artifact_types"`
	VersionScheme     string            `json:"version_scheme"`
	CompatibilityKeys []string          `json:"compatibility_keys"`
	CatalogFormat     string            `json:"catalog_format"`
	DefaultChannels   []ChannelManifest `json:"default_channels"`
}

type ChannelManifest struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

func ParseManifest(raw []byte) (Manifest, json.RawMessage, string, error) {
	if len(raw) == 0 {
		return Manifest{}, nil, "", ErrManifestInvalid
	}
	if len(raw) > maximumManifestBytes {
		return Manifest{}, nil, "", ErrManifestTooLarge
	}
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return Manifest{}, nil, "", err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, nil, "", fmt.Errorf("%w: %v", ErrManifestInvalid, err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Manifest{}, nil, "", err
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, nil, "", err
	}
	canonical, err := json.Marshal(manifest)
	if err != nil {
		return Manifest{}, nil, "", fmt.Errorf("canonicalize product manifest: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return manifest, canonical, hex.EncodeToString(digest[:]), nil
}

func (manifest Manifest) Validate() error {
	if manifest.SchemaVersion != ManifestSchemaVersion {
		return ErrSchemaVersionUnsupported
	}
	if !productIDPattern.MatchString(manifest.ProductID) {
		return ErrProductIDInvalid
	}
	if trimmed := strings.TrimSpace(manifest.DisplayName); trimmed == "" || trimmed != manifest.DisplayName || len(trimmed) > 128 {
		return ErrDisplayNameInvalid
	}
	if len(manifest.ArtifactTypes) == 0 || len(manifest.ArtifactTypes) > 32 {
		return ErrArtifactTypeInvalid
	}
	if err := validateUniqueIdentifiers(manifest.ArtifactTypes, ErrArtifactTypeInvalid, ErrArtifactTypeDuplicate); err != nil {
		return err
	}
	if manifest.VersionScheme != "semver" {
		return ErrVersionSchemeUnsupported
	}
	if len(manifest.CompatibilityKeys) > 32 {
		return ErrCompatibilityKeyInvalid
	}
	if err := validateUniqueIdentifiers(manifest.CompatibilityKeys, ErrCompatibilityKeyInvalid, ErrCompatibilityKeyDuplicate); err != nil {
		return err
	}
	if manifest.CatalogFormat != ManifestCatalogFormat {
		return ErrCatalogFormatUnsupported
	}
	if len(manifest.DefaultChannels) == 0 || len(manifest.DefaultChannels) > 16 {
		return ErrChannelInvalid
	}
	seenChannels := make(map[string]struct{}, len(manifest.DefaultChannels))
	for _, channel := range manifest.DefaultChannels {
		if !identifierPattern.MatchString(channel.Name) {
			return ErrChannelInvalid
		}
		displayName := strings.TrimSpace(channel.DisplayName)
		if displayName == "" || displayName != channel.DisplayName || len(displayName) > 128 {
			return ErrChannelInvalid
		}
		if _, exists := seenChannels[channel.Name]; exists {
			return ErrChannelDuplicate
		}
		seenChannels[channel.Name] = struct{}{}
	}
	return nil
}

func validateUniqueIdentifiers(values []string, invalidError error, duplicateError error) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !identifierPattern.MatchString(value) {
			return invalidError
		}
		if _, exists := seen[value]; exists {
			return duplicateError
		}
		seen[value] = struct{}{}
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrManifestInvalid
	}
	return nil
}

func rejectDuplicateJSONFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := inspectJSONValue(decoder); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func inspectJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrManifestInvalid, err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("%w: %v", ErrManifestInvalid, err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrManifestInvalid
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("%w: %s", ErrManifestDuplicateField, key)
			}
			seen[key] = struct{}{}
			if err := inspectJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := inspectJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return ErrManifestInvalid
	}
	closing, err := decoder.Token()
	if err != nil || closing != matchingDelimiter(delimiter) {
		return ErrManifestInvalid
	}
	return nil
}

func matchingDelimiter(open json.Delim) json.Delim {
	if open == '{' {
		return '}'
	}
	return ']'
}

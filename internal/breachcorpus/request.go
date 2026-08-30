package breachcorpus

import (
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"xminds-release-platform/internal/platform/strictjson"
)

const (
	maximumBuildRequestBytes = 1 << 20
	maximumVersionBytes      = 128
	maximumLicenseRefBytes   = 256
)

var (
	sourceIDPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	licenseRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
)

func ReadBuildRequest(reader io.Reader) (BuildRequest, error) {
	if reader == nil {
		return BuildRequest{}, ErrInvalidRequest
	}
	var request BuildRequest
	if err := strictjson.Decode(reader, maximumBuildRequestBytes, &request); err != nil {
		return BuildRequest{}, ErrInvalidRequest
	}
	if err := validateBuildRequest(request); err != nil {
		return BuildRequest{}, err
	}
	for index := range request.Sources {
		request.Sources[index].ExpectedSHA256 = strings.ToLower(request.Sources[index].ExpectedSHA256)
	}
	return request, nil
}

func ValidateInputs(request BuildRequest, inputs []Input) error {
	if err := validateBuildRequest(request); err != nil || len(inputs) != len(request.Sources) || len(inputs) > MaximumInputCount {
		return ErrInvalidRequest
	}

	required := make(map[string]struct{}, len(request.Sources))
	for _, source := range request.Sources {
		required[source.ID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		if _, exists := required[input.SourceID]; !exists {
			return ErrInvalidRequest
		}
		if _, duplicate := seen[input.SourceID]; duplicate {
			return ErrInvalidRequest
		}
		if input.Path == "" || strings.TrimSpace(input.Path) != input.Path || !filepath.IsAbs(input.Path) || filepath.Clean(input.Path) != input.Path {
			return ErrInvalidRequest
		}
		seen[input.SourceID] = struct{}{}
	}
	if len(seen) != len(required) {
		return ErrInvalidRequest
	}
	return nil
}

func validateBuildRequest(request BuildRequest) error {
	if request.SchemaVersion != ManifestSchemaVersion || !validBoundedText(request.CorpusVersion, maximumVersionBytes) ||
		len(request.Sources) == 0 || len(request.Sources) > MaximumInputCount {
		return ErrInvalidRequest
	}

	seen := make(map[string]struct{}, len(request.Sources))
	for _, source := range request.Sources {
		if !sourceIDPattern.MatchString(source.ID) || !validBoundedText(source.Version, maximumVersionBytes) ||
			!licenseRefPattern.MatchString(source.LicenseReviewRef) || len(source.LicenseReviewRef) > maximumLicenseRefBytes ||
			!validSHA256(source.ExpectedSHA256) {
			return ErrInvalidRequest
		}
		if _, duplicate := seen[source.ID]; duplicate {
			return fmt.Errorf("%w: duplicate source", ErrInvalidRequest)
		}
		seen[source.ID] = struct{}{}
	}
	return nil
}

func validBoundedText(value string, maximumBytes int) bool {
	if value == "" || len(value) > maximumBytes || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

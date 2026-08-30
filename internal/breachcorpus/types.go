package breachcorpus

import "errors"

const (
	ManifestSchemaVersion  = 1
	Format                 = "xminds-breach-corpus/v1"
	MaximumLineBytes       = 4096
	MaximumInputCount      = 32
	MaximumTotalInputBytes = int64(512 << 20)
	MaximumCorpusBytes     = int64(128 << 20)
)

var ErrInvalidRequest = errors.New("breach corpus build request is invalid")

type SourceRequest struct {
	ID               string `json:"id"`
	Version          string `json:"version"`
	ExpectedSHA256   string `json:"expected_sha256"`
	LicenseReviewRef string `json:"license_review_ref"`
}

type BuildRequest struct {
	SchemaVersion int             `json:"schema_version"`
	CorpusVersion string          `json:"corpus_version"`
	Sources       []SourceRequest `json:"sources"`
}

type Input struct {
	SourceID string
	Path     string
}

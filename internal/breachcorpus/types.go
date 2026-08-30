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

var (
	ErrInvalidCorpus  = errors.New("breach corpus is invalid")
	ErrInvalidRequest = errors.New("breach corpus build request is invalid")
)

type Algorithm string

const (
	SHA1   Algorithm = "sha1"
	SHA256 Algorithm = "sha256"
)

type Counts struct {
	SHA1Entries      uint64 `json:"sha1_entries"`
	SHA256Entries    uint64 `json:"sha256_entries"`
	UniqueEntries    uint64 `json:"unique_entries"`
	DuplicateEntries uint64 `json:"duplicate_entries"`
	RejectedEntries  uint64 `json:"rejected_entries"`
}

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

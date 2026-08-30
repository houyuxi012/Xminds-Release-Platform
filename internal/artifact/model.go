package artifact

import (
	"errors"
	"io"
	"regexp"
	"time"

	"github.com/google/uuid"
)

const (
	MaximumObjectSize = int64(20 * 1024 * 1024 * 1024)
	MinimumPartSize   = int64(5 * 1024 * 1024)
	MaximumPartSize   = int64(256 * 1024 * 1024)
	MaximumPartCount  = 10_000
	UploadLifetime    = 24 * time.Hour
)

var (
	ErrProductRequired       = errors.New("artifact product ID is required")
	ErrArtifactTypeInvalid   = errors.New("artifact type is invalid for product")
	ErrFilenameInvalid       = errors.New("artifact filename is invalid")
	ErrContentTypeInvalid    = errors.New("artifact content type is invalid")
	ErrObjectSizeInvalid     = errors.New("artifact object size is invalid")
	ErrDigestInvalid         = errors.New("artifact SHA-256 digest is invalid")
	ErrDigestMismatch        = errors.New("artifact SHA-256 digest does not match uploaded content")
	ErrPartDigestMismatch    = errors.New("artifact part digest does not match uploaded content")
	ErrPartSizeMismatch      = errors.New("artifact part size does not match uploaded content")
	ErrPartNumberInvalid     = errors.New("artifact part number is invalid")
	ErrPartSizeInvalid       = errors.New("artifact part size is invalid")
	ErrPartsIncomplete       = errors.New("artifact upload parts are incomplete")
	ErrUploadNotFound        = errors.New("artifact upload was not found")
	ErrUploadProductMismatch = errors.New("artifact upload does not belong to path product")
	ErrUploadExpired         = errors.New("artifact upload has expired")
	ErrUploadStateInvalid    = errors.New("artifact upload state is invalid")
	ErrArtifactNotFound      = errors.New("artifact was not found")
	ErrObjectConflict        = errors.New("content-addressed object conflicts with verified metadata")
	ErrRepositoryRequired    = errors.New("artifact repository is required")
	ErrTransactorRequired    = errors.New("artifact transactor is required")
	ErrProductReaderRequired = errors.New("artifact product reader is required")
	ErrObjectStoreRequired   = errors.New("artifact object store is required")
	ErrAuditAppenderRequired = errors.New("artifact audit appender is required")
	ErrJobEnqueuerRequired   = errors.New("artifact job enqueuer is required")
)

var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type UploadStatus string

const (
	UploadStatusUploading   UploadStatus = "uploading"
	UploadStatusCompleted   UploadStatus = "completed"
	UploadStatusQuarantined UploadStatus = "quarantined"
	UploadStatusExpired     UploadStatus = "expired"
)

type Upload struct {
	ID             uuid.UUID    `json:"id"`
	ProductID      string       `json:"product_id"`
	ArtifactType   string       `json:"artifact_type"`
	Filename       string       `json:"filename"`
	ContentType    string       `json:"content_type"`
	ExpectedSize   int64        `json:"expected_size"`
	ExpectedSHA256 string       `json:"expected_sha256"`
	StagingKey     string       `json:"-"`
	ObjectUploadID string       `json:"-"`
	Status         UploadStatus `json:"status"`
	ArtifactID     uuid.UUID    `json:"artifact_id,omitempty"`
	ExpiresAt      time.Time    `json:"expires_at"`
	CreatedBy      string       `json:"created_by"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

type UploadPart struct {
	UploadID   uuid.UUID `json:"upload_id"`
	PartNumber int       `json:"part_number"`
	Size       int64     `json:"size"`
	SHA256     string    `json:"sha256"`
	ETag       string    `json:"etag"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type Artifact struct {
	ID           uuid.UUID `json:"id"`
	ProductID    string    `json:"product_id"`
	ArtifactType string    `json:"artifact_type"`
	Filename     string    `json:"filename"`
	ContentType  string    `json:"content_type"`
	Size         int64     `json:"size"`
	SHA256       string    `json:"sha256"`
	ObjectKey    string    `json:"-"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
}

type BeginUpload struct {
	ProductID    string `json:"product_id"`
	ArtifactType string `json:"artifact_type"`
	Filename     string `json:"filename"`
	ContentType  string `json:"content_type"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
}

type PutPart struct {
	PartNumber int
	Size       int64
	SHA256     string
	Body       io.Reader
}

type RequestContext struct {
	RequestID string
	SourceIP  string
}

func ArtifactObjectKey(digest string) string {
	if len(digest) < 2 {
		return ""
	}
	return "artifacts/sha256/" + digest[:2] + "/" + digest
}

func stagingObjectKey(uploadID uuid.UUID) string {
	return "uploads/" + uploadID.String()
}

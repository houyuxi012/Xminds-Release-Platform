package objectstore

import (
	"context"
	"errors"
	"io"
	"time"
)

var (
	ErrConfigurationInvalid = errors.New("object store configuration is invalid")
	ErrUploadNotFound       = errors.New("object store multipart upload was not found")
	ErrObjectNotFound       = errors.New("object was not found")
	ErrObjectAlreadyExists  = errors.New("object already exists")
	ErrSizeMismatch         = errors.New("object size does not match")
	ErrDigestMismatch       = errors.New("object digest does not match")
	ErrRangeInvalid         = errors.New("object range is invalid")
	ErrImmutableObject      = errors.New("verified object is immutable")
)

type Part struct {
	PartNumber int
	Size       int64
	SHA256     string
	ETag       string
}

type ObjectInfo struct {
	Key          string
	Size         int64
	ETag         string
	ContentType  string
	LastModified time.Time
}

// Store is the provider-neutral object storage port. Promote must make the
// destination visible only after the source object already exists. Delete is
// restricted to temporary upload objects; verified content-addressed objects
// are immutable through this port.
type Store interface {
	BeginMultipart(ctx context.Context, key, contentType string) (string, error)
	PutPart(ctx context.Context, key, uploadID string, partNumber int, body io.Reader, size int64, sha256 string) (Part, error)
	CompleteMultipart(ctx context.Context, key, uploadID string, parts []Part) error
	AbortMultipart(ctx context.Context, key, uploadID string) error
	Open(ctx context.Context, key string, offset, length int64) (io.ReadCloser, ObjectInfo, error)
	Stat(ctx context.Context, key string) (ObjectInfo, error)
	Promote(ctx context.Context, sourceKey, destinationKey string) (ObjectInfo, error)
	Delete(ctx context.Context, key string) error
}

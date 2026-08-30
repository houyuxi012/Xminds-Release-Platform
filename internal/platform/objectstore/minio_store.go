package objectstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var ErrRedirectRejected = errors.New("object store redirect was rejected")

var bucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

type MinIOConfig struct {
	EndpointURL          string
	Bucket               string
	Region               string
	AccessKey            string
	SecretKey            string
	SessionToken         string
	TLSRootCAs           *x509.CertPool
	ObjectLocking        bool
	DefaultRetentionDays uint
}

type MinIOStore struct {
	core                 *minio.Core
	bucket               string
	region               string
	objectLocking        bool
	defaultRetentionDays uint
}

func NewMinIOStore(configuration MinIOConfig) (*MinIOStore, error) {
	endpoint, err := url.Parse(strings.TrimSpace(configuration.EndpointURL))
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.Host == "" ||
		(endpoint.Path != "" && endpoint.Path != "/") || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.User != nil {
		return nil, ErrConfigurationInvalid
	}
	bucket := strings.TrimSpace(configuration.Bucket)
	if !bucketNamePattern.MatchString(bucket) || strings.Contains(bucket, "..") {
		return nil, ErrConfigurationInvalid
	}
	accessKey := strings.TrimSpace(configuration.AccessKey)
	secretKey := strings.TrimSpace(configuration.SecretKey)
	if accessKey == "" || secretKey == "" {
		return nil, ErrConfigurationInvalid
	}
	transport, err := minio.DefaultTransport(endpoint.Scheme == "https")
	if err != nil {
		return nil, fmt.Errorf("create MinIO HTTP transport: %w", err)
	}
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    configuration.TLSRootCAs,
	}
	core, err := minio.NewCore(endpoint.Host, &minio.Options{
		Creds:        credentials.NewStaticV4(accessKey, secretKey, strings.TrimSpace(configuration.SessionToken)),
		Secure:       endpoint.Scheme == "https",
		Transport:    rejectingRedirectTransport{base: transport},
		Region:       strings.TrimSpace(configuration.Region),
		BucketLookup: minio.BucketLookupPath,
		MaxRetries:   3,
	})
	if err != nil {
		return nil, fmt.Errorf("create MinIO client: %w", err)
	}
	if configuration.ObjectLocking && (configuration.DefaultRetentionDays < 1 || configuration.DefaultRetentionDays > 3650) {
		return nil, ErrObjectLockInvalid
	}
	return &MinIOStore{core: core, bucket: bucket, region: strings.TrimSpace(configuration.Region), objectLocking: configuration.ObjectLocking, defaultRetentionDays: configuration.DefaultRetentionDays}, nil
}

func (store *MinIOStore) EnsureBucket(ctx context.Context) error {
	if store == nil || store.core == nil {
		return ErrConfigurationInvalid
	}
	exists, err := store.core.BucketExists(ctx, store.bucket)
	if err != nil {
		return fmt.Errorf("check object bucket: %w", mapMinIOError(err))
	}
	if exists {
		if store.objectLocking {
			return store.ensureObjectLock(ctx)
		}
		return nil
	}
	if err := store.core.MakeBucket(ctx, store.bucket, minio.MakeBucketOptions{Region: store.region, ObjectLocking: store.objectLocking}); err != nil {
		if existsAfterRace, existsErr := store.core.BucketExists(ctx, store.bucket); existsErr == nil && existsAfterRace {
			if store.objectLocking {
				return store.ensureObjectLock(ctx)
			}
			return nil
		}
		return fmt.Errorf("create object bucket: %w", mapMinIOError(err))
	}
	if store.objectLocking {
		if err := store.ensureObjectLock(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (store *MinIOStore) ensureObjectLock(ctx context.Context) error {
	if store == nil || store.core == nil || !store.objectLocking || store.defaultRetentionDays < 1 {
		return ErrObjectLockInvalid
	}
	mode := minio.Compliance
	days := store.defaultRetentionDays
	unit := minio.Days
	lockEnabled, currentMode, currentDays, currentUnit, err := store.core.Client.GetObjectLockConfig(ctx, store.bucket)
	if err != nil {
		return fmt.Errorf("read archive object lock configuration: %w", mapMinIOError(err))
	}
	if lockEnabled != "Enabled" {
		return ErrObjectLockInvalid
	}
	if currentMode == nil || *currentMode != mode || currentUnit == nil || *currentUnit != unit || currentDays == nil || *currentDays < days {
		if err := store.core.Client.SetObjectLockConfig(ctx, store.bucket, &mode, &days, &unit); err != nil {
			return fmt.Errorf("set archive object lock configuration: %w", mapMinIOError(err))
		}
	}
	return nil
}

func (store *MinIOStore) BeginMultipart(ctx context.Context, key, contentType string) (string, error) {
	if err := validateObjectKey(key); err != nil {
		return "", err
	}
	uploadID, err := store.core.NewMultipartUpload(ctx, store.bucket, key, minio.PutObjectOptions{ContentType: contentType})
	if err != nil {
		return "", fmt.Errorf("begin MinIO multipart upload: %w", mapMinIOError(err))
	}
	return uploadID, nil
}

func (store *MinIOStore) PutPart(ctx context.Context, key, uploadID string, partNumber int, body io.Reader, size int64, digest string) (Part, error) {
	if err := validateObjectKey(key); err != nil {
		return Part{}, err
	}
	if strings.TrimSpace(uploadID) == "" || partNumber < 1 || body == nil || size <= 0 {
		return Part{}, ErrConfigurationInvalid
	}
	part, err := store.core.PutObjectPart(ctx, store.bucket, key, uploadID, partNumber, body, size, minio.PutObjectPartOptions{Sha256Hex: digest})
	if err != nil {
		return Part{}, fmt.Errorf("put MinIO multipart part: %w", mapMinIOError(err))
	}
	return Part{
		PartNumber: part.PartNumber,
		Size:       part.Size,
		SHA256:     digest,
		ETag:       strings.Trim(part.ETag, `"`),
	}, nil
}

func (store *MinIOStore) CompleteMultipart(ctx context.Context, key, uploadID string, parts []Part) error {
	if err := validateObjectKey(key); err != nil {
		return err
	}
	if strings.TrimSpace(uploadID) == "" || len(parts) == 0 {
		return ErrConfigurationInvalid
	}
	completed := make([]minio.CompletePart, 0, len(parts))
	for _, part := range parts {
		completed = append(completed, minio.CompletePart{PartNumber: part.PartNumber, ETag: strings.Trim(part.ETag, `"`)})
	}
	_, err := store.core.CompleteMultipartUpload(ctx, store.bucket, key, uploadID, completed, minio.PutObjectOptions{})
	if err != nil {
		return fmt.Errorf("complete MinIO multipart upload: %w", mapMinIOError(err))
	}
	return nil
}

func (store *MinIOStore) AbortMultipart(ctx context.Context, key, uploadID string) error {
	if err := validateObjectKey(key); err != nil {
		return err
	}
	if strings.TrimSpace(uploadID) == "" {
		return ErrConfigurationInvalid
	}
	if err := store.core.AbortMultipartUpload(ctx, store.bucket, key, uploadID); err != nil {
		mapped := mapMinIOError(err)
		if errors.Is(mapped, ErrUploadNotFound) {
			return nil
		}
		return fmt.Errorf("abort MinIO multipart upload: %w", mapped)
	}
	return nil
}

func (store *MinIOStore) Open(ctx context.Context, key string, offset, length int64) (io.ReadCloser, ObjectInfo, error) {
	if err := validateObjectKey(key); err != nil {
		return nil, ObjectInfo{}, err
	}
	if offset < 0 || length == 0 || length < -1 || (length > 0 && offset > (1<<63-1)-(length-1)) {
		return nil, ObjectInfo{}, ErrRangeInvalid
	}
	options := minio.GetObjectOptions{}
	if offset > 0 || length > 0 {
		end := int64(0)
		if length < 0 {
			end = 0
		} else {
			end = offset + length - 1
		}
		if err := options.SetRange(offset, end); err != nil {
			return nil, ObjectInfo{}, ErrRangeInvalid
		}
	}
	reader, information, headers, err := store.core.GetObject(ctx, store.bucket, key, options)
	if err != nil {
		return nil, ObjectInfo{}, fmt.Errorf("open MinIO object: %w", mapMinIOError(err))
	}
	result := fromMinIOObjectInfo(key, information)
	if contentRange := headers.Get("Content-Range"); contentRange != "" {
		total, parseErr := totalSizeFromContentRange(contentRange)
		if parseErr != nil {
			_ = reader.Close()
			return nil, ObjectInfo{}, parseErr
		}
		result.Size = total
	}
	return reader, result, nil
}

func (store *MinIOStore) Stat(ctx context.Context, key string) (ObjectInfo, error) {
	if err := validateObjectKey(key); err != nil {
		return ObjectInfo{}, err
	}
	information, err := store.core.StatObject(ctx, store.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		return ObjectInfo{}, fmt.Errorf("stat MinIO object: %w", mapMinIOError(err))
	}
	return fromMinIOObjectInfo(key, information), nil
}

func (store *MinIOStore) Promote(ctx context.Context, sourceKey, destinationKey string) (ObjectInfo, error) {
	if err := validateObjectKey(sourceKey); err != nil {
		return ObjectInfo{}, err
	}
	if err := validateObjectKey(destinationKey); err != nil {
		return ObjectInfo{}, err
	}
	if _, err := store.Stat(ctx, destinationKey); err == nil {
		return ObjectInfo{}, ErrObjectAlreadyExists
	} else if !errors.Is(err, ErrObjectNotFound) {
		return ObjectInfo{}, err
	}
	_, err := store.core.Client.CopyObject(ctx,
		minio.CopyDestOptions{Bucket: store.bucket, Object: destinationKey},
		minio.CopySrcOptions{Bucket: store.bucket, Object: sourceKey},
	)
	if err != nil {
		return ObjectInfo{}, fmt.Errorf("promote MinIO object: %w", mapMinIOError(err))
	}
	promoted, err := store.Stat(ctx, destinationKey)
	if err != nil {
		return ObjectInfo{}, fmt.Errorf("stat promoted MinIO object: %w", err)
	}
	if err := store.Delete(ctx, sourceKey); err != nil {
		return ObjectInfo{}, err
	}
	return promoted, nil
}

func (store *MinIOStore) Delete(ctx context.Context, key string) error {
	if err := validateObjectKey(key); err != nil {
		return err
	}
	if !strings.HasPrefix(key, "uploads/") {
		return ErrImmutableObject
	}
	if err := store.core.RemoveObject(ctx, store.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("delete MinIO object: %w", mapMinIOError(err))
	}
	return nil
}

type rejectingRedirectTransport struct {
	base http.RoundTripper
}

func (transport rejectingRedirectTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
		_ = response.Body.Close()
		return nil, fmt.Errorf("%w: status %d", ErrRedirectRejected, response.StatusCode)
	}
	return response, nil
}

func validateObjectKey(key string) error {
	if key == "" || len(key) > 1024 || strings.HasPrefix(key, "/") || strings.HasSuffix(key, "/") ||
		strings.Contains(key, "\\") || strings.Contains(key, "//") {
		return ErrConfigurationInvalid
	}
	for _, segment := range strings.Split(key, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return ErrConfigurationInvalid
		}
	}
	return nil
}

func mapMinIOError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrRedirectRejected) {
		return err
	}
	response := minio.ToErrorResponse(err)
	switch response.Code {
	case "NoSuchKey", "NotFound", "XMinioInvalidObjectName":
		return fmt.Errorf("%w: %v", ErrObjectNotFound, err)
	case "NoSuchUpload", "InvalidUploadId":
		return fmt.Errorf("%w: %v", ErrUploadNotFound, err)
	case "EntityTooSmall", "EntityTooLarge", "IncompleteBody":
		return fmt.Errorf("%w: %v", ErrSizeMismatch, err)
	case "XAmzContentSHA256Mismatch", "BadDigest", "InvalidDigest":
		return fmt.Errorf("%w: %v", ErrDigestMismatch, err)
	default:
		return err
	}
}

func fromMinIOObjectInfo(key string, information minio.ObjectInfo) ObjectInfo {
	return ObjectInfo{
		Key:          key,
		Size:         information.Size,
		ETag:         strings.Trim(information.ETag, `"`),
		ContentType:  information.ContentType,
		LastModified: information.LastModified.UTC(),
	}
}

func totalSizeFromContentRange(contentRange string) (int64, error) {
	_, totalText, found := strings.Cut(strings.TrimSpace(contentRange), "/")
	if !found || totalText == "" || totalText == "*" {
		return 0, ErrRangeInvalid
	}
	total, err := strconv.ParseInt(totalText, 10, 64)
	if err != nil || total <= 0 {
		return 0, ErrRangeInvalid
	}
	return total, nil
}

var _ Store = (*MinIOStore)(nil)

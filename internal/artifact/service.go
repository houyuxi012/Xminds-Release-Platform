package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/platform/objectstore"
	"xminds-release-platform/internal/product"
)

type ProductReader interface {
	Get(ctx context.Context, productID string) (product.Product, error)
}

type AuditAppender interface {
	Append(ctx context.Context, tx pgx.Tx, command audit.AppendCommand) (audit.Event, error)
}

type JobEnqueuer interface {
	Enqueue(ctx context.Context, tx pgx.Tx, job jobs.Job) error
}

type Service struct {
	repository Repository
	transactor Transactor
	products   ProductReader
	store      objectstore.Store
	auditor    AuditAppender
	jobs       JobEnqueuer
	authorizer *identity.Authorizer
	now        func() time.Time
}

func NewService(repository Repository, transactor Transactor, products ProductReader, store objectstore.Store, auditor AuditAppender, jobEnqueuer JobEnqueuer) *Service {
	return &Service{
		repository: repository,
		transactor: transactor,
		products:   products,
		store:      store,
		auditor:    auditor,
		jobs:       jobEnqueuer,
		authorizer: identity.NewAuthorizer(),
		now:        time.Now,
	}
}

func (service *Service) BeginUpload(ctx context.Context, principal identity.Principal, command BeginUpload, request RequestContext) (Upload, error) {
	if err := service.validateDependencies(); err != nil {
		return Upload{}, err
	}
	command.ProductID = strings.TrimSpace(command.ProductID)
	if err := service.authorizer.Require(principal, identity.ActionArtifactPublish, command.ProductID); err != nil {
		return Upload{}, err
	}
	productRecord, err := service.products.Get(ctx, command.ProductID)
	if err != nil {
		return Upload{}, err
	}
	if productRecord.Status != product.ProductStatusActive || !containsString(productRecord.ArtifactTypes, command.ArtifactType) {
		return Upload{}, ErrArtifactTypeInvalid
	}
	if err := validateBeginUpload(command); err != nil {
		return Upload{}, err
	}
	uploadID, err := uuid.NewV7()
	if err != nil {
		return Upload{}, fmt.Errorf("generate artifact upload ID: %w", err)
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	stagingKey := stagingObjectKey(uploadID)
	objectUploadID, err := service.store.BeginMultipart(ctx, stagingKey, command.ContentType)
	if err != nil {
		return Upload{}, fmt.Errorf("begin object multipart upload: %w", err)
	}
	upload := Upload{
		ID: uploadID, ProductID: command.ProductID, ArtifactType: command.ArtifactType,
		Filename: command.Filename, ContentType: command.ContentType,
		ExpectedSize: command.Size, ExpectedSHA256: command.SHA256,
		StagingKey: stagingKey, ObjectUploadID: objectUploadID,
		Status: UploadStatusUploading, ExpiresAt: now.Add(UploadLifetime),
		CreatedBy: strings.TrimSpace(principal.Subject), CreatedAt: now, UpdatedAt: now,
	}
	err = service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if err := service.repository.CreateUpload(ctx, tx, upload); err != nil {
			return err
		}
		_, err := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: principal, Action: "artifact.upload.begin", ProductID: upload.ProductID,
			ResourceType: "artifact_upload", ResourceID: upload.ID.String(), Outcome: audit.OutcomeSuccess,
			RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"artifact_type": upload.ArtifactType, "expected_size": upload.ExpectedSize, "expected_sha256": upload.ExpectedSHA256},
		})
		return err
	})
	if err != nil {
		_ = service.store.AbortMultipart(ctx, stagingKey, objectUploadID)
		return Upload{}, err
	}
	return upload, nil
}

func (service *Service) PutPart(ctx context.Context, principal identity.Principal, productID string, uploadID uuid.UUID, command PutPart, body io.Reader, request RequestContext) (UploadPart, error) {
	if err := service.validateDependencies(); err != nil {
		return UploadPart{}, err
	}
	productID = strings.TrimSpace(productID)
	if err := service.authorizer.Require(principal, identity.ActionArtifactPublish, productID); err != nil {
		return UploadPart{}, err
	}
	upload, err := service.repository.GetUpload(ctx, uploadID)
	if err != nil {
		return UploadPart{}, err
	}
	if upload.ProductID != productID {
		return UploadPart{}, ErrUploadProductMismatch
	}
	if upload.Status != UploadStatusUploading {
		return UploadPart{}, ErrUploadStateInvalid
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	if now.After(upload.ExpiresAt) {
		if err := service.expireUpload(ctx, principal, upload, request, now); err != nil {
			return UploadPart{}, err
		}
		return UploadPart{}, ErrUploadExpired
	}
	if command.PartNumber < 1 || command.PartNumber > MaximumPartCount {
		return UploadPart{}, ErrPartNumberInvalid
	}
	if command.Size <= 0 || command.Size > MaximumPartSize {
		return UploadPart{}, ErrPartSizeInvalid
	}
	if !sha256Pattern.MatchString(command.SHA256) {
		return UploadPart{}, ErrDigestInvalid
	}
	if body == nil {
		return UploadPart{}, ErrPartSizeMismatch
	}
	stored, err := service.store.PutPart(ctx, upload.StagingKey, upload.ObjectUploadID, command.PartNumber, body, command.Size, command.SHA256)
	if err != nil {
		switch {
		case errors.Is(err, objectstore.ErrDigestMismatch):
			return UploadPart{}, ErrPartDigestMismatch
		case errors.Is(err, objectstore.ErrSizeMismatch):
			return UploadPart{}, ErrPartSizeMismatch
		default:
			return UploadPart{}, fmt.Errorf("store artifact part: %w", err)
		}
	}
	part := UploadPart{
		UploadID: upload.ID, PartNumber: command.PartNumber, Size: command.Size,
		SHA256: command.SHA256, ETag: stored.ETag, CreatedAt: now, UpdatedAt: now,
	}
	if err := service.repository.SavePart(ctx, part); err != nil {
		return UploadPart{}, err
	}
	return part, nil
}

func (service *Service) Complete(ctx context.Context, principal identity.Principal, productID string, uploadID uuid.UUID, request RequestContext) (Artifact, error) {
	if err := service.validateDependencies(); err != nil {
		return Artifact{}, err
	}
	productID = strings.TrimSpace(productID)
	if err := service.authorizer.Require(principal, identity.ActionArtifactPublish, productID); err != nil {
		return Artifact{}, err
	}
	upload, err := service.repository.GetUpload(ctx, uploadID)
	if err != nil {
		return Artifact{}, err
	}
	if upload.ProductID != productID {
		return Artifact{}, ErrUploadProductMismatch
	}
	if upload.Status == UploadStatusCompleted && upload.ArtifactID != uuid.Nil {
		return service.repository.GetArtifact(ctx, upload.ProductID, upload.ArtifactID)
	}
	if upload.Status != UploadStatusUploading {
		return Artifact{}, ErrUploadStateInvalid
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	if now.After(upload.ExpiresAt) {
		if err := service.expireUpload(ctx, principal, upload, request, now); err != nil {
			return Artifact{}, err
		}
		return Artifact{}, ErrUploadExpired
	}
	parts, err := service.repository.ListParts(ctx, upload.ID)
	if err != nil {
		return Artifact{}, err
	}
	objectParts, err := validateCompletionParts(upload, parts)
	if err != nil {
		return Artifact{}, err
	}

	finalKey := ArtifactObjectKey(upload.ExpectedSHA256)
	candidateKey := upload.StagingKey
	if _, statErr := service.store.Stat(ctx, candidateKey); errors.Is(statErr, objectstore.ErrObjectNotFound) {
		if completeErr := service.store.CompleteMultipart(ctx, candidateKey, upload.ObjectUploadID, objectParts); completeErr != nil {
			if _, finalErr := service.store.Stat(ctx, finalKey); finalErr != nil {
				return Artifact{}, fmt.Errorf("complete artifact multipart upload: %w", completeErr)
			}
			candidateKey = finalKey
		}
	} else if statErr != nil {
		return Artifact{}, fmt.Errorf("stat artifact staging object: %w", statErr)
	}

	actualSize, actualDigest, err := service.verifyObject(ctx, candidateKey, upload.ExpectedSize)
	if err != nil {
		return Artifact{}, err
	}
	if actualSize != upload.ExpectedSize || actualDigest != upload.ExpectedSHA256 {
		if err := service.quarantineUpload(ctx, principal, upload, request, actualSize, actualDigest, now); err != nil {
			return Artifact{}, err
		}
		return Artifact{}, ErrDigestMismatch
	}
	deduplicated := candidateKey == finalKey
	if candidateKey != finalKey {
		if existing, statErr := service.store.Stat(ctx, finalKey); statErr == nil {
			if existing.Size != upload.ExpectedSize {
				return Artifact{}, ErrObjectConflict
			}
			if err := service.store.Delete(ctx, candidateKey); err != nil {
				return Artifact{}, fmt.Errorf("delete duplicate staging object: %w", err)
			}
			deduplicated = true
		} else if !errors.Is(statErr, objectstore.ErrObjectNotFound) {
			return Artifact{}, fmt.Errorf("stat final artifact object: %w", statErr)
		} else if promoted, promoteErr := service.store.Promote(ctx, candidateKey, finalKey); promoteErr != nil {
			if !errors.Is(promoteErr, objectstore.ErrObjectAlreadyExists) {
				return Artifact{}, fmt.Errorf("promote verified artifact object: %w", promoteErr)
			}
			existing, statErr := service.store.Stat(ctx, finalKey)
			if statErr != nil || existing.Size != upload.ExpectedSize {
				return Artifact{}, ErrObjectConflict
			}
			if deleteErr := service.store.Delete(ctx, candidateKey); deleteErr != nil {
				return Artifact{}, fmt.Errorf("delete raced staging object: %w", deleteErr)
			}
			deduplicated = true
		} else if promoted.Size != upload.ExpectedSize {
			return Artifact{}, ErrObjectConflict
		}
	}

	artifactID, err := uuid.NewV7()
	if err != nil {
		return Artifact{}, fmt.Errorf("generate artifact ID: %w", err)
	}
	candidate := Artifact{
		ID: artifactID, ProductID: upload.ProductID, ArtifactType: upload.ArtifactType,
		Filename: upload.Filename, ContentType: upload.ContentType,
		Size: upload.ExpectedSize, SHA256: upload.ExpectedSHA256, ObjectKey: finalKey,
		CreatedBy: strings.TrimSpace(principal.Subject), CreatedAt: now,
	}
	var completed Artifact
	err = service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var completeErr error
		completed, completeErr = service.repository.Complete(ctx, tx, upload.ID, candidate)
		if completeErr != nil {
			return completeErr
		}
		_, completeErr = service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: principal, Action: "artifact.upload.complete", ProductID: upload.ProductID,
			ResourceType: "artifact", ResourceID: completed.ID.String(), Outcome: audit.OutcomeSuccess,
			RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"sha256": completed.SHA256, "size": completed.Size, "deduplicated": deduplicated},
		})
		return completeErr
	})
	if err != nil {
		return Artifact{}, err
	}
	return completed, nil
}

func (service *Service) Get(ctx context.Context, principal identity.Principal, productID string, artifactID uuid.UUID) (Artifact, error) {
	if err := service.validateDependencies(); err != nil {
		return Artifact{}, err
	}
	productID = strings.TrimSpace(productID)
	if err := service.authorizer.Require(principal, identity.ActionProductRead, productID); err != nil {
		return Artifact{}, err
	}
	return service.repository.GetArtifact(ctx, productID, artifactID)
}

func (service *Service) verifyObject(ctx context.Context, key string, expectedSize int64) (int64, string, error) {
	reader, _, err := service.store.Open(ctx, key, 0, -1)
	if err != nil {
		return 0, "", fmt.Errorf("open assembled artifact: %w", err)
	}
	defer reader.Close()
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(reader, expectedSize+1))
	if err != nil {
		return 0, "", fmt.Errorf("verify assembled artifact: %w", err)
	}
	return written, hex.EncodeToString(hasher.Sum(nil)), nil
}

func (service *Service) quarantineUpload(ctx context.Context, principal identity.Principal, upload Upload, request RequestContext, actualSize int64, actualDigest string, now time.Time) error {
	return service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if err := service.repository.Quarantine(ctx, tx, upload.ID, now); err != nil {
			return err
		}
		if err := service.enqueueCleanup(ctx, tx, upload, now); err != nil {
			return err
		}
		_, err := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: principal, Action: "artifact.upload.verify", ProductID: upload.ProductID,
			ResourceType: "artifact_upload", ResourceID: upload.ID.String(), Outcome: audit.OutcomeFailed,
			RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"expected_sha256": upload.ExpectedSHA256, "actual_sha256": actualDigest, "expected_size": upload.ExpectedSize, "actual_size": actualSize},
		})
		return err
	})
}

func (service *Service) expireUpload(ctx context.Context, principal identity.Principal, upload Upload, request RequestContext, now time.Time) error {
	return service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if err := service.repository.Expire(ctx, tx, upload.ID, now); err != nil {
			return err
		}
		if err := service.enqueueCleanup(ctx, tx, upload, now); err != nil {
			return err
		}
		_, err := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: principal, Action: "artifact.upload.expire", ProductID: upload.ProductID,
			ResourceType: "artifact_upload", ResourceID: upload.ID.String(), Outcome: audit.OutcomeFailed,
			RequestID: request.RequestID, SourceIP: request.SourceIP,
		})
		return err
	})
}

func (service *Service) enqueueCleanup(ctx context.Context, tx pgx.Tx, upload Upload, now time.Time) error {
	payload, err := json.Marshal(map[string]string{"upload_id": upload.ID.String(), "staging_key": upload.StagingKey, "object_upload_id": upload.ObjectUploadID})
	if err != nil {
		return fmt.Errorf("encode artifact cleanup job: %w", err)
	}
	job, err := jobs.New("artifact.cleanup.v1", upload.ID, payload, now)
	if err != nil {
		return err
	}
	return service.jobs.Enqueue(ctx, tx, job)
}

func (service *Service) validateDependencies() error {
	if service == nil || service.repository == nil {
		return ErrRepositoryRequired
	}
	if service.transactor == nil {
		return ErrTransactorRequired
	}
	if service.products == nil {
		return ErrProductReaderRequired
	}
	if service.store == nil {
		return ErrObjectStoreRequired
	}
	if service.auditor == nil {
		return ErrAuditAppenderRequired
	}
	if service.jobs == nil {
		return ErrJobEnqueuerRequired
	}
	return nil
}

func validateBeginUpload(command BeginUpload) error {
	if command.ProductID == "" {
		return ErrProductRequired
	}
	if strings.TrimSpace(command.ArtifactType) == "" {
		return ErrArtifactTypeInvalid
	}
	filename := strings.TrimSpace(command.Filename)
	if filename == "" || filename != command.Filename || len(filename) > 255 || filepath.Base(filename) != filename ||
		strings.ContainsAny(filename, `/\\`) || strings.ContainsRune(filename, '\x00') {
		return ErrFilenameInvalid
	}
	contentType := strings.TrimSpace(command.ContentType)
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType == "" || len(contentType) > 255 {
		return ErrContentTypeInvalid
	}
	if command.Size <= 0 || command.Size > MaximumObjectSize {
		return ErrObjectSizeInvalid
	}
	if !sha256Pattern.MatchString(command.SHA256) {
		return ErrDigestInvalid
	}
	return nil
}

func validateCompletionParts(upload Upload, parts []UploadPart) ([]objectstore.Part, error) {
	if len(parts) == 0 || len(parts) > MaximumPartCount {
		return nil, ErrPartsIncomplete
	}
	result := make([]objectstore.Part, 0, len(parts))
	var total int64
	for index, part := range parts {
		if part.PartNumber != index+1 || part.Size <= 0 || part.Size > MaximumPartSize {
			return nil, ErrPartsIncomplete
		}
		if index < len(parts)-1 && part.Size < MinimumPartSize {
			return nil, ErrPartsIncomplete
		}
		total += part.Size
		if total > upload.ExpectedSize {
			return nil, ErrPartsIncomplete
		}
		result = append(result, objectstore.Part{PartNumber: part.PartNumber, Size: part.Size, SHA256: part.SHA256, ETag: part.ETag})
	}
	if total != upload.ExpectedSize {
		return nil, ErrPartsIncomplete
	}
	return result, nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

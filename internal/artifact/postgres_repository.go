package artifact

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (repository *PostgresRepository) CreateUpload(ctx context.Context, tx pgx.Tx, upload Upload) error {
	if tx == nil {
		return ErrTransactorRequired
	}
	_, err := tx.Exec(ctx, `
INSERT INTO artifact_uploads (
    id, product_id, artifact_type, filename, content_type,
    expected_size, expected_sha256, staging_key, object_upload_id,
    status, artifact_id, expires_at, created_by, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL, $11, $12, $13, $13)
`,
		upload.ID, upload.ProductID, upload.ArtifactType, upload.Filename, upload.ContentType,
		upload.ExpectedSize, upload.ExpectedSHA256, upload.StagingKey, upload.ObjectUploadID,
		upload.Status, upload.ExpiresAt, upload.CreatedBy, upload.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert artifact upload: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) GetUpload(ctx context.Context, id uuid.UUID) (Upload, error) {
	if repository == nil || repository.pool == nil {
		return Upload{}, ErrRepositoryRequired
	}
	var upload Upload
	err := repository.pool.QueryRow(ctx, `
SELECT
    id, product_id, artifact_type, filename, content_type,
    expected_size, expected_sha256, staging_key, object_upload_id,
    status, COALESCE(artifact_id, '00000000-0000-0000-0000-000000000000'::uuid),
    expires_at, created_by, created_at, updated_at
FROM artifact_uploads
WHERE id = $1
`, id).Scan(
		&upload.ID, &upload.ProductID, &upload.ArtifactType, &upload.Filename, &upload.ContentType,
		&upload.ExpectedSize, &upload.ExpectedSHA256, &upload.StagingKey, &upload.ObjectUploadID,
		&upload.Status, &upload.ArtifactID, &upload.ExpiresAt, &upload.CreatedBy, &upload.CreatedAt, &upload.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Upload{}, ErrUploadNotFound
	}
	if err != nil {
		return Upload{}, fmt.Errorf("get artifact upload: %w", err)
	}
	return upload, nil
}

func (repository *PostgresRepository) SavePart(ctx context.Context, part UploadPart) error {
	if repository == nil || repository.pool == nil {
		return ErrRepositoryRequired
	}
	_, err := repository.pool.Exec(ctx, `
INSERT INTO artifact_upload_parts (
    upload_id, part_number, size_bytes, sha256, etag, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (upload_id, part_number) DO UPDATE
SET size_bytes = EXCLUDED.size_bytes,
    sha256 = EXCLUDED.sha256,
    etag = EXCLUDED.etag,
    updated_at = EXCLUDED.updated_at
`, part.UploadID, part.PartNumber, part.Size, part.SHA256, part.ETag, part.CreatedAt, part.UpdatedAt)
	if err != nil {
		return fmt.Errorf("save artifact upload part: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) ListParts(ctx context.Context, uploadID uuid.UUID) ([]UploadPart, error) {
	if repository == nil || repository.pool == nil {
		return nil, ErrRepositoryRequired
	}
	rows, err := repository.pool.Query(ctx, `
SELECT upload_id, part_number, size_bytes, sha256, etag, created_at, updated_at
FROM artifact_upload_parts
WHERE upload_id = $1
ORDER BY part_number
`, uploadID)
	if err != nil {
		return nil, fmt.Errorf("list artifact upload parts: %w", err)
	}
	defer rows.Close()
	parts := make([]UploadPart, 0)
	for rows.Next() {
		var part UploadPart
		if err := rows.Scan(&part.UploadID, &part.PartNumber, &part.Size, &part.SHA256, &part.ETag, &part.CreatedAt, &part.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan artifact upload part: %w", err)
		}
		parts = append(parts, part)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate artifact upload parts: %w", err)
	}
	return parts, nil
}

func (repository *PostgresRepository) Quarantine(ctx context.Context, tx pgx.Tx, uploadID uuid.UUID, at time.Time) error {
	return transitionUpload(ctx, tx, uploadID, UploadStatusQuarantined, at)
}

func (repository *PostgresRepository) Expire(ctx context.Context, tx pgx.Tx, uploadID uuid.UUID, at time.Time) error {
	return transitionUpload(ctx, tx, uploadID, UploadStatusExpired, at)
}

func transitionUpload(ctx context.Context, tx pgx.Tx, uploadID uuid.UUID, status UploadStatus, at time.Time) error {
	if tx == nil {
		return ErrTransactorRequired
	}
	result, err := tx.Exec(ctx, `
UPDATE artifact_uploads
SET status = $2, updated_at = $3
WHERE id = $1 AND status = 'uploading'
`, uploadID, status, at)
	if err != nil {
		return fmt.Errorf("transition artifact upload to %s: %w", status, err)
	}
	if result.RowsAffected() != 1 {
		return ErrUploadStateInvalid
	}
	return nil
}

func (repository *PostgresRepository) Complete(ctx context.Context, tx pgx.Tx, uploadID uuid.UUID, candidate Artifact) (Artifact, error) {
	if tx == nil {
		return Artifact{}, ErrTransactorRequired
	}
	var upload Upload
	err := tx.QueryRow(ctx, `
SELECT product_id, artifact_type, filename, content_type, expected_size, expected_sha256, status
FROM artifact_uploads
WHERE id = $1
FOR UPDATE
`, uploadID).Scan(
		&upload.ProductID, &upload.ArtifactType, &upload.Filename, &upload.ContentType,
		&upload.ExpectedSize, &upload.ExpectedSHA256, &upload.Status,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Artifact{}, ErrUploadNotFound
	}
	if err != nil {
		return Artifact{}, fmt.Errorf("lock artifact upload: %w", err)
	}
	if upload.Status != UploadStatusUploading {
		return Artifact{}, ErrUploadStateInvalid
	}
	if upload.ProductID != candidate.ProductID || upload.ArtifactType != candidate.ArtifactType ||
		upload.Filename != candidate.Filename || upload.ContentType != candidate.ContentType ||
		upload.ExpectedSize != candidate.Size || upload.ExpectedSHA256 != candidate.SHA256 {
		return Artifact{}, ErrObjectConflict
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO artifacts (id, sha256, size_bytes, object_key, created_by, created_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (sha256) DO NOTHING
`, candidate.ID, candidate.SHA256, candidate.Size, candidate.ObjectKey, candidate.CreatedBy, candidate.CreatedAt); err != nil {
		return Artifact{}, fmt.Errorf("insert verified artifact: %w", err)
	}

	var physical Artifact
	if err := tx.QueryRow(ctx, `
SELECT id, sha256, size_bytes, object_key, created_by, created_at
FROM artifacts
WHERE sha256 = $1
`, candidate.SHA256).Scan(&physical.ID, &physical.SHA256, &physical.Size, &physical.ObjectKey, &physical.CreatedBy, &physical.CreatedAt); err != nil {
		return Artifact{}, fmt.Errorf("select verified artifact: %w", err)
	}
	if physical.Size != candidate.Size || physical.ObjectKey != candidate.ObjectKey {
		return Artifact{}, ErrObjectConflict
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO artifact_product_bindings (
    product_id, artifact_id, artifact_type, filename, content_type, created_by, created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (product_id, artifact_id) DO NOTHING
`, candidate.ProductID, physical.ID, candidate.ArtifactType, candidate.Filename, candidate.ContentType, candidate.CreatedBy, candidate.CreatedAt); err != nil {
		return Artifact{}, fmt.Errorf("bind artifact to product: %w", err)
	}
	result, err := tx.Exec(ctx, `
UPDATE artifact_uploads
SET status = 'completed', artifact_id = $2, updated_at = $3
WHERE id = $1 AND status = 'uploading'
`, uploadID, physical.ID, candidate.CreatedAt)
	if err != nil {
		return Artifact{}, fmt.Errorf("complete artifact upload: %w", err)
	}
	if result.RowsAffected() != 1 {
		return Artifact{}, ErrUploadStateInvalid
	}
	return scanBoundArtifact(tx.QueryRow(ctx, boundArtifactSelect+`
 WHERE binding.product_id = $1 AND artifact.id = $2
`, candidate.ProductID, physical.ID))
}

func (repository *PostgresRepository) GetArtifact(ctx context.Context, productID string, artifactID uuid.UUID) (Artifact, error) {
	if repository == nil || repository.pool == nil {
		return Artifact{}, ErrRepositoryRequired
	}
	item, err := scanBoundArtifact(repository.pool.QueryRow(ctx, boundArtifactSelect+`
 WHERE binding.product_id = $1 AND artifact.id = $2
`, productID, artifactID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Artifact{}, ErrArtifactNotFound
	}
	if err != nil {
		return Artifact{}, fmt.Errorf("get product artifact: %w", err)
	}
	return item, nil
}

const boundArtifactSelect = `
SELECT
    artifact.id, binding.product_id, binding.artifact_type, binding.filename,
    binding.content_type, artifact.size_bytes, artifact.sha256, artifact.object_key,
    binding.created_by, binding.created_at
FROM artifacts AS artifact
JOIN artifact_product_bindings AS binding ON binding.artifact_id = artifact.id`

type artifactRowScanner interface {
	Scan(dest ...any) error
}

func scanBoundArtifact(row artifactRowScanner) (Artifact, error) {
	var item Artifact
	err := row.Scan(
		&item.ID, &item.ProductID, &item.ArtifactType, &item.Filename,
		&item.ContentType, &item.Size, &item.SHA256, &item.ObjectKey,
		&item.CreatedBy, &item.CreatedAt,
	)
	return item, err
}

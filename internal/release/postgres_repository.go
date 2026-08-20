package release

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresRepository struct {
	pool *pgxpool.Pool
}

var publicationFailureCodePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (repository *PostgresRepository) Create(ctx context.Context, tx pgx.Tx, record Release) error {
	if tx == nil {
		return ErrTransactorRequired
	}
	_, err := tx.Exec(ctx, `
INSERT INTO releases (
    id, product_id, channel_name, version, status, lock_version,
    release_notes, release_notes_sha256, compatibility_bytes, compatibility_json, compatibility_sha256,
    source_repository, source_commit_sha, source_tag, source_pipeline_ref,
    created_by, created_at, updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, $13, $14, $15, $16, $17, $17)
`, record.ID, record.ProductID, record.Channel, record.Version, record.Status, record.LockVersion,
		record.ReleaseNotes, record.ReleaseNotesSHA256, []byte(record.Compatibility), string(record.Compatibility), record.CompatibilitySHA256,
		record.Source.Repository, record.Source.CommitSHA, record.Source.Tag, record.Source.PipelineRef,
		record.CreatedBy, record.CreatedAt)
	if err != nil {
		return mapReleaseDatabaseError("insert release", err)
	}
	for position, binding := range record.Artifacts {
		if _, err := tx.Exec(ctx, `
INSERT INTO release_artifacts (release_id, product_id, artifact_id, position)
VALUES ($1, $2, $3, $4)
`, record.ID, record.ProductID, binding.ArtifactID, position); err != nil {
			return mapReleaseDatabaseError("bind release artifact", err)
		}
	}
	return nil
}

func (repository *PostgresRepository) Get(ctx context.Context, productID string, releaseID uuid.UUID) (Release, error) {
	if repository == nil || repository.pool == nil {
		return Release{}, ErrRepositoryRequired
	}
	return loadRelease(ctx, repository.pool, productID, releaseID)
}

func (repository *PostgresRepository) GetByID(ctx context.Context, releaseID uuid.UUID) (Release, error) {
	if repository == nil || repository.pool == nil {
		return Release{}, ErrRepositoryRequired
	}
	var productID string
	if err := repository.pool.QueryRow(ctx, `SELECT product_id FROM releases WHERE id = $1`, releaseID).Scan(&productID); errors.Is(err, pgx.ErrNoRows) {
		return Release{}, ErrReleaseNotFound
	} else if err != nil {
		return Release{}, fmt.Errorf("find release product: %w", err)
	}
	return loadRelease(ctx, repository.pool, productID, releaseID)
}

func (repository *PostgresRepository) Transition(ctx context.Context, tx pgx.Tx, command TransitionCommand) (Release, error) {
	if tx == nil {
		return Release{}, ErrTransactorRequired
	}
	row := tx.QueryRow(ctx, `
UPDATE releases
SET status = $5,
    lock_version = lock_version + 1,
    submitted_by = CASE WHEN $5 = 'SUBMITTED' THEN $6 ELSE submitted_by END,
    submitted_at = CASE WHEN $5 = 'SUBMITTED' THEN $7 ELSE submitted_at END,
    approved_by = CASE WHEN $5 = 'APPROVED' THEN $6 ELSE approved_by END,
    approved_at = CASE WHEN $5 = 'APPROVED' THEN $7 ELSE approved_at END,
    rejected_by = CASE WHEN $5 = 'REJECTED' THEN $6 ELSE rejected_by END,
    rejected_at = CASE WHEN $5 = 'REJECTED' THEN $7 ELSE rejected_at END,
    rejection_reason = CASE WHEN $5 = 'REJECTED' THEN $8 ELSE rejection_reason END,
    updated_at = $7
WHERE id = $1 AND product_id = $2 AND status = $3 AND lock_version = $4
RETURNING `+releaseColumns,
		command.ReleaseID, command.ProductID, command.From, command.ExpectedLockVersion,
		command.To, command.Actor, command.At, nullableReason(command.Reason))
	record, err := scanRelease(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Release{}, classifyReleaseConflict(ctx, tx, command.ProductID, command.ReleaseID, command.ExpectedLockVersion)
	}
	if err != nil {
		return Release{}, fmt.Errorf("transition release: %w", err)
	}
	bindings, err := loadReleaseArtifacts(ctx, tx, record.ID)
	if err != nil {
		return Release{}, err
	}
	record.Artifacts = bindings
	return record, nil
}

func (repository *PostgresRepository) FindAttempt(ctx context.Context, tx pgx.Tx, releaseID uuid.UUID, kind AttemptKind, idempotencyKey string) (Attempt, error) {
	if repository == nil || repository.pool == nil {
		return Attempt{}, ErrRepositoryRequired
	}
	queryer := releaseQueryer(repository.pool)
	if tx != nil {
		queryer = tx
	}
	var attempt Attempt
	err := queryer.QueryRow(ctx, `
SELECT id, release_id, kind, attempt_number, idempotency_key, status,
       COALESCE(error_code, ''), created_by, created_at, updated_at
FROM release_attempts
WHERE release_id = $1 AND kind = $2 AND idempotency_key = $3
`, releaseID, kind, idempotencyKey).Scan(
		&attempt.ID, &attempt.ReleaseID, &attempt.Kind, &attempt.Number,
		&attempt.IdempotencyKey, &attempt.Status, &attempt.ErrorCode,
		&attempt.CreatedBy, &attempt.CreatedAt, &attempt.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Attempt{}, ErrAttemptNotFound
	}
	if err != nil {
		return Attempt{}, fmt.Errorf("find release attempt: %w", err)
	}
	return attempt, nil
}

func (repository *PostgresRepository) GetAttemptByID(ctx context.Context, attemptID uuid.UUID) (Attempt, error) {
	if repository == nil || repository.pool == nil {
		return Attempt{}, ErrRepositoryRequired
	}
	var attempt Attempt
	err := repository.pool.QueryRow(ctx, `
SELECT id, release_id, kind, attempt_number, idempotency_key, status,
       COALESCE(error_code, ''), created_by, created_at, updated_at
FROM release_attempts
WHERE id = $1
`, attemptID).Scan(
		&attempt.ID, &attempt.ReleaseID, &attempt.Kind, &attempt.Number,
		&attempt.IdempotencyKey, &attempt.Status, &attempt.ErrorCode,
		&attempt.CreatedBy, &attempt.CreatedAt, &attempt.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Attempt{}, ErrAttemptNotFound
	}
	if err != nil {
		return Attempt{}, fmt.Errorf("get release attempt: %w", err)
	}
	return attempt, nil
}

func (repository *PostgresRepository) CompletePublication(ctx context.Context, tx pgx.Tx, releaseID, attemptID uuid.UUID, completedAt time.Time) error {
	if tx == nil {
		return ErrTransactorRequired
	}
	if releaseID == uuid.Nil || attemptID == uuid.Nil || completedAt.IsZero() {
		return ErrAttemptStateInvalid
	}
	var attemptReleaseID uuid.UUID
	var attemptKind AttemptKind
	var attemptStatus AttemptStatus
	if err := tx.QueryRow(ctx, `
SELECT release_id, kind, status
FROM release_attempts
WHERE id = $1
FOR UPDATE
`, attemptID).Scan(&attemptReleaseID, &attemptKind, &attemptStatus); errors.Is(err, pgx.ErrNoRows) {
		return ErrAttemptNotFound
	} else if err != nil {
		return fmt.Errorf("lock publication attempt: %w", err)
	}
	if attemptReleaseID != releaseID || attemptKind != AttemptKindPublish {
		return ErrAttemptNotFound
	}
	if attemptStatus == AttemptStatusSucceeded {
		var status Status
		if err := tx.QueryRow(ctx, `SELECT status FROM releases WHERE id = $1`, releaseID).Scan(&status); err != nil {
			return fmt.Errorf("get completed publication release: %w", err)
		}
		if status == StatusPublished {
			return nil
		}
		return ErrAttemptStateInvalid
	}
	if attemptStatus != AttemptStatusPending {
		return ErrAttemptStateInvalid
	}
	completedAt = completedAt.UTC().Truncate(time.Microsecond)
	result, err := tx.Exec(ctx, `
UPDATE releases
SET status = 'PUBLISHED', lock_version = lock_version + 1,
    publication_failure_code = NULL, updated_at = $2
WHERE id = $1 AND status = 'PUBLISHING'
`, releaseID, completedAt)
	if err != nil {
		return fmt.Errorf("mark release published: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrInvalidTransition
	}
	result, err = tx.Exec(ctx, `
UPDATE release_attempts
SET status = 'succeeded', error_code = NULL, updated_at = $3
WHERE id = $1 AND release_id = $2 AND status = 'pending'
`, attemptID, releaseID, completedAt)
	if err != nil {
		return fmt.Errorf("mark publication attempt succeeded: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrAttemptStateInvalid
	}
	return nil
}

func (repository *PostgresRepository) CompleteRevocation(ctx context.Context, tx pgx.Tx, releaseID, attemptID uuid.UUID, completedAt time.Time) error {
	if tx == nil {
		return ErrTransactorRequired
	}
	if releaseID == uuid.Nil || attemptID == uuid.Nil || completedAt.IsZero() {
		return ErrAttemptStateInvalid
	}
	var attemptReleaseID uuid.UUID
	var kind AttemptKind
	var status AttemptStatus
	if err := tx.QueryRow(ctx, `
SELECT release_id, kind, status
FROM release_attempts
WHERE id = $1
FOR UPDATE
`, attemptID).Scan(&attemptReleaseID, &kind, &status); errors.Is(err, pgx.ErrNoRows) {
		return ErrAttemptNotFound
	} else if err != nil {
		return fmt.Errorf("lock revocation attempt: %w", err)
	}
	if attemptReleaseID != releaseID || kind != AttemptKindRevoke {
		return ErrAttemptNotFound
	}
	if status == AttemptStatusSucceeded {
		return nil
	}
	if status != AttemptStatusPending {
		return ErrAttemptStateInvalid
	}
	var releaseStatus Status
	var revokedAt *time.Time
	if err := tx.QueryRow(ctx, `SELECT status, revoked_at FROM releases WHERE id = $1 FOR SHARE`, releaseID).Scan(&releaseStatus, &revokedAt); err != nil {
		return fmt.Errorf("validate revoked release: %w", err)
	}
	if releaseStatus != StatusPublished || revokedAt == nil {
		return ErrInvalidTransition
	}
	result, err := tx.Exec(ctx, `
UPDATE release_attempts
SET status = 'succeeded', error_code = NULL, updated_at = $3
WHERE id = $1 AND release_id = $2 AND status = 'pending'
`, attemptID, releaseID, completedAt.UTC().Truncate(time.Microsecond))
	if err != nil {
		return fmt.Errorf("mark revocation attempt succeeded: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrAttemptStateInvalid
	}
	return nil
}

func (repository *PostgresRepository) FailPublication(ctx context.Context, tx pgx.Tx, releaseID, attemptID uuid.UUID, errorCode string, failedAt time.Time) error {
	if tx == nil {
		return ErrTransactorRequired
	}
	errorCode = strings.TrimSpace(errorCode)
	if releaseID == uuid.Nil || attemptID == uuid.Nil || failedAt.IsZero() || len(errorCode) > 128 || !publicationFailureCodePattern.MatchString(errorCode) {
		return ErrAttemptStateInvalid
	}
	var attemptReleaseID uuid.UUID
	var attemptKind AttemptKind
	var attemptStatus AttemptStatus
	var existingCode string
	if err := tx.QueryRow(ctx, `
SELECT release_id, kind, status, COALESCE(error_code, '')
FROM release_attempts
WHERE id = $1
FOR UPDATE
`, attemptID).Scan(&attemptReleaseID, &attemptKind, &attemptStatus, &existingCode); errors.Is(err, pgx.ErrNoRows) {
		return ErrAttemptNotFound
	} else if err != nil {
		return fmt.Errorf("lock failed publication attempt: %w", err)
	}
	if attemptReleaseID != releaseID || attemptKind != AttemptKindPublish {
		return ErrAttemptNotFound
	}
	if attemptStatus == AttemptStatusFailed {
		var status Status
		var releaseCode string
		if err := tx.QueryRow(ctx, `SELECT status, COALESCE(publication_failure_code, '') FROM releases WHERE id = $1`, releaseID).Scan(&status, &releaseCode); err != nil {
			return fmt.Errorf("get failed publication release: %w", err)
		}
		if status == StatusFailed && existingCode == errorCode && releaseCode == errorCode {
			return nil
		}
		return ErrAttemptStateInvalid
	}
	if attemptStatus != AttemptStatusPending {
		return ErrAttemptStateInvalid
	}
	failedAt = failedAt.UTC().Truncate(time.Microsecond)
	result, err := tx.Exec(ctx, `
UPDATE releases
SET status = 'FAILED', lock_version = lock_version + 1,
    publication_failure_code = $2, updated_at = $3
WHERE id = $1 AND status = 'PUBLISHING'
`, releaseID, errorCode, failedAt)
	if err != nil {
		return fmt.Errorf("mark release publication failed: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrInvalidTransition
	}
	result, err = tx.Exec(ctx, `
UPDATE release_attempts
SET status = 'failed', error_code = $3, updated_at = $4
WHERE id = $1 AND release_id = $2 AND status = 'pending'
`, attemptID, releaseID, errorCode, failedAt)
	if err != nil {
		return fmt.Errorf("mark publication attempt failed: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrAttemptStateInvalid
	}
	return nil
}

func (repository *PostgresRepository) FailRevocation(ctx context.Context, tx pgx.Tx, releaseID, attemptID uuid.UUID, errorCode string, failedAt time.Time) error {
	if tx == nil {
		return ErrTransactorRequired
	}
	errorCode = strings.TrimSpace(errorCode)
	if releaseID == uuid.Nil || attemptID == uuid.Nil || failedAt.IsZero() || len(errorCode) > 128 || !publicationFailureCodePattern.MatchString(errorCode) {
		return ErrAttemptStateInvalid
	}
	var attemptReleaseID uuid.UUID
	var kind AttemptKind
	var status AttemptStatus
	var existingCode string
	if err := tx.QueryRow(ctx, `
SELECT release_id, kind, status, COALESCE(error_code, '')
FROM release_attempts
WHERE id = $1
FOR UPDATE
`, attemptID).Scan(&attemptReleaseID, &kind, &status, &existingCode); errors.Is(err, pgx.ErrNoRows) {
		return ErrAttemptNotFound
	} else if err != nil {
		return fmt.Errorf("lock failed revocation attempt: %w", err)
	}
	if attemptReleaseID != releaseID || kind != AttemptKindRevoke {
		return ErrAttemptNotFound
	}
	if status == AttemptStatusFailed && existingCode == errorCode {
		return nil
	}
	if status != AttemptStatusPending {
		return ErrAttemptStateInvalid
	}
	var releaseStatus Status
	var revokedAt *time.Time
	if err := tx.QueryRow(ctx, `SELECT status, revoked_at FROM releases WHERE id = $1 FOR SHARE`, releaseID).Scan(&releaseStatus, &revokedAt); err != nil {
		return fmt.Errorf("validate failed revocation release: %w", err)
	}
	if releaseStatus != StatusPublished || revokedAt == nil {
		return ErrInvalidTransition
	}
	result, err := tx.Exec(ctx, `
UPDATE release_attempts
SET status = 'failed', error_code = $3, updated_at = $4
WHERE id = $1 AND release_id = $2 AND status = 'pending'
`, attemptID, releaseID, errorCode, failedAt.UTC().Truncate(time.Microsecond))
	if err != nil {
		return fmt.Errorf("mark revocation attempt failed: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrAttemptStateInvalid
	}
	return nil
}

func (repository *PostgresRepository) LockOperation(ctx context.Context, tx pgx.Tx, releaseID uuid.UUID, kind AttemptKind, idempotencyKey string) error {
	if tx == nil {
		return ErrTransactorRequired
	}
	lockKey := releaseID.String() + ":" + string(kind) + ":" + idempotencyKey
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return fmt.Errorf("lock idempotent release operation: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) CreateAttempt(ctx context.Context, tx pgx.Tx, attempt Attempt) (Attempt, error) {
	if tx == nil {
		return Attempt{}, ErrTransactorRequired
	}
	err := tx.QueryRow(ctx, `
INSERT INTO release_attempts (
    id, release_id, kind, attempt_number, idempotency_key, status, created_by, created_at, updated_at
)
SELECT $1, $2, $3, COALESCE(MAX(attempt_number), 0) + 1, $4, $5, $6, $7, $7
FROM release_attempts
WHERE release_id = $2
RETURNING attempt_number
`, attempt.ID, attempt.ReleaseID, attempt.Kind, attempt.IdempotencyKey, attempt.Status, attempt.CreatedBy, attempt.CreatedAt).Scan(&attempt.Number)
	if err != nil {
		return Attempt{}, mapReleaseDatabaseError("insert release attempt", err)
	}
	return attempt, nil
}

func (repository *PostgresRepository) Revoke(ctx context.Context, tx pgx.Tx, command RevokeCommand) (Release, error) {
	if tx == nil {
		return Release{}, ErrTransactorRequired
	}
	record, err := scanRelease(tx.QueryRow(ctx, `
UPDATE releases
SET revoked_at = $4,
    revoked_by = $5,
    revocation_reason = $6,
    lock_version = lock_version + 1,
    updated_at = $4
WHERE id = $1 AND product_id = $2 AND status = 'PUBLISHED' AND lock_version = $3 AND revoked_at IS NULL
RETURNING `+releaseColumns,
		command.ReleaseID, command.ProductID, command.ExpectedLockVersion,
		command.At, command.Actor, command.Reason))
	if errors.Is(err, pgx.ErrNoRows) {
		current, getErr := loadRelease(ctx, tx, command.ProductID, command.ReleaseID)
		if getErr != nil {
			return Release{}, getErr
		}
		if current.RevokedAt != nil {
			return Release{}, ErrReleaseAlreadyRevoked
		}
		if current.LockVersion != command.ExpectedLockVersion {
			return Release{}, ErrStaleRelease
		}
		return Release{}, ErrInvalidTransition
	}
	if err != nil {
		return Release{}, fmt.Errorf("revoke release: %w", err)
	}
	bindings, err := loadReleaseArtifacts(ctx, tx, record.ID)
	if err != nil {
		return Release{}, err
	}
	record.Artifacts = bindings
	return record, nil
}

const releaseColumns = `
id, product_id, channel_name, version, status, lock_version,
release_notes, release_notes_sha256, compatibility_bytes, compatibility_sha256,
source_repository, source_commit_sha, source_tag, source_pipeline_ref,
created_by, created_at, updated_at,
COALESCE(submitted_by, ''), submitted_at, COALESCE(approved_by, ''), approved_at,
COALESCE(rejected_by, ''), rejected_at, COALESCE(rejection_reason, ''),
revoked_at, COALESCE(revoked_by, ''), COALESCE(revocation_reason, ''), COALESCE(publication_failure_code, '')`

type releaseRow interface {
	Scan(dest ...any) error
}

func scanRelease(row releaseRow) (Release, error) {
	var record Release
	var compatibility []byte
	err := row.Scan(
		&record.ID, &record.ProductID, &record.Channel, &record.Version, &record.Status, &record.LockVersion,
		&record.ReleaseNotes, &record.ReleaseNotesSHA256, &compatibility, &record.CompatibilitySHA256,
		&record.Source.Repository, &record.Source.CommitSHA, &record.Source.Tag, &record.Source.PipelineRef,
		&record.CreatedBy, &record.CreatedAt, &record.UpdatedAt,
		&record.SubmittedBy, &record.SubmittedAt, &record.ApprovedBy, &record.ApprovedAt,
		&record.RejectedBy, &record.RejectedAt, &record.RejectionReason,
		&record.RevokedAt, &record.RevokedBy, &record.RevocationReason, &record.PublicationFailureCode,
	)
	record.Compatibility = append(json.RawMessage(nil), compatibility...)
	return record, err
}

type releaseQueryer interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func loadRelease(ctx context.Context, queryer releaseQueryer, productID string, releaseID uuid.UUID) (Release, error) {
	record, err := scanRelease(queryer.QueryRow(ctx, `SELECT `+releaseColumns+` FROM releases WHERE product_id = $1 AND id = $2`, productID, releaseID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Release{}, ErrReleaseNotFound
	}
	if err != nil {
		return Release{}, fmt.Errorf("get release: %w", err)
	}
	bindings, err := loadReleaseArtifacts(ctx, queryer, releaseID)
	if err != nil {
		return Release{}, err
	}
	record.Artifacts = bindings
	return record, nil
}

func loadReleaseArtifacts(ctx context.Context, queryer releaseQueryer, releaseID uuid.UUID) ([]ArtifactBinding, error) {
	rows, err := queryer.Query(ctx, `
SELECT binding.artifact_id, product_binding.artifact_type, product_binding.filename,
       artifact.size_bytes, artifact.sha256
FROM release_artifacts AS binding
JOIN artifact_product_bindings AS product_binding
  ON product_binding.product_id = binding.product_id AND product_binding.artifact_id = binding.artifact_id
JOIN artifacts AS artifact ON artifact.id = binding.artifact_id
WHERE binding.release_id = $1
ORDER BY binding.position
`, releaseID)
	if err != nil {
		return nil, fmt.Errorf("list release artifacts: %w", err)
	}
	defer rows.Close()
	bindings := make([]ArtifactBinding, 0)
	for rows.Next() {
		var binding ArtifactBinding
		if err := rows.Scan(&binding.ArtifactID, &binding.ArtifactType, &binding.Filename, &binding.Size, &binding.SHA256); err != nil {
			return nil, fmt.Errorf("scan release artifact: %w", err)
		}
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate release artifacts: %w", err)
	}
	return bindings, nil
}

func classifyReleaseConflict(ctx context.Context, queryer releaseQueryer, productID string, releaseID uuid.UUID, expectedLockVersion int64) error {
	var lockVersion int64
	if err := queryer.QueryRow(ctx, `SELECT lock_version FROM releases WHERE product_id = $1 AND id = $2`, productID, releaseID).Scan(&lockVersion); errors.Is(err, pgx.ErrNoRows) {
		return ErrReleaseNotFound
	} else if err != nil {
		return fmt.Errorf("classify release transition conflict: %w", err)
	}
	if lockVersion != expectedLockVersion {
		return ErrStaleRelease
	}
	return ErrInvalidTransition
}

func mapReleaseDatabaseError(operation string, err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.ConstraintName {
		case "releases_product_channel_version_unique":
			return fmt.Errorf("%s: %w", operation, ErrReleaseVersionExists)
		case "release_attempts_idempotency_unique":
			return fmt.Errorf("%s: %w", operation, ErrAttemptAlreadyExists)
		}
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func nullableReason(reason string) any {
	if reason == "" {
		return nil
	}
	return reason
}

var _ Repository = (*PostgresRepository)(nil)

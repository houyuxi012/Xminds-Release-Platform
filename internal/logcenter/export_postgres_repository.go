package logcenter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/platform/database"
)

const JobKindExport = "log.export.v1"

const exportJobKind = JobKindExport

type PostgresExportStore struct{ pool *pgxpool.Pool }

func NewPostgresExportStore(pool *pgxpool.Pool) *PostgresExportStore {
	return &PostgresExportStore{pool: pool}
}

// CreateExport is intentionally unavailable without the transactional
// authorization callback; callers must use CreateOrGetExport through the
// ExportService.
func (store *PostgresExportStore) CreateExport(context.Context, ExportRecord) error {
	return ErrExportUnavailable
}

func (store *PostgresExportStore) CreateOrGetExport(ctx context.Context, record ExportRecord, authorize func(context.Context) error) (ExportRecord, error) {
	if store == nil || store.pool == nil {
		return ExportRecord{}, ErrExportUnavailable
	}
	if record.ID == uuid.Nil || strings.TrimSpace(record.Requester) == "" || strings.TrimSpace(record.DedupeKey) == "" || record.CreatedAt.IsZero() {
		return ExportRecord{}, ErrInvalidExportRequest
	}
	returnRecord := ExportRecord{}
	err := database.WithTx(ctx, store.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, record.Requester+"\x00"+record.DedupeKey); err != nil {
			return fmt.Errorf("lock log export dedupe key: %w", err)
		}
		var existing ExportRecord
		found, err := store.selectExport(ctx, tx, record.Requester, record.DedupeKey, &existing)
		if err != nil {
			return err
		}
		if found {
			if !sameExportRequest(existing, record) {
				return ErrExportConflict
			}
			returnRecord = existing
			return nil
		}
		if authorize == nil {
			return ErrExportForbidden
		}
		if err := authorize(WithExportAuthorizationTx(ctx, tx)); err != nil {
			return err
		}
		scopeJSON, err := json.Marshal(record.Scope)
		if err != nil {
			return ErrInvalidExportRequest
		}
		filtersJSON, err := json.Marshal(record.Filters)
		if err != nil {
			return ErrInvalidExportRequest
		}
		jobID, err := uuid.NewV7()
		if err != nil {
			return err
		}
		createdAt := record.CreatedAt.UTC()
		if _, err := tx.Exec(ctx, `
INSERT INTO log_exports (id, requester, log_types, scope, filters, dedupe_key, status, created_at, updated_at)
VALUES ($1, $2, $3::text[], $4::jsonb, $5::jsonb, $6, 'queued', $7, $7)
`, record.ID, record.Requester, logTypeArray(record.LogTypes), scopeJSON, filtersJSON, record.DedupeKey, createdAt); err != nil {
			return fmt.Errorf("insert log export: %w", err)
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO log_export_jobs (id, export_id, status, attempts, next_run_at, created_at, updated_at)
VALUES ($1, $2, 'pending', 0, $3, $3, $3)
`, jobID, record.ID, createdAt); err != nil {
			return fmt.Errorf("insert log export job: %w", err)
		}
		payload, _ := json.Marshal(map[string]string{"export_id": record.ID.String()})
		if _, err := tx.Exec(ctx, `
INSERT INTO outbox_jobs (id, kind, aggregate_id, payload, status, attempts, available_at, created_at, updated_at)
VALUES ($1, $2, $3, $4::jsonb, 'pending', 0, $5, $5, $5)
`, jobID, exportJobKind, record.ID, payload, createdAt); err != nil {
			return fmt.Errorf("enqueue log export job: %w", err)
		}
		record.Status = "queued"
		returnRecord = record
		return nil
	})
	if err != nil {
		return ExportRecord{}, mapExportStoreError(err)
	}
	return returnRecord, nil
}

func (store *PostgresExportStore) GetExport(ctx context.Context, id uuid.UUID, scope LogReadScope) (ExportRecord, bool, error) {
	if store == nil || store.pool == nil {
		return ExportRecord{}, false, ErrRepositoryUnavailable
	}
	var record ExportRecord
	row := store.pool.QueryRow(ctx, exportSelect+" WHERE id=$1", id)
	found, err := scanExport(row, &record)
	if err != nil {
		return ExportRecord{}, false, err
	}
	if !found {
		return ExportRecord{}, false, nil
	}
	if record.Scope.Digest != scope.Digest {
		return ExportRecord{}, false, ErrExportForbidden
	}
	return record, true, nil
}

func (store *PostgresExportStore) GrantDownload(ctx context.Context, id uuid.UUID, scope LogReadScope, _ time.Duration) (string, error) {
	record, found, err := store.GetExport(ctx, id, scope)
	if err != nil {
		return "", err
	}
	if !found {
		return "", ErrExportNotFound
	}
	if record.Status != "completed" || strings.TrimSpace(record.ArchiveKey) == "" {
		return "", ErrExportUnavailable
	}
	// The API serves the immutable archive through an authenticated endpoint;
	// no bearer or storage credential is embedded in the returned URL.
	return "/api/v1/log-exports/" + id.String() + "/content", nil
}

func (store *PostgresExportStore) ClaimExportJob(ctx context.Context, now time.Time) (ExportJob, bool, error) {
	return store.claimExportJob(ctx, now, uuid.Nil)
}

func (store *PostgresExportStore) ClaimExportJobByID(ctx context.Context, now time.Time, id uuid.UUID) (ExportJob, bool, error) {
	if id == uuid.Nil {
		return ExportJob{}, false, ErrInvalidExportJob
	}
	return store.claimExportJob(ctx, now, id)
}

func (store *PostgresExportStore) claimExportJob(ctx context.Context, now time.Time, requestedID uuid.UUID) (ExportJob, bool, error) {
	if store == nil || store.pool == nil {
		return ExportJob{}, false, ErrRepositoryUnavailable
	}
	var job ExportJob
	found := false
	err := database.WithTx(ctx, store.pool, func(tx pgx.Tx) error {
		var id uuid.UUID
		query := `
SELECT id FROM log_export_jobs
WHERE (status IN ('pending','failed') AND next_run_at <= $1)
   OR (status = 'running' AND lease_expires_at <= $1)
ORDER BY next_run_at, created_at
	FOR UPDATE SKIP LOCKED
		`
		args := []any{now.UTC()}
		if requestedID != uuid.Nil {
			query = `SELECT id FROM log_export_jobs WHERE id=$2 AND ((status IN ('pending','failed') AND next_run_at <= $1) OR (status = 'running' AND lease_expires_at <= $1)) FOR UPDATE SKIP LOCKED`
			args = append(args, requestedID)
		}
		err := tx.QueryRow(ctx, query, args...).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("select due log export job: %w", err)
		}
		leaseToken := uuid.New()
		leaseUntil := now.UTC().Add(15 * time.Minute)
		if err := tx.QueryRow(ctx, `
UPDATE log_export_jobs
SET status='running', attempts=attempts+1, lease_token=$2, lease_expires_at=$3, updated_at=$4
WHERE id=$1
RETURNING id, export_id, lease_token, attempts, next_run_at, status`, id, leaseToken, leaseUntil, now.UTC()).Scan(&job.ID, &job.ExportID, &job.LeaseToken, &job.Attempts, &job.NextRunAt, &job.Status); err != nil {
			return fmt.Errorf("claim log export job: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE log_exports SET status='running', updated_at=$2 WHERE id=$1`, job.ExportID, now.UTC()); err != nil {
			return fmt.Errorf("mark log export running: %w", err)
		}
		found = true
		return nil
	})
	if err != nil {
		return ExportJob{}, false, err
	}
	return job, found, nil
}

func (store *PostgresExportStore) CompleteExportJob(ctx context.Context, id, token uuid.UUID) error {
	return store.transitionJob(ctx, id, token, "completed", "completed", time.Time{}, "")
}

func (store *PostgresExportStore) FailExportJob(ctx context.Context, id, token uuid.UUID, next time.Time) error {
	return store.transitionJob(ctx, id, token, "failed", "failed", next, "EXPORT_RETRY")
}

func (store *PostgresExportStore) ExhaustExportJob(ctx context.Context, id, token uuid.UUID, cause error) error {
	code := "EXPORT_EXHAUSTED"
	if cause != nil && strings.TrimSpace(cause.Error()) != "" {
		code = "EXPORT_EXHAUSTED"
	}
	return store.transitionJob(ctx, id, token, "exhausted", "exhausted", time.Time{}, code)
}

func (store *PostgresExportStore) ExhaustExportJobTx(ctx context.Context, tx pgx.Tx, id, exportID uuid.UUID, cause string) error {
	if store == nil || tx == nil || id == uuid.Nil || exportID == uuid.Nil {
		return ErrRepositoryUnavailable
	}
	code := strings.TrimSpace(cause)
	if code == "" || len(code) > 128 {
		code = "EXPORT_EXHAUSTED"
	}
	var transitionedExportID uuid.UUID
	if err := tx.QueryRow(ctx, `
UPDATE log_export_jobs
SET status='exhausted', lease_token=NULL, lease_expires_at=NULL, last_error_code=$3, updated_at=clock_timestamp()
WHERE id=$1 AND export_id=$2 AND (status IN ('pending','failed') OR (status='running' AND lease_expires_at <= clock_timestamp()))
RETURNING export_id`, id, exportID, code).Scan(&transitionedExportID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return fmt.Errorf("exhaust log export job in dead letter: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE log_exports SET status='exhausted', last_error_code=$2, updated_at=clock_timestamp() WHERE id=$1 AND status <> 'completed'`, transitionedExportID, code); err != nil {
		return fmt.Errorf("exhaust log export in dead letter: %w", err)
	}
	return nil
}

func (store *PostgresExportStore) SetExportArtifact(ctx context.Context, id, jobID, leaseToken uuid.UUID, key, downloadURL string, manifest ExportManifest, signature []byte) error {
	if store == nil || store.pool == nil {
		return ErrRepositoryUnavailable
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return ErrInvalidExportRecord
	}
	if len(signature) != 64 {
		return ErrInvalidExportRecord
	}
	if id == uuid.Nil || jobID == uuid.Nil || leaseToken == uuid.Nil {
		return ErrExportLeaseLost
	}
	return database.WithTx(ctx, store.pool, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, `
UPDATE log_exports
SET archive_key=$4, archive_url=$5, manifest=$6::jsonb, manifest_signature=$7, updated_at=clock_timestamp()
WHERE id=$1 AND EXISTS (
    SELECT 1 FROM log_export_jobs
    WHERE id=$2 AND export_id=$1 AND status='running' AND lease_token=$3
)`, id, jobID, leaseToken, key, downloadURL, manifestJSON, signature)
		if err != nil {
			return fmt.Errorf("store log export artifact: %w", err)
		}
		if result.RowsAffected() != 1 {
			return ErrExportLeaseLost
		}
		return nil
	})
}

func (store *PostgresExportStore) SetExportArtifactAndComplete(ctx context.Context, id, jobID, leaseToken uuid.UUID, key, downloadURL string, manifest ExportManifest, signature []byte) error {
	if store == nil || store.pool == nil {
		return ErrRepositoryUnavailable
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return ErrInvalidExportRecord
	}
	if len(signature) != 64 || id == uuid.Nil || jobID == uuid.Nil || leaseToken == uuid.Nil {
		return ErrExportLeaseLost
	}
	return database.WithTx(ctx, store.pool, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, `
UPDATE log_exports
SET archive_key=$4, archive_url=$5, manifest=$6::jsonb, manifest_signature=$7, status='completed', updated_at=clock_timestamp()
WHERE id=$1 AND EXISTS (
    SELECT 1 FROM log_export_jobs
    WHERE id=$2 AND export_id=$1 AND status='running' AND lease_token=$3
)`, id, jobID, leaseToken, key, downloadURL, manifestJSON, signature)
		if err != nil {
			return fmt.Errorf("store and complete log export artifact: %w", err)
		}
		if result.RowsAffected() != 1 {
			return ErrExportLeaseLost
		}
		var exportID uuid.UUID
		if err := tx.QueryRow(ctx, `
UPDATE log_export_jobs
SET status='completed', lease_token=NULL, lease_expires_at=NULL, last_error_code=NULL, updated_at=clock_timestamp()
WHERE id=$1 AND export_id=$2 AND status='running' AND lease_token=$3
RETURNING export_id`, jobID, id, leaseToken).Scan(&exportID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrExportLeaseLost
			}
			return fmt.Errorf("complete log export job with artifact: %w", err)
		}
		if exportID != id {
			return ErrExportLeaseLost
		}
		return nil
	})
}

func (store *PostgresExportStore) transitionJob(ctx context.Context, id, token uuid.UUID, jobStatus, exportStatus string, next time.Time, errorCode string) error {
	if store == nil || store.pool == nil || id == uuid.Nil || token == uuid.Nil {
		return ErrRepositoryUnavailable
	}
	return database.WithTx(ctx, store.pool, func(tx pgx.Tx) error {
		var exportID uuid.UUID
		row := tx.QueryRow(ctx, `UPDATE log_export_jobs SET status=$3, next_run_at=CASE WHEN $3='failed' THEN $4 ELSE next_run_at END, lease_token=NULL, lease_expires_at=NULL, last_error_code=NULLIF($5,''), updated_at=clock_timestamp() WHERE id=$1 AND status='running' AND lease_token=$2 RETURNING export_id`, id, token, jobStatus, next.UTC(), errorCode)
		if err := row.Scan(&exportID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrExportLeaseLost
			}
			return fmt.Errorf("transition log export job: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE log_exports SET status=$2, last_error_code=NULLIF($3,''), updated_at=clock_timestamp() WHERE id=$1`, exportID, exportStatus, errorCode); err != nil {
			return fmt.Errorf("transition log export: %w", err)
		}
		return nil
	})
}

const exportSelect = `SELECT id, requester, log_types, scope, filters, dedupe_key, status, COALESCE(archive_key,''), COALESCE(archive_url,''), COALESCE(manifest,'{}'::jsonb), COALESCE(manifest_signature,''::bytea), COALESCE(last_error_code,''), created_at, updated_at FROM log_exports`

func (store *PostgresExportStore) selectExport(ctx context.Context, tx pgx.Tx, requester, dedupe string, record *ExportRecord) (bool, error) {
	row := tx.QueryRow(ctx, exportSelect+" WHERE requester=$1 AND dedupe_key=$2 FOR UPDATE", requester, dedupe)
	found, err := scanExport(row, record)
	return found, err
}

type exportRowScanner interface{ Scan(...any) error }

func scanExport(row exportRowScanner, record *ExportRecord) (bool, error) {
	var logTypes []string
	var scopeJSON, filtersJSON, manifestJSON []byte
	err := row.Scan(&record.ID, &record.Requester, &logTypes, &scopeJSON, &filtersJSON, &record.DedupeKey, &record.Status, &record.ArchiveKey, &record.DownloadURL, &manifestJSON, &record.ManifestSignature, &record.LastErrorCode, &record.CreatedAt, &record.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("scan log export: %w", err)
	}
	for _, value := range logTypes {
		record.LogTypes = append(record.LogTypes, ScopeTable(value))
	}
	if json.Unmarshal(scopeJSON, &record.Scope) != nil || json.Unmarshal(filtersJSON, &record.Filters) != nil || json.Unmarshal(manifestJSON, &record.Manifest) != nil {
		return false, ErrInvalidExportRecord
	}
	return true, nil
}

func sameExportRequest(left, right ExportRecord) bool {
	if left.Scope.Digest != right.Scope.Digest {
		return false
	}
	leftTypes := append([]ScopeTable(nil), left.LogTypes...)
	rightTypes := append([]ScopeTable(nil), right.LogTypes...)
	sort.Slice(leftTypes, func(i, j int) bool { return leftTypes[i] < leftTypes[j] })
	sort.Slice(rightTypes, func(i, j int) bool { return rightTypes[i] < rightTypes[j] })
	if len(leftTypes) != len(rightTypes) {
		return false
	}
	for i := range leftTypes {
		if leftTypes[i] != rightTypes[i] {
			return false
		}
	}
	leftFilters, _ := json.Marshal(left.Filters)
	rightFilters, _ := json.Marshal(right.Filters)
	return string(leftFilters) == string(rightFilters)
}

func logTypeArray(types []ScopeTable) []string {
	result := make([]string, 0, len(types))
	for _, value := range types {
		result = append(result, string(value))
	}
	return result
}

func mapExportStoreError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrExportNotFound
	}
	return err
}

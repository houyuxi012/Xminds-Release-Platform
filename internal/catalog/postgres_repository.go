package catalog

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (repository *PostgresRepository) ReserveVersions(ctx context.Context, tx pgx.Tx, productID, channel string, rootVersion uint64) (Versions, error) {
	if tx == nil {
		return Versions{}, ErrTransactionRequired
	}
	if productID == "" || channel == "" || rootVersion == 0 {
		return Versions{}, ErrVersionsInvalid
	}
	var versions Versions
	err := tx.QueryRow(ctx, `
INSERT INTO catalog_version_counters (
    product_id, channel_name, root_version, targets_version, snapshot_version, timestamp_version, revocation_version
)
VALUES ($1, $2, $3, 1, 1, 1, 1)
ON CONFLICT (product_id, channel_name) DO UPDATE
SET root_version = EXCLUDED.root_version,
    targets_version = catalog_version_counters.targets_version + 1,
    snapshot_version = catalog_version_counters.snapshot_version + 1,
    timestamp_version = catalog_version_counters.timestamp_version + 1,
    revocation_version = catalog_version_counters.revocation_version + 1
WHERE catalog_version_counters.root_version <= EXCLUDED.root_version
RETURNING root_version, targets_version, snapshot_version, timestamp_version, revocation_version
`, productID, channel, rootVersion).Scan(
		&versions.Root, &versions.Targets, &versions.Snapshot, &versions.Timestamp, &versions.Revocation,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Versions{}, ErrMetadataVersionRollback
	}
	if err != nil {
		return Versions{}, fmt.Errorf("reserve catalog metadata versions: %w", err)
	}
	return versions, nil
}

func (repository *PostgresRepository) Create(ctx context.Context, tx pgx.Tx, record VersionRecord) error {
	if tx == nil {
		return ErrTransactionRequired
	}
	if err := validateVersionRecord(record); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
INSERT INTO catalog_versions (
    id, publication_attempt_id, product_id, channel_name, release_id,
    root_version, targets_version, snapshot_version, timestamp_version, revocation_version,
    bundle_sha256, created_at
)
VALUES ($1, NULLIF($2, '00000000-0000-0000-0000-000000000000'::uuid), $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
`, record.ID, record.AttemptID, record.ProductID, record.Channel, record.ReleaseID,
		record.Versions.Root, record.Versions.Targets, record.Versions.Snapshot, record.Versions.Timestamp, record.Versions.Revocation,
		record.BundleSHA256, record.CreatedAt.UTC())
	if err != nil {
		return mapCatalogDatabaseError("insert catalog version", err)
	}
	for _, role := range []Role{RoleRoot, RoleTargets, RoleSnapshot, RoleTimestamp, RoleRevocation} {
		document := record.Roles[role]
		if _, err := tx.Exec(ctx, `
INSERT INTO catalog_role_documents (
    catalog_version_id, role, role_version, envelope_sha256, object_key, signatures, envelope_bytes
)
VALUES ($1, $2, $3, $4, $5, $6::jsonb, NULLIF($7, ''::bytea))
`, record.ID, role, document.Version, document.EnvelopeSHA256, document.ObjectKey, document.Signatures, document.Envelope); err != nil {
			return mapCatalogDatabaseError("insert catalog role document", err)
		}
	}
	return nil
}

func (repository *PostgresRepository) FindByAttempt(ctx context.Context, attemptID uuid.UUID) (VersionRecord, error) {
	if repository == nil || repository.pool == nil {
		return VersionRecord{}, ErrRepositoryRequired
	}
	if attemptID == uuid.Nil {
		return VersionRecord{}, ErrVersionRecordNotFound
	}
	record, err := scanVersionRecord(repository.pool.QueryRow(ctx, catalogVersionSelect+` WHERE version.publication_attempt_id = $1`, attemptID))
	if errors.Is(err, pgx.ErrNoRows) {
		return VersionRecord{}, ErrVersionRecordNotFound
	}
	if err != nil {
		return VersionRecord{}, fmt.Errorf("find catalog version by publication attempt: %w", err)
	}
	record.Roles, err = loadRoleDocuments(ctx, repository.pool, record.ID)
	if err != nil {
		return VersionRecord{}, err
	}
	return record, nil
}

func (repository *PostgresRepository) Get(ctx context.Context, catalogVersionID uuid.UUID) (VersionRecord, error) {
	if repository == nil || repository.pool == nil {
		return VersionRecord{}, ErrRepositoryRequired
	}
	record, err := scanVersionRecord(repository.pool.QueryRow(ctx, catalogVersionSelect+` WHERE version.id = $1`, catalogVersionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return VersionRecord{}, ErrVersionRecordNotFound
	}
	if err != nil {
		return VersionRecord{}, fmt.Errorf("get catalog version: %w", err)
	}
	roles, err := loadRoleDocuments(ctx, repository.pool, record.ID)
	if err != nil {
		return VersionRecord{}, err
	}
	record.Roles = roles
	return record, nil
}

func (repository *PostgresRepository) SetCurrent(ctx context.Context, tx pgx.Tx, productID, channel string, catalogVersionID uuid.UUID, switchedAt time.Time) error {
	if tx == nil {
		return ErrTransactionRequired
	}
	if productID == "" || channel == "" || catalogVersionID == uuid.Nil || switchedAt.IsZero() {
		return ErrVersionRecordInvalid
	}
	_, err := tx.Exec(ctx, `
INSERT INTO catalog_current_pointers (product_id, channel_name, catalog_version_id, switched_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (product_id, channel_name) DO UPDATE
SET catalog_version_id = EXCLUDED.catalog_version_id,
    switched_at = EXCLUDED.switched_at
`, productID, channel, catalogVersionID, switchedAt.UTC())
	if err != nil {
		return mapCatalogDatabaseError("switch current catalog", err)
	}
	return nil
}

func (repository *PostgresRepository) Current(ctx context.Context, productID, channel string) (VersionRecord, error) {
	if repository == nil || repository.pool == nil {
		return VersionRecord{}, ErrRepositoryRequired
	}
	record, err := scanVersionRecord(repository.pool.QueryRow(ctx, catalogVersionSelect+`
 JOIN catalog_current_pointers AS current_pointer
   ON current_pointer.catalog_version_id = version.id
  AND current_pointer.product_id = version.product_id
  AND current_pointer.channel_name = version.channel_name
 WHERE current_pointer.product_id = $1 AND current_pointer.channel_name = $2
`, productID, channel))
	if errors.Is(err, pgx.ErrNoRows) {
		return VersionRecord{}, ErrCurrentCatalogNotFound
	}
	if err != nil {
		return VersionRecord{}, fmt.Errorf("get current catalog: %w", err)
	}
	roles, err := loadRoleDocuments(ctx, repository.pool, record.ID)
	if err != nil {
		return VersionRecord{}, err
	}
	record.Roles = roles
	return record, nil
}

const catalogVersionSelect = `
SELECT version.id, COALESCE(version.publication_attempt_id, '00000000-0000-0000-0000-000000000000'::uuid),
       version.product_id, version.channel_name, version.release_id,
       version.root_version, version.targets_version, version.snapshot_version,
       version.timestamp_version, version.revocation_version,
       version.bundle_sha256, version.created_at, version.published_at
FROM catalog_versions AS version`

type catalogRow interface {
	Scan(dest ...any) error
}

func scanVersionRecord(row catalogRow) (VersionRecord, error) {
	var record VersionRecord
	err := row.Scan(
		&record.ID, &record.AttemptID, &record.ProductID, &record.Channel, &record.ReleaseID,
		&record.Versions.Root, &record.Versions.Targets, &record.Versions.Snapshot,
		&record.Versions.Timestamp, &record.Versions.Revocation,
		&record.BundleSHA256, &record.CreatedAt, &record.PublishedAt,
	)
	return record, err
}

type catalogRoleQueryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

func loadRoleDocuments(ctx context.Context, queryer catalogRoleQueryer, catalogVersionID uuid.UUID) (map[Role]RoleDocument, error) {
	rows, err := queryer.Query(ctx, `
SELECT role, role_version, envelope_sha256, object_key, signatures, COALESCE(envelope_bytes, ''::bytea)
FROM catalog_role_documents
WHERE catalog_version_id = $1
ORDER BY role
`, catalogVersionID)
	if err != nil {
		return nil, fmt.Errorf("list catalog role documents: %w", err)
	}
	defer rows.Close()
	result := make(map[Role]RoleDocument, 5)
	for rows.Next() {
		var document RoleDocument
		if err := rows.Scan(&document.Role, &document.Version, &document.EnvelopeSHA256, &document.ObjectKey, &document.Signatures, &document.Envelope); err != nil {
			return nil, fmt.Errorf("scan catalog role document: %w", err)
		}
		result[document.Role] = document
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate catalog role documents: %w", err)
	}
	if len(result) != 5 {
		return nil, ErrBundleIncomplete
	}
	return result, nil
}

func validateVersionRecord(record VersionRecord) error {
	if record.ID == uuid.Nil || record.ReleaseID == uuid.Nil || record.ProductID == "" || record.Channel == "" || record.CreatedAt.IsZero() || !record.Versions.valid() || len(record.Roles) != 5 || !unprefixedDigest(record.BundleSHA256) {
		return ErrVersionRecordInvalid
	}
	expected := map[Role]uint64{
		RoleRoot: record.Versions.Root, RoleTargets: record.Versions.Targets, RoleSnapshot: record.Versions.Snapshot,
		RoleTimestamp: record.Versions.Timestamp, RoleRevocation: record.Versions.Revocation,
	}
	for role, version := range expected {
		document, exists := record.Roles[role]
		if !exists || document.Role != role || document.Version != version || !unprefixedDigest(document.EnvelopeSHA256) || !validCatalogObjectKey(document.ObjectKey) || !validSignatures(document.Signatures) {
			return ErrVersionRecordInvalid
		}
		if record.AttemptID != uuid.Nil && (len(document.Envelope) == 0 || len(document.Envelope) > maximumRoleEnvelopeBytes) {
			return ErrVersionRecordInvalid
		}
	}
	return nil
}

func validSignatures(raw json.RawMessage) bool {
	value, err := strictJSONValue(raw)
	if err != nil {
		return false
	}
	items, ok := value.([]any)
	if !ok || len(items) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(items))
	for _, rawItem := range items {
		item, ok := rawItem.(map[string]any)
		if !ok || len(item) != 2 {
			return false
		}
		keyID, keyOK := item["keyid"].(string)
		signatureText, signatureOK := item["sig"].(string)
		if !keyOK || !signatureOK || !keyIDPattern.MatchString(keyID) || !base64URLPattern.MatchString(signatureText) {
			return false
		}
		if _, duplicate := seen[keyID]; duplicate {
			return false
		}
		seen[keyID] = struct{}{}
		signature, decodeErr := base64.RawURLEncoding.DecodeString(signatureText)
		if decodeErr != nil || len(signature) != 64 {
			return false
		}
	}
	return true
}

func validCatalogObjectKey(value string) bool {
	return strings.HasPrefix(value, "catalogs/") && !strings.Contains(value, "..") && !strings.ContainsAny(value, "\\\x00\r\n") && len(value) <= 2048
}

func unprefixedDigest(value string) bool {
	return len(value) == 64 && digestPattern.MatchString(value) && !strings.HasPrefix(value, "sha256:")
}

func mapCatalogDatabaseError(operation string, err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		if postgresError.Code == "23505" {
			return ErrVersionRecordExists
		}
		if postgresError.Code == "55000" && strings.Contains(postgresError.Message, "rollback") {
			return ErrMetadataVersionRollback
		}
	}
	return fmt.Errorf("%s: %w", operation, err)
}

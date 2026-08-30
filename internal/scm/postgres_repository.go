package scm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/platform/database"
)

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (repository *PostgresRepository) WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error {
	if repository == nil || repository.pool == nil || function == nil {
		return ErrWebhookServiceConfig
	}
	return database.WithTx(ctx, repository.pool, function)
}

func (repository *PostgresRepository) GetConnection(ctx context.Context, id uuid.UUID) (Connection, error) {
	if repository == nil || repository.pool == nil || id == uuid.Nil {
		return Connection{}, ErrConnectionNotFound
	}
	var connection Connection
	var capabilities []byte
	err := repository.pool.QueryRow(ctx, `
SELECT id, product_id, name, provider, status, api_base_url, api_version,
       COALESCE(credential_id, '00000000-0000-0000-0000-000000000000'::uuid),
       COALESCE(webhook_credential_id, '00000000-0000-0000-0000-000000000000'::uuid),
       oidc_issuer, oidc_audience, allowed_repositories, resolved_addresses,
       enterprise_ca_bundle_pem, proxy_url, proxy_resolved_addresses, no_proxy,
       capabilities, certificate_sha256, created_at, updated_at
FROM scm_connections WHERE id = $1
`, id).Scan(
		&connection.ID, &connection.ProductID, &connection.Name, &connection.Provider, &connection.Status,
		&connection.APIBaseURL, &connection.APIVersion, &connection.CredentialID, &connection.WebhookCredentialID,
		&connection.OIDCIssuer, &connection.OIDCAudience, &connection.AllowedRepositories, &connection.ResolvedAddresses,
		&connection.EnterpriseCABundlePEM, &connection.ProxyURL, &connection.ProxyResolvedAddresses, &connection.NoProxy,
		&capabilities, &connection.CertificateSHA256, &connection.CreatedAt, &connection.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Connection{}, ErrConnectionNotFound
	}
	if err != nil {
		return Connection{}, fmt.Errorf("get SCM connection: %w", err)
	}
	if err := json.Unmarshal(capabilities, &connection.Capabilities); err != nil {
		return Connection{}, fmt.Errorf("decode SCM connection capabilities: %w", err)
	}
	return connection, nil
}

func (repository *PostgresRepository) FindDelivery(ctx context.Context, tx pgx.Tx, connectionID uuid.UUID, eventID string) (Delivery, error) {
	if tx == nil {
		return Delivery{}, ErrWebhookServiceConfig
	}
	// Serialize first-seen processing for the same provider event so concurrent
	// deliveries cannot both pass the lookup and invoke the domain sink.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, connectionID.String()+":"+eventID); err != nil {
		return Delivery{}, fmt.Errorf("lock SCM webhook delivery identity: %w", err)
	}
	var delivery Delivery
	err := tx.QueryRow(ctx, `
SELECT id, connection_id, event_id, event_type, payload_digest, repository, commit_sha, occurred_at, received_at
FROM scm_webhook_deliveries
WHERE connection_id = $1 AND event_id = $2
FOR SHARE
`, connectionID, eventID).Scan(
		&delivery.ID, &delivery.ConnectionID, &delivery.EventID, &delivery.EventType, &delivery.PayloadDigest,
		&delivery.Repository, &delivery.CommitSHA, &delivery.OccurredAt, &delivery.ReceivedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Delivery{}, ErrDeliveryNotFound
	}
	if err != nil {
		return Delivery{}, fmt.Errorf("find SCM webhook delivery: %w", err)
	}
	return delivery, nil
}

func (repository *PostgresRepository) CreateDelivery(ctx context.Context, tx pgx.Tx, delivery Delivery) error {
	if tx == nil {
		return ErrWebhookServiceConfig
	}
	_, err := tx.Exec(ctx, `
INSERT INTO scm_webhook_deliveries (
    id, connection_id, event_id, event_type, payload_digest, repository, commit_sha, occurred_at, received_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
`, delivery.ID, delivery.ConnectionID, delivery.EventID, delivery.EventType, delivery.PayloadDigest,
		delivery.Repository, delivery.CommitSHA, delivery.OccurredAt, delivery.ReceivedAt)
	if err != nil {
		return fmt.Errorf("create SCM webhook delivery: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) GetActiveCredential(ctx context.Context, id uuid.UUID) (CredentialRecord, error) {
	if repository == nil || repository.pool == nil || id == uuid.Nil {
		return CredentialRecord{}, ErrCredentialUnavailable
	}
	var record CredentialRecord
	err := repository.pool.QueryRow(ctx, `
SELECT id, connection_id, version, kind, key_id, nonce, ciphertext, last_four,
       expires_at, revoked_at, created_at, updated_at
FROM scm_credentials
WHERE id = $1 AND revoked_at IS NULL
`, id).Scan(
		&record.ID, &record.ConnectionID, &record.Version, &record.Kind, &record.Encrypted.KeyID,
		&record.Encrypted.Nonce, &record.Encrypted.Ciphertext, &record.LastFour,
		&record.ExpiresAt, &record.RevokedAt, &record.CreatedAt, &record.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return CredentialRecord{}, ErrCredentialUnavailable
	}
	if err != nil {
		return CredentialRecord{}, fmt.Errorf("get active SCM credential: %w", err)
	}
	return record, nil
}

func (repository *PostgresRepository) FindActiveCredential(ctx context.Context, tx pgx.Tx, connectionID uuid.UUID, kind CredentialKind) (CredentialRecord, error) {
	if tx == nil {
		return CredentialRecord{}, ErrCredentialUnavailable
	}
	var record CredentialRecord
	err := tx.QueryRow(ctx, `
SELECT id, connection_id, version, kind, key_id, nonce, ciphertext, last_four,
       expires_at, revoked_at, created_at, updated_at
FROM scm_credentials
WHERE connection_id = $1 AND kind = $2 AND revoked_at IS NULL
FOR UPDATE
`, connectionID, kind).Scan(
		&record.ID, &record.ConnectionID, &record.Version, &record.Kind, &record.Encrypted.KeyID,
		&record.Encrypted.Nonce, &record.Encrypted.Ciphertext, &record.LastFour,
		&record.ExpiresAt, &record.RevokedAt, &record.CreatedAt, &record.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return CredentialRecord{}, ErrCredentialUnavailable
	}
	if err != nil {
		return CredentialRecord{}, fmt.Errorf("find active SCM credential: %w", err)
	}
	return record, nil
}

func (repository *PostgresRepository) NextCredentialVersion(ctx context.Context, tx pgx.Tx, connectionID uuid.UUID, kind CredentialKind) (int, error) {
	if tx == nil {
		return 0, ErrCredentialUnavailable
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, connectionID.String()+":"+string(kind)); err != nil {
		return 0, fmt.Errorf("lock SCM credential rotation: %w", err)
	}
	var version int
	if err := tx.QueryRow(ctx, `
SELECT COALESCE(MAX(version), 0) + 1 FROM scm_credentials
WHERE connection_id = $1 AND kind = $2
`, connectionID, kind).Scan(&version); err != nil {
		return 0, fmt.Errorf("get next SCM credential version: %w", err)
	}
	return version, nil
}

func (repository *PostgresRepository) CreateCredential(ctx context.Context, tx pgx.Tx, record CredentialRecord) error {
	if tx == nil {
		return ErrCredentialUnavailable
	}
	_, err := tx.Exec(ctx, `
INSERT INTO scm_credentials (
    id, connection_id, version, kind, key_id, nonce, ciphertext, last_four,
    expires_at, revoked_at, created_at, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NULL,$10,$10)
`, record.ID, record.ConnectionID, record.Version, record.Kind, record.Encrypted.KeyID,
		record.Encrypted.Nonce, record.Encrypted.Ciphertext, record.LastFour, record.ExpiresAt, record.CreatedAt)
	if err != nil {
		return fmt.Errorf("create SCM credential: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) BindCredential(ctx context.Context, tx pgx.Tx, connectionID uuid.UUID, kind CredentialKind, credentialID uuid.UUID, at time.Time) error {
	if tx == nil || connectionID == uuid.Nil || credentialID == uuid.Nil {
		return ErrCredentialUnavailable
	}
	column := "credential_id"
	if kind == CredentialKindWebhookSecret || kind == CredentialKindWebhookSigningToken {
		column = "webhook_credential_id"
	}
	query := `UPDATE scm_connections SET ` + column + ` = $2, updated_at = $3 WHERE id = $1 AND status = 'active'`
	result, err := tx.Exec(ctx, query, connectionID, credentialID, at.UTC())
	if err != nil {
		return fmt.Errorf("bind SCM credential to connection: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrConnectionInactive
	}
	return nil
}

func (repository *PostgresRepository) RevokeCredential(ctx context.Context, tx pgx.Tx, id uuid.UUID, at time.Time) error {
	if tx == nil {
		return ErrCredentialUnavailable
	}
	result, err := tx.Exec(ctx, `
UPDATE scm_credentials SET revoked_at = $2, updated_at = $2
WHERE id = $1 AND revoked_at IS NULL
`, id, at.UTC())
	if err != nil {
		return fmt.Errorf("revoke SCM credential: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrCredentialUnavailable
	}
	return nil
}

package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresAPITokenStore struct {
	pool *pgxpool.Pool
}

func NewPostgresAPITokenStore(pool *pgxpool.Pool) *PostgresAPITokenStore {
	return &PostgresAPITokenStore{pool: pool}
}

func (store *PostgresAPITokenStore) FindByID(ctx context.Context, id uuid.UUID) (APITokenRecord, error) {
	if store == nil || store.pool == nil || id == uuid.Nil {
		return APITokenRecord{}, ErrAPITokenInvalid
	}
	var record APITokenRecord
	var roleValues []string
	err := store.pool.QueryRow(ctx, `
SELECT id, secret_hash, subject, roles, product_ids, expires_at, revoked_at
FROM api_tokens
WHERE id = $1
`, id).Scan(
		&record.ID,
		&record.SecretHash,
		&record.Subject,
		&roleValues,
		&record.ProductIDs,
		&record.ExpiresAt,
		&record.RevokedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return APITokenRecord{}, ErrAPITokenInvalid
	}
	if err != nil {
		return APITokenRecord{}, fmt.Errorf("query API token: %w", err)
	}
	record.Roles = make([]Role, len(roleValues))
	for index, role := range roleValues {
		record.Roles[index] = Role(role)
	}
	return record, nil
}

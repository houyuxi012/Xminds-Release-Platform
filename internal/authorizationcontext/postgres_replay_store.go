package authorizationcontext

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PostgresReplayStore struct {
	pool *pgxpool.Pool
}

func NewPostgresReplayStore(pool *pgxpool.Pool) *PostgresReplayStore {
	return &PostgresReplayStore{pool: pool}
}

func (store *PostgresReplayStore) Claim(ctx context.Context, issuer, contextID string, expiresAt, now time.Time) (bool, error) {
	if store == nil || store.pool == nil {
		return false, ErrReplayStoreUnavailable
	}
	issuer, contextID, ok := canonicalReplayIdentity(issuer, contextID)
	if !ok || !expiresAt.After(now) {
		return false, nil
	}
	var claimedID string
	err := store.pool.QueryRow(ctx, `
INSERT INTO authorization_context_replay_claims (validator_issuer, context_id, claimed_at, expires_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT DO NOTHING
RETURNING context_id
`, issuer, contextID, now.UTC(), expiresAt.UTC()).Scan(&claimedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("claim authorization context replay: %w", err)
	}
	return claimedID == contextID, nil
}

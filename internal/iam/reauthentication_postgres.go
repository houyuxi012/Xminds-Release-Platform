package iam

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (repository *PostgresRepository) CleanupReauthenticationChallenges(ctx context.Context, tx pgx.Tx, now time.Time, retention time.Duration, limit int) error {
	if repository == nil || repository.pool == nil || tx == nil || retention < time.Hour || limit < 1 || limit > 1000 {
		return ErrIAMConfiguration
	}
	if _, err := tx.Exec(ctx, `
WITH expired AS (
    SELECT id FROM iam_reauthentication_challenges
    WHERE (status='pending' AND challenge_expires_at <= $1)
       OR (status='verified' AND evidence_expires_at <= $1)
    ORDER BY COALESCE(evidence_expires_at, challenge_expires_at), id
    LIMIT $2
    FOR UPDATE SKIP LOCKED
)
UPDATE iam_reauthentication_challenges challenge
SET status='expired', version=challenge.version+1
FROM expired WHERE challenge.id=expired.id`, now.UTC(), limit); err != nil {
		return fmt.Errorf("expire reauthentication challenges: %w", err)
	}
	if _, err := tx.Exec(ctx, `
WITH removable AS (
    SELECT id FROM iam_reauthentication_challenges
    WHERE status IN ('expired', 'consumed')
      AND COALESCE(consumed_at, evidence_expires_at, challenge_expires_at) <= $1
    ORDER BY COALESCE(consumed_at, evidence_expires_at, challenge_expires_at), id
    LIMIT $2
    FOR UPDATE SKIP LOCKED
)
DELETE FROM iam_reauthentication_challenges challenge
USING removable WHERE challenge.id=removable.id`, now.UTC().Add(-retention), limit); err != nil {
		return fmt.Errorf("cleanup terminal reauthentication challenges: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) InsertReauthenticationChallenge(ctx context.Context, tx pgx.Tx, challenge ReauthenticationChallenge) error {
	if repository == nil || repository.pool == nil || tx == nil || challenge.ID == uuid.Nil || challenge.ID.Version() != 7 ||
		strings.TrimSpace(challenge.ActorSubject) == "" || challenge.ActorBindingVersion != reauthenticationActorBindingVersion ||
		!validReauthenticationDigest(challenge.ActorBindingDigest) || !validReauthenticationOperation(challenge.Operation) || challenge.Status != ReauthenticationStatusPending || challenge.Version != 1 {
		return ErrIAMConfiguration
	}
	_, err := tx.Exec(ctx, `
INSERT INTO iam_reauthentication_challenges (
    id, actor_subject, actor_kind, actor_binding_version, actor_binding_digest,
    created_token_digest, operation, status, created_at, challenge_expires_at, created_request_id, version
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		challenge.ID, challenge.ActorSubject, challenge.ActorKind, challenge.ActorBindingVersion, challenge.ActorBindingDigest,
		challenge.CreatedTokenDigest, challenge.Operation, challenge.Status, challenge.CreatedAt.UTC(),
		challenge.ChallengeExpiresAt.UTC(), challenge.CreatedRequestID, challenge.Version)
	if err != nil {
		return fmt.Errorf("insert reauthentication challenge: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) GetReauthenticationChallenge(ctx context.Context, tx pgx.Tx, id uuid.UUID) (ReauthenticationChallenge, error) {
	if repository == nil || repository.pool == nil || id == uuid.Nil {
		return ReauthenticationChallenge{}, ErrIAMConfiguration
	}
	query := `SELECT id, actor_subject, actor_kind, actor_binding_version, actor_binding_digest,
       created_token_digest, operation, status,
       verified_token_digest, evidence_digest, created_at, verified_at, challenge_expires_at,
       evidence_expires_at, consumed_at, created_request_id::text, completed_request_id::text, version
FROM iam_reauthentication_challenges WHERE id=$1`
	queryer := iamQueryer(repository.pool)
	if tx != nil {
		queryer = tx
		query += ` FOR UPDATE`
	}
	return scanReauthenticationChallenge(queryer.QueryRow(ctx, query, id))
}

func (repository *PostgresRepository) SaveReauthenticationChallenge(ctx context.Context, tx pgx.Tx, challenge ReauthenticationChallenge, expectedVersion int64) error {
	if repository == nil || repository.pool == nil || tx == nil || challenge.ID == uuid.Nil || expectedVersion < 1 || challenge.Version != expectedVersion+1 {
		return ErrIAMConfiguration
	}
	result, err := tx.Exec(ctx, `
UPDATE iam_reauthentication_challenges SET
    status=$2, verified_token_digest=$3, evidence_digest=$4, verified_at=$5,
    evidence_expires_at=$6, consumed_at=$7, completed_request_id=$8, version=$9
WHERE id=$1 AND version=$10`, challenge.ID, challenge.Status, nullableReauthenticationString(challenge.VerifiedTokenDigest),
		nullableReauthenticationString(challenge.EvidenceDigest), nullableTime(challenge.VerifiedAt), nullableTime(challenge.EvidenceExpiresAt),
		nullableTime(challenge.ConsumedAt), nullableReauthenticationString(challenge.CompletedRequestID), challenge.Version, expectedVersion)
	if err != nil {
		return fmt.Errorf("save reauthentication challenge: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrIAMConflict
	}
	return nil
}

func scanReauthenticationChallenge(row pgx.Row) (ReauthenticationChallenge, error) {
	var challenge ReauthenticationChallenge
	var verifiedTokenDigest, evidenceDigest, completedRequestID *string
	var verifiedAt, evidenceExpiresAt, consumedAt *time.Time
	err := row.Scan(
		&challenge.ID, &challenge.ActorSubject, &challenge.ActorKind, &challenge.ActorBindingVersion, &challenge.ActorBindingDigest,
		&challenge.CreatedTokenDigest, &challenge.Operation, &challenge.Status,
		&verifiedTokenDigest, &evidenceDigest, &challenge.CreatedAt, &verifiedAt, &challenge.ChallengeExpiresAt,
		&evidenceExpiresAt, &consumedAt, &challenge.CreatedRequestID, &completedRequestID, &challenge.Version,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ReauthenticationChallenge{}, ErrHighRiskConfirmationRequired
	}
	if err != nil {
		return ReauthenticationChallenge{}, fmt.Errorf("scan reauthentication challenge: %w", err)
	}
	if verifiedTokenDigest != nil {
		challenge.VerifiedTokenDigest = *verifiedTokenDigest
	}
	if evidenceDigest != nil {
		challenge.EvidenceDigest = *evidenceDigest
	}
	if completedRequestID != nil {
		challenge.CompletedRequestID = *completedRequestID
	}
	if verifiedAt != nil {
		challenge.VerifiedAt = verifiedAt.UTC()
	}
	if evidenceExpiresAt != nil {
		challenge.EvidenceExpiresAt = evidenceExpiresAt.UTC()
	}
	if consumedAt != nil {
		challenge.ConsumedAt = consumedAt.UTC()
	}
	return challenge, nil
}

func nullableReauthenticationString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return value
}

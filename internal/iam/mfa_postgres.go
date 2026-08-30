package iam

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (repository *PostgresRepository) GetMFAActivationPreflight(ctx context.Context, activationDigest string, enrollmentID uuid.UUID) (MFAEnrollment, error) {
	if repository == nil || repository.pool == nil || !validLowerSHA256Digest(activationDigest) || enrollmentID == uuid.Nil {
		return MFAEnrollment{}, ErrIAMConfiguration
	}
	return scanMFAEnrollment(repository.pool.QueryRow(ctx, `
SELECT enrollment.id,enrollment.user_id,enrollment.purpose,enrollment.status,enrollment.secret_reference,
       COALESCE(enrollment.created_by_user_id,'00000000-0000-0000-0000-000000000000'::uuid),
       COALESCE(enrollment.creator_binding_version,0),COALESCE(enrollment.creator_binding_digest,'\x'::bytea),
       enrollment.expected_user_version,enrollment.expires_at,enrollment.confirmed_at,enrollment.version,enrollment.created_at,enrollment.updated_at
FROM iam_mfa_enrollments enrollment
JOIN local_credentials credential ON credential.user_id=enrollment.user_id
JOIN user_principals user_record ON user_record.id=enrollment.user_id
WHERE enrollment.id=$1 AND credential.activation_digest=$2 AND user_record.status='pending'`, enrollmentID, activationDigest))
}

func (repository *PostgresRepository) GetMFAEnrollment(ctx context.Context, enrollmentID uuid.UUID) (MFAEnrollment, error) {
	if repository == nil || repository.pool == nil || enrollmentID == uuid.Nil {
		return MFAEnrollment{}, ErrIAMConfiguration
	}
	return scanMFAEnrollment(repository.pool.QueryRow(ctx, `
SELECT id,user_id,purpose,status,secret_reference,
       COALESCE(created_by_user_id,'00000000-0000-0000-0000-000000000000'::uuid),
       COALESCE(creator_binding_version,0),COALESCE(creator_binding_digest,'\x'::bytea),
       expected_user_version,expires_at,confirmed_at,version,created_at,updated_at
FROM iam_mfa_enrollments WHERE id=$1`, enrollmentID))
}

func (repository *PostgresRepository) GetMFAEnrollmentForUpdate(ctx context.Context, tx pgx.Tx, enrollmentID uuid.UUID) (MFAEnrollment, error) {
	if repository == nil || repository.pool == nil || tx == nil || enrollmentID == uuid.Nil {
		return MFAEnrollment{}, ErrIAMConfiguration
	}
	return scanMFAEnrollment(tx.QueryRow(ctx, `
SELECT id,user_id,purpose,status,secret_reference,
       COALESCE(created_by_user_id,'00000000-0000-0000-0000-000000000000'::uuid),
       COALESCE(creator_binding_version,0),COALESCE(creator_binding_digest,'\x'::bytea),
       expected_user_version,expires_at,confirmed_at,version,created_at,updated_at
FROM iam_mfa_enrollments
WHERE id=$1
FOR UPDATE`, enrollmentID))
}

type mfaEnrollmentRow interface {
	Scan(dest ...any) error
}

func scanMFAEnrollment(row mfaEnrollmentRow) (MFAEnrollment, error) {
	var enrollment MFAEnrollment
	var creatorBindingDigest []byte
	var confirmedAt *time.Time
	err := row.Scan(
		&enrollment.ID, &enrollment.UserID, &enrollment.Purpose, &enrollment.Status, &enrollment.SecretReference,
		&enrollment.CreatedByUserID, &enrollment.CreatorBindingVersion, &creatorBindingDigest,
		&enrollment.ExpectedUserVersion, &enrollment.ExpiresAt, &confirmedAt, &enrollment.Version,
		&enrollment.CreatedAt, &enrollment.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return MFAEnrollment{}, ErrMFAEnrollmentNotFound
	}
	if err != nil {
		return MFAEnrollment{}, fmt.Errorf("get MFA enrollment: %w", err)
	}
	if len(creatorBindingDigest) > 0 {
		if len(creatorBindingDigest) != len(enrollment.CreatorBindingDigest) {
			return MFAEnrollment{}, ErrMFAEnrollmentInvalid
		}
		copy(enrollment.CreatorBindingDigest[:], creatorBindingDigest)
	}
	if confirmedAt != nil {
		enrollment.ConfirmedAt = confirmedAt.UTC()
	}
	return enrollment, nil
}

func (repository *PostgresRepository) GetPendingMFAEnrollmentForUpdate(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (MFAEnrollment, error) {
	if repository == nil || repository.pool == nil || tx == nil || userID == uuid.Nil {
		return MFAEnrollment{}, ErrIAMConfiguration
	}
	var enrollmentID uuid.UUID
	err := tx.QueryRow(ctx, `SELECT id FROM iam_mfa_enrollments WHERE user_id=$1 AND status='pending' FOR UPDATE`, userID).Scan(&enrollmentID)
	if errors.Is(err, pgx.ErrNoRows) {
		return MFAEnrollment{}, ErrMFAEnrollmentNotFound
	}
	if err != nil {
		return MFAEnrollment{}, fmt.Errorf("get pending MFA enrollment: %w", err)
	}
	return repository.GetMFAEnrollmentForUpdate(ctx, tx, enrollmentID)
}

func (repository *PostgresRepository) InsertMFAEnrollment(ctx context.Context, tx pgx.Tx, enrollment MFAEnrollment) error {
	if repository == nil || repository.pool == nil || tx == nil || !validMFAEnrollmentForInsert(enrollment) {
		return ErrMFAEnrollmentInvalid
	}
	if err := repository.LockMFASecretReference(ctx, tx, enrollment.SecretReference); err != nil {
		return err
	}
	tombstone, err := repository.MFASecretReferenceHasTombstone(ctx, tx, enrollment.SecretReference)
	if err != nil {
		return err
	}
	if tombstone {
		return ErrIAMConflict
	}
	var createdBy any
	var bindingVersion any
	var bindingDigest any
	if enrollment.Purpose == MFAEnrollmentPurposeRotation {
		createdBy = enrollment.CreatedByUserID
		bindingVersion = enrollment.CreatorBindingVersion
		bindingDigest = enrollment.CreatorBindingDigest[:]
	}
	_, err = tx.Exec(ctx, `
INSERT INTO iam_mfa_enrollments (
    id,user_id,purpose,status,secret_reference,created_by_user_id,creator_binding_version,creator_binding_digest,
    expected_user_version,expires_at,confirmed_at,version,created_at,updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULL,$11,$12,$13)`,
		enrollment.ID, enrollment.UserID, enrollment.Purpose, enrollment.Status, enrollment.SecretReference,
		createdBy, bindingVersion, bindingDigest, enrollment.ExpectedUserVersion, enrollment.ExpiresAt.UTC(),
		enrollment.Version, enrollment.CreatedAt.UTC(), enrollment.UpdatedAt.UTC())
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return ErrIAMConflict
		}
		return fmt.Errorf("insert MFA enrollment: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) ConfirmMFAEnrollment(ctx context.Context, tx pgx.Tx, enrollmentID uuid.UUID, expectedVersion int64, confirmedAt time.Time) error {
	if tx == nil || enrollmentID == uuid.Nil || expectedVersion < 1 || confirmedAt.IsZero() {
		return ErrMFAEnrollmentInvalid
	}
	result, err := tx.Exec(ctx, `
UPDATE iam_mfa_enrollments
SET status='confirmed',confirmed_at=$3,version=version+1,updated_at=$3
WHERE id=$1 AND status='pending' AND version=$2 AND expires_at>$3`, enrollmentID, expectedVersion, confirmedAt.UTC())
	if err != nil {
		return fmt.Errorf("confirm MFA enrollment: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrIAMConflict
	}
	return nil
}

func (repository *PostgresRepository) ExpireMFAEnrollment(ctx context.Context, tx pgx.Tx, enrollmentID uuid.UUID, expectedVersion int64, expiredAt time.Time) error {
	if tx == nil || enrollmentID == uuid.Nil || expectedVersion < 1 || expiredAt.IsZero() {
		return ErrMFAEnrollmentInvalid
	}
	var reference string
	err := tx.QueryRow(ctx, `
UPDATE iam_mfa_enrollments
SET status='expired',confirmed_at=NULL,version=version+1,updated_at=$3
WHERE id=$1 AND status='pending' AND version=$2
RETURNING secret_reference`, enrollmentID, expectedVersion, expiredAt.UTC()).Scan(&reference)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrIAMConflict
	}
	if err != nil {
		return fmt.Errorf("expire MFA enrollment: %w", err)
	}
	return repository.EnqueueMFASecretGC(ctx, tx, reference, expiredAt.UTC(), expiredAt.UTC())
}

func (repository *PostgresRepository) ReplaceMFARecoveryCodes(ctx context.Context, tx pgx.Tx, userID, generationID uuid.UUID, digests []string, createdAt time.Time) error {
	if tx == nil || userID == uuid.Nil || generationID == uuid.Nil || createdAt.IsZero() || len(digests) < 1 || len(digests) > 32 {
		return ErrMFARecoveryCodeInvalid
	}
	seen := make(map[string]struct{}, len(digests))
	for _, digest := range digests {
		if !validLowerSHA256Digest(digest) {
			return ErrMFARecoveryCodeInvalid
		}
		if _, duplicate := seen[digest]; duplicate {
			return ErrMFARecoveryCodeInvalid
		}
		seen[digest] = struct{}{}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM iam_mfa_recovery_codes WHERE user_id=$1`, userID); err != nil {
		return fmt.Errorf("replace MFA recovery codes: %w", err)
	}
	for _, digest := range digests {
		if _, err := tx.Exec(ctx, `INSERT INTO iam_mfa_recovery_codes (user_id,code_digest,generation_id,created_at) VALUES ($1,$2,$3,$4)`, userID, digest, generationID, createdAt.UTC()); err != nil {
			return fmt.Errorf("insert MFA recovery code digest: %w", err)
		}
	}
	return nil
}

func (repository *PostgresRepository) GetLocalCredential(ctx context.Context, userID uuid.UUID) (LocalCredential, error) {
	if repository == nil || repository.pool == nil || userID == uuid.Nil {
		return LocalCredential{}, ErrIAMConfiguration
	}
	return scanMFALocalCredential(repository.pool.QueryRow(ctx, `
SELECT user_id,mfa_secret_reference,mfa_last_counter,COALESCE(activation_digest,''),activation_expires_at
FROM local_credentials WHERE user_id=$1`, userID))
}

func (repository *PostgresRepository) GetLocalCredentialForUpdate(ctx context.Context, tx pgx.Tx, userID uuid.UUID) (LocalCredential, error) {
	if repository == nil || repository.pool == nil || tx == nil || userID == uuid.Nil {
		return LocalCredential{}, ErrIAMConfiguration
	}
	return scanMFALocalCredential(tx.QueryRow(ctx, `
SELECT user_id,mfa_secret_reference,mfa_last_counter,COALESCE(activation_digest,''),activation_expires_at
FROM local_credentials WHERE user_id=$1 FOR UPDATE`, userID))
}

func scanMFALocalCredential(row mfaEnrollmentRow) (LocalCredential, error) {
	var credential LocalCredential
	var activationExpiresAt *time.Time
	err := row.Scan(&credential.UserID, &credential.MFASecretReference, &credential.MFALastCounter, &credential.ActivationDigest, &activationExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return LocalCredential{}, ErrUserNotFound
	}
	if err != nil {
		return LocalCredential{}, fmt.Errorf("get MFA local credential: %w", err)
	}
	if activationExpiresAt != nil {
		credential.ActivationExpiresAt = activationExpiresAt.UTC()
	}
	return credential, nil
}

func (repository *PostgresRepository) SaveMFACredential(ctx context.Context, tx pgx.Tx, credential LocalCredential) error {
	if tx == nil || credential.UserID == uuid.Nil || credential.MFASecretReference == "" || credential.MFALastCounter < 1 {
		return ErrIAMConfiguration
	}
	result, err := tx.Exec(ctx, `UPDATE local_credentials SET mfa_secret_reference=$2,mfa_last_counter=$3 WHERE user_id=$1`, credential.UserID, credential.MFASecretReference, credential.MFALastCounter)
	if err != nil {
		return fmt.Errorf("save MFA local credential: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrIAMConflict
	}
	return nil
}

func (repository *PostgresRepository) ConsumeMFARecoveryCode(ctx context.Context, tx pgx.Tx, userID uuid.UUID, digest string, usedAt time.Time) (bool, error) {
	if tx == nil || userID == uuid.Nil || !validLowerSHA256Digest(digest) || usedAt.IsZero() {
		return false, ErrMFARecoveryCodeInvalid
	}
	result, err := tx.Exec(ctx, `
UPDATE iam_mfa_recovery_codes
SET used_at=$3
WHERE user_id=$1 AND code_digest=$2 AND used_at IS NULL`, userID, digest, usedAt.UTC())
	if err != nil {
		return false, fmt.Errorf("consume MFA recovery code: %w", err)
	}
	return result.RowsAffected() == 1, nil
}

func (repository *PostgresRepository) LockMFASecretReference(ctx context.Context, tx pgx.Tx, reference string) error {
	if tx == nil {
		return ErrIAMConfiguration
	}
	if _, ok := parseMFASecretReference(reference); !ok {
		return ErrSecretReferenceInvalid
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, reference); err != nil {
		return fmt.Errorf("lock MFA secret reference: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) MFASecretReferenceIsLive(ctx context.Context, tx pgx.Tx, reference string, at time.Time) (bool, error) {
	if tx == nil || at.IsZero() {
		return false, ErrIAMConfiguration
	}
	if _, ok := parseMFASecretReference(reference); !ok {
		return false, ErrSecretReferenceInvalid
	}
	var live bool
	err := tx.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM local_credentials WHERE mfa_secret_reference=$1)
    OR EXISTS (
        SELECT 1 FROM iam_mfa_enrollments
        WHERE secret_reference=$1 AND status='pending' AND expires_at>$2
    )`, reference, at.UTC()).Scan(&live)
	if err != nil {
		return false, fmt.Errorf("check MFA secret liveness: %w", err)
	}
	return live, nil
}

func (repository *PostgresRepository) MFASecretReferenceHasTombstone(ctx context.Context, tx pgx.Tx, reference string) (bool, error) {
	if tx == nil {
		return false, ErrIAMConfiguration
	}
	if _, ok := parseMFASecretReference(reference); !ok {
		return false, ErrSecretReferenceInvalid
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM iam_mfa_secret_gc WHERE secret_reference=$1)`, reference).Scan(&exists); err != nil {
		return false, fmt.Errorf("check MFA secret tombstone: %w", err)
	}
	return exists, nil
}

func (repository *PostgresRepository) EnqueueMFASecretGC(ctx context.Context, tx pgx.Tx, reference string, notBefore, createdAt time.Time) error {
	if tx == nil || notBefore.IsZero() || createdAt.IsZero() || notBefore.Before(createdAt) {
		return ErrIAMConfiguration
	}
	if err := repository.LockMFASecretReference(ctx, tx, reference); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
INSERT INTO iam_mfa_secret_gc (secret_reference,state,not_before,attempts,last_error_code,lease_token,leased_until,created_at,updated_at)
VALUES ($1,'pending',$2,0,'',NULL,NULL,$3,$3)
ON CONFLICT (secret_reference) DO NOTHING`, reference, notBefore.UTC(), createdAt.UTC())
	if err != nil {
		return fmt.Errorf("enqueue MFA secret GC: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) ListDueMFASecretGC(ctx context.Context, at time.Time, limit int) ([]MFASecretGCItem, error) {
	if repository == nil || repository.pool == nil || at.IsZero() || limit < 1 || limit > mfaSecretMaximumBatch {
		return nil, ErrIAMConfiguration
	}
	rows, err := repository.pool.Query(ctx, `
SELECT secret_reference,state,not_before,attempts,last_error_code,
       COALESCE(lease_token,'00000000-0000-0000-0000-000000000000'::uuid),leased_until,created_at,updated_at
FROM iam_mfa_secret_gc
WHERE not_before<=$1 AND (state='pending' OR (state='leased' AND leased_until<=$1))
ORDER BY not_before,secret_reference
LIMIT $2`, at.UTC(), limit)
	if err != nil {
		return nil, fmt.Errorf("list due MFA secret GC: %w", err)
	}
	defer rows.Close()
	items := make([]MFASecretGCItem, 0, limit)
	for rows.Next() {
		var item MFASecretGCItem
		var leasedUntil *time.Time
		if err := rows.Scan(&item.SecretReference, &item.State, &item.NotBefore, &item.Attempts, &item.LastErrorCode, &item.LeaseToken, &leasedUntil, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan due MFA secret GC: %w", err)
		}
		if leasedUntil != nil {
			item.LeasedUntil = leasedUntil.UTC()
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (repository *PostgresRepository) LeaseDueMFASecretGC(ctx context.Context, tx pgx.Tx, reference string, at time.Time, leaseToken uuid.UUID, leasedUntil time.Time) (bool, error) {
	if tx == nil || at.IsZero() || leaseToken == uuid.Nil || leaseToken.Version() != 7 || !leasedUntil.After(at) {
		return false, ErrIAMConfiguration
	}
	if err := repository.LockMFASecretReference(ctx, tx, reference); err != nil {
		return false, err
	}
	live, err := repository.MFASecretReferenceIsLive(ctx, tx, reference, at)
	if err != nil {
		return false, err
	}
	if live {
		if _, err := tx.Exec(ctx, `DELETE FROM iam_mfa_secret_gc WHERE secret_reference=$1`, reference); err != nil {
			return false, fmt.Errorf("cancel live MFA secret GC: %w", err)
		}
		return false, nil
	}
	result, err := tx.Exec(ctx, `
UPDATE iam_mfa_secret_gc
SET state='leased',lease_token=$3,leased_until=$4,updated_at=$2
WHERE secret_reference=$1 AND not_before<=$2
  AND (state='pending' OR (state='leased' AND leased_until<=$2))`, reference, at.UTC(), leaseToken, leasedUntil.UTC())
	if err != nil {
		return false, fmt.Errorf("lease due MFA secret GC: %w", err)
	}
	return result.RowsAffected() == 1, nil
}

func (repository *PostgresRepository) CompleteMFASecretGC(ctx context.Context, tx pgx.Tx, reference string, leaseToken uuid.UUID) error {
	if tx == nil || leaseToken == uuid.Nil || leaseToken.Version() != 7 {
		return ErrIAMConfiguration
	}
	if err := repository.LockMFASecretReference(ctx, tx, reference); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `DELETE FROM iam_mfa_secret_gc WHERE secret_reference=$1 AND state='leased' AND lease_token=$2`, reference, leaseToken)
	if err != nil {
		return fmt.Errorf("complete MFA secret GC: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrIAMConflict
	}
	return nil
}

func (repository *PostgresRepository) FailMFASecretGC(ctx context.Context, tx pgx.Tx, reference string, leaseToken uuid.UUID, retryAt time.Time, errorCode string, failedAt time.Time) error {
	if tx == nil || leaseToken == uuid.Nil || leaseToken.Version() != 7 || retryAt.IsZero() || failedAt.IsZero() || retryAt.Before(failedAt) || !validStableMFAErrorCode(errorCode) {
		return ErrIAMConfiguration
	}
	if err := repository.LockMFASecretReference(ctx, tx, reference); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `
UPDATE iam_mfa_secret_gc
SET state='pending',lease_token=NULL,leased_until=NULL,not_before=$3,
    attempts=attempts+1,last_error_code=$4,updated_at=$5
WHERE secret_reference=$1 AND state='leased' AND lease_token=$2`, reference, leaseToken, retryAt.UTC(), errorCode, failedAt.UTC())
	if err != nil {
		return fmt.Errorf("fail MFA secret GC: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrIAMConflict
	}
	return nil
}

func validMFAEnrollmentForInsert(enrollment MFAEnrollment) bool {
	if enrollment.ID == uuid.Nil || enrollment.ID.Version() != 7 || enrollment.UserID == uuid.Nil ||
		enrollment.Status != MFAEnrollmentStatusPending || enrollment.ExpectedUserVersion < 1 || enrollment.Version != 1 ||
		enrollment.CreatedAt.IsZero() || !enrollment.ExpiresAt.After(enrollment.CreatedAt) || enrollment.UpdatedAt.Before(enrollment.CreatedAt) || !enrollment.ConfirmedAt.IsZero() {
		return false
	}
	_, wantReference, validReference := mfaSecretIdentity(enrollment.ID)
	if !validReference || enrollment.SecretReference != wantReference {
		return false
	}
	switch enrollment.Purpose {
	case MFAEnrollmentPurposeActivation:
		return enrollment.CreatedByUserID == uuid.Nil && enrollment.CreatorBindingVersion == 0 && enrollment.CreatorBindingDigest == [32]byte{}
	case MFAEnrollmentPurposeRotation:
		return enrollment.CreatedByUserID != uuid.Nil && enrollment.CreatorBindingVersion == 1 && enrollment.CreatorBindingDigest != [32]byte{}
	default:
		return false
	}
}

func validLowerSHA256Digest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func validStableMFAErrorCode(value string) bool {
	if len(value) < 3 || len(value) > 64 || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

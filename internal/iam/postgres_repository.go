package iam

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/platform/database"
)

const emergencyCredentialMaximumAge = 180 * 24 * time.Hour

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (repository *PostgresRepository) WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error {
	if repository == nil || repository.pool == nil || function == nil {
		return ErrIAMConfiguration
	}
	return database.WithTx(ctx, repository.pool, function)
}

func (repository *PostgresRepository) GetLoginState(ctx context.Context, tx pgx.Tx) (LoginState, error) {
	if repository == nil || repository.pool == nil {
		return LoginState{}, ErrIAMConfiguration
	}
	query := `
SELECT login_mode, COALESCE(active_source_id, '00000000-0000-0000-0000-000000000000'::uuid),
       fault_code, version, updated_by, updated_at
FROM iam_login_state
WHERE singleton = TRUE`
	queryer := iamQueryer(repository.pool)
	if tx != nil {
		query += " FOR UPDATE"
		queryer = tx
	}
	var state LoginState
	if err := queryer.QueryRow(ctx, query).Scan(
		&state.Mode, &state.ActiveSourceID, &state.FaultCode, &state.Version, &state.UpdatedBy, &state.UpdatedAt,
	); err != nil {
		return LoginState{}, fmt.Errorf("get IAM login state: %w", err)
	}
	return state, nil
}

func (repository *PostgresRepository) SetLoginState(ctx context.Context, tx pgx.Tx, state LoginState, expectedVersion int64) error {
	if tx == nil {
		return ErrIAMConfiguration
	}
	var activeSourceID any
	if state.ActiveSourceID != uuid.Nil {
		activeSourceID = state.ActiveSourceID
	}
	result, err := tx.Exec(ctx, `
UPDATE iam_login_state
SET login_mode = $1, active_source_id = $2, fault_code = $3, version = $4,
    updated_by = $5, updated_at = $6
WHERE singleton = TRUE AND version = $7
`, state.Mode, activeSourceID, state.FaultCode, state.Version, state.UpdatedBy, state.UpdatedAt.UTC(), expectedVersion)
	if err != nil {
		return fmt.Errorf("set IAM login state: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrIAMConflict
	}
	return nil
}

func (repository *PostgresRepository) GetIdentitySource(ctx context.Context, tx pgx.Tx, id uuid.UUID) (IdentitySource, error) {
	if repository == nil || repository.pool == nil || id == uuid.Nil {
		return IdentitySource{}, ErrIdentitySourceNotFound
	}
	query := `
SELECT id, name, source_kind, status, secret_reference, required_mappings_complete,
       verified_at, previewed_at, fault_code, version, created_at, updated_at
FROM identity_sources WHERE id = $1`
	queryer := iamQueryer(repository.pool)
	if tx != nil {
		query += " FOR UPDATE"
		queryer = tx
	}
	var source IdentitySource
	var verifiedAt, previewedAt *time.Time
	err := queryer.QueryRow(ctx, query, id).Scan(
		&source.ID, &source.Name, &source.Kind, &source.Status, &source.SecretReference, &source.RequiredMappingsComplete,
		&verifiedAt, &previewedAt, &source.FaultCode, &source.Version, &source.CreatedAt, &source.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return IdentitySource{}, ErrIdentitySourceNotFound
	}
	if err != nil {
		return IdentitySource{}, fmt.Errorf("get identity source: %w", err)
	}
	if verifiedAt != nil {
		source.VerifiedAt = verifiedAt.UTC()
	}
	if previewedAt != nil {
		source.PreviewedAt = previewedAt.UTC()
	}
	return source, nil
}

func (repository *PostgresRepository) SaveIdentitySource(ctx context.Context, tx pgx.Tx, source IdentitySource, expectedVersion int64) error {
	if tx == nil {
		return ErrIAMConfiguration
	}
	result, err := tx.Exec(ctx, `
UPDATE identity_sources
SET status = $2, required_mappings_complete = $3, verified_at = $4, previewed_at = $5,
    fault_code = $6, version = $7, updated_at = $8
WHERE id = $1 AND version = $9
`, source.ID, source.Status, source.RequiredMappingsComplete, nullableTime(source.VerifiedAt), nullableTime(source.PreviewedAt),
		source.FaultCode, source.Version, source.UpdatedAt.UTC(), expectedVersion)
	if err != nil {
		return fmt.Errorf("save identity source: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrIAMConflict
	}
	return nil
}

func (repository *PostgresRepository) CountUsableEmergencyAdministrators(ctx context.Context, tx pgx.Tx, excluding uuid.UUID, at time.Time) (int, error) {
	if repository == nil || repository.pool == nil {
		return 0, ErrIAMConfiguration
	}
	queryer := iamQueryer(repository.pool)
	if tx != nil {
		queryer = tx
	}
	var count int
	err := queryer.QueryRow(ctx, `
SELECT count(*)
FROM user_principals
WHERE user_kind = 'emergency' AND status = 'active' AND mfa_enrolled = TRUE
  AND credential_rotated_at IS NOT NULL AND credential_rotated_at >= $2
  AND ($1::uuid = '00000000-0000-0000-0000-000000000000'::uuid OR id <> $1)
`, excluding, at.UTC().Add(-emergencyCredentialMaximumAge)).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count usable emergency administrators: %w", err)
	}
	return count, nil
}

func (repository *PostgresRepository) GetUser(ctx context.Context, tx pgx.Tx, id uuid.UUID) (UserPrincipal, error) {
	if repository == nil || repository.pool == nil || id == uuid.Nil {
		return UserPrincipal{}, ErrUserNotFound
	}
	query := userSelect + " WHERE id = $1"
	queryer := iamQueryer(repository.pool)
	if tx != nil {
		query += " FOR UPDATE"
		queryer = tx
	}
	return scanUser(queryer.QueryRow(ctx, query, id))
}

func (repository *PostgresRepository) SaveUser(ctx context.Context, tx pgx.Tx, user UserPrincipal, expectedVersion int64) error {
	if tx == nil {
		return ErrIAMConfiguration
	}
	result, err := tx.Exec(ctx, `
UPDATE user_principals
SET status = $2, mfa_enrolled = $3, credential_rotated_at = $4, version = $5,
    updated_at = $6, disabled_at = $7, disabled_reason = $8
WHERE id = $1 AND version = $9
`, user.ID, user.Status, user.MFAEnrolled, nullableTime(user.CredentialRotatedAt), user.Version,
		user.UpdatedAt.UTC(), nullableTime(user.DisabledAt), user.DisabledReason, expectedVersion)
	if err != nil {
		return fmt.Errorf("save user principal: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrIAMConflict
	}
	return nil
}

func (repository *PostgresRepository) FindLocalAuthentication(ctx context.Context, canonicalUsername string) (LoginState, UserPrincipal, LocalCredential, error) {
	state, err := repository.GetLoginState(ctx, nil)
	if err != nil {
		return LoginState{}, UserPrincipal{}, LocalCredential{}, err
	}
	canonicalUsername = strings.ToLower(strings.TrimSpace(canonicalUsername))
	if canonicalUsername == "" {
		return state, UserPrincipal{}, LocalCredential{}, ErrLocalCredentialInvalid
	}
	row := repository.pool.QueryRow(ctx, `SELECT `+userColumns+`,
       credential.algorithm, credential.parameters, credential.salt, credential.derived_key,
       credential.failed_attempts, credential.locked_until, credential.password_changed_at,
       credential.activation_digest, credential.activation_expires_at
FROM user_principals AS user_record
JOIN local_credentials AS credential ON credential.user_id = user_record.id
WHERE lower(user_record.username) = $1
`, canonicalUsername)
	user, credential, err := scanLocalAuthentication(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return state, UserPrincipal{}, LocalCredential{}, ErrLocalCredentialInvalid
	}
	if err != nil {
		return state, UserPrincipal{}, LocalCredential{}, fmt.Errorf("find local authentication: %w", err)
	}
	return state, user, credential, nil
}

const userColumns = `user_record.id, COALESCE(user_record.identity_source_id, '00000000-0000-0000-0000-000000000000'::uuid),
       external_subject, username, display_name, email, user_kind, status, mfa_enrolled,
       credential_rotated_at, version, created_at, updated_at, disabled_at, disabled_reason
`

const userSelect = `SELECT ` + userColumns + ` FROM user_principals AS user_record`

type iamQueryer interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func scanUser(row pgx.Row) (UserPrincipal, error) {
	var user UserPrincipal
	var credentialRotatedAt, disabledAt *time.Time
	err := row.Scan(
		&user.ID, &user.IdentitySourceID, &user.ExternalSubject, &user.Username, &user.DisplayName, &user.Email,
		&user.Kind, &user.Status, &user.MFAEnrolled, &credentialRotatedAt, &user.Version, &user.CreatedAt,
		&user.UpdatedAt, &disabledAt, &user.DisabledReason,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return UserPrincipal{}, ErrUserNotFound
	}
	if err != nil {
		return UserPrincipal{}, fmt.Errorf("scan user principal: %w", err)
	}
	if credentialRotatedAt != nil {
		user.CredentialRotatedAt = credentialRotatedAt.UTC()
	}
	if disabledAt != nil {
		user.DisabledAt = disabledAt.UTC()
	}
	return user, nil
}

func scanLocalAuthentication(row pgx.Row) (UserPrincipal, LocalCredential, error) {
	var user UserPrincipal
	var credential LocalCredential
	var credentialRotatedAt, disabledAt, lockedUntil, activationExpiresAt *time.Time
	var activationDigest *string
	err := row.Scan(
		&user.ID, &user.IdentitySourceID, &user.ExternalSubject, &user.Username, &user.DisplayName, &user.Email,
		&user.Kind, &user.Status, &user.MFAEnrolled, &credentialRotatedAt, &user.Version, &user.CreatedAt,
		&user.UpdatedAt, &disabledAt, &user.DisabledReason,
		&credential.Password.Algorithm, &credential.Password.Parameters, &credential.Password.Salt, &credential.Password.DerivedKey,
		&credential.FailedAttempts, &lockedUntil, &credential.PasswordChangedAt, &activationDigest, &activationExpiresAt,
	)
	if err != nil {
		return UserPrincipal{}, LocalCredential{}, err
	}
	credential.UserID = user.ID
	if credentialRotatedAt != nil {
		user.CredentialRotatedAt = credentialRotatedAt.UTC()
	}
	if disabledAt != nil {
		user.DisabledAt = disabledAt.UTC()
	}
	if lockedUntil != nil {
		credential.LockedUntil = lockedUntil.UTC()
	}
	if activationDigest != nil {
		credential.ActivationDigest = *activationDigest
	}
	if activationExpiresAt != nil {
		credential.ActivationExpiresAt = activationExpiresAt.UTC()
	}
	return user, credential, nil
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

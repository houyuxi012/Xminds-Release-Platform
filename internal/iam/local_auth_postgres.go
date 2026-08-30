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

const platformAdministratorExistsSQL = `EXISTS (
    SELECT 1 FROM role_bindings binding
    WHERE (
        (binding.subject_type='user' AND binding.subject_id=user_record.id)
        OR (
            binding.subject_type='organization'
            AND EXISTS (
                SELECT 1 FROM organization_memberships membership
                WHERE membership.organization_id=binding.subject_id
                  AND membership.user_id=user_record.id
				  AND membership.status='active'
            )
        )
    )
      AND binding.role_name='admin' AND binding.scope_type='platform' AND binding.effect='allow'
      AND binding.valid_from <= clock_timestamp()
      AND (binding.valid_until IS NULL OR binding.valid_until > clock_timestamp())
)`

func (repository *PostgresRepository) FindActivation(ctx context.Context, tx pgx.Tx, digest string) (UserPrincipal, LocalCredential, []PasswordDigest, bool, error) {
	if repository == nil || repository.pool == nil || tx == nil {
		return UserPrincipal{}, LocalCredential{}, nil, false, ErrIAMConfiguration
	}
	row := tx.QueryRow(ctx, `SELECT `+userColumns+`,
       COALESCE(credential.algorithm, ''), COALESCE(credential.parameters, ''),
       COALESCE(credential.salt, '\x'::bytea), COALESCE(credential.derived_key, '\x'::bytea),
       credential.failed_attempts, credential.locked_until, credential.password_changed_at,
       credential.activation_digest, credential.activation_expires_at,
       credential.mfa_secret_reference, credential.mfa_last_counter,
	   `+platformAdministratorExistsSQL+`
FROM user_principals user_record
JOIN local_credentials credential ON credential.user_id=user_record.id
WHERE credential.activation_digest=$1
FOR UPDATE OF user_record, credential`, digest)
	user, credential, administrator, err := scanAuthRecord(row, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return UserPrincipal{}, LocalCredential{}, nil, false, ErrLocalAuthenticationFailed
	}
	if err != nil {
		return UserPrincipal{}, LocalCredential{}, nil, false, fmt.Errorf("find local activation: %w", err)
	}
	rows, err := tx.Query(ctx, `
SELECT algorithm, parameters, salt, derived_key
FROM local_password_history WHERE user_id=$1
ORDER BY sequence DESC LIMIT $2`, user.ID, passwordHistoryDepth)
	if err != nil {
		return UserPrincipal{}, LocalCredential{}, nil, false, fmt.Errorf("load local password history: %w", err)
	}
	defer rows.Close()
	history := make([]PasswordDigest, 0, passwordHistoryDepth)
	for rows.Next() {
		var digest PasswordDigest
		if err := rows.Scan(&digest.Algorithm, &digest.Parameters, &digest.Salt, &digest.DerivedKey); err != nil {
			return UserPrincipal{}, LocalCredential{}, nil, false, fmt.Errorf("scan local password history: %w", err)
		}
		history = append(history, digest)
	}
	if err := rows.Err(); err != nil {
		return UserPrincipal{}, LocalCredential{}, nil, false, err
	}
	return user, credential, history, administrator, nil
}

func (repository *PostgresRepository) SaveActivation(ctx context.Context, tx pgx.Tx, user UserPrincipal, credential LocalCredential, history PasswordDigest, expectedVersion int64) error {
	if tx == nil || user.ID == uuid.Nil || credential.UserID != user.ID {
		return ErrIAMConfiguration
	}
	result, err := tx.Exec(ctx, `
UPDATE user_principals SET status=$2, mfa_enrolled=$3, credential_rotated_at=$4,
    version=$5, updated_at=$6
WHERE id=$1 AND status='pending' AND version=$7`, user.ID, user.Status, user.MFAEnrolled,
		user.CredentialRotatedAt.UTC(), user.Version, user.UpdatedAt.UTC(), expectedVersion)
	if err != nil {
		return fmt.Errorf("activate local user: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrLocalAuthenticationFailed
	}
	result, err = tx.Exec(ctx, `
UPDATE local_credentials SET algorithm=$2, parameters=$3, salt=$4, derived_key=$5,
    failed_attempts=0, locked_until=NULL, password_changed_at=$6,
    activation_digest=NULL, activation_expires_at=NULL,
    mfa_secret_reference=$7, mfa_last_counter=$8
WHERE user_id=$1 AND activation_digest IS NOT NULL`, credential.UserID, credential.Password.Algorithm,
		credential.Password.Parameters, credential.Password.Salt, credential.Password.DerivedKey,
		credential.PasswordChangedAt.UTC(), credential.MFASecretReference, credential.MFALastCounter)
	if err != nil {
		return fmt.Errorf("save activated credential: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrLocalAuthenticationFailed
	}
	_, err = tx.Exec(ctx, `
INSERT INTO local_password_history (user_id, sequence, algorithm, parameters, salt, derived_key, created_at)
VALUES ($1, COALESCE((SELECT max(sequence)+1 FROM local_password_history WHERE user_id=$1), 1), $2, $3, $4, $5, $6)`,
		user.ID, history.Algorithm, history.Parameters, history.Salt, history.DerivedKey, user.CredentialRotatedAt.UTC())
	if err != nil {
		return fmt.Errorf("append local password history: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) FindLogin(ctx context.Context, tx pgx.Tx, canonicalUsername string) (LoginState, UserPrincipal, LocalCredential, bool, error) {
	if repository == nil || repository.pool == nil || tx == nil {
		return LoginState{}, UserPrincipal{}, LocalCredential{}, false, ErrIAMConfiguration
	}
	var state LoginState
	err := tx.QueryRow(ctx, `
SELECT login_mode, COALESCE(active_source_id, '00000000-0000-0000-0000-000000000000'::uuid),
       fault_code, version, updated_by, updated_at
FROM iam_login_state WHERE singleton=TRUE
FOR SHARE`).Scan(&state.Mode, &state.ActiveSourceID, &state.FaultCode, &state.Version, &state.UpdatedBy, &state.UpdatedAt)
	if err != nil {
		return LoginState{}, UserPrincipal{}, LocalCredential{}, false, fmt.Errorf("read IAM login state for authentication: %w", err)
	}
	row := tx.QueryRow(ctx, `SELECT `+userColumns+`,
       COALESCE(credential.algorithm, ''), COALESCE(credential.parameters, ''),
       COALESCE(credential.salt, '\x'::bytea), COALESCE(credential.derived_key, '\x'::bytea),
       credential.failed_attempts, credential.locked_until, credential.password_changed_at,
       credential.activation_digest, credential.activation_expires_at,
       credential.mfa_secret_reference, credential.mfa_last_counter,
	   `+platformAdministratorExistsSQL+`
FROM user_principals user_record
JOIN local_credentials credential ON credential.user_id=user_record.id
WHERE lower(user_record.username)=$1
FOR UPDATE OF user_record, credential`, canonicalUsername)
	user, credential, administrator, err := scanAuthRecord(row, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return state, UserPrincipal{}, LocalCredential{}, false, ErrLocalAuthenticationFailed
	}
	if err != nil {
		return state, UserPrincipal{}, LocalCredential{}, false, fmt.Errorf("find local login: %w", err)
	}
	return state, user, credential, administrator, nil
}

func (repository *PostgresRepository) FindLoginPreflight(ctx context.Context, canonicalUsername string) (LoginState, UserPrincipal, LocalCredential, bool, error) {
	if repository == nil || repository.pool == nil {
		return LoginState{}, UserPrincipal{}, LocalCredential{}, false, ErrIAMConfiguration
	}
	state, err := repository.GetLoginState(ctx, nil)
	if err != nil {
		return LoginState{}, UserPrincipal{}, LocalCredential{}, false, err
	}
	row := repository.pool.QueryRow(ctx, `SELECT `+userColumns+`,
       COALESCE(credential.algorithm, ''), COALESCE(credential.parameters, ''),
       COALESCE(credential.salt, '\x'::bytea), COALESCE(credential.derived_key, '\x'::bytea),
       credential.failed_attempts, credential.locked_until, credential.password_changed_at,
       credential.activation_digest, credential.activation_expires_at,
       credential.mfa_secret_reference, credential.mfa_last_counter,
	   `+platformAdministratorExistsSQL+`
FROM user_principals user_record
JOIN local_credentials credential ON credential.user_id=user_record.id
WHERE lower(user_record.username)=$1`, canonicalUsername)
	user, credential, administrator, err := scanAuthRecord(row, true)
	if errors.Is(err, pgx.ErrNoRows) {
		return state, UserPrincipal{}, LocalCredential{}, false, ErrLocalAuthenticationFailed
	}
	if err != nil {
		return state, UserPrincipal{}, LocalCredential{}, false, fmt.Errorf("preflight local login: %w", err)
	}
	return state, user, credential, administrator, nil
}

func (repository *PostgresRepository) FindLocalReauthentication(ctx context.Context, tx pgx.Tx, canonicalUsername string, sessionID uuid.UUID) (LoginState, UserPrincipal, LocalCredential, Session, bool, error) {
	state, user, credential, administrator, err := repository.FindLogin(ctx, tx, canonicalUsername)
	if err != nil {
		return state, UserPrincipal{}, LocalCredential{}, Session{}, false, err
	}
	var session Session
	var revokedAt *time.Time
	err = tx.QueryRow(ctx, `
SELECT id, token_digest, subject_id, authentication_method, mfa_level, authenticated_at,
       last_used_at, absolute_expires_at, idle_expires_at, revoked_at, revocation_reason, version
FROM local_sessions WHERE id=$1
FOR UPDATE`, sessionID).Scan(
		&session.ID, &session.TokenDigest, &session.SubjectID, &session.AuthenticationMethod, &session.MFALevel,
		&session.AuthenticatedAt, &session.LastUsedAt, &session.AbsoluteExpiresAt, &session.IdleExpiresAt,
		&revokedAt, &session.RevocationReason, &session.Version,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return state, UserPrincipal{}, LocalCredential{}, Session{}, false, ErrLocalAuthenticationFailed
	}
	if err != nil {
		return state, UserPrincipal{}, LocalCredential{}, Session{}, false, fmt.Errorf("find local reauthentication session: %w", err)
	}
	if revokedAt != nil {
		session.RevokedAt = revokedAt.UTC()
	}
	return state, user, credential, session, administrator, nil
}

func (repository *PostgresRepository) FindLocalReauthenticationPreflight(ctx context.Context, canonicalUsername string, sessionID uuid.UUID) (LoginState, UserPrincipal, LocalCredential, Session, bool, error) {
	state, user, credential, administrator, err := repository.FindLoginPreflight(ctx, canonicalUsername)
	if err != nil {
		return state, UserPrincipal{}, LocalCredential{}, Session{}, false, err
	}
	session, err := scanLocalSession(repository.pool.QueryRow(ctx, `
SELECT id, token_digest, subject_id, authentication_method, mfa_level, authenticated_at,
       last_used_at, absolute_expires_at, idle_expires_at, revoked_at, revocation_reason, version
FROM local_sessions WHERE id=$1`, sessionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return state, UserPrincipal{}, LocalCredential{}, Session{}, false, ErrLocalAuthenticationFailed
	}
	if err != nil {
		return state, UserPrincipal{}, LocalCredential{}, Session{}, false, fmt.Errorf("preflight local reauthentication session: %w", err)
	}
	return state, user, credential, session, administrator, nil
}

func scanLocalSession(row pgx.Row) (Session, error) {
	var session Session
	var revokedAt *time.Time
	err := row.Scan(
		&session.ID, &session.TokenDigest, &session.SubjectID, &session.AuthenticationMethod, &session.MFALevel,
		&session.AuthenticatedAt, &session.LastUsedAt, &session.AbsoluteExpiresAt, &session.IdleExpiresAt,
		&revokedAt, &session.RevocationReason, &session.Version,
	)
	if revokedAt != nil {
		session.RevokedAt = revokedAt.UTC()
	}
	return session, err
}

func (repository *PostgresRepository) SaveReauthenticationSuccess(ctx context.Context, tx pgx.Tx, userID uuid.UUID, mfaCounter int64) error {
	if repository == nil || repository.pool == nil || tx == nil || userID == uuid.Nil {
		return ErrIAMConfiguration
	}
	_, err := tx.Exec(ctx, `
UPDATE local_credentials SET failed_attempts=0, locked_until=NULL,
    mfa_last_counter=CASE WHEN $2 > mfa_last_counter THEN $2 ELSE mfa_last_counter END
WHERE user_id=$1`, userID, mfaCounter)
	if err != nil {
		return fmt.Errorf("save local reauthentication success: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) ConsumeRateLimit(ctx context.Context, tx pgx.Tx, scope RateLimitScope, keyDigest string, windowStart time.Time, limit int, expiresAt time.Time) (bool, error) {
	if repository == nil || repository.pool == nil {
		return false, ErrIAMConfiguration
	}
	queryer := iamQueryer(repository.pool)
	if tx != nil {
		queryer = tx
	}
	var allowed bool
	err := queryer.QueryRow(ctx, `
INSERT INTO local_auth_rate_limits (scope, key_digest, window_started_at, attempt_count, expires_at)
VALUES ($1, $2, $3, 1, $4)
ON CONFLICT (scope, key_digest, window_started_at)
DO UPDATE SET attempt_count=local_auth_rate_limits.attempt_count+1, expires_at=EXCLUDED.expires_at
RETURNING attempt_count <= $5`, scope, keyDigest, windowStart.UTC(), expiresAt.UTC(), limit).Scan(&allowed)
	if err != nil {
		return false, fmt.Errorf("consume local authentication rate limit: %w", err)
	}
	return allowed, nil
}

func (repository *PostgresRepository) CleanupExpiredRateLimits(ctx context.Context, tx pgx.Tx, before time.Time, limit int) (int64, error) {
	if repository == nil || repository.pool == nil || tx == nil || limit < 1 || limit > 1000 {
		return 0, ErrIAMConfiguration
	}
	result, err := tx.Exec(ctx, `
WITH expired AS (
    SELECT scope, key_digest, window_started_at
    FROM local_auth_rate_limits
    WHERE expires_at <= $1
    ORDER BY expires_at, scope, key_digest, window_started_at
    LIMIT $2
    FOR UPDATE SKIP LOCKED
)
DELETE FROM local_auth_rate_limits target
USING expired
WHERE target.scope=expired.scope
  AND target.key_digest=expired.key_digest
  AND target.window_started_at=expired.window_started_at`, before.UTC(), limit)
	if err != nil {
		return 0, fmt.Errorf("cleanup expired local authentication rate limits: %w", err)
	}
	return result.RowsAffected(), nil
}

func (repository *PostgresRepository) SaveAuthenticationFailure(ctx context.Context, tx pgx.Tx, userID uuid.UUID, failedAttempts int, lockedUntil time.Time) error {
	if tx == nil || userID == uuid.Nil {
		return ErrIAMConfiguration
	}
	_, err := tx.Exec(ctx, `UPDATE local_credentials SET failed_attempts=$2, locked_until=$3 WHERE user_id=$1`, userID, failedAttempts, nullableTime(lockedUntil))
	return err
}

func (repository *PostgresRepository) SaveAuthenticationSuccess(ctx context.Context, tx pgx.Tx, userID uuid.UUID, mfaCounter int64, session Session) error {
	if tx == nil || userID == uuid.Nil || session.ID == uuid.Nil || session.SubjectID != userID {
		return ErrIAMConfiguration
	}
	if _, err := tx.Exec(ctx, `
UPDATE local_credentials SET failed_attempts=0, locked_until=NULL,
    mfa_last_counter=CASE WHEN $2 > mfa_last_counter THEN $2 ELSE mfa_last_counter END
WHERE user_id=$1`, userID, mfaCounter); err != nil {
		return fmt.Errorf("reset local authentication failures: %w", err)
	}
	_, err := tx.Exec(ctx, `
INSERT INTO local_sessions (
    id, token_digest, subject_id, authentication_method, mfa_level, authenticated_at,
    last_used_at, absolute_expires_at, idle_expires_at, version
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, session.ID, session.TokenDigest, session.SubjectID,
		session.AuthenticationMethod, session.MFALevel, session.AuthenticatedAt.UTC(), session.LastUsedAt.UTC(),
		session.AbsoluteExpiresAt.UTC(), session.IdleExpiresAt.UTC(), session.Version)
	if err != nil {
		return fmt.Errorf("insert local session: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) FindSession(ctx context.Context, tx pgx.Tx, tokenDigest string) (Session, UserPrincipal, LoginState, error) {
	if repository == nil || repository.pool == nil || tx == nil {
		return Session{}, UserPrincipal{}, LoginState{}, ErrIAMConfiguration
	}
	var session Session
	var user UserPrincipal
	var state LoginState
	var revokedAt *time.Time
	err := tx.QueryRow(ctx, `
SELECT login_mode, COALESCE(active_source_id, '00000000-0000-0000-0000-000000000000'::uuid),
       fault_code, version, updated_by, updated_at
FROM iam_login_state WHERE singleton=TRUE
FOR SHARE`).Scan(&state.Mode, &state.ActiveSourceID, &state.FaultCode, &state.Version, &state.UpdatedBy, &state.UpdatedAt)
	if err != nil {
		return Session{}, UserPrincipal{}, LoginState{}, fmt.Errorf("lock IAM login state for session verification: %w", err)
	}
	err = tx.QueryRow(ctx, `
SELECT session.id, session.token_digest, session.subject_id, session.authentication_method,
       session.mfa_level, session.authenticated_at, session.last_used_at, session.absolute_expires_at,
       session.idle_expires_at, session.revoked_at, session.revocation_reason, session.version,
       user_record.id, user_record.username, user_record.display_name, user_record.user_kind, user_record.status
FROM local_sessions session
JOIN user_principals user_record ON user_record.id=session.subject_id
WHERE session.token_digest=$1
FOR UPDATE OF session`, tokenDigest).Scan(
		&session.ID, &session.TokenDigest, &session.SubjectID, &session.AuthenticationMethod,
		&session.MFALevel, &session.AuthenticatedAt, &session.LastUsedAt, &session.AbsoluteExpiresAt,
		&session.IdleExpiresAt, &revokedAt, &session.RevocationReason, &session.Version,
		&user.ID, &user.Username, &user.DisplayName, &user.Kind, &user.Status,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, UserPrincipal{}, LoginState{}, ErrLocalAuthenticationFailed
	}
	if err != nil {
		return Session{}, UserPrincipal{}, LoginState{}, fmt.Errorf("find local session: %w", err)
	}
	if revokedAt != nil {
		session.RevokedAt = revokedAt.UTC()
	}
	return session, user, state, nil
}

func (repository *PostgresRepository) TouchSession(ctx context.Context, tx pgx.Tx, sessionID uuid.UUID, lastUsedAt, idleExpiresAt time.Time, expectedVersion int64) error {
	if tx == nil || sessionID == uuid.Nil {
		return ErrIAMConfiguration
	}
	result, err := tx.Exec(ctx, `
UPDATE local_sessions SET last_used_at=$2, idle_expires_at=$3, version=version+1
WHERE id=$1 AND version=$4 AND revoked_at IS NULL`, sessionID, lastUsedAt.UTC(), idleExpiresAt.UTC(), expectedVersion)
	if err != nil {
		return fmt.Errorf("touch local session: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrIAMConflict
	}
	return nil
}

func (repository *PostgresRepository) RevokeCurrentSession(ctx context.Context, tx pgx.Tx, sessionID uuid.UUID, revokedAt time.Time, reason string) error {
	reason = strings.TrimSpace(reason)
	if repository == nil || repository.pool == nil || tx == nil || sessionID == uuid.Nil || reason == "" || len(reason) > 256 || revokedAt.IsZero() {
		return ErrIAMConfiguration
	}
	result, err := tx.Exec(ctx, `
UPDATE local_sessions SET revoked_at=$2, revocation_reason=$3, version=version+1
WHERE id=$1 AND revoked_at IS NULL`, sessionID, revokedAt.UTC(), reason)
	if err != nil {
		return fmt.Errorf("revoke current local session: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrLocalAuthenticationFailed
	}
	return nil
}

func (repository *PostgresRepository) RevokeSubject(ctx context.Context, tx pgx.Tx, subjectID uuid.UUID, reason string) error {
	reason = strings.TrimSpace(reason)
	if repository == nil || repository.pool == nil || tx == nil || subjectID == uuid.Nil || reason == "" || len(reason) > 256 {
		return ErrIAMConfiguration
	}
	_, err := tx.Exec(ctx, `
UPDATE local_sessions SET revoked_at=clock_timestamp(), revocation_reason=$2, version=version+1
WHERE subject_id=$1 AND revoked_at IS NULL`, subjectID, reason)
	if err != nil {
		return fmt.Errorf("revoke subject sessions: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) RevokeOrganizationMembers(ctx context.Context, tx pgx.Tx, organizationID uuid.UUID, reason string) error {
	reason = strings.TrimSpace(reason)
	if repository == nil || repository.pool == nil || tx == nil || organizationID == uuid.Nil || reason == "" || len(reason) > 256 {
		return ErrIAMConfiguration
	}
	_, err := tx.Exec(ctx, `
UPDATE local_sessions session
SET revoked_at=clock_timestamp(), revocation_reason=$2, version=version+1
WHERE session.subject_id IN (
    SELECT DISTINCT membership.user_id FROM organization_memberships membership
    WHERE membership.organization_id=$1 AND membership.status='active'
)
  AND session.revoked_at IS NULL`, organizationID, reason)
	if err != nil {
		return fmt.Errorf("revoke organization member sessions: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) RevokeRegularLocalSessions(ctx context.Context, tx pgx.Tx, reason string) error {
	reason = strings.TrimSpace(reason)
	if repository == nil || repository.pool == nil || tx == nil || reason == "" || len(reason) > 256 {
		return ErrIAMConfiguration
	}
	_, err := tx.Exec(ctx, `
UPDATE local_sessions SET revoked_at=clock_timestamp(), revocation_reason=$1, version=version+1
WHERE authentication_method='local_password' AND revoked_at IS NULL`, reason)
	if err != nil {
		return fmt.Errorf("revoke regular local sessions: %w", err)
	}
	return nil
}

func scanAuthRecord(row pgx.Row, includeAdministrator bool) (UserPrincipal, LocalCredential, bool, error) {
	var user UserPrincipal
	var credential LocalCredential
	var credentialRotatedAt, disabledAt, lockedUntil, passwordChangedAt, activationExpiresAt *time.Time
	var activationDigest *string
	administrator := false
	targets := []any{
		&user.ID, &user.IdentitySourceID, &user.ExternalSubject, &user.Username, &user.DisplayName, &user.Email,
		&user.Kind, &user.Status, &user.MFAEnrolled, &credentialRotatedAt, &user.Version, &user.CreatedAt,
		&user.UpdatedAt, &disabledAt, &user.DisabledReason,
		&credential.Password.Algorithm, &credential.Password.Parameters, &credential.Password.Salt, &credential.Password.DerivedKey,
		&credential.FailedAttempts, &lockedUntil, &passwordChangedAt, &activationDigest, &activationExpiresAt,
		&credential.MFASecretReference, &credential.MFALastCounter,
	}
	if includeAdministrator {
		targets = append(targets, &administrator)
	}
	if err := row.Scan(targets...); err != nil {
		return UserPrincipal{}, LocalCredential{}, false, err
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
	if passwordChangedAt != nil {
		credential.PasswordChangedAt = passwordChangedAt.UTC()
	}
	if activationDigest != nil {
		credential.ActivationDigest = *activationDigest
	}
	if activationExpiresAt != nil {
		credential.ActivationExpiresAt = activationExpiresAt.UTC()
	}
	return user, credential, administrator, nil
}

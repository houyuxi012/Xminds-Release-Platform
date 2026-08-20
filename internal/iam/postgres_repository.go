package iam

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

func (repository *PostgresRepository) LockBreakGlassInvariant(ctx context.Context, tx pgx.Tx) error {
	if repository == nil || repository.pool == nil || tx == nil {
		return ErrIAMConfiguration
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('xminds-release-platform:iam:break-glass-invariant', 0))`); err != nil {
		return fmt.Errorf("lock break-glass invariant: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) EvaluateBreakGlassInvariant(ctx context.Context, tx pgx.Tx, at time.Time) (BreakGlassInvariantEvaluation, error) {
	if repository == nil || repository.pool == nil || tx == nil {
		return BreakGlassInvariantEvaluation{}, ErrIAMConfiguration
	}
	var evaluation BreakGlassInvariantEvaluation
	var scheduledGap *time.Time
	err := tx.QueryRow(ctx, `
WITH structural_candidates AS (
    SELECT user_record.id,
           user_record.credential_rotated_at IS NOT NULL
               AND user_record.credential_rotated_at >= $2
               AND (credential.locked_until IS NULL OR credential.locked_until <= $1)
               AS currently_usable
    FROM user_principals AS user_record
    JOIN local_credentials AS credential ON credential.user_id=user_record.id
    CROSS JOIN LATERAL regexp_match(
        credential.parameters,
        '^m=([0-9]{1,6}),t=([0-9]{1,2}),p=([0-9]),l=([0-9]{1,2})$'
    ) AS parsed
    WHERE user_record.user_kind='emergency'
      AND user_record.status='active'
      AND user_record.mfa_enrolled=TRUE
      AND credential.algorithm='argon2id'
      AND credential.activation_digest IS NULL
      AND credential.password_changed_at IS NOT NULL
      AND credential.mfa_secret_reference <> ''
      AND octet_length(credential.salt) BETWEEN 16 AND 64
      AND octet_length(credential.derived_key) BETWEEN 16 AND 64
      AND parsed[1]::integer BETWEEN 19456 AND 262144
      AND parsed[2]::integer BETWEEN 1 AND 10
      AND parsed[3]::integer BETWEEN 1 AND 8
      AND parsed[4]::integer BETWEEN 16 AND 64
      AND parsed[4]::integer = octet_length(credential.derived_key)
      AND credential.parameters = format(
          'm=%s,t=%s,p=%s,l=%s', parsed[1]::integer, parsed[2]::integer,
          parsed[3]::integer, parsed[4]::integer
      )
), permission_boundaries AS (
    SELECT binding.valid_from AS boundary_at
    FROM role_bindings AS binding
    WHERE binding.role_name='admin'
      AND binding.scope_type='platform'
      AND binding.valid_from > $1
    UNION
    SELECT binding.valid_until AS boundary_at
    FROM role_bindings AS binding
    WHERE binding.role_name='admin'
      AND binding.scope_type='platform'
      AND binding.valid_until IS NOT NULL
      AND binding.valid_until > $1
), evaluation_points AS (
    SELECT $1::timestamptz AS evaluated_at, TRUE AS is_current
    UNION ALL
    SELECT boundary_at, FALSE FROM permission_boundaries
), candidate_access AS (
    SELECT point.evaluated_at,
           point.is_current,
           candidate.id,
           candidate.currently_usable,
           EXISTS (
               SELECT 1
               FROM role_bindings AS binding
               WHERE binding.role_name='admin'
                 AND binding.scope_type='platform'
                 AND binding.effect='allow'
                 AND binding.valid_from <= point.evaluated_at
                 AND (binding.valid_until IS NULL OR binding.valid_until > point.evaluated_at)
                 AND (
                     (binding.subject_type='user' AND binding.subject_id=candidate.id)
                     OR (
                         binding.subject_type='organization'
                         AND EXISTS (
                             SELECT 1 FROM organization_memberships AS membership
                             WHERE membership.organization_id=binding.subject_id
                               AND membership.user_id=candidate.id
                         )
                     )
                 )
           ) AND NOT EXISTS (
               SELECT 1
               FROM role_bindings AS binding
               WHERE binding.role_name='admin'
                 AND binding.scope_type='platform'
                 AND binding.effect='deny'
                 AND binding.valid_from <= point.evaluated_at
                 AND (binding.valid_until IS NULL OR binding.valid_until > point.evaluated_at)
                 AND (
                     (binding.subject_type='user' AND binding.subject_id=candidate.id)
                     OR (
                         binding.subject_type='organization'
                         AND EXISTS (
                             SELECT 1 FROM organization_memberships AS membership
                             WHERE membership.organization_id=binding.subject_id
                               AND membership.user_id=candidate.id
                         )
                     )
                 )
           ) AS has_access
    FROM evaluation_points AS point
    CROSS JOIN structural_candidates AS candidate
), point_counts AS (
    SELECT point.evaluated_at,
           point.is_current,
           count(*) FILTER (
               WHERE access.has_access
                 AND (NOT point.is_current OR access.currently_usable)
           ) AS administrator_count
    FROM evaluation_points AS point
    LEFT JOIN candidate_access AS access
      ON access.evaluated_at=point.evaluated_at
     AND access.is_current=point.is_current
    GROUP BY point.evaluated_at, point.is_current
)
SELECT COALESCE(max(administrator_count) FILTER (WHERE is_current), 0),
       min(evaluated_at) FILTER (WHERE NOT is_current AND administrator_count=0)
FROM point_counts
`, at.UTC(), at.UTC().Add(-emergencyCredentialMaximumAge)).Scan(&evaluation.CurrentUsableAdministrators, &scheduledGap)
	if err != nil {
		return BreakGlassInvariantEvaluation{}, fmt.Errorf("evaluate break-glass invariant: %w", err)
	}
	if scheduledGap != nil {
		evaluation.FirstScheduledPermissionGap = scheduledGap.UTC()
	}
	return evaluation, nil
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

func (repository *PostgresRepository) UserCanBeEnabled(ctx context.Context, tx pgx.Tx, user UserPrincipal) (bool, error) {
	if repository == nil || repository.pool == nil || user.ID == uuid.Nil {
		return false, ErrIAMConfiguration
	}
	queryer := iamQueryer(repository.pool)
	if tx != nil {
		queryer = tx
	}
	var usable bool
	switch user.Kind {
	case UserKindExternal:
		if user.IdentitySourceID == uuid.Nil {
			return false, nil
		}
		err := queryer.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity_sources WHERE id=$1 AND status='enabled')`, user.IdentitySourceID).Scan(&usable)
		return usable, err
	case UserKindLocal, UserKindEmergency:
		err := queryer.QueryRow(ctx, `SELECT EXISTS(
    SELECT 1 FROM local_credentials
    WHERE user_id=$1 AND algorithm='argon2id' AND password_changed_at IS NOT NULL AND activation_digest IS NULL
      AND ($2::boolean=FALSE OR (mfa_secret_reference <> '' AND $3::boolean=TRUE))
)`, user.ID, user.Kind == UserKindEmergency, user.MFAEnrolled).Scan(&usable)
		return usable, err
	default:
		return false, nil
	}
}

func (repository *PostgresRepository) InsertLocalUser(ctx context.Context, tx pgx.Tx, user UserPrincipal, credential LocalCredential) error {
	if tx == nil || user.ID == uuid.Nil || credential.UserID != user.ID || user.Kind != UserKindLocal {
		return ErrIAMConfiguration
	}
	_, err := tx.Exec(ctx, `
INSERT INTO user_principals (
    id, identity_source_id, external_subject, username, display_name, email, user_kind, status,
    mfa_enrolled, credential_rotated_at, version, created_at, updated_at, disabled_at, disabled_reason
) VALUES ($1, NULL, '', $2, $3, $4, $5, $6, FALSE, NULL, $7, $8, $9, NULL, '')
`, user.ID, user.Username, user.DisplayName, user.Email, user.Kind, user.Status, user.Version, user.CreatedAt.UTC(), user.UpdatedAt.UTC())
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return ErrIAMConflict
		}
		return fmt.Errorf("insert local user principal: %w", err)
	}
	_, err = tx.Exec(ctx, `
INSERT INTO local_credentials (
    user_id, algorithm, parameters, salt, derived_key, failed_attempts, locked_until,
    password_changed_at, activation_digest, activation_expires_at
) VALUES ($1, $2, $3, $4, $5, 0, NULL, $6, $7, $8)
`, credential.UserID, nullablePasswordString(credential.Password.Algorithm), nullablePasswordString(credential.Password.Parameters),
		nullablePasswordBytes(credential.Password.Salt), nullablePasswordBytes(credential.Password.DerivedKey),
		nullableTime(credential.PasswordChangedAt), credential.ActivationDigest, credential.ActivationExpiresAt.UTC())
	if err != nil {
		return fmt.Errorf("insert local credential: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) ListUsers(ctx context.Context, page Page) (UserPage, error) {
	if repository == nil || repository.pool == nil {
		return UserPage{}, ErrIAMConfiguration
	}
	limit := page.Limit
	if limit == 0 {
		limit = 50
	}
	if limit < 1 || limit > 200 || (page.BeforeTime.IsZero() != (page.BeforeID == uuid.Nil)) {
		return UserPage{}, ErrPageInvalid
	}
	rows, err := repository.pool.Query(ctx, userSelect+`
WHERE ($1::timestamptz IS NULL OR (created_at, id) < ($1, $2))
ORDER BY created_at DESC, id DESC
LIMIT $3
`, nullableTime(page.BeforeTime), page.BeforeID, limit+1)
	if err != nil {
		return UserPage{}, fmt.Errorf("list user principals: %w", err)
	}
	defer rows.Close()
	items := make([]UserPrincipal, 0, limit+1)
	for rows.Next() {
		item, scanErr := scanUser(rows)
		if scanErr != nil {
			return UserPage{}, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return UserPage{}, fmt.Errorf("iterate user principals: %w", err)
	}
	result := UserPage{Items: items}
	if len(items) > limit {
		last := items[limit-1]
		result.Items = items[:limit]
		result.NextCursor = encodeIAMCursor(last.CreatedAt, last.ID)
	}
	return result, nil
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

func (repository *PostgresRepository) InsertOrganization(ctx context.Context, tx pgx.Tx, organization OrganizationUnit) error {
	if tx == nil || organization.ID == uuid.Nil || organization.SourceOwned || organization.Status != OrganizationStatusActive || organization.Version != 1 {
		return ErrIAMConfiguration
	}
	_, err := tx.Exec(ctx, `
INSERT INTO organization_units (id, identity_source_id, external_id, parent_id, name, source_owned, status, version, created_at, updated_at)
VALUES ($1, NULL, '', $2, $3, FALSE, $4, $5, $6, $7)`, organization.ID, nullableUUID(organization.ParentID), organization.Name, organization.Status, organization.Version, organization.CreatedAt.UTC(), organization.UpdatedAt.UTC())
	if err != nil {
		return fmt.Errorf("insert organization unit: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) GetOrganization(ctx context.Context, tx pgx.Tx, id uuid.UUID) (OrganizationUnit, error) {
	if repository == nil || repository.pool == nil || id == uuid.Nil {
		return OrganizationUnit{}, ErrOrganizationNotFound
	}
	query := organizationSelect + " WHERE id = $1"
	queryer := iamQueryer(repository.pool)
	if tx != nil {
		query += " FOR UPDATE"
		queryer = tx
	}
	return scanOrganization(queryer.QueryRow(ctx, query, id))
}

func (repository *PostgresRepository) ListOrganizations(ctx context.Context, page Page) (OrganizationPage, error) {
	if repository == nil || repository.pool == nil {
		return OrganizationPage{}, ErrIAMConfiguration
	}
	limit, err := pageLimit(page)
	if err != nil {
		return OrganizationPage{}, err
	}
	rows, err := repository.pool.Query(ctx, organizationSelect+`
WHERE ($1::timestamptz IS NULL OR (created_at, id) < ($1, $2))
ORDER BY created_at DESC, id DESC
LIMIT $3`, nullableTime(page.BeforeTime), page.BeforeID, limit+1)
	if err != nil {
		return OrganizationPage{}, fmt.Errorf("list organization units: %w", err)
	}
	defer rows.Close()
	items := make([]OrganizationUnit, 0, limit+1)
	for rows.Next() {
		item, scanErr := scanOrganization(rows)
		if scanErr != nil {
			return OrganizationPage{}, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return OrganizationPage{}, fmt.Errorf("iterate organization units: %w", err)
	}
	result := OrganizationPage{Items: items}
	if len(items) > limit {
		last := items[limit-1]
		result.Items, result.NextCursor = items[:limit], encodeIAMCursor(last.CreatedAt, last.ID)
	}
	return result, nil
}

func (repository *PostgresRepository) InsertRoleBinding(ctx context.Context, tx pgx.Tx, binding RoleBinding) error {
	if tx == nil || binding.ID == uuid.Nil || binding.Version != 1 {
		return ErrIAMConfiguration
	}
	_, err := tx.Exec(ctx, `
INSERT INTO role_bindings (id, subject_type, subject_id, role_name, scope_type, product_id, channel_name, effect, valid_from, valid_until, created_by, version, created_at, updated_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`, binding.ID, binding.SubjectType, binding.SubjectID, binding.Role, binding.ScopeType, nullableString(binding.ProductID), nullableString(binding.ChannelName), binding.Effect, binding.ValidFrom.UTC(), nullableTime(binding.ValidUntil), binding.CreatedBy, binding.Version, binding.CreatedAt.UTC(), binding.UpdatedAt.UTC())
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && (postgresError.Code == "23503" ||
			postgresError.ConstraintName == "role_bindings_product_id_length" ||
			postgresError.ConstraintName == "role_bindings_channel_name_length") {
			return ErrRoleBindingInvalid
		}
		return fmt.Errorf("insert role binding: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) ValidateRoleBindingScope(ctx context.Context, tx pgx.Tx, scope CatalogScope) error {
	if repository == nil || repository.pool == nil {
		return ErrIAMConfiguration
	}
	if scope.Type == ScopeTypePlatform {
		return nil
	}
	queryer := iamQueryer(repository.pool)
	query := `SELECT 1 FROM products WHERE id=$1`
	arguments := []any{scope.ProductID}
	if scope.Type == ScopeTypeChannel {
		query = `SELECT 1 FROM product_channels WHERE product_id=$1 AND name=$2`
		arguments = append(arguments, scope.ChannelName)
	} else if scope.Type != ScopeTypeProduct {
		return ErrRoleBindingInvalid
	}
	if tx != nil {
		queryer = tx
		query += ` FOR KEY SHARE`
	}
	var marker int
	if err := queryer.QueryRow(ctx, query, arguments...).Scan(&marker); errors.Is(err, pgx.ErrNoRows) {
		return ErrRoleBindingInvalid
	} else if err != nil {
		return fmt.Errorf("validate role binding catalog scope: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) GetRoleBinding(ctx context.Context, tx pgx.Tx, id uuid.UUID) (RoleBinding, error) {
	if repository == nil || repository.pool == nil || id == uuid.Nil {
		return RoleBinding{}, ErrRoleBindingNotFound
	}
	query := roleBindingSelect + " WHERE id = $1"
	queryer := iamQueryer(repository.pool)
	if tx != nil {
		query += " FOR UPDATE"
		queryer = tx
	}
	return scanRoleBinding(queryer.QueryRow(ctx, query, id))
}

func (repository *PostgresRepository) ListRoleBindings(ctx context.Context, page Page) (RoleBindingPage, error) {
	if repository == nil || repository.pool == nil {
		return RoleBindingPage{}, ErrIAMConfiguration
	}
	limit, err := pageLimit(page)
	if err != nil {
		return RoleBindingPage{}, err
	}
	rows, err := repository.pool.Query(ctx, roleBindingSelect+`
WHERE ($1::timestamptz IS NULL OR (created_at, id) < ($1, $2))
ORDER BY created_at DESC, id DESC
LIMIT $3`, nullableTime(page.BeforeTime), page.BeforeID, limit+1)
	if err != nil {
		return RoleBindingPage{}, fmt.Errorf("list role bindings: %w", err)
	}
	defer rows.Close()
	items := make([]RoleBinding, 0, limit+1)
	for rows.Next() {
		item, scanErr := scanRoleBinding(rows)
		if scanErr != nil {
			return RoleBindingPage{}, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return RoleBindingPage{}, fmt.Errorf("iterate role bindings: %w", err)
	}
	result := RoleBindingPage{Items: items}
	if len(items) > limit {
		last := items[limit-1]
		result.Items, result.NextCursor = items[:limit], encodeIAMCursor(last.CreatedAt, last.ID)
	}
	return result, nil
}

func (repository *PostgresRepository) DeleteRoleBinding(ctx context.Context, tx pgx.Tx, id uuid.UUID, expectedVersion int64) error {
	if tx == nil || id == uuid.Nil || expectedVersion < 1 {
		return ErrIAMConfiguration
	}
	result, err := tx.Exec(ctx, `DELETE FROM role_bindings WHERE id = $1 AND version = $2`, id, expectedVersion)
	if err != nil {
		return fmt.Errorf("delete role binding: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrIAMConflict
	}
	return nil
}

func (repository *PostgresRepository) InsertIdentitySource(ctx context.Context, tx pgx.Tx, source IdentitySource) error {
	if tx == nil || source.ID == uuid.Nil || source.Status != IdentitySourceStatusDraft || source.Version != 1 {
		return ErrIAMConfiguration
	}
	_, err := tx.Exec(ctx, `
INSERT INTO identity_sources (id, name, source_kind, status, secret_reference, required_mappings_complete, verified_at, previewed_at, fault_code, version, created_at, updated_at)
VALUES ($1, $2, $3, 'draft', $4, $5, NULL, NULL, '', 1, $6, $7)`, source.ID, source.Name, source.Kind, source.SecretReference, source.RequiredMappingsComplete, source.CreatedAt.UTC(), source.UpdatedAt.UTC())
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			return ErrIAMConflict
		}
		return fmt.Errorf("insert identity source: %w", err)
	}
	return nil
}

func (repository *PostgresRepository) ListIdentitySources(ctx context.Context, page Page) (IdentitySourcePage, error) {
	if repository == nil || repository.pool == nil {
		return IdentitySourcePage{}, ErrIAMConfiguration
	}
	limit, err := pageLimit(page)
	if err != nil {
		return IdentitySourcePage{}, err
	}
	rows, err := repository.pool.Query(ctx, identitySourceSelect+`
WHERE ($1::timestamptz IS NULL OR (created_at, id) < ($1, $2))
ORDER BY created_at DESC, id DESC
LIMIT $3`, nullableTime(page.BeforeTime), page.BeforeID, limit+1)
	if err != nil {
		return IdentitySourcePage{}, fmt.Errorf("list identity sources: %w", err)
	}
	defer rows.Close()
	items := make([]IdentitySource, 0, limit+1)
	for rows.Next() {
		item, scanErr := scanIdentitySource(rows)
		if scanErr != nil {
			return IdentitySourcePage{}, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return IdentitySourcePage{}, fmt.Errorf("iterate identity sources: %w", err)
	}
	result := IdentitySourcePage{Items: items}
	if len(items) > limit {
		last := items[limit-1]
		result.Items, result.NextCursor = items[:limit], encodeIAMCursor(last.CreatedAt, last.ID)
	}
	return result, nil
}

func (repository *PostgresRepository) UpdateIdentitySourceDraft(ctx context.Context, tx pgx.Tx, source IdentitySource, expectedVersion int64) error {
	if tx == nil || source.ID == uuid.Nil || expectedVersion < 1 || source.Version != expectedVersion+1 {
		return ErrIAMConfiguration
	}
	result, err := tx.Exec(ctx, `
UPDATE identity_sources SET name = $2, secret_reference = $3, required_mappings_complete = $4, version = $5, updated_at = $6
WHERE id = $1 AND status = 'draft' AND version = $7`, source.ID, source.Name, source.SecretReference, source.RequiredMappingsComplete, source.Version, source.UpdatedAt.UTC(), expectedVersion)
	if err != nil {
		return fmt.Errorf("update identity source draft: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrIAMConflict
	}
	return nil
}

const userColumns = `user_record.id, COALESCE(user_record.identity_source_id, '00000000-0000-0000-0000-000000000000'::uuid),
       external_subject, username, display_name, email, user_kind, status, mfa_enrolled,
       credential_rotated_at, version, created_at, updated_at, disabled_at, disabled_reason
`

const userSelect = `SELECT ` + userColumns + ` FROM user_principals AS user_record`

const organizationSelect = `SELECT id, COALESCE(identity_source_id, '00000000-0000-0000-0000-000000000000'::uuid), external_id,
       COALESCE(parent_id, '00000000-0000-0000-0000-000000000000'::uuid), name, source_owned, status, version, created_at, updated_at
FROM organization_units`

const roleBindingSelect = `SELECT id, subject_type, subject_id, role_name, scope_type, COALESCE(product_id, ''), COALESCE(channel_name, ''), effect,
       valid_from, valid_until, created_by, version, created_at, updated_at
FROM role_bindings`

const identitySourceSelect = `SELECT id, name, source_kind, status, secret_reference, required_mappings_complete,
       verified_at, previewed_at, fault_code, version, created_at, updated_at
FROM identity_sources`

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

func scanOrganization(row pgx.Row) (OrganizationUnit, error) {
	var organization OrganizationUnit
	err := row.Scan(&organization.ID, &organization.IdentitySourceID, &organization.ExternalID, &organization.ParentID, &organization.Name, &organization.SourceOwned, &organization.Status, &organization.Version, &organization.CreatedAt, &organization.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return OrganizationUnit{}, ErrOrganizationNotFound
	}
	if err != nil {
		return OrganizationUnit{}, fmt.Errorf("scan organization unit: %w", err)
	}
	return organization, nil
}

func scanRoleBinding(row pgx.Row) (RoleBinding, error) {
	var binding RoleBinding
	var validUntil *time.Time
	err := row.Scan(&binding.ID, &binding.SubjectType, &binding.SubjectID, &binding.Role, &binding.ScopeType, &binding.ProductID, &binding.ChannelName, &binding.Effect, &binding.ValidFrom, &validUntil, &binding.CreatedBy, &binding.Version, &binding.CreatedAt, &binding.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return RoleBinding{}, ErrRoleBindingNotFound
	}
	if err != nil {
		return RoleBinding{}, fmt.Errorf("scan role binding: %w", err)
	}
	if validUntil != nil {
		binding.ValidUntil = validUntil.UTC()
	}
	return binding, nil
}

func scanIdentitySource(row pgx.Row) (IdentitySource, error) {
	var source IdentitySource
	var verifiedAt, previewedAt *time.Time
	err := row.Scan(&source.ID, &source.Name, &source.Kind, &source.Status, &source.SecretReference, &source.RequiredMappingsComplete, &verifiedAt, &previewedAt, &source.FaultCode, &source.Version, &source.CreatedAt, &source.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return IdentitySource{}, ErrIdentitySourceNotFound
	}
	if err != nil {
		return IdentitySource{}, fmt.Errorf("scan identity source: %w", err)
	}
	if verifiedAt != nil {
		source.VerifiedAt = verifiedAt.UTC()
	}
	if previewedAt != nil {
		source.PreviewedAt = previewedAt.UTC()
	}
	return source, nil
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

func nullableUUID(value uuid.UUID) any {
	if value == uuid.Nil {
		return nil
	}
	return value
}
func nullableString(value string) any {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return strings.TrimSpace(value)
}

func nullablePasswordString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullablePasswordBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}
func pageLimit(page Page) (int, error) {
	if !validIAMPage(page) {
		return 0, ErrPageInvalid
	}
	if page.Limit == 0 {
		return 50, nil
	}
	return page.Limit, nil
}

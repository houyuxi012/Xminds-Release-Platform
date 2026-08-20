package iam

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
)

func (executor *PostgresDirectorySyncExecutor) prepareSnapshot(ctx context.Context, tx pgx.Tx, job *DirectorySyncJob, source *IdentitySource) error {
	if source.Kind == IdentitySourceOIDC {
		if job.Mode != DirectorySyncModePreview {
			return ErrDirectoryApplyUnsupported
		}
		return executor.completeDirectoryPreview(ctx, tx, job, source)
	}
	if err := executor.discoverConflicts(ctx, tx, *job); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
UPDATE directory_sync_stage_users AS staged
SET processed=TRUE
WHERE sync_job_id=$1 AND EXISTS (
    SELECT 1 FROM directory_sync_conflicts conflict
    WHERE conflict.sync_job_id=staged.sync_job_id AND conflict.object_type='user' AND conflict.external_id=staged.external_subject
)
`, job.ID); err != nil {
		return fmt.Errorf("mark conflicting directory stage users: %w", err)
	}
	if _, err := tx.Exec(ctx, `
UPDATE directory_sync_stage_organizations AS staged
SET processed=TRUE
WHERE sync_job_id=$1 AND EXISTS (
    SELECT 1 FROM directory_sync_conflicts conflict
    WHERE conflict.sync_job_id=staged.sync_job_id AND conflict.object_type='organization' AND conflict.external_id=staged.external_id
)`, job.ID); err != nil {
		return fmt.Errorf("mark conflicting directory stage organizations: %w", err)
	}
	var createCount, updateCount, disableCount, conflictCount int
	if err := tx.QueryRow(ctx, `
WITH safe_users AS (
    SELECT staged.* FROM directory_sync_stage_users staged
    WHERE staged.sync_job_id=$1 AND staged.processed=FALSE
), safe_organizations AS (
    SELECT staged.* FROM directory_sync_stage_organizations staged
    WHERE staged.sync_job_id=$1 AND staged.processed=FALSE
)
SELECT
    (SELECT count(*) FROM safe_users staged
     WHERE NOT EXISTS (SELECT 1 FROM user_principals principal WHERE principal.identity_source_id=$2 AND principal.external_subject=staged.external_subject))
  + (SELECT count(*) FROM safe_organizations staged
     WHERE NOT EXISTS (SELECT 1 FROM organization_units organization WHERE organization.identity_source_id=$2 AND organization.external_id=staged.external_id)),
    (SELECT count(*) FROM safe_users staged
     JOIN user_principals principal ON principal.identity_source_id=$2 AND principal.external_subject=staged.external_subject
     WHERE principal.username IS DISTINCT FROM staged.username OR principal.display_name IS DISTINCT FROM staged.display_name
        OR principal.email IS DISTINCT FROM staged.email OR (principal.status='active') IS DISTINCT FROM staged.enabled)
  + (SELECT count(*) FROM safe_organizations staged
     JOIN organization_units organization ON organization.identity_source_id=$2 AND organization.external_id=staged.external_id
     WHERE organization.name IS DISTINCT FROM staged.name OR organization.status <> 'active')
  + (SELECT count(*) FROM directory_sync_stage_memberships staged
     JOIN organization_units organization ON organization.identity_source_id=$2 AND organization.external_id=staged.organization_external_id
     JOIN user_principals principal ON principal.identity_source_id=$2 AND principal.external_subject=staged.user_external_subject
     WHERE staged.sync_job_id=$1 AND staged.processed=FALSE
       AND NOT EXISTS (SELECT 1 FROM organization_memberships membership WHERE membership.organization_id=organization.id AND membership.user_id=principal.id)),
    (SELECT count(*) FROM user_principals principal
     WHERE principal.identity_source_id=$2 AND principal.status='active'
       AND NOT EXISTS (
           SELECT 1 FROM directory_sync_stage_users staged
           WHERE staged.sync_job_id=$1 AND staged.external_subject=principal.external_subject
       ))
  + (SELECT count(*) FROM safe_users staged
     JOIN user_principals principal ON principal.identity_source_id=$2 AND principal.external_subject=staged.external_subject
     WHERE principal.status='active' AND staged.enabled=FALSE)
  + (SELECT count(*) FROM organization_units organization
     WHERE organization.identity_source_id=$2 AND organization.status='active'
       AND NOT EXISTS (
           SELECT 1 FROM directory_sync_stage_organizations staged
           WHERE staged.sync_job_id=$1 AND staged.external_id=organization.external_id
       )),
    (SELECT count(*) FROM directory_sync_conflicts WHERE sync_job_id=$1)`, job.ID, job.IdentitySourceID).Scan(&createCount, &updateCount, &disableCount, &conflictCount); err != nil {
		return fmt.Errorf("calculate directory synchronization diff: %w", err)
	}
	job.CreateCount, job.UpdateCount, job.DisableCount, job.ConflictCount = createCount, updateCount, disableCount, conflictCount
	if job.Mode == DirectorySyncModePreview {
		return executor.completeDirectoryPreview(ctx, tx, job, source)
	}
	now := executor.now()
	job.Phase = DirectorySyncPhaseUsers
	job.UpdatedAt = now
	if _, err := tx.Exec(ctx, `
UPDATE directory_sync_jobs SET phase='apply_users', create_count=$2, update_count=$3,
    disable_count=$4, conflict_count=$5, updated_at=$6, cursor=''
WHERE id=$1`, job.ID, createCount, updateCount, disableCount, conflictCount, now); err != nil {
		return fmt.Errorf("prepare directory synchronization apply: %w", err)
	}
	return nil
}

func (executor *PostgresDirectorySyncExecutor) completeDirectoryPreview(ctx context.Context, tx pgx.Tx, job *DirectorySyncJob, source *IdentitySource) error {
	now := executor.now()
	previousVersion := source.Version
	source.PreviewedAt = now
	source.Version++
	source.UpdatedAt = now
	if err := executor.repository.SaveIdentitySource(ctx, tx, *source, previousVersion); err != nil {
		return err
	}
	job.Status = DirectorySyncStatusCompleted
	job.CompletedAt = now
	job.UpdatedAt = now
	if _, err := tx.Exec(ctx, `
UPDATE directory_sync_jobs SET status='completed', create_count=$2, update_count=$3, disable_count=$4,
    conflict_count=$5, completed_at=$6, updated_at=$6, cursor=''
WHERE id=$1`, job.ID, job.CreateCount, job.UpdateCount, job.DisableCount, job.ConflictCount, now); err != nil {
		return fmt.Errorf("complete directory synchronization preview: %w", err)
	}
	if err := executor.appendCompletionAudit(ctx, tx, *job); err != nil {
		return err
	}
	return executor.deleteStages(ctx, tx, job.ID)
}

func (executor *PostgresDirectorySyncExecutor) applyUsers(ctx context.Context, tx pgx.Tx, job *DirectorySyncJob) error {
	rows, err := tx.Query(ctx, `
SELECT external_subject, username, display_name, email, enabled
FROM directory_sync_stage_users
WHERE sync_job_id=$1 AND processed=FALSE
ORDER BY external_subject
FOR UPDATE SKIP LOCKED
LIMIT $2`, job.ID, executor.batchSize)
	if err != nil {
		return fmt.Errorf("select staged directory users: %w", err)
	}
	type stagedUser struct {
		externalSubject, username, displayName, email string
		enabled                                       bool
	}
	staged := make([]stagedUser, 0, executor.batchSize)
	for rows.Next() {
		var user stagedUser
		if err := rows.Scan(&user.externalSubject, &user.username, &user.displayName, &user.email, &user.enabled); err != nil {
			rows.Close()
			return fmt.Errorf("scan staged directory user: %w", err)
		}
		staged = append(staged, user)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate staged directory users: %w", err)
	}
	rows.Close()
	if len(staged) == 0 {
		job.Phase = DirectorySyncPhaseOrganizations
		job.UpdatedAt = executor.now()
		_, err := tx.Exec(ctx, `UPDATE directory_sync_jobs SET phase='apply_organizations', updated_at=$2 WHERE id=$1`, job.ID, job.UpdatedAt)
		return err
	}
	now := executor.now()
	for _, stagedUser := range staged {
		var existingID uuid.UUID
		var existingStatus UserStatus
		var existingVersion int64
		err := tx.QueryRow(ctx, `
SELECT id, status, version FROM user_principals
WHERE identity_source_id=$1 AND external_subject=$2 FOR UPDATE`, job.IdentitySourceID, stagedUser.externalSubject).Scan(&existingID, &existingStatus, &existingVersion)
		status := UserStatusActive
		var disabledAt any
		disabledReason := ""
		if !stagedUser.enabled {
			status = UserStatusDisabled
			disabledAt = now
			disabledReason = "directory source disabled"
		}
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			newID, idErr := uuid.NewV7()
			if idErr != nil {
				return idErr
			}
			if _, err := tx.Exec(ctx, `
INSERT INTO user_principals (
    id, identity_source_id, external_subject, username, display_name, email, user_kind, status,
    version, created_at, updated_at, disabled_at, disabled_reason, last_directory_run_id
) VALUES ($1, $2, $3, $4, $5, $6, 'external', $7, 1, $8, $8, $9, $10, $11)`,
				newID, job.IdentitySourceID, stagedUser.externalSubject, stagedUser.username, stagedUser.displayName, stagedUser.email,
				status, now, disabledAt, disabledReason, job.RunMarker); err != nil {
				return fmt.Errorf("insert directory user: %w", err)
			}
		case err != nil:
			return fmt.Errorf("load directory user: %w", err)
		default:
			if _, err := tx.Exec(ctx, `
UPDATE user_principals
SET username=$2, display_name=$3, email=$4, status=$5, disabled_at=$6, disabled_reason=$7,
    version=version+1, updated_at=$8, last_directory_run_id=$9
WHERE id=$1 AND version=$10`, existingID, stagedUser.username, stagedUser.displayName, stagedUser.email, status,
				disabledAt, disabledReason, now, job.RunMarker, existingVersion); err != nil {
				return fmt.Errorf("update directory user: %w", err)
			}
			if existingStatus != UserStatusDisabled && status == UserStatusDisabled {
				if err := executor.sessions.RevokeSubject(ctx, tx, existingID, disabledReason); err != nil {
					return err
				}
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE directory_sync_stage_users SET processed=TRUE WHERE sync_job_id=$1 AND external_subject=$2`, job.ID, stagedUser.externalSubject); err != nil {
			return fmt.Errorf("mark directory user processed: %w", err)
		}
	}
	job.ProcessedUsers += len(staged)
	job.UpdatedAt = now
	_, err = tx.Exec(ctx, `UPDATE directory_sync_jobs SET processed_users=$2, updated_at=$3 WHERE id=$1`, job.ID, job.ProcessedUsers, now)
	return err
}

func (executor *PostgresDirectorySyncExecutor) applyOrganizations(ctx context.Context, tx pgx.Tx, job *DirectorySyncJob) error {
	rows, err := tx.Query(ctx, `
SELECT external_id, name FROM directory_sync_stage_organizations
WHERE sync_job_id=$1 AND processed=FALSE
ORDER BY external_id
FOR UPDATE SKIP LOCKED
LIMIT $2`, job.ID, executor.batchSize)
	if err != nil {
		return fmt.Errorf("select staged directory organizations: %w", err)
	}
	type stagedOrganization struct{ externalID, name string }
	staged := make([]stagedOrganization, 0, executor.batchSize)
	for rows.Next() {
		var organization stagedOrganization
		if err := rows.Scan(&organization.externalID, &organization.name); err != nil {
			rows.Close()
			return fmt.Errorf("scan staged directory organization: %w", err)
		}
		staged = append(staged, organization)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate staged directory organizations: %w", err)
	}
	rows.Close()
	now := executor.now()
	if len(staged) == 0 {
		if _, err := tx.Exec(ctx, `
UPDATE organization_units AS organization
SET parent_id=(
        SELECT parent.id
        FROM directory_sync_stage_parents relation
        JOIN organization_units parent
          ON parent.identity_source_id=organization.identity_source_id AND parent.external_id=relation.parent_external_id
        WHERE relation.sync_job_id=$1 AND relation.organization_external_id=organization.external_id
        LIMIT 1
    ), version=organization.version+1, updated_at=$3
WHERE organization.identity_source_id=$2
  AND EXISTS (SELECT 1 FROM directory_sync_stage_organizations staged WHERE staged.sync_job_id=$1 AND staged.external_id=organization.external_id AND staged.processed=TRUE)
  AND NOT EXISTS (SELECT 1 FROM directory_sync_conflicts conflict WHERE conflict.sync_job_id=$1 AND conflict.object_type='organization' AND conflict.external_id=organization.external_id)`,
			job.ID, job.IdentitySourceID, now); err != nil {
			return fmt.Errorf("apply directory organization parents: %w", err)
		}
		job.Phase = DirectorySyncPhaseMemberships
		job.UpdatedAt = now
		_, err := tx.Exec(ctx, `UPDATE directory_sync_jobs SET phase='apply_memberships', updated_at=$2 WHERE id=$1`, job.ID, now)
		return err
	}
	for _, stagedOrganization := range staged {
		var existingID uuid.UUID
		var version int64
		err := tx.QueryRow(ctx, `
SELECT id, version FROM organization_units
WHERE identity_source_id=$1 AND external_id=$2 FOR UPDATE`, job.IdentitySourceID, stagedOrganization.externalID).Scan(&existingID, &version)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			newID, idErr := uuid.NewV7()
			if idErr != nil {
				return idErr
			}
			if _, err := tx.Exec(ctx, `
INSERT INTO organization_units (
    id, identity_source_id, external_id, name, source_owned, status, version, created_at, updated_at, last_directory_run_id
) VALUES ($1, $2, $3, $4, TRUE, 'active', 1, $5, $5, $6)`,
				newID, job.IdentitySourceID, stagedOrganization.externalID, stagedOrganization.name, now, job.RunMarker); err != nil {
				return fmt.Errorf("insert directory organization: %w", err)
			}
		case err != nil:
			return fmt.Errorf("load directory organization: %w", err)
		default:
			if _, err := tx.Exec(ctx, `
UPDATE organization_units SET name=$2, status='active', version=version+1, updated_at=$3, last_directory_run_id=$4
WHERE id=$1 AND version=$5`, existingID, stagedOrganization.name, now, job.RunMarker, version); err != nil {
				return fmt.Errorf("update directory organization: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE directory_sync_stage_organizations SET processed=TRUE WHERE sync_job_id=$1 AND external_id=$2`, job.ID, stagedOrganization.externalID); err != nil {
			return fmt.Errorf("mark directory organization processed: %w", err)
		}
	}
	job.ProcessedOrganizations += len(staged)
	job.UpdatedAt = now
	_, err = tx.Exec(ctx, `UPDATE directory_sync_jobs SET processed_organizations=$2, updated_at=$3 WHERE id=$1`, job.ID, job.ProcessedOrganizations, now)
	return err
}

func (executor *PostgresDirectorySyncExecutor) applyMemberships(ctx context.Context, tx pgx.Tx, job *DirectorySyncJob) error {
	rows, err := tx.Query(ctx, `
SELECT staged.organization_external_id, staged.user_external_subject
FROM directory_sync_stage_memberships staged
WHERE staged.sync_job_id=$1 AND staged.processed=FALSE
ORDER BY staged.organization_external_id, staged.user_external_subject
FOR UPDATE SKIP LOCKED
LIMIT $2`, job.ID, executor.batchSize)
	if err != nil {
		return fmt.Errorf("select staged directory memberships: %w", err)
	}
	type stagedMembership struct{ organizationExternalID, userExternalSubject string }
	staged := make([]stagedMembership, 0, executor.batchSize)
	for rows.Next() {
		var membership stagedMembership
		if err := rows.Scan(&membership.organizationExternalID, &membership.userExternalSubject); err != nil {
			rows.Close()
			return fmt.Errorf("scan staged directory membership: %w", err)
		}
		staged = append(staged, membership)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate staged directory memberships: %w", err)
	}
	rows.Close()
	now := executor.now()
	if len(staged) == 0 {
		job.Phase = DirectorySyncPhaseFinalize
		job.UpdatedAt = now
		_, err := tx.Exec(ctx, `UPDATE directory_sync_jobs SET phase='finalize', updated_at=$2 WHERE id=$1`, job.ID, now)
		return err
	}
	for _, stagedMembership := range staged {
		if _, err := tx.Exec(ctx, `
INSERT INTO organization_memberships (organization_id, user_id, source_owned, created_at)
SELECT organization.id, principal.id, TRUE, $3
FROM organization_units organization, user_principals principal
WHERE organization.identity_source_id=$1 AND organization.external_id=$2
  AND principal.identity_source_id=$1 AND principal.external_subject=$4
ON CONFLICT (organization_id, user_id) DO NOTHING`,
			job.IdentitySourceID, stagedMembership.organizationExternalID, now, stagedMembership.userExternalSubject); err != nil {
			return fmt.Errorf("apply directory membership: %w", err)
		}
		if _, err := tx.Exec(ctx, `
UPDATE directory_sync_stage_memberships SET processed=TRUE
WHERE sync_job_id=$1 AND organization_external_id=$2 AND user_external_subject=$3`,
			job.ID, stagedMembership.organizationExternalID, stagedMembership.userExternalSubject); err != nil {
			return fmt.Errorf("mark directory membership processed: %w", err)
		}
	}
	job.ProcessedMemberships += len(staged)
	job.UpdatedAt = now
	_, err = tx.Exec(ctx, `UPDATE directory_sync_jobs SET processed_memberships=$2, updated_at=$3 WHERE id=$1`, job.ID, job.ProcessedMemberships, now)
	return err
}

func (executor *PostgresDirectorySyncExecutor) finalizeApply(ctx context.Context, tx pgx.Tx, job *DirectorySyncJob) error {
	now := executor.now()
	userRows, err := tx.Query(ctx, `
UPDATE user_principals principal
SET status='disabled', disabled_at=$3, disabled_reason='directory snapshot missing', version=version+1, updated_at=$3
WHERE principal.identity_source_id=$2 AND principal.status <> 'disabled'
  AND principal.last_directory_run_id IS DISTINCT FROM $4
  AND NOT EXISTS (
      SELECT 1 FROM directory_sync_stage_users staged
      WHERE staged.sync_job_id=$1 AND staged.external_subject=principal.external_subject
  )
RETURNING principal.id`, job.ID, job.IdentitySourceID, now, job.RunMarker)
	if err != nil {
		return fmt.Errorf("disable missing directory users: %w", err)
	}
	disabledUsers := make([]uuid.UUID, 0)
	for userRows.Next() {
		var id uuid.UUID
		if err := userRows.Scan(&id); err != nil {
			userRows.Close()
			return err
		}
		disabledUsers = append(disabledUsers, id)
	}
	if err := userRows.Err(); err != nil {
		userRows.Close()
		return err
	}
	userRows.Close()
	for _, id := range disabledUsers {
		if err := executor.sessions.RevokeSubject(ctx, tx, id, "directory snapshot missing"); err != nil {
			return err
		}
	}
	organizationRows, err := tx.Query(ctx, `
UPDATE organization_units organization
SET status='disabled', version=version+1, updated_at=$3
WHERE organization.identity_source_id=$2 AND organization.status <> 'disabled'
  AND organization.last_directory_run_id IS DISTINCT FROM $4
  AND NOT EXISTS (
      SELECT 1 FROM directory_sync_stage_organizations staged
      WHERE staged.sync_job_id=$1 AND staged.external_id=organization.external_id
  )
RETURNING organization.id`, job.ID, job.IdentitySourceID, now, job.RunMarker)
	if err != nil {
		return fmt.Errorf("disable missing directory organizations: %w", err)
	}
	disabledOrganizations := make([]uuid.UUID, 0)
	for organizationRows.Next() {
		var id uuid.UUID
		if err := organizationRows.Scan(&id); err != nil {
			organizationRows.Close()
			return err
		}
		disabledOrganizations = append(disabledOrganizations, id)
	}
	if err := organizationRows.Err(); err != nil {
		organizationRows.Close()
		return err
	}
	organizationRows.Close()
	for _, id := range disabledOrganizations {
		if err := executor.sessions.RevokeOrganizationMembers(ctx, tx, id, "directory organization disabled"); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `
DELETE FROM organization_memberships membership
USING organization_units organization, user_principals principal
WHERE membership.organization_id=organization.id AND membership.user_id=principal.id
  AND membership.source_owned=TRUE
  AND organization.identity_source_id=$2 AND principal.identity_source_id=$2
  AND NOT EXISTS (
      SELECT 1 FROM directory_sync_stage_memberships staged
      WHERE staged.sync_job_id=$1 AND staged.organization_external_id=organization.external_id
        AND staged.user_external_subject=principal.external_subject
  )`, job.ID, job.IdentitySourceID); err != nil {
		return fmt.Errorf("clean missing directory memberships: %w", err)
	}
	job.Status = DirectorySyncStatusCompleted
	job.CompletedAt = now
	job.UpdatedAt = now
	if _, err := tx.Exec(ctx, `
UPDATE directory_sync_jobs SET status='completed', completed_at=$2, updated_at=$2 WHERE id=$1`, job.ID, now); err != nil {
		return fmt.Errorf("complete directory synchronization apply: %w", err)
	}
	if err := executor.appendCompletionAudit(ctx, tx, *job); err != nil {
		return err
	}
	return executor.deleteStages(ctx, tx, job.ID)
}

func (executor *PostgresDirectorySyncExecutor) appendCompletionAudit(ctx context.Context, tx pgx.Tx, job DirectorySyncJob) error {
	_, err := executor.auditor.Append(ctx, tx, audit.AppendCommand{
		Actor: directorySyncWorkerPrincipal(), Action: "identity.directory_sync." + string(job.Mode) + ".complete",
		ResourceType: "directory_sync_job", ResourceID: job.ID.String(), Outcome: audit.OutcomeSuccess,
		RequestID: job.RequestID.String(), Metadata: map[string]any{
			"identity_source_id": job.IdentitySourceID.String(), "requested_by": job.RequestedBy, "source_version": job.SourceVersion,
			"create_count": job.CreateCount, "update_count": job.UpdateCount, "disable_count": job.DisableCount, "conflict_count": job.ConflictCount,
		},
	})
	return err
}

func (executor *PostgresDirectorySyncExecutor) deleteStages(ctx context.Context, tx pgx.Tx, jobID uuid.UUID) error {
	statements := []string{
		`DELETE FROM directory_sync_stage_parents WHERE sync_job_id=$1`,
		`DELETE FROM directory_sync_stage_memberships WHERE sync_job_id=$1`,
		`DELETE FROM directory_sync_stage_organizations WHERE sync_job_id=$1`,
		`DELETE FROM directory_sync_stage_users WHERE sync_job_id=$1`,
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement, jobID); err != nil {
			return fmt.Errorf("delete completed directory synchronization stage: %w", err)
		}
	}
	return nil
}

func (executor *PostgresDirectorySyncExecutor) discoverConflicts(ctx context.Context, tx pgx.Tx, job DirectorySyncJob) error {
	if err := executor.discoverDuplicateConflicts(ctx, tx, job); err != nil {
		return err
	}
	if err := executor.discoverUserMappingConflicts(ctx, tx, job); err != nil {
		return err
	}
	if err := executor.discoverOrganizationConflicts(ctx, tx, job); err != nil {
		return err
	}
	return executor.discoverMembershipConflicts(ctx, tx, job)
}

func (executor *PostgresDirectorySyncExecutor) discoverDuplicateConflicts(ctx context.Context, tx pgx.Tx, job DirectorySyncJob) error {
	rows, err := tx.Query(ctx, `
SELECT 'user', external_subject, occurrence_count FROM directory_sync_stage_users WHERE sync_job_id=$1 AND occurrence_count > 1
UNION ALL
SELECT 'organization', external_id, occurrence_count FROM directory_sync_stage_organizations WHERE sync_job_id=$1 AND occurrence_count > 1`, job.ID)
	if err != nil {
		return err
	}
	type duplicateConflict struct {
		objectType, externalID string
		count                  int
	}
	conflicts := make([]duplicateConflict, 0)
	for rows.Next() {
		var conflict duplicateConflict
		if err := rows.Scan(&conflict.objectType, &conflict.externalID, &conflict.count); err != nil {
			rows.Close()
			return err
		}
		conflicts = append(conflicts, conflict)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, conflict := range conflicts {
		if err := executor.insertConflict(ctx, tx, job, conflict.objectType, conflict.externalID, "DUPLICATE_STABLE_SUBJECT", "stable_id", conflict.count); err != nil {
			return err
		}
	}
	return nil
}

func (executor *PostgresDirectorySyncExecutor) discoverUserMappingConflicts(ctx context.Context, tx pgx.Tx, job DirectorySyncJob) error {
	rows, err := tx.Query(ctx, `
SELECT staged.external_subject,
       EXISTS (
           SELECT 1 FROM directory_sync_stage_users other
           WHERE other.sync_job_id=staged.sync_job_id AND other.external_subject<>staged.external_subject
             AND other.email<>'' AND lower(other.email)=lower(staged.email)
       ) OR EXISTS (
           SELECT 1 FROM user_principals principal
           WHERE staged.email<>'' AND lower(principal.email)=lower(staged.email)
             AND NOT (principal.identity_source_id=$2 AND principal.external_subject=staged.external_subject)
       ) AS ambiguous_email,
       EXISTS (
           SELECT 1 FROM user_principals principal
           WHERE lower(principal.username)=lower(staged.username)
             AND NOT (principal.identity_source_id=$2 AND principal.external_subject=staged.external_subject)
       ) OR EXISTS (
           SELECT 1 FROM directory_sync_stage_users other
           WHERE other.sync_job_id=staged.sync_job_id AND other.external_subject<>staged.external_subject
             AND lower(other.username)=lower(staged.username)
       ) AS username_conflict,
       EXISTS (
           SELECT 1 FROM directory_sync_stage_organizations organization
           WHERE organization.sync_job_id=staged.sync_job_id AND organization.external_id=staged.external_subject
       ) AS cross_type_duplicate
FROM directory_sync_stage_users staged WHERE staged.sync_job_id=$1`, job.ID, job.IdentitySourceID)
	if err != nil {
		return err
	}
	type userMappingConflict struct {
		externalID                                  string
		ambiguousEmail, usernameConflict, crossType bool
	}
	conflicts := make([]userMappingConflict, 0)
	for rows.Next() {
		var conflict userMappingConflict
		if err := rows.Scan(&conflict.externalID, &conflict.ambiguousEmail, &conflict.usernameConflict, &conflict.crossType); err != nil {
			rows.Close()
			return err
		}
		conflicts = append(conflicts, conflict)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, conflict := range conflicts {
		if conflict.ambiguousEmail {
			if err := executor.insertConflict(ctx, tx, job, "user", conflict.externalID, "AMBIGUOUS_EMAIL", "email", 2); err != nil {
				return err
			}
		}
		if conflict.usernameConflict {
			if err := executor.insertConflict(ctx, tx, job, "user", conflict.externalID, "CANONICAL_USERNAME_CONFLICT", "username", 1); err != nil {
				return err
			}
		}
		if conflict.crossType {
			if err := executor.insertConflict(ctx, tx, job, "user", conflict.externalID, "DUPLICATE_STABLE_SUBJECT", "object_type", 2); err != nil {
				return err
			}
			if err := executor.insertConflict(ctx, tx, job, "organization", conflict.externalID, "DUPLICATE_STABLE_SUBJECT", "object_type", 2); err != nil {
				return err
			}
		}
	}
	return nil
}

func (executor *PostgresDirectorySyncExecutor) discoverOrganizationConflicts(ctx context.Context, tx pgx.Tx, job DirectorySyncJob) error {
	rows, err := tx.Query(ctx, `
SELECT relation.organization_external_id,
       count(DISTINCT relation.parent_external_id),
       bool_or(child.external_id IS NULL OR parent.external_id IS NULL)
FROM directory_sync_stage_parents relation
LEFT JOIN directory_sync_stage_organizations child ON child.sync_job_id=relation.sync_job_id AND child.external_id=relation.organization_external_id
LEFT JOIN directory_sync_stage_organizations parent ON parent.sync_job_id=relation.sync_job_id AND parent.external_id=relation.parent_external_id
WHERE relation.sync_job_id=$1
GROUP BY relation.organization_external_id`, job.ID)
	if err != nil {
		return err
	}
	type organizationRelationConflict struct {
		externalID  string
		parentCount int
		missing     bool
	}
	relationConflicts := make([]organizationRelationConflict, 0)
	for rows.Next() {
		var conflict organizationRelationConflict
		if err := rows.Scan(&conflict.externalID, &conflict.parentCount, &conflict.missing); err != nil {
			rows.Close()
			return err
		}
		relationConflicts = append(relationConflicts, conflict)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, conflict := range relationConflicts {
		if conflict.parentCount > 1 {
			if err := executor.insertConflict(ctx, tx, job, "organization", conflict.externalID, "MULTIPLE_ORGANIZATION_PARENTS", "parent_external_id", conflict.parentCount); err != nil {
				return err
			}
		}
		if conflict.missing {
			if err := executor.insertConflict(ctx, tx, job, "organization", conflict.externalID, "MISSING_ORGANIZATION_PARENT", "parent_external_id", 1); err != nil {
				return err
			}
		}
	}
	parentRows, err := tx.Query(ctx, `SELECT organization_external_id, parent_external_id FROM directory_sync_stage_parents WHERE sync_job_id=$1`, job.ID)
	if err != nil {
		return err
	}
	parents := make(map[string][]string)
	for parentRows.Next() {
		var child, parent string
		if err := parentRows.Scan(&child, &parent); err != nil {
			parentRows.Close()
			return err
		}
		parents[child] = append(parents[child], parent)
	}
	if err := parentRows.Err(); err != nil {
		parentRows.Close()
		return err
	}
	parentRows.Close()
	cycleMembers := directoryOrganizationCycleMembers(parents)
	for _, externalID := range cycleMembers {
		if err := executor.insertConflict(ctx, tx, job, "organization", externalID, "ORGANIZATION_CYCLE", "parent_external_id", len(cycleMembers)); err != nil {
			return err
		}
	}
	return executor.propagateOrganizationParentConflicts(ctx, tx, job, parents)
}

func (executor *PostgresDirectorySyncExecutor) propagateOrganizationParentConflicts(ctx context.Context, tx pgx.Tx, job DirectorySyncJob, parents map[string][]string) error {
	rows, err := tx.Query(ctx, `
SELECT DISTINCT external_id FROM directory_sync_conflicts
WHERE sync_job_id=$1 AND object_type='organization'`, job.ID)
	if err != nil {
		return err
	}
	unsafe := make(map[string]struct{})
	queue := make([]string, 0)
	for rows.Next() {
		var externalID string
		if err := rows.Scan(&externalID); err != nil {
			rows.Close()
			return err
		}
		unsafe[externalID] = struct{}{}
		queue = append(queue, externalID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	children := make(map[string][]string, len(parents))
	for child, parentIDs := range parents {
		for _, parent := range parentIDs {
			children[parent] = append(children[parent], child)
		}
	}
	propagated := make([]string, 0)
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		for _, child := range children[parent] {
			if _, found := unsafe[child]; found {
				continue
			}
			unsafe[child] = struct{}{}
			queue = append(queue, child)
			propagated = append(propagated, child)
		}
	}
	sort.Strings(propagated)
	for _, externalID := range propagated {
		if err := executor.insertConflict(ctx, tx, job, "organization", externalID, "CONFLICTING_ORGANIZATION_PARENT", "parent_external_id", 1); err != nil {
			return err
		}
	}
	return nil
}

func (executor *PostgresDirectorySyncExecutor) discoverMembershipConflicts(ctx context.Context, tx pgx.Tx, job DirectorySyncJob) error {
	rows, err := tx.Query(ctx, `
SELECT membership.organization_external_id, membership.user_external_subject
FROM directory_sync_stage_memberships membership
LEFT JOIN directory_sync_stage_organizations organization
  ON organization.sync_job_id=membership.sync_job_id AND organization.external_id=membership.organization_external_id
LEFT JOIN directory_sync_stage_users principal
  ON principal.sync_job_id=membership.sync_job_id AND principal.external_subject=membership.user_external_subject
WHERE membership.sync_job_id=$1 AND (
    organization.external_id IS NULL OR principal.external_subject IS NULL
    OR EXISTS (
        SELECT 1 FROM directory_sync_conflicts conflict
        WHERE conflict.sync_job_id=membership.sync_job_id
          AND ((conflict.object_type='organization' AND conflict.external_id=membership.organization_external_id)
            OR (conflict.object_type='user' AND conflict.external_id=membership.user_external_subject))
    )
)`, job.ID)
	if err != nil {
		return err
	}
	type missingMembership struct{ organizationID, userID string }
	missingMemberships := make([]missingMembership, 0)
	for rows.Next() {
		var membership missingMembership
		if err := rows.Scan(&membership.organizationID, &membership.userID); err != nil {
			rows.Close()
			return err
		}
		missingMemberships = append(missingMemberships, membership)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, membership := range missingMemberships {
		externalID := membership.organizationID + ":" + membership.userID
		if len(externalID) > 512 {
			digest := sha256.Sum256([]byte(externalID))
			externalID = "sha256:" + hex.EncodeToString(digest[:])
		}
		if err := executor.insertConflict(ctx, tx, job, "membership", externalID, "MISSING_MEMBERSHIP_SUBJECT", "stable_id", 1); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
UPDATE directory_sync_stage_memberships SET processed=TRUE
WHERE sync_job_id=$1 AND organization_external_id=$2 AND user_external_subject=$3`, job.ID, membership.organizationID, membership.userID); err != nil {
			return err
		}
	}
	return nil
}

func directoryOrganizationCycleMembers(parents map[string][]string) []string {
	state := make(map[string]int, len(parents))
	stack := make([]string, 0, len(parents))
	cycle := make(map[string]struct{})
	var visit func(string)
	visit = func(node string) {
		if state[node] == 2 {
			return
		}
		if state[node] == 1 {
			for index := len(stack) - 1; index >= 0; index-- {
				cycle[stack[index]] = struct{}{}
				if stack[index] == node {
					break
				}
			}
			return
		}
		state[node] = 1
		stack = append(stack, node)
		for _, parent := range parents[node] {
			visit(parent)
		}
		stack = stack[:len(stack)-1]
		state[node] = 2
	}
	keys := make([]string, 0, len(parents))
	for node := range parents {
		keys = append(keys, node)
	}
	sort.Strings(keys)
	for _, node := range keys {
		visit(node)
	}
	result := make([]string, 0, len(cycle))
	for node := range cycle {
		result = append(result, node)
	}
	sort.Strings(result)
	return result
}

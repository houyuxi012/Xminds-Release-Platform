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

type directoryMembershipIdentity struct {
	organizationID uuid.UUID
	userID         uuid.UUID
}

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
       AND NOT EXISTS (SELECT 1 FROM organization_memberships membership WHERE membership.organization_id=organization.id AND membership.user_id=principal.id AND membership.source_owned=TRUE AND membership.status='active')),
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
	if err := executor.deleteStages(ctx, tx, job.ID); err != nil {
		return err
	}
	return executor.appendCompletionAudit(ctx, tx, *job)
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
		phase := job.Phase
		job.Phase = DirectorySyncPhaseOrganizations
		job.UpdatedAt = executor.now()
		if _, err := tx.Exec(ctx, `UPDATE directory_sync_jobs SET phase='apply_organizations', updated_at=$2 WHERE id=$1`, job.ID, job.UpdatedAt); err != nil {
			return err
		}
		return executor.appendDirectoryBatchAudit(ctx, tx, *job, phase, 0, job.ProcessedUsers, true)
	}
	mappingCandidates := make([]principalMappingCandidate, 0, len(staged))
	for _, stagedUser := range staged {
		mappingCandidates = append(mappingCandidates, principalMappingCandidate{username: stagedUser.username, email: stagedUser.email})
	}
	if err := lockPrincipalMappingCandidates(ctx, tx, mappingCandidates); err != nil {
		return err
	}
	now := executor.now()
	for _, stagedUser := range staged {
		mappingConflicts, err := directoryUserMappingConflictsUnderLock(ctx, tx, job.IdentitySourceID, stagedUser.externalSubject, stagedUser.username, stagedUser.email)
		if err != nil {
			return err
		}
		if mappingConflicts.ambiguousEmail {
			if err := executor.insertConflict(ctx, tx, *job, "user", stagedUser.externalSubject, "AMBIGUOUS_EMAIL", "email", 2); err != nil {
				return err
			}
		}
		if mappingConflicts.usernameConflict {
			if err := executor.insertConflict(ctx, tx, *job, "user", stagedUser.externalSubject, "CANONICAL_USERNAME_CONFLICT", "username", 1); err != nil {
				return err
			}
		}
		if mappingConflicts.ambiguousEmail || mappingConflicts.usernameConflict {
			if _, err := tx.Exec(ctx, `UPDATE directory_sync_stage_users SET processed=TRUE WHERE sync_job_id=$1 AND external_subject=$2`, job.ID, stagedUser.externalSubject); err != nil {
				return fmt.Errorf("mark conflicting directory user processed: %w", err)
			}
			continue
		}
		var existingID uuid.UUID
		var existingStatus UserStatus
		var existingVersion int64
		err = tx.QueryRow(ctx, `
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
	if err = tx.QueryRow(ctx, `
UPDATE directory_sync_jobs
SET processed_users=$2,
    conflict_count=(SELECT count(*) FROM directory_sync_conflicts WHERE sync_job_id=$1),
    updated_at=$3
WHERE id=$1
RETURNING conflict_count`, job.ID, job.ProcessedUsers, now).Scan(&job.ConflictCount); err != nil {
		return err
	}
	return executor.appendDirectoryBatchAudit(ctx, tx, *job, DirectorySyncPhaseUsers, len(staged), job.ProcessedUsers, false)
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
		if _, err := tx.Exec(ctx, `UPDATE directory_sync_jobs SET phase='apply_memberships', updated_at=$2 WHERE id=$1`, job.ID, now); err != nil {
			return err
		}
		return executor.appendDirectoryBatchAudit(ctx, tx, *job, DirectorySyncPhaseOrganizations, 0, job.ProcessedOrganizations, true)
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
	if _, err = tx.Exec(ctx, `UPDATE directory_sync_jobs SET processed_organizations=$2, updated_at=$3 WHERE id=$1`, job.ID, job.ProcessedOrganizations, now); err != nil {
		return err
	}
	return executor.appendDirectoryBatchAudit(ctx, tx, *job, DirectorySyncPhaseOrganizations, len(staged), job.ProcessedOrganizations, false)
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
		phase := job.Phase
		job.Phase = DirectorySyncPhaseFinalize
		job.UpdatedAt = now
		if _, err := tx.Exec(ctx, `UPDATE directory_sync_jobs SET phase='finalize', updated_at=$2 WHERE id=$1`, job.ID, now); err != nil {
			return err
		}
		return executor.appendDirectoryBatchAudit(ctx, tx, *job, phase, 0, job.ProcessedMemberships, true)
	}
	type resolvedMembership struct {
		stagedMembership
		directoryMembershipIdentity
	}
	resolved := make([]resolvedMembership, 0, len(staged))
	for _, stagedMembership := range staged {
		var item resolvedMembership
		item.stagedMembership = stagedMembership
		if err := tx.QueryRow(ctx, `SELECT organization.id,principal.id FROM organization_units organization,user_principals principal WHERE organization.identity_source_id=$1 AND organization.external_id=$2 AND principal.identity_source_id=$1 AND principal.external_subject=$3`, job.IdentitySourceID, stagedMembership.organizationExternalID, stagedMembership.userExternalSubject).Scan(&item.organizationID, &item.userID); err != nil {
			return fmt.Errorf("resolve directory membership subjects: %w", err)
		}
		resolved = append(resolved, item)
	}
	sort.Slice(resolved, func(left, right int) bool {
		if resolved[left].organizationID != resolved[right].organizationID {
			return resolved[left].organizationID.String() < resolved[right].organizationID.String()
		}
		return resolved[left].userID.String() < resolved[right].userID.String()
	})
	organizationIDs := make([]uuid.UUID, 0, len(resolved))
	userIDs := make([]uuid.UUID, 0, len(resolved))
	for _, membership := range resolved {
		organizationIDs = append(organizationIDs, membership.organizationID)
		userIDs = append(userIDs, membership.userID)
	}
	lockedOrganizations := make(map[uuid.UUID]OrganizationUnit, len(organizationIDs))
	for _, organizationID := range sortedUniqueUUIDs(organizationIDs) {
		organization, err := executor.repository.GetOrganization(ctx, tx, organizationID)
		if err != nil {
			return err
		}
		lockedOrganizations[organizationID] = organization
	}
	for _, userID := range sortedUniqueUUIDs(userIDs) {
		if _, err := executor.repository.GetUser(ctx, tx, userID); err != nil {
			return err
		}
	}
	lockedMemberships := make(map[directoryMembershipIdentity]OrganizationMembership, len(resolved))
	membershipExists := make(map[directoryMembershipIdentity]bool, len(resolved))
	for _, resolvedMembership := range resolved {
		identity := resolvedMembership.directoryMembershipIdentity
		membership, err := executor.repository.GetOrganizationMembership(ctx, tx, identity.organizationID, identity.userID, true)
		if errors.Is(err, ErrOrganizationMembershipNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		lockedMemberships[identity] = membership
		membershipExists[identity] = true
	}
	changedUsers := make(map[uuid.UUID]struct{}, len(resolved))
	for _, resolvedMembership := range resolved {
		identity := resolvedMembership.directoryMembershipIdentity
		organization := lockedOrganizations[identity.organizationID]
		membership := lockedMemberships[identity]
		membershipChanged := false
		switch {
		case !membershipExists[identity]:
			if _, err := tx.Exec(ctx, `INSERT INTO organization_memberships (organization_id,user_id,source_owned,status,version,created_at,updated_at) VALUES ($1,$2,TRUE,'active',1,$3,$3)`, resolvedMembership.organizationID, resolvedMembership.userID, now); err != nil {
				return fmt.Errorf("insert source-owned directory membership: %w", err)
			}
			membershipChanged = true
		case membership.Status == OrganizationMembershipStatusRemoved:
			result, err := tx.Exec(ctx, `UPDATE organization_memberships SET status='active',version=version+1,updated_at=$3 WHERE organization_id=$1 AND user_id=$2 AND source_owned=TRUE AND status='removed' AND version=$4`, resolvedMembership.organizationID, resolvedMembership.userID, now, membership.Version)
			if err != nil {
				return fmt.Errorf("reactivate source-owned directory membership: %w", err)
			}
			if result.RowsAffected() != 1 {
				return ErrIAMConflict
			}
			membershipChanged = true
		case membership.Status != OrganizationMembershipStatusActive:
			return ErrDirectorySyncConfiguration
		}
		if membershipChanged {
			previousOrganizationVersion := organization.Version
			organization.Version++
			organization.UpdatedAt = now
			if err := executor.repository.SaveOrganization(ctx, tx, organization, previousOrganizationVersion); err != nil {
				return err
			}
			lockedOrganizations[identity.organizationID] = organization
			changedUsers[resolvedMembership.userID] = struct{}{}
		}
		if _, err := tx.Exec(ctx, `
UPDATE directory_sync_stage_memberships SET processed=TRUE
WHERE sync_job_id=$1 AND organization_external_id=$2 AND user_external_subject=$3`,
			job.ID, resolvedMembership.organizationExternalID, resolvedMembership.userExternalSubject); err != nil {
			return fmt.Errorf("mark directory membership processed: %w", err)
		}
	}
	if len(changedUsers) > 0 {
		if err := executor.requireBreakGlassContinuity(ctx, tx, now); err != nil {
			return err
		}
		userIDs := make([]uuid.UUID, 0, len(changedUsers))
		for userID := range changedUsers {
			userIDs = append(userIDs, userID)
		}
		sort.Slice(userIDs, func(left, right int) bool { return userIDs[left].String() < userIDs[right].String() })
		for _, userID := range userIDs {
			if err := executor.sessions.RevokeSubject(ctx, tx, userID, "directory membership changed"); err != nil {
				return err
			}
		}
	}
	job.ProcessedMemberships += len(staged)
	job.UpdatedAt = now
	if _, err = tx.Exec(ctx, `UPDATE directory_sync_jobs SET processed_memberships=$2, updated_at=$3 WHERE id=$1`, job.ID, job.ProcessedMemberships, now); err != nil {
		return err
	}
	return executor.appendDirectoryBatchAudit(ctx, tx, *job, DirectorySyncPhaseMemberships, len(staged), job.ProcessedMemberships, false)
}

func (executor *PostgresDirectorySyncExecutor) finalizeApply(ctx context.Context, tx pgx.Tx, job *DirectorySyncJob) error {
	now := executor.now()
	disabledUsers, err := queryDirectoryUUIDs(ctx, tx, `
SELECT principal.id FROM user_principals principal
WHERE principal.identity_source_id=$2 AND principal.status <> 'disabled'
  AND principal.last_directory_run_id IS DISTINCT FROM $3
  AND NOT EXISTS (
      SELECT 1 FROM directory_sync_stage_users staged
      WHERE staged.sync_job_id=$1 AND staged.external_subject=principal.external_subject
  ) ORDER BY principal.id`, job.ID, job.IdentitySourceID, job.RunMarker)
	if err != nil {
		return fmt.Errorf("list missing directory users: %w", err)
	}
	disabledOrganizations, err := queryDirectoryUUIDs(ctx, tx, `
SELECT organization.id FROM organization_units organization
WHERE organization.identity_source_id=$2 AND organization.status <> 'disabled'
  AND organization.last_directory_run_id IS DISTINCT FROM $3
  AND NOT EXISTS (
      SELECT 1 FROM directory_sync_stage_organizations staged
      WHERE staged.sync_job_id=$1 AND staged.external_id=organization.external_id
  ) ORDER BY organization.id`, job.ID, job.IdentitySourceID, job.RunMarker)
	if err != nil {
		return fmt.Errorf("list missing directory organizations: %w", err)
	}
	missingMembershipRows, err := tx.Query(ctx, `
SELECT membership.organization_id,membership.user_id
FROM organization_memberships membership
JOIN organization_units organization ON organization.id=membership.organization_id
JOIN user_principals principal ON principal.id=membership.user_id
WHERE membership.source_owned=TRUE AND membership.status='active'
  AND organization.identity_source_id=$2 AND principal.identity_source_id=$2
  AND NOT EXISTS (
      SELECT 1 FROM directory_sync_stage_memberships staged
      WHERE staged.sync_job_id=$1 AND staged.organization_external_id=organization.external_id
        AND staged.user_external_subject=principal.external_subject
  )
ORDER BY membership.organization_id,membership.user_id`, job.ID, job.IdentitySourceID)
	if err != nil {
		return fmt.Errorf("list missing directory memberships: %w", err)
	}
	missingMemberships := make([]directoryMembershipIdentity, 0)
	for missingMembershipRows.Next() {
		var identity directoryMembershipIdentity
		if err := missingMembershipRows.Scan(&identity.organizationID, &identity.userID); err != nil {
			missingMembershipRows.Close()
			return err
		}
		missingMemberships = append(missingMemberships, identity)
	}
	if err := missingMembershipRows.Err(); err != nil {
		missingMembershipRows.Close()
		return err
	}
	missingMembershipRows.Close()
	organizationIDs := append([]uuid.UUID(nil), disabledOrganizations...)
	userIDs := append([]uuid.UUID(nil), disabledUsers...)
	for _, membership := range missingMemberships {
		organizationIDs = append(organizationIDs, membership.organizationID)
		userIDs = append(userIDs, membership.userID)
	}
	organizationIDs = sortedUniqueUUIDs(organizationIDs)
	userIDs = sortedUniqueUUIDs(userIDs)
	lockedOrganizations := make(map[uuid.UUID]OrganizationUnit, len(organizationIDs))
	for _, organizationID := range organizationIDs {
		organization, err := executor.repository.GetOrganization(ctx, tx, organizationID)
		if err != nil {
			return err
		}
		lockedOrganizations[organizationID] = organization
	}
	lockedUsers := make(map[uuid.UUID]UserPrincipal, len(userIDs))
	for _, userID := range userIDs {
		user, err := executor.repository.GetUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		lockedUsers[userID] = user
	}
	lockedMemberships := make(map[directoryMembershipIdentity]OrganizationMembership, len(missingMemberships))
	for _, identity := range missingMemberships {
		membership, err := executor.repository.GetOrganizationMembership(ctx, tx, identity.organizationID, identity.userID, true)
		if err != nil {
			return err
		}
		lockedMemberships[identity] = membership
	}
	for _, organizationID := range disabledOrganizations {
		organization := lockedOrganizations[organizationID]
		result, err := tx.Exec(ctx, `UPDATE organization_units SET status='disabled',version=version+1,updated_at=$2 WHERE id=$1 AND status<>'disabled' AND version=$3`, organizationID, now, organization.Version)
		if err != nil {
			return fmt.Errorf("disable missing directory organization: %w", err)
		}
		if result.RowsAffected() != 1 {
			return ErrIAMConflict
		}
		organization.Status = OrganizationStatusDisabled
		organization.Version++
		organization.UpdatedAt = now
		lockedOrganizations[organizationID] = organization
	}
	for _, userID := range disabledUsers {
		user := lockedUsers[userID]
		if user.Status == UserStatusDisabled {
			continue
		}
		previousVersion := user.Version
		user.Status = UserStatusDisabled
		user.DisabledAt = now
		user.DisabledReason = "directory snapshot missing"
		user.Version++
		user.UpdatedAt = now
		if err := executor.repository.SaveUser(ctx, tx, user, previousVersion); err != nil {
			return err
		}
		lockedUsers[userID] = user
	}
	revokedMembershipUsers := make(map[uuid.UUID]struct{}, len(missingMemberships))
	for _, identity := range missingMemberships {
		organization := lockedOrganizations[identity.organizationID]
		membership := lockedMemberships[identity]
		if membership.Status != OrganizationMembershipStatusActive {
			continue
		}
		result, err := tx.Exec(ctx, `UPDATE organization_memberships SET status='removed',version=version+1,updated_at=$3 WHERE organization_id=$1 AND user_id=$2 AND source_owned=TRUE AND status='active' AND version=$4`, identity.organizationID, identity.userID, now, membership.Version)
		if err != nil {
			return fmt.Errorf("soft-remove missing source-owned directory membership: %w", err)
		}
		if result.RowsAffected() != 1 {
			return ErrIAMConflict
		}
		previousOrganizationVersion := organization.Version
		organization.Version++
		organization.UpdatedAt = now
		if err := executor.repository.SaveOrganization(ctx, tx, organization, previousOrganizationVersion); err != nil {
			return err
		}
		lockedOrganizations[identity.organizationID] = organization
		revokedMembershipUsers[identity.userID] = struct{}{}
	}
	if len(disabledUsers) > 0 || len(disabledOrganizations) > 0 || len(revokedMembershipUsers) > 0 {
		if err := executor.requireBreakGlassContinuity(ctx, tx, now); err != nil {
			return err
		}
		revokedUsers := append([]uuid.UUID(nil), disabledUsers...)
		disabledUserSet := make(map[uuid.UUID]struct{}, len(disabledUsers))
		for _, userID := range disabledUsers {
			disabledUserSet[userID] = struct{}{}
		}
		for userID := range revokedMembershipUsers {
			revokedUsers = append(revokedUsers, userID)
		}
		for _, userID := range sortedUniqueUUIDs(revokedUsers) {
			reason := "directory membership removed"
			if _, disabled := disabledUserSet[userID]; disabled {
				reason = "directory snapshot missing"
			}
			if err := executor.sessions.RevokeSubject(ctx, tx, userID, reason); err != nil {
				return err
			}
		}
		for _, organizationID := range disabledOrganizations {
			if err := executor.sessions.RevokeOrganizationMembers(ctx, tx, organizationID, "directory organization disabled"); err != nil {
				return err
			}
		}
	}
	job.Status = DirectorySyncStatusCompleted
	job.CompletedAt = now
	job.UpdatedAt = now
	if _, err := tx.Exec(ctx, `
UPDATE directory_sync_jobs SET status='completed', completed_at=$2, updated_at=$2 WHERE id=$1`, job.ID, now); err != nil {
		return fmt.Errorf("complete directory synchronization apply: %w", err)
	}
	if err := executor.deleteStages(ctx, tx, job.ID); err != nil {
		return err
	}
	return executor.appendCompletionAudit(ctx, tx, *job)
}

func queryDirectoryUUIDs(ctx context.Context, tx pgx.Tx, query string, arguments ...any) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, query, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]uuid.UUID, 0)
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

func sortedUniqueUUIDs(values []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]struct{}, len(values))
	result := make([]uuid.UUID, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].String() < result[right].String() })
	return result
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

func (executor *PostgresDirectorySyncExecutor) appendDirectoryBatchAudit(ctx context.Context, tx pgx.Tx, job DirectorySyncJob, phase DirectorySyncPhase, batchCount, processedTotal int, phaseCompleted bool) error {
	if batchCount < 0 || processedTotal < 0 || (phase != DirectorySyncPhaseUsers && phase != DirectorySyncPhaseOrganizations && phase != DirectorySyncPhaseMemberships) {
		return ErrDirectorySyncConfiguration
	}
	_, err := executor.auditor.Append(ctx, tx, audit.AppendCommand{
		Actor: directorySyncWorkerPrincipal(), Action: directorySyncBatchAuditAction,
		ResourceType: "directory_sync_job", ResourceID: job.ID.String(), Outcome: audit.OutcomeSuccess,
		RequestID: job.RequestID.String(), Metadata: map[string]any{
			"identity_source_id": job.IdentitySourceID.String(), "source_version": job.SourceVersion,
			"mode": job.Mode, "phase": phase, "batch_count": batchCount,
			"processed_total": processedTotal, "phase_completed": phaseCompleted,
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

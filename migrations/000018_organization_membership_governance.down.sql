UPDATE iam_reauthentication_challenges
SET status='expired',version=version+1
WHERE operation IN (
    'identity.organization_membership.create',
    'identity.organization_membership.delete'
)
AND status IN ('pending','verified');

DELETE FROM iam_reauthentication_challenges
WHERE operation IN (
    'identity.organization_membership.create',
    'identity.organization_membership.delete'
);

ALTER TABLE iam_reauthentication_challenges
    DROP CONSTRAINT iam_reauthentication_challenges_operation_check,
    ADD CONSTRAINT iam_reauthentication_challenges_operation_check CHECK (operation IN (
        'identity.role_binding.create',
        'identity.role_binding.delete',
        'identity.user.disable',
        'identity.user.enable',
        'identity.user.revoke_sessions',
        'identity.sso.enable',
        'identity.sso.disable',
        'identity.directory_conflict.resolve'
    ));

DELETE FROM organization_memberships
WHERE status='removed';

DELETE FROM organization_memberships AS platform
WHERE platform.source_owned=FALSE
  AND EXISTS (
      SELECT 1
      FROM organization_memberships AS source
      WHERE source.organization_id=platform.organization_id
        AND source.user_id=platform.user_id
        AND source.source_owned=TRUE
        AND source.status='active'
  );

DROP INDEX organization_units_parent_created_idx;
DROP INDEX organization_memberships_active_user_idx;
DROP INDEX organization_memberships_active_organization_idx;

ALTER TABLE organization_memberships
    DROP CONSTRAINT organization_memberships_pkey,
    ADD PRIMARY KEY (organization_id,user_id),
    DROP CONSTRAINT organization_memberships_updated_at_check,
    DROP CONSTRAINT organization_memberships_version_check,
    DROP CONSTRAINT organization_memberships_status_check,
    DROP COLUMN updated_at,
    DROP COLUMN version,
    DROP COLUMN status;

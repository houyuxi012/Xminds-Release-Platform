ALTER TABLE organization_memberships
    DROP CONSTRAINT organization_memberships_pkey,
    ADD COLUMN status TEXT NOT NULL DEFAULT 'active',
    ADD COLUMN version BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN updated_at TIMESTAMPTZ;

UPDATE organization_memberships
SET updated_at = created_at
WHERE updated_at IS NULL;

ALTER TABLE organization_memberships
    ALTER COLUMN updated_at SET NOT NULL,
    ADD CONSTRAINT organization_memberships_status_check CHECK (
        status IS NOT NULL AND status IN ('active','removed')
    ),
    ADD CONSTRAINT organization_memberships_version_check CHECK (
        version IS NOT NULL AND version > 0
    ),
    ADD CONSTRAINT organization_memberships_updated_at_check CHECK (
        updated_at IS NOT NULL AND created_at IS NOT NULL AND updated_at >= created_at
    ),
    ADD PRIMARY KEY (organization_id,user_id,source_owned);

CREATE INDEX organization_memberships_active_organization_idx
    ON organization_memberships (organization_id,created_at DESC,user_id DESC,source_owned DESC)
    WHERE status='active';

CREATE INDEX organization_memberships_active_user_idx
    ON organization_memberships (user_id,organization_id)
    WHERE status='active';

CREATE INDEX organization_units_parent_created_idx
    ON organization_units (parent_id,created_at DESC,id DESC);

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
        'identity.directory_conflict.resolve',
        'identity.organization_membership.create',
        'identity.organization_membership.delete'
    ));

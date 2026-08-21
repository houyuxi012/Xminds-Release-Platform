-- Historical resolved rows predate an explicit, auditable decision and cannot
-- be attributed safely. Reopen them before installing the stronger invariant.
UPDATE directory_sync_conflicts
SET status = 'open',
    resolved_by = NULL,
    resolved_at = NULL
WHERE status = 'resolved';

ALTER TABLE directory_sync_conflicts
    ADD COLUMN resolution_decision TEXT,
    ADD COLUMN resolution_reason TEXT,
    ADD COLUMN version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    ADD CONSTRAINT directory_sync_conflicts_resolution_state_check CHECK (
        (
            status = 'open'
            AND resolution_decision IS NULL
            AND resolution_reason IS NULL
            AND resolved_by IS NULL
            AND resolved_at IS NULL
        )
        OR
        (
            status = 'resolved'
            AND resolution_decision IS NOT NULL
            AND resolution_decision = 'keep_last_safe'
            AND resolution_reason IS NOT NULL
            AND char_length(resolution_reason) BETWEEN 8 AND 512
            AND resolution_reason = btrim(resolution_reason)
            AND resolved_by IS NOT NULL
            AND resolved_by ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
            AND resolved_at IS NOT NULL
        )
    );

CREATE INDEX directory_sync_conflicts_source_status_created_idx
    ON directory_sync_conflicts (identity_source_id, status, created_at DESC, id DESC);

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

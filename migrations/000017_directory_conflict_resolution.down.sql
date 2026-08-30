-- A v16 runtime cannot consume or reason about this operation. Expire active
-- proofs first, then remove all terminal verifier summaries for the operation.
UPDATE iam_reauthentication_challenges
SET status = 'expired', version = version + 1
WHERE operation = 'identity.directory_conflict.resolve'
  AND status IN ('pending', 'verified');

DELETE FROM iam_reauthentication_challenges
WHERE operation = 'identity.directory_conflict.resolve';

ALTER TABLE iam_reauthentication_challenges
    DROP CONSTRAINT iam_reauthentication_challenges_operation_check,
    ADD CONSTRAINT iam_reauthentication_challenges_operation_check CHECK (operation IN (
        'identity.role_binding.create',
        'identity.role_binding.delete',
        'identity.user.disable',
        'identity.user.enable',
        'identity.user.revoke_sessions',
        'identity.sso.enable',
        'identity.sso.disable'
    ));

-- Preserve the only state understood by v16; no v16 route can represent the
-- explicit decision or its reason.
UPDATE directory_sync_conflicts
SET status = 'open',
    resolution_decision = NULL,
    resolution_reason = NULL,
    resolved_by = NULL,
    resolved_at = NULL
WHERE status = 'resolved';

DROP INDEX directory_sync_conflicts_source_status_created_idx;

ALTER TABLE directory_sync_conflicts
    DROP CONSTRAINT directory_sync_conflicts_resolution_state_check,
    DROP COLUMN version,
    DROP COLUMN resolution_reason,
    DROP COLUMN resolution_decision;

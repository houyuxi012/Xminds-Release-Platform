-- A v15 runtime cannot enforce the governed-user/source binding. Expire every
-- active v16 proof before removing the columns so rollback remains fail closed.
UPDATE iam_reauthentication_challenges
SET status = 'expired', version = version + 1
WHERE status IN ('pending', 'verified');

ALTER TABLE iam_reauthentication_challenges
    DROP CONSTRAINT iam_reauthentication_challenges_active_actor_binding_check,
    DROP CONSTRAINT iam_reauthentication_challenges_actor_binding_format_check,
    DROP COLUMN actor_binding_digest,
    DROP COLUMN actor_binding_version;

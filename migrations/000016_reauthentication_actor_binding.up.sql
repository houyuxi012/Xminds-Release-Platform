ALTER TABLE iam_reauthentication_challenges
    ADD COLUMN actor_binding_version SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN actor_binding_digest CHAR(64);

-- Legacy challenges cannot be bound safely to an internal governed user from
-- actor_subject alone. Fail closed instead of guessing an identity mapping.
UPDATE iam_reauthentication_challenges
SET status = 'expired', version = version + 1
WHERE status IN ('pending', 'verified');

ALTER TABLE iam_reauthentication_challenges
    ADD CONSTRAINT iam_reauthentication_challenges_actor_binding_format_check CHECK (
        (actor_binding_version = 0 AND actor_binding_digest IS NULL)
        OR
        (actor_binding_version = 1 AND actor_binding_digest ~ '^[0-9a-f]{64}$')
    ),
    ADD CONSTRAINT iam_reauthentication_challenges_active_actor_binding_check CHECK (
        status NOT IN ('pending', 'verified') OR actor_binding_version = 1
    );

CREATE TABLE iam_reauthentication_challenges (
    id UUID PRIMARY KEY CHECK ((get_byte(uuid_send(id), 6) >> 4) = 7),
    actor_subject TEXT NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 512),
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('human', 'local')),
    created_token_digest CHAR(64) NOT NULL CHECK (created_token_digest ~ '^[0-9a-f]{64}$'),
    operation TEXT NOT NULL CHECK (operation IN (
        'identity.role_binding.create',
        'identity.role_binding.delete',
        'identity.user.disable',
        'identity.user.enable',
        'identity.user.revoke_sessions',
        'identity.sso.enable',
        'identity.sso.disable'
    )),
    status TEXT NOT NULL CHECK (status IN ('pending', 'verified', 'consumed', 'expired')),
    verified_token_digest CHAR(64) CHECK (verified_token_digest IS NULL OR verified_token_digest ~ '^[0-9a-f]{64}$'),
    evidence_digest CHAR(64) CHECK (evidence_digest IS NULL OR evidence_digest ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ,
    challenge_expires_at TIMESTAMPTZ NOT NULL,
    evidence_expires_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    created_request_id UUID NOT NULL,
    completed_request_id UUID,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    CHECK (challenge_expires_at > created_at),
    CHECK (verified_at IS NULL OR verified_at >= created_at),
    CHECK (evidence_expires_at IS NULL OR (verified_at IS NOT NULL AND evidence_expires_at > verified_at AND evidence_expires_at <= challenge_expires_at)),
    CHECK (consumed_at IS NULL OR (verified_at IS NOT NULL AND consumed_at >= verified_at)),
    CHECK (
        (status = 'pending' AND verified_token_digest IS NULL AND evidence_digest IS NULL AND verified_at IS NULL AND evidence_expires_at IS NULL AND consumed_at IS NULL AND completed_request_id IS NULL)
        OR
        (status = 'verified' AND verified_token_digest IS NOT NULL AND evidence_digest IS NOT NULL AND verified_at IS NOT NULL AND evidence_expires_at IS NOT NULL AND consumed_at IS NULL AND completed_request_id IS NOT NULL)
        OR
        (status = 'consumed' AND verified_token_digest IS NOT NULL AND evidence_digest IS NOT NULL AND verified_at IS NOT NULL AND evidence_expires_at IS NOT NULL AND consumed_at IS NOT NULL AND completed_request_id IS NOT NULL)
        OR status = 'expired'
    )
);

CREATE INDEX iam_reauthentication_challenges_active_expiry_idx
    ON iam_reauthentication_challenges (challenge_expires_at, evidence_expires_at)
    WHERE status IN ('pending', 'verified');

CREATE INDEX iam_reauthentication_challenges_actor_idx
    ON iam_reauthentication_challenges (actor_subject, actor_kind, created_at DESC);

REVOKE DELETE, TRUNCATE ON iam_reauthentication_challenges FROM PUBLIC;

CREATE TABLE iam_mfa_enrollments (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES user_principals(id) ON DELETE RESTRICT,
    purpose TEXT NOT NULL CHECK (purpose IN ('activation', 'rotation')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'confirmed', 'expired')),
    secret_reference TEXT NOT NULL,
    created_by_user_id UUID REFERENCES user_principals(id) ON DELETE RESTRICT,
    creator_binding_version SMALLINT,
    creator_binding_digest BYTEA,
    expected_user_version BIGINT NOT NULL CHECK (expected_user_version > 0),
    expires_at TIMESTAMPTZ NOT NULL,
    confirmed_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (substring(id::text FROM 15 FOR 1) = '7'),
    CHECK (secret_reference = 'secret://iam-mfa/mfa-' || id::text || '.totp'),
    CHECK (
        (
            purpose = 'activation'
            AND created_by_user_id IS NULL
            AND creator_binding_version IS NULL
            AND creator_binding_digest IS NULL
        )
        OR (
            purpose = 'rotation'
            AND created_by_user_id IS NOT NULL
            AND creator_binding_version IS NOT NULL
            AND creator_binding_version = 1
            AND creator_binding_digest IS NOT NULL
            AND octet_length(creator_binding_digest) = 32
        )
    ),
    CHECK (expires_at > created_at),
    CHECK (updated_at >= created_at),
    CHECK (
        (status = 'pending' AND confirmed_at IS NULL)
        OR (status = 'expired' AND confirmed_at IS NULL)
        OR (
            status = 'confirmed'
            AND confirmed_at IS NOT NULL
            AND confirmed_at >= created_at
            AND confirmed_at < expires_at
            AND updated_at >= confirmed_at
        )
    )
);

CREATE UNIQUE INDEX iam_mfa_enrollments_user_pending_uidx
    ON iam_mfa_enrollments (user_id)
    WHERE status = 'pending';

CREATE INDEX iam_mfa_enrollments_expiry_idx
    ON iam_mfa_enrollments (expires_at, id)
    WHERE status = 'pending';

CREATE TABLE iam_mfa_secret_gc (
    secret_reference TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased')),
    not_before TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error_code TEXT NOT NULL DEFAULT ''
        CHECK (last_error_code = '' OR last_error_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    lease_token UUID,
    leased_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (secret_reference ~ '^secret://iam-mfa/mfa-[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.totp$'),
    CHECK (not_before >= created_at),
    CHECK (updated_at >= created_at),
    CHECK (
        (state = 'pending' AND lease_token IS NULL AND leased_until IS NULL)
        OR (
            state = 'leased'
            AND lease_token IS NOT NULL
            AND substring(lease_token::text FROM 15 FOR 1) = '7'
            AND leased_until IS NOT NULL
            AND leased_until > updated_at
        )
    )
);

CREATE INDEX iam_mfa_secret_gc_due_idx
    ON iam_mfa_secret_gc (state, not_before, leased_until, secret_reference);

CREATE TABLE iam_mfa_recovery_codes (
    user_id UUID NOT NULL REFERENCES user_principals(id) ON DELETE RESTRICT,
    code_digest CHAR(64) NOT NULL CHECK (code_digest ~ '^[0-9a-f]{64}$'),
    generation_id UUID NOT NULL CHECK (generation_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    created_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    PRIMARY KEY (user_id, code_digest),
    CHECK (used_at IS NULL OR (used_at IS NOT NULL AND used_at >= created_at))
);

CREATE INDEX iam_mfa_recovery_codes_generation_idx
    ON iam_mfa_recovery_codes (user_id, generation_id, created_at);

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
        'identity.organization_membership.delete',
        'mfa.enrollment.begin',
        'mfa.recovery_codes.regenerate',
        'emergency.user.create',
        'emergency.user.activation.reissue'
    ));

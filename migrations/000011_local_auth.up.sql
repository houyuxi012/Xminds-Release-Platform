ALTER TABLE local_credentials
    DROP CONSTRAINT local_credentials_algorithm_check,
    DROP CONSTRAINT local_credentials_parameters_check,
    DROP CONSTRAINT local_credentials_salt_check,
    DROP CONSTRAINT local_credentials_derived_key_check,
    ALTER COLUMN algorithm DROP NOT NULL,
    ALTER COLUMN parameters DROP NOT NULL,
    ALTER COLUMN salt DROP NOT NULL,
    ALTER COLUMN derived_key DROP NOT NULL,
    ALTER COLUMN password_changed_at DROP NOT NULL;

ALTER TABLE local_credentials
    ADD COLUMN mfa_secret_reference TEXT NOT NULL DEFAULT '' CHECK (length(mfa_secret_reference) <= 256),
    ADD COLUMN mfa_last_counter BIGINT NOT NULL DEFAULT -1 CHECK (mfa_last_counter >= -1),
    ADD CONSTRAINT local_credentials_password_material_check CHECK (
        (algorithm IS NULL AND parameters IS NULL AND salt IS NULL AND derived_key IS NULL AND password_changed_at IS NULL)
        OR
        (algorithm = 'argon2id' AND parameters IS NOT NULL AND length(parameters) BETWEEN 1 AND 128
         AND salt IS NOT NULL AND octet_length(salt) BETWEEN 16 AND 64
         AND derived_key IS NOT NULL AND octet_length(derived_key) BETWEEN 16 AND 64
         AND password_changed_at IS NOT NULL)
    );

CREATE TABLE local_auth_rate_limits (
    scope TEXT NOT NULL CHECK (scope IN ('account', 'ip')),
    key_digest CHAR(64) NOT NULL CHECK (key_digest ~ '^[0-9a-f]{64}$'),
    window_started_at TIMESTAMPTZ NOT NULL,
    attempt_count INTEGER NOT NULL CHECK (attempt_count > 0),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scope, key_digest, window_started_at),
    CHECK (expires_at > window_started_at)
);

CREATE INDEX local_auth_rate_limits_expiry_idx ON local_auth_rate_limits (expires_at);

CREATE TABLE local_sessions (
    id UUID PRIMARY KEY,
    token_digest CHAR(64) NOT NULL UNIQUE CHECK (token_digest ~ '^[0-9a-f]{64}$'),
    subject_id UUID NOT NULL REFERENCES user_principals(id) ON DELETE RESTRICT,
    authentication_method TEXT NOT NULL CHECK (authentication_method IN ('local_password', 'emergency_password')),
    mfa_level SMALLINT NOT NULL CHECK (mfa_level BETWEEN 0 AND 3),
    authenticated_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    idle_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revocation_reason TEXT NOT NULL DEFAULT '' CHECK (length(revocation_reason) <= 256),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    CHECK (last_used_at >= authenticated_at),
    CHECK (absolute_expires_at > authenticated_at),
    CHECK (idle_expires_at > authenticated_at AND idle_expires_at <= absolute_expires_at),
    CHECK ((revoked_at IS NULL) = (revocation_reason = ''))
);

CREATE INDEX local_sessions_subject_active_idx ON local_sessions (subject_id, absolute_expires_at) WHERE revoked_at IS NULL;
CREATE INDEX local_sessions_expiry_idx ON local_sessions (absolute_expires_at, idle_expires_at) WHERE revoked_at IS NULL;

REVOKE UPDATE (token_digest, subject_id, authentication_method, mfa_level, authenticated_at, absolute_expires_at)
    ON local_sessions FROM PUBLIC;

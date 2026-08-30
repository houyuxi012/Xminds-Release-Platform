CREATE TABLE identity_sources (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    source_kind TEXT NOT NULL CHECK (source_kind IN ('local', 'oidc', 'scim')),
    status TEXT NOT NULL CHECK (status IN ('draft', 'verified', 'enabled', 'fault', 'disabled')),
    secret_reference TEXT NOT NULL DEFAULT '' CHECK (length(secret_reference) <= 256),
    required_mappings_complete BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ,
    previewed_at TIMESTAMPTZ,
    fault_code TEXT NOT NULL DEFAULT '' CHECK (fault_code = '' OR fault_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (name),
    CHECK (updated_at >= created_at)
);

CREATE TABLE iam_login_state (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    login_mode TEXT NOT NULL CHECK (login_mode IN ('local', 'configuring', 'sso', 'fault')),
    active_source_id UUID REFERENCES identity_sources(id) ON DELETE RESTRICT,
    fault_code TEXT NOT NULL DEFAULT '' CHECK (fault_code = '' OR fault_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK ((login_mode IN ('sso', 'fault')) = (active_source_id IS NOT NULL)),
    CHECK ((login_mode = 'fault') = (fault_code <> ''))
);

INSERT INTO iam_login_state (singleton, login_mode, version, updated_by, updated_at)
VALUES (TRUE, 'local', 1, 'system:bootstrap', clock_timestamp());

CREATE TABLE user_principals (
    id UUID PRIMARY KEY,
    identity_source_id UUID REFERENCES identity_sources(id) ON DELETE RESTRICT,
    external_subject TEXT NOT NULL DEFAULT '' CHECK (length(external_subject) <= 512),
    username TEXT NOT NULL CHECK (length(username) BETWEEN 1 AND 128),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    email TEXT NOT NULL DEFAULT '' CHECK (length(email) <= 320),
    user_kind TEXT NOT NULL CHECK (user_kind IN ('external', 'local', 'emergency')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'disabled', 'locked')),
    mfa_enrolled BOOLEAN NOT NULL DEFAULT FALSE,
    credential_rotated_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    disabled_at TIMESTAMPTZ,
    disabled_reason TEXT NOT NULL DEFAULT '' CHECK (length(disabled_reason) <= 512),
    CHECK ((user_kind = 'external') = (identity_source_id IS NOT NULL)),
    CHECK ((user_kind = 'external') = (external_subject <> '')),
    CHECK ((status = 'disabled') = (disabled_at IS NOT NULL)),
    CHECK (updated_at >= created_at),
    UNIQUE (identity_source_id, external_subject)
);

CREATE UNIQUE INDEX user_principals_username_canonical_uidx ON user_principals (lower(username));

CREATE TABLE local_credentials (
    user_id UUID PRIMARY KEY REFERENCES user_principals(id) ON DELETE RESTRICT,
    algorithm TEXT NOT NULL CHECK (algorithm = 'argon2id'),
    parameters TEXT NOT NULL CHECK (length(parameters) BETWEEN 1 AND 128),
    salt BYTEA NOT NULL CHECK (octet_length(salt) BETWEEN 16 AND 64),
    derived_key BYTEA NOT NULL CHECK (octet_length(derived_key) BETWEEN 16 AND 64),
    failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    locked_until TIMESTAMPTZ,
    password_changed_at TIMESTAMPTZ NOT NULL,
    activation_digest CHAR(64),
    activation_expires_at TIMESTAMPTZ,
    CHECK ((activation_digest IS NULL) = (activation_expires_at IS NULL)),
    CHECK (activation_digest IS NULL OR activation_digest ~ '^[0-9a-f]{64}$')
);

CREATE TABLE local_password_history (
    user_id UUID NOT NULL REFERENCES user_principals(id) ON DELETE RESTRICT,
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    algorithm TEXT NOT NULL CHECK (algorithm = 'argon2id'),
    parameters TEXT NOT NULL,
    salt BYTEA NOT NULL CHECK (octet_length(salt) BETWEEN 16 AND 64),
    derived_key BYTEA NOT NULL CHECK (octet_length(derived_key) BETWEEN 16 AND 64),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, sequence)
);

CREATE TABLE organization_units (
    id UUID PRIMARY KEY,
    identity_source_id UUID REFERENCES identity_sources(id) ON DELETE RESTRICT,
    external_id TEXT NOT NULL DEFAULT '' CHECK (length(external_id) <= 512),
    parent_id UUID REFERENCES organization_units(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
    source_owned BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (id IS DISTINCT FROM parent_id),
    CHECK (updated_at >= created_at),
    UNIQUE (identity_source_id, external_id)
);

CREATE TABLE organization_memberships (
    organization_id UUID NOT NULL REFERENCES organization_units(id) ON DELETE RESTRICT,
    user_id UUID NOT NULL REFERENCES user_principals(id) ON DELETE RESTRICT,
    source_owned BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (organization_id, user_id)
);

CREATE TABLE role_bindings (
    id UUID PRIMARY KEY,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('user', 'organization')),
    subject_id UUID NOT NULL,
    role_name TEXT NOT NULL CHECK (role_name IN ('admin', 'publisher', 'approver', 'auditor', 'viewer')),
    scope_type TEXT NOT NULL CHECK (scope_type IN ('platform', 'product', 'channel')),
    product_id TEXT REFERENCES products(id) ON DELETE RESTRICT,
    channel_name TEXT,
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ,
    created_by TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (valid_until IS NULL OR valid_until > valid_from),
    CHECK ((scope_type = 'platform') = (product_id IS NULL)),
    CHECK ((scope_type = 'channel') = (channel_name IS NOT NULL)),
    CHECK (scope_type = 'channel' OR channel_name IS NULL),
    CHECK (updated_at >= created_at)
);

CREATE INDEX role_bindings_subject_idx ON role_bindings (subject_type, subject_id, valid_from, valid_until);
CREATE INDEX role_bindings_scope_idx ON role_bindings (product_id, channel_name, role_name, effect);

CREATE TABLE directory_sync_jobs (
    id UUID PRIMARY KEY,
    identity_source_id UUID NOT NULL REFERENCES identity_sources(id) ON DELETE RESTRICT,
    mode TEXT NOT NULL CHECK (mode IN ('preview', 'apply')),
    status TEXT NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'partial')),
    cursor TEXT NOT NULL DEFAULT '' CHECK (length(cursor) <= 2048),
    create_count INTEGER NOT NULL DEFAULT 0 CHECK (create_count >= 0),
    update_count INTEGER NOT NULL DEFAULT 0 CHECK (update_count >= 0),
    disable_count INTEGER NOT NULL DEFAULT 0 CHECK (disable_count >= 0),
    conflict_count INTEGER NOT NULL DEFAULT 0 CHECK (conflict_count >= 0),
    error_code TEXT NOT NULL DEFAULT '' CHECK (length(error_code) <= 128),
    requested_by TEXT NOT NULL,
    request_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    CHECK (updated_at >= created_at)
);

CREATE TABLE directory_sync_conflicts (
    id UUID PRIMARY KEY,
    sync_job_id UUID NOT NULL REFERENCES directory_sync_jobs(id) ON DELETE RESTRICT,
    identity_source_id UUID NOT NULL REFERENCES identity_sources(id) ON DELETE RESTRICT,
    object_type TEXT NOT NULL CHECK (object_type IN ('user', 'organization', 'membership')),
    external_id TEXT NOT NULL CHECK (length(external_id) BETWEEN 1 AND 512),
    conflict_code TEXT NOT NULL CHECK (conflict_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL CHECK (status IN ('open', 'resolved')),
    resolved_by TEXT,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    CHECK ((status = 'resolved') = (resolved_at IS NOT NULL))
);

CREATE TABLE emergency_access_events (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES user_principals(id) ON DELETE RESTRICT,
    action TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 128),
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'denied', 'failed')),
    reason_code TEXT NOT NULL CHECK (length(reason_code) BETWEEN 1 AND 128),
    request_id UUID NOT NULL,
    source_ip INET,
    occurred_at TIMESTAMPTZ NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

REVOKE DELETE, TRUNCATE ON emergency_access_events FROM PUBLIC;

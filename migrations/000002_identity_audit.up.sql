CREATE TABLE audit_chain_heads (
    partition_key TEXT PRIMARY KEY,
    head_hash CHAR(64) NOT NULL
        CHECK (head_hash ~ '^[0-9a-f]{64}$'),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE api_tokens (
    id UUID PRIMARY KEY,
    secret_hash TEXT NOT NULL
        CHECK (secret_hash LIKE '$argon2id$%'),
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
    roles TEXT[] NOT NULL DEFAULT '{}',
    product_ids TEXT[] NOT NULL DEFAULT '{}',
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at)
);

CREATE INDEX api_tokens_expiry_idx ON api_tokens (expires_at);

CREATE TABLE audit_events (
    id UUID PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL,
    product_id TEXT NOT NULL DEFAULT '',
    actor_subject TEXT NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 512),
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('human', 'workload', 'local')),
    actor_provider TEXT NOT NULL DEFAULT ''
        CHECK (actor_provider IN ('', 'github-actions', 'github-enterprise-actions', 'gitlab-ci', 'api-token')),
    actor_roles TEXT[] NOT NULL DEFAULT '{}',
    actor_product_ids TEXT[] NOT NULL DEFAULT '{}',
    token_id TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL CHECK (length(action) BETWEEN 3 AND 128),
    resource_type TEXT NOT NULL CHECK (length(resource_type) BETWEEN 1 AND 128),
    resource_id TEXT NOT NULL CHECK (length(resource_id) BETWEEN 1 AND 512),
    outcome TEXT NOT NULL CHECK (outcome IN ('success', 'denied', 'failed')),
    request_id UUID NOT NULL,
    source_ip INET,
    metadata JSONB NOT NULL CHECK (jsonb_typeof(metadata) = 'object'),
    previous_hash CHAR(64) NOT NULL
        CHECK (previous_hash ~ '^[0-9a-f]{64}$'),
    event_hash CHAR(64) NOT NULL UNIQUE
        CHECK (event_hash ~ '^[0-9a-f]{64}$'),
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX audit_events_product_time_idx
    ON audit_events (product_id, occurred_at DESC, id DESC);

CREATE INDEX audit_events_actor_time_idx
    ON audit_events (actor_subject, occurred_at DESC, id DESC);

CREATE INDEX audit_events_action_time_idx
    ON audit_events (action, occurred_at DESC, id DESC);

CREATE TABLE audit_exports (
    id UUID PRIMARY KEY,
    product_id TEXT NOT NULL,
    requested_by TEXT NOT NULL CHECK (length(requested_by) BETWEEN 1 AND 512),
    request_id UUID NOT NULL,
    filter JSONB NOT NULL CHECK (jsonb_typeof(filter) = 'object'),
    status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'failed')),
    object_key TEXT NOT NULL DEFAULT '',
    error_code TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX audit_exports_product_time_idx
    ON audit_exports (product_id, created_at DESC, id DESC);

CREATE OR REPLACE FUNCTION reject_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit events are immutable' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER audit_events_immutable
BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_events
FOR EACH STATEMENT
EXECUTE FUNCTION reject_audit_event_mutation();

CREATE OR REPLACE FUNCTION protect_audit_export_request()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.id IS DISTINCT FROM NEW.id
        OR OLD.product_id IS DISTINCT FROM NEW.product_id
        OR OLD.requested_by IS DISTINCT FROM NEW.requested_by
        OR OLD.request_id IS DISTINCT FROM NEW.request_id
        OR OLD.filter IS DISTINCT FROM NEW.filter
        OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'audit export request fields are immutable' USING ERRCODE = '55000';
    END IF;
    NEW.updated_at = clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER audit_exports_protect_request
BEFORE UPDATE ON audit_exports
FOR EACH ROW
EXECUTE FUNCTION protect_audit_export_request();

CREATE TRIGGER audit_exports_no_delete
BEFORE DELETE OR TRUNCATE ON audit_exports
FOR EACH STATEMENT
EXECUTE FUNCTION reject_audit_event_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM PUBLIC;
REVOKE DELETE, TRUNCATE ON audit_exports FROM PUBLIC;

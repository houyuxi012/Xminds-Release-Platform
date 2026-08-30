CREATE TABLE distribution_endpoints (
    id UUID PRIMARY KEY,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    endpoint_type TEXT NOT NULL CHECK (endpoint_type IN ('origin', 'cdn', 'private')),
    region TEXT NOT NULL CHECK (region ~ '^[a-z][a-z0-9-]{1,62}$'),
    priority INTEGER NOT NULL CHECK (priority BETWEEN 0 AND 1000),
    base_url TEXT NOT NULL CHECK (base_url LIKE 'https://%'),
    path_prefix TEXT NOT NULL CHECK (path_prefix LIKE '/%' AND position('..' IN path_prefix) = 0),
    health_path TEXT NOT NULL CHECK (health_path LIKE '/%' AND position('..' IN health_path) = 0),
    tls_ca_ref TEXT NOT NULL DEFAULT '' CHECK (length(tls_ca_ref) <= 256),
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'unhealthy', 'disabled')),
    last_root_digest CHAR(64),
    last_timestamp_digest CHAR(64),
    last_checked_at TIMESTAMPTZ,
    failure_count INTEGER NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (product_id, name),
    CHECK (last_root_digest IS NULL OR last_root_digest ~ '^[0-9a-f]{64}$'),
    CHECK (last_timestamp_digest IS NULL OR last_timestamp_digest ~ '^[0-9a-f]{64}$'),
    CHECK ((last_root_digest IS NULL) = (last_timestamp_digest IS NULL)),
    CHECK (updated_at >= created_at)
);

CREATE INDEX distribution_endpoints_selection_idx
    ON distribution_endpoints (product_id, status, priority, region, id);

CREATE OR REPLACE FUNCTION protect_distribution_endpoint_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.id IS DISTINCT FROM NEW.id
        OR OLD.product_id IS DISTINCT FROM NEW.product_id
        OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'distribution endpoint identity is immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.status = 'disabled' AND NEW.status IS DISTINCT FROM OLD.status THEN
        RAISE EXCEPTION 'disabled distribution endpoint cannot be reactivated' USING ERRCODE = '55000';
    END IF;
    NEW.updated_at = GREATEST(OLD.updated_at, NEW.updated_at, clock_timestamp());
    RETURN NEW;
END;
$$;

CREATE TRIGGER distribution_endpoints_protect_identity
BEFORE UPDATE ON distribution_endpoints
FOR EACH ROW EXECUTE FUNCTION protect_distribution_endpoint_identity();

CREATE OR REPLACE FUNCTION reject_distribution_endpoint_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'distribution endpoints cannot be deleted' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER distribution_endpoints_no_delete
BEFORE DELETE OR TRUNCATE ON distribution_endpoints
FOR EACH STATEMENT EXECUTE FUNCTION reject_distribution_endpoint_delete();

REVOKE DELETE, TRUNCATE ON distribution_endpoints FROM PUBLIC;

-- Durable log-center export requests and worker leases.
CREATE TABLE log_exports (
    id UUID PRIMARY KEY,
    requester TEXT NOT NULL CHECK (length(requester) BETWEEN 1 AND 256),
    log_types TEXT[] NOT NULL CHECK (cardinality(log_types) BETWEEN 1 AND 4),
    scope JSONB NOT NULL CHECK (jsonb_typeof(scope) = 'object'),
    filters JSONB NOT NULL CHECK (jsonb_typeof(filters) = 'object'),
    dedupe_key TEXT NOT NULL CHECK (length(dedupe_key) BETWEEN 1 AND 256),
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','completed','failed','exhausted')),
    archive_key TEXT,
    archive_url TEXT,
    manifest JSONB CHECK (manifest IS NULL OR jsonb_typeof(manifest) = 'object'),
    manifest_signature BYTEA CHECK (manifest_signature IS NULL OR octet_length(manifest_signature) = 64),
    last_error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (updated_at >= created_at)
);
CREATE UNIQUE INDEX log_exports_requester_dedupe_uidx ON log_exports (requester, dedupe_key);

CREATE TABLE log_export_jobs (
    id UUID PRIMARY KEY,
    export_id UUID NOT NULL REFERENCES log_exports(id) ON DELETE RESTRICT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','running','completed','failed','exhausted')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_run_at TIMESTAMPTZ NOT NULL,
    lease_token UUID,
    lease_expires_at TIMESTAMPTZ,
    last_error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK ((status = 'running' AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR (status <> 'running' AND lease_token IS NULL AND lease_expires_at IS NULL)),
    CHECK (updated_at >= created_at)
);
CREATE UNIQUE INDEX log_export_jobs_export_uidx ON log_export_jobs (export_id);
CREATE INDEX log_export_jobs_due_idx ON log_export_jobs (next_run_at, created_at) WHERE status IN ('pending','failed');
CREATE INDEX log_export_jobs_expired_lease_idx ON log_export_jobs (lease_expires_at, created_at) WHERE status = 'running';

-- The durable worker consumes this through the shared outbox contract.
COMMENT ON TABLE log_exports IS 'log-center export requests; outbox kind log.export.v1';
COMMENT ON TABLE log_export_jobs IS 'lease-fenced log-center export execution state';

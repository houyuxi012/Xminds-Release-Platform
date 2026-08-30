CREATE TABLE scm_connections (
    id UUID PRIMARY KEY,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
    provider TEXT NOT NULL CHECK (provider IN ('github', 'gitlab')),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    api_base_url TEXT NOT NULL CHECK (api_base_url LIKE 'https://%'),
    api_version TEXT NOT NULL DEFAULT '',
    credential_id UUID,
    webhook_credential_id UUID,
    oidc_issuer TEXT NOT NULL DEFAULT '',
    oidc_audience TEXT NOT NULL DEFAULT '',
    allowed_repositories TEXT[] NOT NULL DEFAULT '{}',
    resolved_addresses TEXT[] NOT NULL CHECK (cardinality(resolved_addresses) > 0),
    enterprise_ca_bundle_pem BYTEA NOT NULL DEFAULT ''::bytea,
    proxy_url TEXT NOT NULL DEFAULT '',
    proxy_resolved_addresses TEXT[] NOT NULL DEFAULT '{}',
    no_proxy TEXT[] NOT NULL DEFAULT '{}',
    capabilities JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(capabilities) = 'object'),
    certificate_sha256 CHAR(64) NOT NULL CHECK (certificate_sha256 ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT scm_connections_status_time_consistent CHECK (
        (status = 'active' AND revoked_at IS NULL) OR (status = 'revoked' AND revoked_at IS NOT NULL)
    )
);

CREATE INDEX scm_connections_product_idx ON scm_connections (product_id, created_at DESC, id DESC);

CREATE TABLE scm_credentials (
    id UUID NOT NULL,
    connection_id UUID NOT NULL REFERENCES scm_connections(id) ON DELETE RESTRICT,
    version INTEGER NOT NULL CHECK (version > 0),
    kind TEXT NOT NULL CHECK (kind IN ('webhook_secret', 'webhook_signing_token', 'github_token', 'github_app_token', 'gitlab_access_token')),
    key_id TEXT NOT NULL CHECK (length(key_id) BETWEEN 1 AND 128),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) BETWEEN 24 AND 65552),
    last_four TEXT NOT NULL CHECK (length(last_four) <= 4),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (id, version),
    UNIQUE (id),
    UNIQUE (connection_id, kind, version),
    CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE UNIQUE INDEX scm_credentials_one_active_kind_idx
    ON scm_credentials (connection_id, kind) WHERE revoked_at IS NULL;

ALTER TABLE scm_connections
    ADD CONSTRAINT scm_connections_credential_fk
        FOREIGN KEY (credential_id) REFERENCES scm_credentials(id) DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT scm_connections_webhook_credential_fk
        FOREIGN KEY (webhook_credential_id) REFERENCES scm_credentials(id) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE scm_webhook_deliveries (
    id UUID PRIMARY KEY,
    connection_id UUID NOT NULL REFERENCES scm_connections(id) ON DELETE RESTRICT,
    event_id TEXT NOT NULL CHECK (length(event_id) BETWEEN 1 AND 256),
    event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 64),
    payload_digest CHAR(64) NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    repository TEXT NOT NULL CHECK (length(repository) BETWEEN 3 AND 256),
    commit_sha TEXT NOT NULL CHECK (commit_sha ~ '^[0-9a-f]{40}([0-9a-f]{24})?$'),
    occurred_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    UNIQUE (connection_id, event_id)
);

CREATE INDEX scm_webhook_deliveries_received_idx
    ON scm_webhook_deliveries (connection_id, received_at DESC, id DESC);

CREATE OR REPLACE FUNCTION protect_scm_credential_secret()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF ROW(OLD.id, OLD.connection_id, OLD.version, OLD.kind, OLD.key_id, OLD.nonce, OLD.ciphertext, OLD.last_four, OLD.expires_at, OLD.created_at)
       IS DISTINCT FROM
       ROW(NEW.id, NEW.connection_id, NEW.version, NEW.kind, NEW.key_id, NEW.nonce, NEW.ciphertext, NEW.last_four, NEW.expires_at, NEW.created_at) THEN
        RAISE EXCEPTION 'SCM credential secret fields are immutable' USING ERRCODE = '55000';
    END IF;
    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN
        RAISE EXCEPTION 'revoked SCM credential is immutable' USING ERRCODE = '55000';
    END IF;
    NEW.updated_at = GREATEST(OLD.updated_at, NEW.updated_at, clock_timestamp());
    RETURN NEW;
END;
$$;

CREATE TRIGGER scm_credentials_protect_secret
BEFORE UPDATE ON scm_credentials
FOR EACH ROW EXECUTE FUNCTION protect_scm_credential_secret();

CREATE OR REPLACE FUNCTION reject_scm_delivery_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'SCM webhook deliveries are immutable' USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER scm_webhook_deliveries_immutable
BEFORE UPDATE OR DELETE OR TRUNCATE ON scm_webhook_deliveries
FOR EACH STATEMENT EXECUTE FUNCTION reject_scm_delivery_mutation();

REVOKE DELETE, TRUNCATE ON scm_credentials FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON scm_webhook_deliveries FROM PUBLIC;

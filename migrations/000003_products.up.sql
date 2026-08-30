CREATE TABLE products (
    id TEXT PRIMARY KEY
        CONSTRAINT products_id_format CHECK (id ~ '^[a-z][a-z0-9-]{1,62}$'),
    display_name TEXT NOT NULL
        CONSTRAINT products_display_name_length CHECK (length(display_name) BETWEEN 1 AND 128),
    schema_version TEXT NOT NULL
        CONSTRAINT products_schema_version_v1 CHECK (schema_version = 'xminds-product-manifest/v1'),
    artifact_types TEXT[] NOT NULL
        CONSTRAINT products_artifact_types_count CHECK (cardinality(artifact_types) BETWEEN 1 AND 32),
    version_scheme TEXT NOT NULL
        CONSTRAINT products_version_scheme_semver CHECK (version_scheme = 'semver'),
    compatibility_keys TEXT[] NOT NULL DEFAULT '{}'
        CONSTRAINT products_compatibility_keys_count CHECK (cardinality(compatibility_keys) <= 32),
    catalog_format TEXT NOT NULL
        CONSTRAINT products_catalog_format_v1 CHECK (catalog_format = 'xminds-tuf-v1'),
    manifest_json JSONB NOT NULL
        CONSTRAINT products_manifest_object CHECK (jsonb_typeof(manifest_json) = 'object'),
    manifest_digest CHAR(64) NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
        CONSTRAINT products_status_valid CHECK (status IN ('active', 'inactive')),
    created_by TEXT NOT NULL
        CONSTRAINT products_created_by_length CHECK (length(created_by) BETWEEN 1 AND 512),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deactivated_at TIMESTAMPTZ,
    CONSTRAINT products_manifest_digest_unique UNIQUE (manifest_digest),
    CONSTRAINT products_manifest_digest_format CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT products_manifest_id_matches CHECK (manifest_json ->> 'product_id' = id),
    CONSTRAINT products_manifest_schema_matches CHECK (manifest_json ->> 'schema_version' = schema_version),
    CONSTRAINT products_status_timestamp_consistent CHECK (
        (status = 'active' AND deactivated_at IS NULL)
        OR (status = 'inactive' AND deactivated_at IS NOT NULL)
    ),
    CONSTRAINT products_updated_after_created CHECK (updated_at >= created_at)
);

CREATE INDEX products_status_created_idx ON products (status, created_at DESC, id DESC);

CREATE TABLE product_channels (
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    name TEXT NOT NULL
        CONSTRAINT product_channels_name_format CHECK (name ~ '^[a-z][a-z0-9._-]{0,63}$'),
    display_name TEXT NOT NULL
        CONSTRAINT product_channels_display_name_length CHECK (length(display_name) BETWEEN 1 AND 128),
    position INTEGER NOT NULL
        CONSTRAINT product_channels_position_nonnegative CHECK (position >= 0),
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (product_id, name),
    CONSTRAINT product_channels_position_unique UNIQUE (product_id, position)
);

CREATE OR REPLACE FUNCTION protect_product_manifest()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.id IS DISTINCT FROM NEW.id
        OR OLD.display_name IS DISTINCT FROM NEW.display_name
        OR OLD.schema_version IS DISTINCT FROM NEW.schema_version
        OR OLD.artifact_types IS DISTINCT FROM NEW.artifact_types
        OR OLD.version_scheme IS DISTINCT FROM NEW.version_scheme
        OR OLD.compatibility_keys IS DISTINCT FROM NEW.compatibility_keys
        OR OLD.catalog_format IS DISTINCT FROM NEW.catalog_format
        OR OLD.manifest_json IS DISTINCT FROM NEW.manifest_json
        OR OLD.manifest_digest IS DISTINCT FROM NEW.manifest_digest
        OR OLD.created_by IS DISTINCT FROM NEW.created_by
        OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
        RAISE EXCEPTION 'registered product manifest fields are immutable' USING ERRCODE = '55000';
    END IF;
    NEW.updated_at = clock_timestamp();
    RETURN NEW;
END;
$$;

CREATE TRIGGER products_protect_manifest
BEFORE UPDATE ON products
FOR EACH ROW
EXECUTE FUNCTION protect_product_manifest();

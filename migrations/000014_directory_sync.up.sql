ALTER TABLE directory_sync_jobs
    ADD COLUMN source_version BIGINT,
    ADD COLUMN run_marker UUID,
    ADD COLUMN phase TEXT NOT NULL DEFAULT 'fetch',
    ADD COLUMN processed_users INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN processed_organizations INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN processed_memberships INTEGER NOT NULL DEFAULT 0;

UPDATE directory_sync_jobs AS sync_job
SET source_version = source.version,
    run_marker = sync_job.id
FROM identity_sources AS source
WHERE source.id = sync_job.identity_source_id;

ALTER TABLE directory_sync_jobs
    ALTER COLUMN source_version SET NOT NULL,
    ALTER COLUMN run_marker SET NOT NULL,
    ADD CONSTRAINT directory_sync_jobs_source_version_positive CHECK (source_version > 0),
    ADD CONSTRAINT directory_sync_jobs_phase_valid CHECK (
        phase IN ('fetch', 'prepare', 'apply_users', 'apply_organizations', 'apply_memberships', 'finalize')
    ),
    ADD CONSTRAINT directory_sync_jobs_processed_counts_nonnegative CHECK (
        processed_users >= 0 AND processed_organizations >= 0 AND processed_memberships >= 0
    );

CREATE UNIQUE INDEX directory_sync_jobs_one_active_source_uidx
    ON directory_sync_jobs (identity_source_id)
    WHERE status IN ('pending', 'running', 'partial');

CREATE INDEX directory_sync_jobs_source_created_idx
    ON directory_sync_jobs (identity_source_id, created_at DESC, id DESC);

ALTER TABLE directory_sync_conflicts
    ADD CONSTRAINT directory_sync_conflicts_details_object CHECK (jsonb_typeof(details) = 'object'),
    ADD CONSTRAINT directory_sync_conflicts_details_bounded CHECK (octet_length(details::text) <= 4096),
    ADD CONSTRAINT directory_sync_conflicts_job_object_code_unique UNIQUE (sync_job_id, object_type, external_id, conflict_code);

CREATE INDEX directory_sync_conflicts_source_created_idx
    ON directory_sync_conflicts (identity_source_id, created_at DESC, id DESC);

ALTER TABLE user_principals
    ADD COLUMN last_directory_run_id UUID;

ALTER TABLE organization_units
    ADD COLUMN last_directory_run_id UUID;

CREATE TABLE directory_sync_stage_users (
    sync_job_id UUID NOT NULL REFERENCES directory_sync_jobs(id) ON DELETE CASCADE,
    external_subject TEXT NOT NULL CHECK (length(external_subject) BETWEEN 1 AND 512),
    username TEXT NOT NULL CHECK (length(username) BETWEEN 1 AND 128),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 256),
    email TEXT NOT NULL DEFAULT '' CHECK (length(email) <= 320),
    enabled BOOLEAN NOT NULL,
    occurrence_count INTEGER NOT NULL DEFAULT 1 CHECK (occurrence_count > 0),
    conflicting BOOLEAN NOT NULL DEFAULT FALSE,
    processed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (sync_job_id, external_subject)
);

CREATE INDEX directory_sync_stage_users_email_idx
    ON directory_sync_stage_users (sync_job_id, lower(email))
    WHERE email <> '';

CREATE INDEX directory_sync_stage_users_username_idx
    ON directory_sync_stage_users (sync_job_id, lower(username));

CREATE INDEX directory_sync_stage_users_pending_idx
    ON directory_sync_stage_users (sync_job_id, external_subject)
    WHERE processed = FALSE;

CREATE TABLE directory_sync_stage_organizations (
    sync_job_id UUID NOT NULL REFERENCES directory_sync_jobs(id) ON DELETE CASCADE,
    external_id TEXT NOT NULL CHECK (length(external_id) BETWEEN 1 AND 512),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
    occurrence_count INTEGER NOT NULL DEFAULT 1 CHECK (occurrence_count > 0),
    conflicting BOOLEAN NOT NULL DEFAULT FALSE,
    processed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (sync_job_id, external_id)
);

CREATE INDEX directory_sync_stage_organizations_pending_idx
    ON directory_sync_stage_organizations (sync_job_id, external_id)
    WHERE processed = FALSE;

CREATE TABLE directory_sync_stage_memberships (
    sync_job_id UUID NOT NULL REFERENCES directory_sync_jobs(id) ON DELETE CASCADE,
    organization_external_id TEXT NOT NULL CHECK (length(organization_external_id) BETWEEN 1 AND 512),
    user_external_subject TEXT NOT NULL CHECK (length(user_external_subject) BETWEEN 1 AND 512),
    processed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (sync_job_id, organization_external_id, user_external_subject)
);

CREATE INDEX directory_sync_stage_memberships_pending_idx
    ON directory_sync_stage_memberships (sync_job_id, organization_external_id, user_external_subject)
    WHERE processed = FALSE;

CREATE TABLE directory_sync_stage_parents (
    sync_job_id UUID NOT NULL REFERENCES directory_sync_jobs(id) ON DELETE CASCADE,
    organization_external_id TEXT NOT NULL CHECK (length(organization_external_id) BETWEEN 1 AND 512),
    parent_external_id TEXT NOT NULL CHECK (length(parent_external_id) BETWEEN 1 AND 512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (sync_job_id, organization_external_id, parent_external_id),
    CHECK (organization_external_id <> parent_external_id)
);

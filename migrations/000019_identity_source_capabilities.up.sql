ALTER TABLE identity_sources
    ADD COLUMN configuration_version BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN verified_configuration_version BIGINT;

UPDATE identity_sources
SET required_mappings_complete = FALSE,
    verified_configuration_version = NULL;

ALTER TABLE identity_sources
    ADD CONSTRAINT identity_sources_configuration_version_check
        CHECK (configuration_version >= 1),
    ADD CONSTRAINT identity_sources_verified_configuration_version_check
        CHECK (
            (verified_configuration_version IS NULL AND required_mappings_complete = FALSE)
            OR (
                required_mappings_complete = TRUE
                AND verified_configuration_version IS NOT NULL
                AND verified_configuration_version = configuration_version
            )
        );

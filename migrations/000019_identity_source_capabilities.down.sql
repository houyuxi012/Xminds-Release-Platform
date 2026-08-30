ALTER TABLE identity_sources
    DROP CONSTRAINT identity_sources_verified_configuration_version_check,
    DROP CONSTRAINT identity_sources_configuration_version_check,
    DROP COLUMN verified_configuration_version,
    DROP COLUMN configuration_version;

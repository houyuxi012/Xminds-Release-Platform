DROP TABLE IF EXISTS local_sessions;
DROP TABLE IF EXISTS local_auth_rate_limits;

ALTER TABLE local_credentials
    DROP CONSTRAINT local_credentials_password_material_check,
    DROP COLUMN mfa_last_counter,
    DROP COLUMN mfa_secret_reference;

UPDATE local_credentials
SET algorithm = 'argon2id',
    parameters = 'm=65536,t=3,p=2,l=32',
    salt = decode(repeat('00', 16), 'hex'),
    derived_key = decode(repeat('00', 32), 'hex'),
    password_changed_at = COALESCE(activation_expires_at, clock_timestamp())
WHERE algorithm IS NULL;

ALTER TABLE local_credentials
    ALTER COLUMN algorithm SET NOT NULL,
    ALTER COLUMN parameters SET NOT NULL,
    ALTER COLUMN salt SET NOT NULL,
    ALTER COLUMN derived_key SET NOT NULL,
    ALTER COLUMN password_changed_at SET NOT NULL,
    ADD CONSTRAINT local_credentials_algorithm_check CHECK (algorithm = 'argon2id'),
    ADD CONSTRAINT local_credentials_parameters_check CHECK (length(parameters) BETWEEN 1 AND 128),
    ADD CONSTRAINT local_credentials_salt_check CHECK (octet_length(salt) BETWEEN 16 AND 64),
    ADD CONSTRAINT local_credentials_derived_key_check CHECK (octet_length(derived_key) BETWEEN 16 AND 64);

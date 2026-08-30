DROP TRIGGER IF EXISTS scm_webhook_deliveries_immutable ON scm_webhook_deliveries;
DROP FUNCTION IF EXISTS reject_scm_delivery_mutation();
DROP TRIGGER IF EXISTS scm_credentials_protect_secret ON scm_credentials;
DROP FUNCTION IF EXISTS protect_scm_credential_secret();
DROP TABLE IF EXISTS scm_webhook_deliveries;
DROP TABLE IF EXISTS scm_connections;
DROP TABLE IF EXISTS scm_credentials;

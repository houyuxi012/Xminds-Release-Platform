DROP TRIGGER IF EXISTS distribution_endpoints_no_delete ON distribution_endpoints;
DROP FUNCTION IF EXISTS reject_distribution_endpoint_delete();
DROP TRIGGER IF EXISTS distribution_endpoints_protect_identity ON distribution_endpoints;
DROP FUNCTION IF EXISTS protect_distribution_endpoint_identity();
DROP TABLE IF EXISTS distribution_endpoints;

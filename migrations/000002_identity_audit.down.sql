DROP TRIGGER IF EXISTS audit_events_immutable ON audit_events;
DROP TRIGGER IF EXISTS audit_exports_protect_request ON audit_exports;
DROP TRIGGER IF EXISTS audit_exports_no_delete ON audit_exports;
DROP FUNCTION IF EXISTS protect_audit_export_request();
DROP FUNCTION IF EXISTS reject_audit_event_mutation();
DROP TABLE IF EXISTS audit_exports;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS audit_chain_heads;
DROP TABLE IF EXISTS api_tokens;

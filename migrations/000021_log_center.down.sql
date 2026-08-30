DROP TRIGGER IF EXISTS audit_events_log_center_projection ON public.audit_events;
SET ROLE xminds_log_owner;
DROP FUNCTION IF EXISTS public.ensure_log_monthly_partitions(DATE);
DROP FUNCTION IF EXISTS public.project_audit_event();
DROP FUNCTION IF EXISTS public.project_audit_event_row(public.audit_events);
DROP FUNCTION IF EXISTS public.logcenter_reject_mutation();
RESET ROLE;
DROP TABLE public.log_git_sync_events;
DROP TABLE public.log_application_request_events;
DROP TABLE public.log_authentication_events;
DROP TABLE public.log_operation_events;
DROP TABLE public.log_event_identities;
DROP TABLE public.log_maintenance_schedule;
DROP TABLE public.authorization_context_replay_claims;
DO $$ DECLARE role_created BOOLEAN; role_oid OID; BEGIN
    SELECT created_by_migration INTO role_created FROM public.log_center_role_provenance WHERE id=TRUE;
    IF role_created THEN REVOKE xminds_log_owner FROM CURRENT_USER; END IF;
    DROP TABLE public.log_center_role_provenance;
    SELECT oid INTO role_oid FROM pg_roles WHERE rolname='xminds_log_owner';
    IF role_created AND role_oid IS NOT NULL AND NOT EXISTS (SELECT 1 FROM pg_shdepend WHERE refclassid='pg_authid'::regclass AND refobjid=role_oid AND deptype='n') THEN
        DROP ROLE xminds_log_owner;
    END IF;
END $$;

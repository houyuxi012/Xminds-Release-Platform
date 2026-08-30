package migrations

import (
	"strings"
	"testing"
)

func TestLogCenterMigrationDeclaresEvidenceAndImmutabilityContracts(t *testing.T) {
	contents, err := FS.ReadFile("000021_log_center.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(contents)
	for _, required := range []string{
		"CREATE TABLE log_operation_events",
		"CREATE TABLE log_authentication_events",
		"CREATE TABLE log_application_request_events",
		"CREATE TABLE log_git_sync_events",
		"CREATE TABLE log_event_identities",
		"CREATE OR REPLACE FUNCTION logcenter_reject_mutation",
		"CREATE OR REPLACE FUNCTION public.project_audit_event",
		"CREATE OR REPLACE FUNCTION public.project_audit_event_row(p public.audit_events)",
		"SECURITY DEFINER",
		"PARTITION BY RANGE",
		"license_id VARCHAR(128)",
		"CREATE TRIGGER audit_events_log_center_projection",
		"PERFORM public.project_audit_event_row(audit_row)",
		"PERFORM public.ensure_log_monthly_partitions(month_start::date)",
		"p.metadata -> 'correlation_id'",
		"p.metadata -> 'trace_id'",
		"REVOKE ALL ON FUNCTION public.project_audit_event_row(public.audit_events) FROM PUBLIC",
		"REVOKE ALL ON FUNCTION public.project_audit_event() FROM PUBLIC",
		"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON log_operation_events,",
		"xminds_log_owner",
		"ALTER FUNCTION public.project_audit_event_row(public.audit_events) OWNER TO xminds_log_owner",
		"CREATE OR REPLACE FUNCTION public.ensure_log_monthly_partitions(p_month DATE)",
		"pg_advisory_xact_lock",
		"xminds-log-partition:",
		"ALTER TABLE public.log_operation_events OWNER TO xminds_log_owner",
		"REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON public.%I_%s FROM PUBLIC",
		"CREATE TABLE IF NOT EXISTS public.%I_%s PARTITION OF public.%I",
		"GRANT xminds_log_owner TO CURRENT_USER",
		"GRANT USAGE, CREATE ON SCHEMA public TO xminds_log_owner",
		"role_granted_to_executor",
		"GRANT SELECT, INSERT ON log_event_identities TO xminds_log_owner",
		"GRANT SELECT, INSERT ON log_operation_events TO xminds_log_owner",
		"log_center_role_provenance",
		"logcenter_reject_mutation",
		"event hash is invalid",
		"changed fields metadata is invalid",
		"reason metadata is invalid",
		"sensitive metadata is invalid",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration missing %q", required)
		}
	}
	if strings.Contains(sql, "UPDATE log_operation_events") { t.Fatal("projection must not update immutable operation rows") }
	down, err := FS.ReadFile("000021_log_center.down.sql")
	if err != nil { t.Fatal(err) }
	downSQL := string(down)
	if !strings.Contains(downSQL, "SET ROLE xminds_log_owner;") || !strings.Contains(downSQL, "RESET ROLE;") { t.Fatal("down migration must use owner role cleanup") }
	if strings.Index(downSQL, "SET ROLE xminds_log_owner;") > strings.Index(downSQL, "DROP FUNCTION IF EXISTS public.project_audit_event();") { t.Fatal("owner role must be selected before function cleanup") }
	if strings.Index(downSQL, "RESET ROLE;") < strings.Index(downSQL, "DROP FUNCTION IF EXISTS public.project_audit_event();") { t.Fatal("owner role must remain selected through function cleanup") }
}

func TestLogCenterDownDropsProjectionHelperAfterTrigger(t *testing.T) {
	contents, err := FS.ReadFile("000021_log_center.down.sql")
	if err != nil { t.Fatal(err) }
	sql := string(contents)
	if !strings.Contains(sql, "DROP FUNCTION IF EXISTS public.project_audit_event_row(public.audit_events)") { t.Fatal("down migration must drop projection helper") }
	if strings.Index(sql, "DROP TRIGGER IF EXISTS audit_events_log_center_projection") > strings.Index(sql, "DROP FUNCTION IF EXISTS public.project_audit_event_row(public.audit_events)") { t.Fatal("trigger must be dropped before projection helper") }
}

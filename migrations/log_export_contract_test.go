package migrations

import (
	"strings"
	"testing"
)

func TestLogExportMigrationDeclaresTransactionalExportAndLeaseTables(t *testing.T) {
	contents, err := FS.ReadFile("000022_log_export.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(contents)
	for _, required := range []string{
		"CREATE TABLE log_exports",
		"CREATE TABLE log_export_jobs",
		"CREATE UNIQUE INDEX log_exports_requester_dedupe_uidx",
		"REFERENCES log_exports(id)",
		"status IN ('queued','running','completed','failed','exhausted')",
		"lease_expires_at",
		"lease_token",
		"manifest_signature",
		"CREATE UNIQUE INDEX log_export_jobs_export_uidx",
		"CREATE INDEX log_export_jobs_due_idx",
		"log.export.v1",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration missing %q", required)
		}
	}
	down, err := FS.ReadFile("000022_log_export.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(down), "DROP TABLE IF EXISTS log_export_jobs") || !strings.Contains(string(down), "DROP TABLE IF EXISTS log_exports") {
		t.Fatal("down migration must drop export tables")
	}
}

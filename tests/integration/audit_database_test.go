package integration_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/migrations"
)

func TestAuditDatabaseBuildsHashChainAndRejectsMutation(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("database.ApplyMigrations() error = %v", err)
	}

	productID := "audit-test-" + uuid.NewString()
	repository := audit.NewPostgresRepository(pool)
	service := audit.NewService(repository)
	principal := identity.Principal{
		Subject:    "auditor-test",
		Kind:       identity.PrincipalKindHuman,
		Roles:      []identity.Role{identity.RoleApprover},
		ProductIDs: []string{productID},
		TokenID:    "audit-test-token",
	}
	appendEvent := func(resourceID string) audit.Event {
		t.Helper()
		var event audit.Event
		err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
			var appendErr error
			event, appendErr = service.Append(ctx, tx, audit.AppendCommand{
				Actor:        principal,
				Action:       "release.approve",
				ProductID:    productID,
				ResourceType: "release",
				ResourceID:   resourceID,
				Outcome:      audit.OutcomeSuccess,
				RequestID:    uuid.NewString(),
				SourceIP:     "192.0.2.10",
				Metadata:     map[string]any{"channel": "stable"},
			})
			return appendErr
		})
		if err != nil {
			t.Fatalf("append audit event: %v", err)
		}
		return event
	}

	first := appendEvent("release-1")
	second := appendEvent("release-2")
	if first.PreviousHash != strings.Repeat("0", 64) {
		t.Fatalf("first previous hash = %q", first.PreviousHash)
	}
	if second.PreviousHash != first.EventHash || second.EventHash == first.EventHash {
		t.Fatalf("invalid hash chain: first=%#v second=%#v", first, second)
	}

	events, err := service.Query(ctx, identity.Principal{
		Subject:    "audit-reader",
		Kind:       identity.PrincipalKindHuman,
		Roles:      []identity.Role{identity.RoleAuditor},
		ProductIDs: []string{productID},
	}, audit.QueryFilter{ProductID: productID, Limit: 10})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(events) != 2 || events[0].ID != second.ID || events[1].ID != first.ID {
		t.Fatalf("query order/events = %#v", events)
	}

	if _, err := pool.Exec(ctx, "UPDATE audit_events SET action = 'release.delete' WHERE id = $1", first.ID); err == nil {
		t.Fatal("immutable audit event update succeeded")
	}
	if _, err := pool.Exec(ctx, "DELETE FROM audit_events WHERE id = $1", first.ID); err == nil {
		t.Fatal("immutable audit event delete succeeded")
	}
}

func TestAuditDatabaseStartsExportTransactionally(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("database.Open() error = %v", err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("database.ApplyMigrations() error = %v", err)
	}

	productID := "audit-export-test-" + uuid.NewString()
	repository := audit.NewPostgresRepository(pool)
	service := audit.NewService(repository, jobs.NewPostgresRepository(pool))
	principal := identity.Principal{
		Subject:    "audit-exporter",
		Kind:       identity.PrincipalKindHuman,
		Roles:      []identity.Role{identity.RoleAuditor},
		ProductIDs: []string{productID},
		TokenID:    "audit-export-token",
	}
	var export audit.Export
	err = database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		var startErr error
		export, startErr = service.StartExport(ctx, tx, audit.StartExportCommand{
			Actor:     principal,
			ProductID: productID,
			Filter: audit.QueryFilter{
				Action: "release.approve",
				Since:  time.Now().Add(-24 * time.Hour),
				Until:  time.Now(),
			},
			RequestID: uuid.NewString(),
			SourceIP:  "192.0.2.11",
		})
		return startErr
	})
	if err != nil {
		t.Fatalf("StartExport() transaction error = %v", err)
	}

	stored, err := service.GetExport(ctx, principal, export.ID)
	if err != nil {
		t.Fatalf("GetExport() error = %v", err)
	}
	if stored.Status != audit.ExportStatusPending || stored.ProductID != productID {
		t.Fatalf("stored export = %#v", stored)
	}
	var jobCount int
	if err := pool.QueryRow(ctx, `
SELECT count(*)
FROM outbox_jobs
WHERE kind = 'audit.export.v1' AND aggregate_id = $1
`, export.ID).Scan(&jobCount); err != nil {
		t.Fatalf("query export job: %v", err)
	}
	if jobCount != 1 {
		t.Fatalf("export job count = %d, want 1", jobCount)
	}
	if _, err := pool.Exec(ctx, "UPDATE audit_exports SET product_id = 'other-product' WHERE id = $1", export.ID); err == nil {
		t.Fatal("immutable audit export request fields were updated")
	}
	if _, err := pool.Exec(ctx, "UPDATE audit_exports SET status = 'completed', object_key = 'audit/export.json' WHERE id = $1", export.ID); err == nil {
		t.Fatal("incomplete worker export update succeeded without digest, size and expiry")
	}
	completed := stored
	completed.Status = audit.ExportStatusCompleted
	completed.ObjectKey = "audit-exports/" + productID + "/" + export.ID.String() + "/" + strings.Repeat("a", 64) + ".jsonl"
	completed.SHA256 = strings.Repeat("a", 64)
	completed.SizeBytes = 128
	completed.ExpiresAt = time.Now().UTC().Add(time.Hour).Truncate(time.Microsecond)
	completed.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		return repository.CompleteExport(ctx, tx, completed)
	}); err != nil {
		t.Fatalf("CompleteExport() error = %v", err)
	}
	completedStored, err := repository.GetExport(ctx, export.ID)
	if err != nil || completedStored.Status != audit.ExportStatusCompleted || completedStored.SHA256 != completed.SHA256 || completedStored.SizeBytes != completed.SizeBytes {
		t.Fatalf("completed export=%#v error=%v", completedStored, err)
	}
}

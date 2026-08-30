package integration_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/platform/objectstore"
	"xminds-release-platform/internal/release"
	"xminds-release-platform/migrations"
)

func TestAuditExportPersistsVerifiedJSONLinesToPostgresAndMinIO(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	minioConfig := integrationMinIOConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}
	store, err := objectstore.NewMinIOStore(minioConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureBucket(ctx); err != nil {
		t.Fatal(err)
	}

	productID := "audit-export-e2e-" + uuid.NewString()
	repository := audit.NewPostgresRepository(pool)
	jobRepository := jobs.NewPostgresRepository(pool)
	service := audit.NewService(repository, jobRepository)
	principal := identity.Principal{
		Subject: "audit-export-e2e", Kind: identity.PrincipalKindHuman,
		Roles: []identity.Role{identity.RoleAuditor}, ProductIDs: []string{productID}, TokenID: "audit-export-e2e-token",
	}
	for _, resourceID := range []string{"release-1", "release-2"} {
		resourceID := resourceID
		if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
			_, appendErr := service.Append(ctx, tx, audit.AppendCommand{
				Actor: principal, Action: "release.approve", ProductID: productID,
				ResourceType: "release", ResourceID: resourceID, Outcome: audit.OutcomeSuccess,
				RequestID: uuid.NewString(), Metadata: map[string]any{"channel": "stable"},
			})
			return appendErr
		}); err != nil {
			t.Fatal(err)
		}
	}

	var export audit.Export
	if err := database.WithTx(ctx, pool, func(tx pgx.Tx) error {
		var startErr error
		export, startErr = service.StartExport(ctx, tx, audit.StartExportCommand{
			Actor: principal, ProductID: productID,
			Filter: audit.QueryFilter{Action: "release.approve"}, RequestID: uuid.NewString(),
		})
		return startErr
	}); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]string{"export_id": export.ID.String(), "product_id": productID})
	if err != nil {
		t.Fatal(err)
	}
	job := jobs.Job{ID: uuid.New(), Kind: audit.JobKindAuditExport, AggregateID: export.ID, Payload: payload, Attempts: 1}
	handler, err := audit.NewExportHandler(audit.ExportHandlerConfig{
		Repository: repository, Transactor: release.PoolTransactor{Pool: pool}, Store: store,
		Auditor: audit.NewService(repository), Clock: time.Now, TempDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.Handle(ctx, job); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	completed, err := repository.GetExport(ctx, export.ID)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Status != audit.ExportStatusCompleted || completed.SHA256 == "" || completed.SizeBytes <= 0 || completed.ExpiresAt.IsZero() {
		t.Fatalf("completed export = %+v", completed)
	}
	reader, information, err := store.Open(ctx, completed.ObjectKey, 0, -1)
	if err != nil {
		t.Fatal(err)
	}
	payload, err = io.ReadAll(reader)
	_ = reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	if information.Size != completed.SizeBytes || hex.EncodeToString(digest[:]) != completed.SHA256 {
		t.Fatalf("object info/digest = %+v/%s", information, hex.EncodeToString(digest[:]))
	}
	if _, err := service.GetExportDownload(ctx, principal, export.ID); err != nil {
		t.Fatalf("GetExportDownload() error = %v", err)
	}
	if err := handler.Handle(ctx, job); err != nil {
		t.Fatalf("replayed Handle() error = %v", err)
	}
}

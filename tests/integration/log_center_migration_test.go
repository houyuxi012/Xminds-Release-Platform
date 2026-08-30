package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/migrations"
)

func TestLogCenterFoundationMigrationCreatesReplayAndScheduleContracts(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.ApplyMigrations(ctx, pool, migrations.FS); err != nil {
		t.Fatal(err)
	}

	for _, table := range []string{"authorization_context_replay_claims", "log_maintenance_schedule", "log_exports", "log_export_jobs"} {
		var exists bool
		if err := pool.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", "public."+table).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if !exists {
			t.Fatalf("table %s does not exist", table)
		}
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	contextID := uuid.NewString()
	_, err = pool.Exec(ctx, `
INSERT INTO authorization_context_replay_claims (validator_issuer, context_id, claimed_at, expires_at)
VALUES ('integration-test', $1, $2, $3)
`, contextID, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `
INSERT INTO authorization_context_replay_claims (validator_issuer, context_id, claimed_at, expires_at)
VALUES ('integration-test', $1, $2, $3)
ON CONFLICT DO NOTHING
`, contextID, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM authorization_context_replay_claims WHERE validator_issuer='integration-test' AND context_id=$1`, contextID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("replay claim count=%d err=%v", count, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO log_maintenance_schedule (id,job_kind,period_key,run_no,dedupe_key,created_at,updated_at) VALUES ($1,'authorization.context_replay_gc.v1','2026-08-29',288,'bad',now(),now())`, uuid.New()); err == nil {
		t.Fatal("invalid replay run_no was accepted")
	}
	if _, err := pool.Exec(ctx, `DELETE FROM log_maintenance_schedule WHERE job_kind='log.partition.ensure.v1' AND period_key='2026-08'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO log_maintenance_schedule (id,job_kind,period_key,run_no,dedupe_key,created_at,updated_at) VALUES ($1,'log.partition.ensure.v1','2026-08',0,'ensure-2026-08',now(),now())`, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO log_maintenance_schedule (id,job_kind,period_key,run_no,dedupe_key,created_at,updated_at) VALUES ($1,'log.partition.ensure.v1','2026-08',0,'ensure-2026-08-duplicate',now(),now())`, uuid.New()); err == nil {
		t.Fatal("duplicate partition schedule was accepted")
	}
}

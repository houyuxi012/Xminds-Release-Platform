package integration_test

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/migrations"
)

func TestReauthenticationActorBindingMigrationExpiresLegacyProofsAndRollsBackSafely(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	adminPool, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer adminPool.Close()
	databaseName := "reauth_binding_migration_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := adminPool.Exec(ctx, `CREATE DATABASE `+databaseName); err != nil {
		t.Fatal(err)
	}
	configuration, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	configuration.ConnConfig.Database = databaseName
	pool, err := pgxpool.NewWithConfig(ctx, configuration)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = adminPool.Exec(context.Background(), `DROP DATABASE `+databaseName)
	})
	if err := database.ApplyMigrations(ctx, pool, directoryMigrationSubset(t, 15)); err != nil {
		t.Fatalf("apply migrations 1..15: %v", err)
	}
	now := time.Date(2026, 8, 21, 18, 0, 0, 0, time.UTC)
	pendingID, _ := uuid.NewV7()
	verifiedID, _ := uuid.NewV7()
	if _, err := pool.Exec(ctx, `
INSERT INTO iam_reauthentication_challenges (
    id, actor_subject, actor_kind, created_token_digest, operation, status,
    created_at, challenge_expires_at, created_request_id, version
) VALUES ($1, 'shared-subject', 'human', repeat('a', 64), 'identity.user.disable', 'pending', $2, $3, $4, 1)`,
		pendingID, now.Add(-2*time.Minute), now.Add(3*time.Minute), uuid.New()); err != nil {
		t.Fatalf("seed pending legacy challenge: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO iam_reauthentication_challenges (
    id, actor_subject, actor_kind, created_token_digest, operation, status,
    verified_token_digest, evidence_digest, created_at, verified_at,
    challenge_expires_at, evidence_expires_at, created_request_id, completed_request_id, version
) VALUES ($1, 'shared-subject', 'human', repeat('a', 64), 'identity.user.enable', 'verified',
		  repeat('b', 64), repeat('c', 64), $2::timestamptz, $2::timestamptz + interval '1 minute',
		  $3, $2::timestamptz + interval '2 minutes', $4, $5, 2)`,
		verifiedID, now.Add(-2*time.Minute), now.Add(3*time.Minute), uuid.New(), uuid.New()); err != nil {
		t.Fatalf("seed verified legacy challenge: %v", err)
	}

	if err := database.ApplyMigrations(ctx, pool, directoryMigrationSubset(t, 16)); err != nil {
		t.Fatalf("upgrade migrations: %v", err)
	}
	rows, err := pool.Query(ctx, `
SELECT id, status, actor_binding_version, actor_binding_digest IS NULL
FROM iam_reauthentication_challenges ORDER BY id`)
	if err != nil {
		t.Fatalf("load migrated challenges: %v", err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var id uuid.UUID
		var status string
		var bindingVersion int16
		var digestIsNull bool
		if err := rows.Scan(&id, &status, &bindingVersion, &digestIsNull); err != nil {
			t.Fatal(err)
		}
		if status != "expired" || bindingVersion != 0 || !digestIsNull {
			t.Fatalf("legacy challenge %s status=%s binding_version=%d digest_null=%t", id, status, bindingVersion, digestIsNull)
		}
		seen++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if seen != 2 {
		t.Fatalf("migrated challenge count=%d", seen)
	}
	var pendingVersion, verifiedVersion int64
	if err := pool.QueryRow(ctx, `SELECT version FROM iam_reauthentication_challenges WHERE id=$1`, pendingID).Scan(&pendingVersion); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT version FROM iam_reauthentication_challenges WHERE id=$1`, verifiedID).Scan(&verifiedVersion); err != nil {
		t.Fatal(err)
	}
	if pendingVersion != 2 || verifiedVersion != 3 {
		t.Fatalf("legacy versions pending=%d verified=%d", pendingVersion, verifiedVersion)
	}
	var maximumVersion int
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&maximumVersion); err != nil || maximumVersion != 16 {
		t.Fatalf("maximum migration version=%d error=%v", maximumVersion, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE iam_reauthentication_challenges SET status='pending' WHERE id=$1`, pendingID); err == nil {
		t.Fatal("v16 allowed an active challenge without a governed actor binding")
	}

	v16PendingID, _ := uuid.NewV7()
	if _, err := pool.Exec(ctx, `
INSERT INTO iam_reauthentication_challenges (
    id, actor_subject, actor_kind, actor_binding_version, actor_binding_digest,
    created_token_digest, operation, status, created_at, challenge_expires_at,
    created_request_id, version
) VALUES ($1, 'v16-user', 'human', 1, repeat('d', 64), repeat('a', 64),
          'identity.user.disable', 'pending', $2, $3, $4, 1)`,
		v16PendingID, now, now.Add(time.Minute), uuid.New()); err != nil {
		t.Fatalf("seed v16 challenge: %v", err)
	}
	downSQL, err := fs.ReadFile(migrations.FS, "000016_reauthentication_actor_binding.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, string(downSQL)); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatalf("apply migration 16 down: %v", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM schema_migrations WHERE version=16`); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM iam_reauthentication_challenges WHERE id=$1`, v16PendingID).Scan(&status); err != nil || status != "expired" {
		t.Fatalf("v16 rollback challenge status=%q error=%v", status, err)
	}
	var bindingColumns int
	if err := pool.QueryRow(ctx, `
SELECT count(*) FROM information_schema.columns
WHERE table_schema='public' AND table_name='iam_reauthentication_challenges'
  AND column_name IN ('actor_binding_version', 'actor_binding_digest')`).Scan(&bindingColumns); err != nil {
		t.Fatal(err)
	}
	if bindingColumns != 0 {
		t.Fatalf("binding columns after rollback=%d", bindingColumns)
	}
	if err := pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&maximumVersion); err != nil || maximumVersion != 15 {
		t.Fatalf("maximum migration version after rollback=%d error=%v", maximumVersion, err)
	}
}

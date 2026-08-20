package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const migrationAdvisoryLockID int64 = 0x584d494e44535250

type migration struct {
	version   int64
	name      string
	fileName  string
	contents  string
	checksum  string
	preflight *migrationPreflight
}

type migrationPreflight struct {
	fileName string
	contents string
	checksum string
}

// ApplyMigrations serializes migration execution with a PostgreSQL advisory
// lock and rejects modified migrations that have already been applied.
func ApplyMigrations(ctx context.Context, pool *pgxpool.Pool, migrationFS fs.FS) error {
	connection, err := pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer connection.Release()

	if _, err := connection.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationAdvisoryLockID); err != nil {
		return fmt.Errorf("acquire migration advisory lock: %w", err)
	}
	defer func() {
		unlockContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = connection.Exec(unlockContext, "SELECT pg_advisory_unlock($1)", migrationAdvisoryLockID)
	}()

	migrations, err := loadMigrations(migrationFS)
	if err != nil {
		return err
	}
	for _, item := range migrations {
		if err := applyMigration(ctx, connection, item); err != nil {
			return err
		}
	}
	return nil
}

func applyMigration(ctx context.Context, connection *pgxpool.Conn, item migration) error {
	var migrationTableExists bool
	if err := connection.QueryRow(ctx, "SELECT to_regclass('public.schema_migrations') IS NOT NULL").Scan(&migrationTableExists); err != nil {
		return fmt.Errorf("check migration table: %w", err)
	}

	if migrationTableExists {
		var existingChecksum string
		err := connection.QueryRow(ctx, "SELECT checksum FROM schema_migrations WHERE version = $1", item.version).Scan(&existingChecksum)
		if err == nil {
			if existingChecksum != item.checksum {
				return fmt.Errorf("migration %s checksum changed: stored=%s current=%s", item.fileName, existingChecksum, item.checksum)
			}
			if err := verifyRecordedPreflight(ctx, connection, item); err != nil {
				return err
			}
			return nil
		}
		if err != pgx.ErrNoRows {
			return fmt.Errorf("read migration %s state: %w", item.fileName, err)
		}
	}

	tx, err := connection.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", item.fileName, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if item.preflight != nil {
		if _, err := tx.Exec(ctx, `
CREATE TABLE IF NOT EXISTS schema_migration_preflights (
    migration_version BIGINT NOT NULL,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    checksum CHAR(64) NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
    applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (migration_version, name),
    FOREIGN KEY (migration_version) REFERENCES schema_migrations(version) ON DELETE RESTRICT
)`); err != nil {
			return fmt.Errorf("create migration preflight ledger for %s: %w", item.fileName, err)
		}
		var existingChecksum string
		err := tx.QueryRow(ctx, `SELECT checksum FROM schema_migration_preflights WHERE migration_version=$1 AND name=$2`, item.version, item.name).Scan(&existingChecksum)
		if err == nil {
			return fmt.Errorf("migration %s has a preflight record without its migration record", item.fileName)
		}
		if err != pgx.ErrNoRows {
			return fmt.Errorf("read migration preflight %s state: %w", item.preflight.fileName, err)
		}
		if _, err := tx.Exec(ctx, item.preflight.contents); err != nil {
			return fmt.Errorf("execute migration preflight %s: %w", item.preflight.fileName, err)
		}
	}
	if _, err := tx.Exec(ctx, item.contents); err != nil {
		return fmt.Errorf("execute migration %s: %w", item.fileName, err)
	}
	if _, err := tx.Exec(
		ctx,
		"INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)",
		item.version,
		item.name,
		item.checksum,
	); err != nil {
		return fmt.Errorf("record migration %s: %w", item.fileName, err)
	}
	if item.preflight != nil {
		if _, err := tx.Exec(ctx, `
INSERT INTO schema_migration_preflights (migration_version, name, checksum)
VALUES ($1, $2, $3)`, item.version, item.name, item.preflight.checksum); err != nil {
			return fmt.Errorf("record migration preflight %s: %w", item.preflight.fileName, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration %s: %w", item.fileName, err)
	}
	return nil
}

func verifyRecordedPreflight(ctx context.Context, connection *pgxpool.Conn, item migration) error {
	if item.preflight == nil {
		return nil
	}
	var ledgerExists bool
	if err := connection.QueryRow(ctx, "SELECT to_regclass('public.schema_migration_preflights') IS NOT NULL").Scan(&ledgerExists); err != nil {
		return fmt.Errorf("check migration preflight ledger: %w", err)
	}
	if !ledgerExists {
		return nil
	}
	var existingChecksum string
	err := connection.QueryRow(ctx, `SELECT checksum FROM schema_migration_preflights WHERE migration_version=$1 AND name=$2`, item.version, item.name).Scan(&existingChecksum)
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read migration preflight %s state: %w", item.preflight.fileName, err)
	}
	if existingChecksum != item.preflight.checksum {
		return fmt.Errorf("migration preflight %s checksum changed: stored=%s current=%s", item.preflight.fileName, existingChecksum, item.preflight.checksum)
	}
	return nil
}

func loadMigrations(migrationFS fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, ".")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	result := make([]migration, 0, len(entries))
	versions := make(map[int64]string)
	preflights := make(map[int64]migrationPreflight)
	for _, entry := range entries {
		version, name, ok := parseMigrationName(entry.Name())
		preflightVersion, _, isPreflight := parseMigrationPreflightName(entry.Name())
		if entry.IsDir() || (!ok && !isPreflight) {
			continue
		}
		contents, readErr := fs.ReadFile(migrationFS, entry.Name())
		if readErr != nil {
			return nil, fmt.Errorf("read migration %s: %w", entry.Name(), readErr)
		}
		digest := sha256.Sum256(contents)
		if isPreflight {
			if previous, exists := preflights[preflightVersion]; exists {
				return nil, fmt.Errorf("duplicate migration preflight version %d in %s and %s", preflightVersion, previous.fileName, entry.Name())
			}
			preflights[preflightVersion] = migrationPreflight{fileName: entry.Name(), contents: string(contents), checksum: hex.EncodeToString(digest[:])}
			continue
		}
		if previous, exists := versions[version]; exists {
			return nil, fmt.Errorf("duplicate migration version %d in %s and %s", version, previous, entry.Name())
		}
		result = append(result, migration{
			version:  version,
			name:     name,
			fileName: entry.Name(),
			contents: string(contents),
			checksum: hex.EncodeToString(digest[:]),
		})
		versions[version] = entry.Name()
	}
	for index := range result {
		preflight, exists := preflights[result[index].version]
		if !exists {
			continue
		}
		_, preflightName, _ := parseMigrationPreflightName(preflight.fileName)
		if preflightName != result[index].name {
			return nil, fmt.Errorf("migration preflight %s does not match migration %s", preflight.fileName, result[index].fileName)
		}
		result[index].preflight = &preflight
		delete(preflights, result[index].version)
	}
	for version, preflight := range preflights {
		return nil, fmt.Errorf("orphan migration preflight version %d in %s", version, preflight.fileName)
	}
	slices.SortFunc(result, func(left, right migration) int {
		if left.version < right.version {
			return -1
		}
		if left.version > right.version {
			return 1
		}
		return 0
	})
	return result, nil
}

func parseMigrationPreflightName(fileName string) (int64, string, bool) {
	const suffix = ".pre.sql"
	if !strings.HasSuffix(fileName, suffix) {
		return 0, "", false
	}
	stem := strings.TrimSuffix(fileName, suffix)
	versionText, name, found := strings.Cut(stem, "_")
	if !found || versionText == "" || name == "" {
		return 0, "", false
	}
	version, err := strconv.ParseInt(versionText, 10, 64)
	if err != nil || version <= 0 {
		return 0, "", false
	}
	return version, name, true
}

func parseMigrationName(fileName string) (int64, string, bool) {
	const suffix = ".up.sql"
	if !strings.HasSuffix(fileName, suffix) {
		return 0, "", false
	}
	stem := strings.TrimSuffix(fileName, suffix)
	versionText, name, found := strings.Cut(stem, "_")
	if !found || versionText == "" || name == "" {
		return 0, "", false
	}
	version, err := strconv.ParseInt(versionText, 10, 64)
	if err != nil || version <= 0 {
		return 0, "", false
	}
	return version, name, true
}

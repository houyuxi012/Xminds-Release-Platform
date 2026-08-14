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
	version  int64
	name     string
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
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration %s: %w", item.fileName, err)
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
	for _, entry := range entries {
		version, name, ok := parseMigrationName(entry.Name())
		if entry.IsDir() || !ok {
			continue
		}
		if previous, exists := versions[version]; exists {
			return nil, fmt.Errorf("duplicate migration version %d in %s and %s", version, previous, entry.Name())
		}
		contents, readErr := fs.ReadFile(migrationFS, entry.Name())
		if readErr != nil {
			return nil, fmt.Errorf("read migration %s: %w", entry.Name(), readErr)
		}
		digest := sha256.Sum256(contents)
		result = append(result, migration{
			version:  version,
			name:     name,
			fileName: entry.Name(),
			contents: string(contents),
			checksum: hex.EncodeToString(digest[:]),
		})
		versions[version] = entry.Name()
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

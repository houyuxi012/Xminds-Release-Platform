package database

import "testing"

func TestParseMigrationName(t *testing.T) {
	t.Parallel()

	version, name, ok := parseMigrationName("000001_platform.up.sql")
	if !ok {
		t.Fatal("parseMigrationName() ok = false")
	}
	if version != 1 || name != "platform" {
		t.Fatalf("parseMigrationName() = (%d, %q), want (1, %q)", version, name, "platform")
	}

	if _, _, ok := parseMigrationName("000001_platform.down.sql"); ok {
		t.Fatal("down migration was accepted as an up migration")
	}
}

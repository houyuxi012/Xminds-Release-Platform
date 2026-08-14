package catalog

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestValidateVersionRecordRejectsStructurallyInvalidEd25519Signature(t *testing.T) {
	record := validRepositoryRecord()
	targets := record.Roles[RoleTargets]
	targets.Signatures = json.RawMessage(`[{"keyid":"targets-key","sig":"AQ"}]`)
	record.Roles[RoleTargets] = targets

	if err := validateVersionRecord(record); !errors.Is(err, ErrVersionRecordInvalid) {
		t.Fatalf("expected invalid signature rejection, got %v", err)
	}
}

func TestValidSignaturesRejectsMalformedAndAmbiguousCollections(t *testing.T) {
	validSignature := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	tests := map[string]json.RawMessage{
		"invalid JSON":   json.RawMessage(`{`),
		"not array":      json.RawMessage(`{}`),
		"empty":          json.RawMessage(`[]`),
		"not object":     json.RawMessage(`[true]`),
		"extra field":    json.RawMessage(`[{"keyid":"key","sig":"` + validSignature + `","extra":true}]`),
		"invalid key ID": json.RawMessage(`[{"keyid":"bad key","sig":"` + validSignature + `"}]`),
		"invalid base64": json.RawMessage(`[{"keyid":"key","sig":"!"}]`),
		"duplicate key":  json.RawMessage(`[{"keyid":"key","sig":"` + validSignature + `"},{"keyid":"key","sig":"` + validSignature + `"}]`),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if validSignatures(raw) {
				t.Fatalf("malformed signatures accepted: %s", raw)
			}
		})
	}
}

func TestValidateVersionRecordRejectsIncompleteRoleEvidence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*VersionRecord)
	}{
		{"missing identity", func(record *VersionRecord) { record.ID = uuid.Nil }},
		{"missing role", func(record *VersionRecord) { delete(record.Roles, RoleTimestamp) }},
		{"wrong role version", func(record *VersionRecord) {
			document := record.Roles[RoleTargets]
			document.Version++
			record.Roles[RoleTargets] = document
		}},
		{"invalid object key", func(record *VersionRecord) {
			document := record.Roles[RoleSnapshot]
			document.ObjectKey = "../snapshot.json"
			record.Roles[RoleSnapshot] = document
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := validRepositoryRecord()
			test.mutate(&record)
			if err := validateVersionRecord(record); !errors.Is(err, ErrVersionRecordInvalid) {
				t.Fatalf("expected invalid record, got %v", err)
			}
		})
	}
}

func TestMapCatalogDatabaseErrorPreservesStableDomainErrors(t *testing.T) {
	if err := mapCatalogDatabaseError("insert", &pgconn.PgError{Code: "23505"}); !errors.Is(err, ErrVersionRecordExists) {
		t.Fatalf("unique error = %v", err)
	}
	if err := mapCatalogDatabaseError("switch", &pgconn.PgError{Code: "55000", Message: "catalog metadata rollback is forbidden"}); !errors.Is(err, ErrMetadataVersionRollback) {
		t.Fatalf("rollback error = %v", err)
	}
	original := errors.New("database unavailable")
	if err := mapCatalogDatabaseError("query", original); !errors.Is(err, original) {
		t.Fatalf("wrapped error = %v", err)
	}
}

func validRepositoryRecord() VersionRecord {
	id := uuid.Must(uuid.NewV7())
	versions := Versions{Root: 1, Targets: 2, Snapshot: 3, Timestamp: 4, Revocation: 5}
	validSignature := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
	roles := map[Role]RoleDocument{}
	for _, item := range []struct {
		role    Role
		version uint64
	}{{RoleRoot, versions.Root}, {RoleTargets, versions.Targets}, {RoleSnapshot, versions.Snapshot}, {RoleTimestamp, versions.Timestamp}, {RoleRevocation, versions.Revocation}} {
		roles[item.role] = RoleDocument{
			Role: item.role, Version: item.version, EnvelopeSHA256: repeat("a", 64),
			ObjectKey:  "catalogs/product/stable/1/" + string(item.role) + ".json",
			Signatures: json.RawMessage(`[{"keyid":"` + string(item.role) + `-key","sig":"` + validSignature + `"}]`),
		}
	}
	return VersionRecord{
		ID: id, ProductID: "product", Channel: "stable", ReleaseID: uuid.Must(uuid.NewV7()),
		Versions: versions, BundleSHA256: repeat("b", 64), Roles: roles, CreatedAt: time.Now().UTC(),
	}
}

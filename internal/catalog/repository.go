package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrRepositoryRequired      = errors.New("catalog repository is required")
	ErrTransactionRequired     = errors.New("catalog transaction is required")
	ErrVersionRecordInvalid    = errors.New("catalog version record is invalid")
	ErrVersionRecordExists     = errors.New("catalog version record already exists")
	ErrVersionRecordNotFound   = errors.New("catalog version record was not found")
	ErrCurrentCatalogNotFound  = errors.New("current catalog was not found")
	ErrMetadataVersionRollback = errors.New("catalog metadata version rollback is forbidden")
)

type RoleDocument struct {
	Role           Role
	Version        uint64
	EnvelopeSHA256 string
	ObjectKey      string
	Signatures     json.RawMessage
	Envelope       []byte
}

type VersionRecord struct {
	ID           uuid.UUID
	AttemptID    uuid.UUID
	ProductID    string
	Channel      string
	ReleaseID    uuid.UUID
	Versions     Versions
	BundleSHA256 string
	Roles        map[Role]RoleDocument
	CreatedAt    time.Time
	PublishedAt  *time.Time
}

type Repository interface {
	ReserveVersions(ctx context.Context, tx pgx.Tx, productID, channel string, rootVersion uint64) (Versions, error)
	Create(ctx context.Context, tx pgx.Tx, record VersionRecord) error
	Get(ctx context.Context, catalogVersionID uuid.UUID) (VersionRecord, error)
	SetCurrent(ctx context.Context, tx pgx.Tx, productID, channel string, catalogVersionID uuid.UUID, switchedAt time.Time) error
	Current(ctx context.Context, productID, channel string) (VersionRecord, error)
	FindByAttempt(ctx context.Context, attemptID uuid.UUID) (VersionRecord, error)
}

package logcenter

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrInvalidExportRequest = errors.New("invalid export request")
var ErrExportUnavailable = errors.New("export service unavailable")
var ErrExportForbidden = errors.New("export forbidden")
var ErrExportNotFound = errors.New("export not found")
var ErrExportConflict = errors.New("export dedupe conflict")

type ExportRequest struct {
	Requester        string          `json:"-"`
	LogTypes         []ScopeTable    `json:"log_types"`
	Filters          LogQueryFilters `json:"filters"`
	Format           string          `json:"format"`
	Reauthentication any             `json:"reauthentication"`
	DedupeKey        string          `json:"dedupe_key"`
}
type ExportContextResolver func(context.Context) (requester string, scope LogReadScope, err error)
type ExportRecord struct {
	ID                uuid.UUID
	LogTypes          []ScopeTable
	Scope             LogReadScope
	Filters           LogQueryFilters
	DedupeKey         string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	Status            string
	Requester         string
	ArchiveKey        string
	DownloadURL       string
	Manifest          ExportManifest
	ManifestSignature []byte
	LastErrorCode     string
}
type ExportAuthorizer interface {
	AuthorizeExport(context.Context, ExportAuthorization) error
}
type ExportAuthorization struct {
	Requester string
	Proof     any
}
type ExportStore interface {
	CreateExport(context.Context, ExportRecord) error
}
type ExportStatusStore interface {
	GetExport(context.Context, uuid.UUID, LogReadScope) (ExportRecord, bool, error)
	GrantDownload(context.Context, uuid.UUID, LogReadScope, time.Duration) (string, error)
}
type ExportTransactionStore interface {
	// The store performs the dedupe lookup and, only for a new key, invokes
	// authorize before committing the export, outbox and audit row atomically.
	CreateOrGetExport(context.Context, ExportRecord, func(context.Context) error) (ExportRecord, error)
}
type ExportService struct {
	Authorizer ExportAuthorizer
	Store      ExportStore
	Now        func() time.Time
}

func (s *ExportService) Create(ctx context.Context, req ExportRequest, scope LogReadScope) (ExportRecord, error) {
	if s == nil || s.Authorizer == nil || s.Store == nil {
		return ExportRecord{}, ErrExportUnavailable
	}
	if req.Format != "ndjson" || strings.TrimSpace(req.Requester) == "" || !validExportLogTypes(req.LogTypes) || len(req.DedupeKey) > 256 || strings.TrimSpace(req.DedupeKey) != req.DedupeKey || !validExportProof(req.Reauthentication) {
		return ExportRecord{}, ErrInvalidExportRequest
	}
	if err := validateExportFilters(req.Filters); err != nil {
		return ExportRecord{}, err
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	id, err := uuid.NewV7()
	if err != nil {
		return ExportRecord{}, err
	}
	r := ExportRecord{ID: id, LogTypes: append([]ScopeTable(nil), req.LogTypes...), Scope: scope, Filters: req.Filters, DedupeKey: req.DedupeKey, Requester: req.Requester, CreatedAt: now.UTC(), Status: "queued"}
	if tx, ok := s.Store.(ExportTransactionStore); ok {
		authorize := func(authorizeCtx context.Context) error {
			return s.Authorizer.AuthorizeExport(authorizeCtx, ExportAuthorization{Requester: req.Requester, Proof: req.Reauthentication})
		}
		return tx.CreateOrGetExport(ctx, r, authorize)
	} else {
		return ExportRecord{}, ErrExportUnavailable
	}
}

func validateExportFilters(filters LogQueryFilters) error {
	if filters.Cursor != "" || filters.Limit != 0 {
		return ErrInvalidExportRequest
	}
	return validateLogFilters(filters)
}

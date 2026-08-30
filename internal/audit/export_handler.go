package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/platform/objectstore"
)

const (
	JobKindAuditExport      = "audit.export.v1"
	auditExportLifetime     = 24 * time.Hour
	auditExportPageSize     = 500
	maximumAuditExportBytes = int64(2 * 1024 * 1024 * 1024)
)

var (
	ErrExportHandlerConfiguration = errors.New("audit export handler configuration is invalid")
	ErrExportJobInvalid           = errors.New("audit export job is invalid")
	ErrExportDigestMismatch       = errors.New("audit export read-back digest does not match")
	ErrExportEmpty                = errors.New("audit export contains no events")
)

type ExportHandlerRepository interface {
	GetExport(ctx context.Context, id uuid.UUID) (Export, error)
	Query(ctx context.Context, filter QueryFilter) ([]Event, error)
	CompleteExport(ctx context.Context, tx pgx.Tx, completed Export) error
	FailExport(ctx context.Context, tx pgx.Tx, id uuid.UUID, code string, failedAt time.Time) error
}

type ExportTransactor interface {
	WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error
}

type ExportAuditor interface {
	Append(ctx context.Context, tx pgx.Tx, command AppendCommand) (Event, error)
}

type ExportHandlerConfig struct {
	Repository ExportHandlerRepository
	Transactor ExportTransactor
	Store      objectstore.Store
	Auditor    ExportAuditor
	Clock      func() time.Time
	TempDir    string
}

type ExportHandler struct {
	repository ExportHandlerRepository
	transactor ExportTransactor
	store      objectstore.Store
	auditor    ExportAuditor
	clock      func() time.Time
	tempDir    string
}

func NewExportHandler(config ExportHandlerConfig) (*ExportHandler, error) {
	if config.Repository == nil || config.Transactor == nil || config.Store == nil || config.Auditor == nil || config.Clock == nil {
		return nil, ErrExportHandlerConfiguration
	}
	return &ExportHandler{
		repository: config.Repository, transactor: config.Transactor, store: config.Store,
		auditor: config.Auditor, clock: config.Clock, tempDir: strings.TrimSpace(config.TempDir),
	}, nil
}

func (handler *ExportHandler) Handle(ctx context.Context, job jobs.Job) error {
	err := handler.export(ctx, job)
	if err == nil {
		return nil
	}
	return jobs.NewCodedError(auditExportErrorCode(err), err)
}

func (handler *ExportHandler) HandleDeadLetter(ctx context.Context, job jobs.Job, code string) error {
	if handler == nil {
		return ErrExportHandlerConfiguration
	}
	payload, err := decodeExportJob(job)
	if err != nil {
		return err
	}
	export, err := handler.repository.GetExport(ctx, payload.ExportID)
	if err != nil {
		return err
	}
	if export.ProductID != payload.ProductID {
		return ErrExportJobInvalid
	}
	code = jobs.ErrorCode(jobs.NewCodedError(code, errors.New("audit export failed")))
	if export.Status == ExportStatusFailed && export.ErrorCode == code {
		return nil
	}
	if export.Status != ExportStatusPending {
		return ErrExportNotReady
	}
	now := handler.clock().UTC().Truncate(time.Microsecond)
	return handler.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if err := handler.repository.FailExport(ctx, tx, export.ID, code, now); err != nil {
			return err
		}
		_, err := handler.auditor.Append(ctx, tx, AppendCommand{
			Actor: exportWorkerPrincipal(export.ProductID), Action: "audit.export.failed",
			ProductID: export.ProductID, ResourceType: "audit_export", ResourceID: export.ID.String(),
			Outcome: OutcomeFailed, RequestID: job.ID.String(), Metadata: map[string]any{"error_code": code},
		})
		return err
	})
}

func (handler *ExportHandler) export(ctx context.Context, job jobs.Job) error {
	payload, err := decodeExportJob(job)
	if err != nil {
		return err
	}
	export, err := handler.repository.GetExport(ctx, payload.ExportID)
	if err != nil {
		return err
	}
	if export.ProductID != payload.ProductID {
		return ErrExportJobInvalid
	}
	if export.Status == ExportStatusCompleted {
		return handler.verifyObject(ctx, export.ObjectKey, export.SHA256, export.SizeBytes)
	}
	if export.Status != ExportStatusPending {
		return ErrExportNotReady
	}
	filter, err := decodeExportFilter(export.Filter, export.ProductID)
	if err != nil {
		return err
	}
	file, size, digest, err := handler.writeJSONLines(ctx, filter)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}()
	objectKey := path.Join("audit-exports", export.ProductID, export.ID.String(), digest+".jsonl")
	if err := handler.putImmutable(ctx, export.ID, objectKey, file, size, digest); err != nil {
		return err
	}
	now := handler.clock().UTC().Truncate(time.Microsecond)
	export.Status = ExportStatusCompleted
	export.ObjectKey = objectKey
	export.SHA256 = digest
	export.SizeBytes = size
	export.ExpiresAt = now.Add(auditExportLifetime)
	export.ErrorCode = ""
	export.UpdatedAt = now
	return handler.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if err := handler.repository.CompleteExport(ctx, tx, export); err != nil {
			return err
		}
		_, err := handler.auditor.Append(ctx, tx, AppendCommand{
			Actor: exportWorkerPrincipal(export.ProductID), Action: "audit.export.complete",
			ProductID: export.ProductID, ResourceType: "audit_export", ResourceID: export.ID.String(),
			Outcome: OutcomeSuccess, RequestID: job.ID.String(),
			Metadata: map[string]any{"sha256": digest, "size_bytes": size, "expires_at": export.ExpiresAt.Format(time.RFC3339)},
		})
		return err
	})
}

func (handler *ExportHandler) writeJSONLines(ctx context.Context, filter QueryFilter) (*os.File, int64, string, error) {
	file, err := os.CreateTemp(handler.tempDir, "xminds-audit-export-*.jsonl")
	if err != nil {
		return nil, 0, "", fmt.Errorf("create audit export staging file: %w", err)
	}
	cleanup := func(exportErr error) (*os.File, int64, string, error) {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return nil, 0, "", exportErr
	}
	digest := sha256.New()
	counting := &limitedCountingWriter{writer: io.MultiWriter(file, digest), limit: maximumAuditExportBytes}
	encoder := json.NewEncoder(counting)
	encoder.SetEscapeHTML(false)
	count := 0
	filter.Limit = auditExportPageSize
	for {
		events, err := handler.repository.Query(ctx, filter)
		if err != nil {
			return cleanup(err)
		}
		for _, event := range events {
			if err := encoder.Encode(toExportEvent(event)); err != nil {
				return cleanup(err)
			}
			count++
		}
		if len(events) < auditExportPageSize {
			break
		}
		last := events[len(events)-1]
		filter.BeforeTime = last.OccurredAt
		filter.BeforeID = last.ID
	}
	if count == 0 {
		return cleanup(ErrExportEmpty)
	}
	if err := file.Sync(); err != nil {
		return cleanup(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return cleanup(err)
	}
	return file, counting.written, hex.EncodeToString(digest.Sum(nil)), nil
}

func (handler *ExportHandler) putImmutable(ctx context.Context, exportID uuid.UUID, objectKey string, file *os.File, size int64, digest string) error {
	if _, err := handler.store.Stat(ctx, objectKey); err == nil {
		return handler.verifyObject(ctx, objectKey, digest, size)
	} else if !errors.Is(err, objectstore.ErrObjectNotFound) {
		return err
	}
	stagingKey := path.Join("uploads", "audit-exports", exportID.String(), digest+".jsonl")
	uploadID, err := handler.store.BeginMultipart(ctx, stagingKey, "application/x-ndjson; charset=utf-8")
	if err != nil {
		return err
	}
	completed := false
	defer func() {
		if completed {
			_ = handler.store.Delete(context.WithoutCancel(ctx), stagingKey)
		} else {
			_ = handler.store.AbortMultipart(context.WithoutCancel(ctx), stagingKey, uploadID)
		}
	}()
	part, err := handler.store.PutPart(ctx, stagingKey, uploadID, 1, file, size, digest)
	if err != nil {
		return err
	}
	if err := handler.store.CompleteMultipart(ctx, stagingKey, uploadID, []objectstore.Part{part}); err != nil {
		return err
	}
	completed = true
	if _, err := handler.store.Promote(ctx, stagingKey, objectKey); err != nil && !errors.Is(err, objectstore.ErrObjectAlreadyExists) {
		return err
	}
	return handler.verifyObject(ctx, objectKey, digest, size)
}

func (handler *ExportHandler) verifyObject(ctx context.Context, key, expectedDigest string, expectedSize int64) error {
	reader, information, err := handler.store.Open(ctx, key, 0, -1)
	if err != nil {
		return err
	}
	defer reader.Close()
	if information.Size != expectedSize || expectedSize <= 0 || expectedSize > maximumAuditExportBytes {
		return ErrExportDigestMismatch
	}
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(reader, maximumAuditExportBytes+1))
	if err != nil {
		return err
	}
	if written != expectedSize || !strings.EqualFold(hex.EncodeToString(digest.Sum(nil)), expectedDigest) {
		return ErrExportDigestMismatch
	}
	return nil
}

type exportJobPayload struct {
	ExportID  uuid.UUID `json:"export_id"`
	ProductID string    `json:"product_id"`
}

func decodeExportJob(job jobs.Job) (exportJobPayload, error) {
	if job.ID == uuid.Nil || job.Kind != JobKindAuditExport || job.AggregateID == uuid.Nil {
		return exportJobPayload{}, ErrExportJobInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(job.Payload))
	decoder.DisallowUnknownFields()
	var payload exportJobPayload
	if err := decoder.Decode(&payload); err != nil {
		return exportJobPayload{}, ErrExportJobInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || payload.ExportID == uuid.Nil || payload.ExportID != job.AggregateID || strings.TrimSpace(payload.ProductID) == "" {
		return exportJobPayload{}, ErrExportJobInvalid
	}
	return payload, nil
}

func decodeExportFilter(raw json.RawMessage, productID string) (QueryFilter, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var filter QueryFilter
	if err := decoder.Decode(&filter); err != nil {
		return QueryFilter{}, ErrExportFilterInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) || filter.ProductID != productID {
		return QueryFilter{}, ErrExportFilterInvalid
	}
	filter.Limit = auditExportPageSize
	filter.BeforeTime = time.Time{}
	filter.BeforeID = uuid.Nil
	return filter, nil
}

type limitedCountingWriter struct {
	writer  io.Writer
	limit   int64
	written int64
}

func (writer *limitedCountingWriter) Write(payload []byte) (int, error) {
	if !utf8.Valid(payload) || int64(len(payload)) > writer.limit-writer.written {
		return 0, ErrMetadataTooLarge
	}
	written, err := writer.writer.Write(payload)
	writer.written += int64(written)
	return written, err
}

type exportEvent struct {
	ID           string          `json:"id"`
	OccurredAt   string          `json:"occurred_at"`
	ProductID    string          `json:"product_id"`
	ActorSubject string          `json:"actor_subject"`
	ActorKind    string          `json:"actor_kind"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Outcome      Outcome         `json:"outcome"`
	RequestID    string          `json:"request_id"`
	SourceIP     string          `json:"source_ip,omitempty"`
	Metadata     json.RawMessage `json:"metadata"`
	PreviousHash string          `json:"previous_hash"`
	EventHash    string          `json:"event_hash"`
}

func toExportEvent(event Event) exportEvent {
	return exportEvent{
		ID: event.ID.String(), OccurredAt: event.OccurredAt.UTC().Format(time.RFC3339Nano), ProductID: event.ProductID,
		ActorSubject: event.ActorSubject, ActorKind: string(event.ActorKind), Action: event.Action,
		ResourceType: event.ResourceType, ResourceID: event.ResourceID, Outcome: event.Outcome,
		RequestID: event.RequestID.String(), SourceIP: event.SourceIP, Metadata: event.Metadata,
		PreviousHash: event.PreviousHash, EventHash: event.EventHash,
	}
}

func auditExportErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrExportDigestMismatch), errors.Is(err, objectstore.ErrDigestMismatch):
		return "audit_export_digest_mismatch"
	case errors.Is(err, ErrExportJobInvalid), errors.Is(err, ErrExportFilterInvalid):
		return "audit_export_invalid"
	case errors.Is(err, ErrExportEmpty):
		return "audit_export_empty"
	case errors.Is(err, objectstore.ErrObjectNotFound), errors.Is(err, objectstore.ErrUploadNotFound), errors.Is(err, objectstore.ErrConfigurationInvalid):
		return "audit_export_store_failed"
	default:
		return "audit_export_failed"
	}
}

func exportWorkerPrincipal(productID string) identity.Principal {
	return identity.Principal{
		Subject: "release-worker", Kind: identity.PrincipalKindWorkload,
		Provider: identity.WorkloadProviderAPIToken, Roles: []identity.Role{identity.RoleAuditor},
		ProductIDs: []string{productID},
	}
}

package logcenter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/signing"
)

var (
	ErrExportWorkerConfiguration = errors.New("log export worker configuration is invalid")
	ErrExportWorkerJobInvalid    = errors.New("log export worker job is invalid")
	ErrExportEmpty               = errors.New("log export contains no records")
)

type logExportJobPayload struct {
	ExportID uuid.UUID `json:"export_id"`
}

func decodeLogExportJob(job jobs.Job) (logExportJobPayload, error) {
	if job.Kind != exportJobKind || job.ID == uuid.Nil || job.AggregateID == uuid.Nil {
		return logExportJobPayload{}, ErrExportWorkerJobInvalid
	}
	var payload logExportJobPayload
	decoder := json.NewDecoder(bytes.NewReader(job.Payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil || payload.ExportID == uuid.Nil || payload.ExportID != job.AggregateID {
		return logExportJobPayload{}, ErrExportWorkerJobInvalid
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return logExportJobPayload{}, ErrExportWorkerJobInvalid
	}
	return payload, nil
}

type ExportWorkerConfig struct {
	Exports         *PostgresExportStore
	Queries         *QueryRepository
	Objects         ArchiveStore
	Signer          signing.Provider
	SigningKeyRef   string
	Clock           func() time.Time
	MaximumBytes    int64
	LeaseRetryDelay time.Duration
}

type ExportWorker struct {
	exports         *PostgresExportStore
	queries         *QueryRepository
	objects         ArchiveStore
	signer          signing.Provider
	signingKeyRef   string
	clock           func() time.Time
	maximumBytes    int64
	leaseRetryDelay time.Duration
}

func NewExportWorker(config ExportWorkerConfig) (*ExportWorker, error) {
	if config.Exports == nil || config.Queries == nil || config.Objects == nil || config.Signer == nil || strings.TrimSpace(config.SigningKeyRef) == "" {
		return nil, ErrExportWorkerConfiguration
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.MaximumBytes == 0 {
		config.MaximumBytes = 2 << 30
	}
	if config.MaximumBytes < 1 || config.MaximumBytes > 2<<30 || config.LeaseRetryDelay < 0 || config.LeaseRetryDelay > time.Hour {
		return nil, ErrExportWorkerConfiguration
	}
	return &ExportWorker{exports: config.Exports, queries: config.Queries, objects: config.Objects, signer: config.Signer, signingKeyRef: strings.TrimSpace(config.SigningKeyRef), clock: config.Clock, maximumBytes: config.MaximumBytes, leaseRetryDelay: config.LeaseRetryDelay}, nil
}

func (worker *ExportWorker) Handle(ctx context.Context, job jobs.Job) error {
	if worker == nil {
		return ErrExportWorkerConfiguration
	}
	payload, err := decodeLogExportJob(job)
	if err != nil {
		return jobs.NewCodedError("log_export_job_invalid", err)
	}
	record, found, err := worker.exports.getExportForWorker(ctx, payload.ExportID)
	if err != nil {
		return jobs.NewCodedError("log_export_store_unavailable", err)
	}
	if !found {
		return jobs.NewCodedError("log_export_not_found", ErrExportNotFound)
	}
	if record.Status == "completed" && record.ArchiveKey != "" {
		return nil
	}
	now := worker.clock().UTC()
	claimed, found, err := worker.exports.ClaimExportJobByID(ctx, now, job.ID)
	if err != nil {
		return jobs.NewCodedError("log_export_claim_failed", err)
	}
	if !found {
		return jobs.NewCodedError("log_export_lease_unavailable", ErrExportLeaseLost)
	}
	if claimed.ExportID != payload.ExportID {
		if transitionErr := worker.exports.ExhaustExportJob(ctx, claimed.ID, claimed.LeaseToken, ErrExportWorkerJobInvalid); transitionErr != nil {
			return jobs.NewCodedError("log_export_transition_failed", transitionErr)
		}
		return jobs.NewCodedError("log_export_job_invalid", ErrExportWorkerJobInvalid)
	}
	key, manifest, signature, err := worker.buildAndUpload(ctx, record)
	if err != nil {
		if transitionErr := worker.exports.FailExportJob(ctx, claimed.ID, claimed.LeaseToken, now.Add(worker.leaseRetryDelay)); transitionErr != nil {
			return jobs.NewCodedError("log_export_transition_failed", transitionErr)
		}
		return jobs.NewCodedError("log_export_failed", err)
	}
	if err := worker.exports.SetExportArtifactAndComplete(ctx, record.ID, claimed.ID, claimed.LeaseToken, key, "", manifest, signature); err != nil {
		transitionErr := worker.exports.FailExportJob(ctx, claimed.ID, claimed.LeaseToken, now.Add(worker.leaseRetryDelay))
		if transitionErr != nil {
			return jobs.NewCodedError("log_export_transition_failed", errors.Join(err, transitionErr))
		}
		return jobs.NewCodedError("log_export_metadata_failed", err)
	}
	return nil
}

func (worker *ExportWorker) HandleDeadLetterTx(ctx context.Context, tx pgx.Tx, job jobs.Job, code string) error {
	if worker == nil || worker.exports == nil {
		return ErrExportWorkerConfiguration
	}
	payload, err := decodeLogExportJob(job)
	if err != nil {
		return err
	}
	return worker.exports.ExhaustExportJobTx(ctx, tx, job.ID, payload.ExportID, code)
}

func (worker *ExportWorker) HandleDeadLetter(context.Context, jobs.Job, string) error {
	return ErrExportWorkerConfiguration
}

func (worker *ExportWorker) buildAndUpload(ctx context.Context, record ExportRecord) (string, ExportManifest, []byte, error) {
	rows := make([]map[string]any, 0)
	for _, logType := range record.LogTypes {
		filters := record.Filters
		filters.Cursor = ""
		filters.Limit = 200
		for {
			page, err := worker.queries.Query(ctx, record.Scope, logType, filters)
			if err != nil {
				return "", ExportManifest{}, nil, err
			}
			for _, row := range page.Items {
				values := make(map[string]any, len(row.Values)+1)
				for key, value := range row.Values {
					values[key] = value
				}
				values["log_type"] = string(logType)
				rows = append(rows, values)
			}
			if page.NextCursor == "" {
				break
			}
			filters.Cursor = page.NextCursor
		}
	}
	data, err := CanonicalNDJSON(rows)
	if err != nil {
		return "", ExportManifest{}, nil, err
	}
	if len(data) == 0 {
		return "", ExportManifest{}, nil, ErrExportEmpty
	}
	if int64(len(data)) > worker.maximumBytes {
		return "", ExportManifest{}, nil, ErrExportUnavailable
	}
	dataDigest := ManifestDigest(data)
	filterJSON, _ := json.Marshal(record.Filters)
	manifest := ExportManifest{SchemaVersion: 1, FiltersDigest: ManifestDigest(filterJSON), ScopeDigest: ScopeDigestHex(record.Scope), RecordCount: len(rows), ByteSize: len(data), DataSHA256: dataDigest, CreatedAt: worker.clock().UTC(), SigningKeyID: ""}
	keys, err := worker.signer.PublicKeys(ctx, []string{worker.signingKeyRef})
	if err != nil || len(keys) != 1 || strings.TrimSpace(keys[0].KeyID) == "" || keys[0].Algorithm != signing.AlgorithmEd25519 || len(keys[0].Value) != 32 {
		return "", ExportManifest{}, nil, ErrArchiveSignature
	}
	manifest.SigningKeyID = keys[0].KeyID
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return "", ExportManifest{}, nil, err
	}
	hash := sha256.Sum256(manifestJSON)
	signature, err := worker.signer.Sign(ctx, worker.signingKeyRef, hash[:])
	if err != nil || signature.Algorithm != signing.AlgorithmEd25519 || len(signature.Value) != 64 {
		return "", ExportManifest{}, nil, ErrArchiveSignature
	}
	key := "log-exports/" + record.ID.String() + "/" + dataDigest + ".ndjson"
	if err := worker.objects.PutImmutable(ctx, key, data, "application/x-ndjson"); err != nil {
		return "", ExportManifest{}, nil, err
	}
	return key, manifest, append([]byte(nil), signature.Value...), nil
}

func (store *PostgresExportStore) getExportForWorker(ctx context.Context, id uuid.UUID) (ExportRecord, bool, error) {
	if store == nil || store.pool == nil {
		return ExportRecord{}, false, ErrRepositoryUnavailable
	}
	var record ExportRecord
	found, err := scanExport(store.pool.QueryRow(ctx, exportSelect+" WHERE id=$1", id), &record)
	return record, found, err
}

var _ jobs.Handler = (*ExportWorker)(nil)

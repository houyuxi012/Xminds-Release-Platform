package endpoint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"

	"github.com/google/uuid"

	"xminds-release-platform/internal/artifact"
	"xminds-release-platform/internal/catalog"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/platform/objectstore"
)

const (
	JobKindEndpointSync   = "endpoint.sync.v1"
	maximumTargetsBytes   = 4 * 1024 * 1024
	maximumTargetCount    = 10_000
	synchronizationBuffer = 128 * 1024
)

var (
	ErrSynchronizerConfiguration = errors.New("endpoint synchronizer configuration is invalid")
	ErrSyncJobInvalid            = errors.New("endpoint synchronization job is invalid")
	ErrSyncDigestMismatch        = errors.New("endpoint synchronization read-back digest does not match")
	ErrSyncTargetsInvalid        = errors.New("endpoint synchronization targets metadata is invalid")
)

type SyncJobPayload struct {
	EndpointID uuid.UUID `json:"endpoint_id"`
	ProductID  string    `json:"product_id"`
	Channel    string    `json:"channel"`
}

type SyncCatalogReader interface {
	Current(ctx context.Context, productID, channel string) (catalog.VersionRecord, error)
}

type SyncArtifactReader interface {
	GetByDigest(ctx context.Context, productID, digest string) (artifact.Artifact, error)
}

type SyncSource interface {
	Open(ctx context.Context, key string, offset, length int64) (io.ReadCloser, objectstore.ObjectInfo, error)
}

type SyncDestination interface {
	Put(ctx context.Context, endpoint Endpoint, path string, body io.Reader, size int64, contentType, sha256 string) error
	Open(ctx context.Context, endpoint Endpoint, path string) (io.ReadCloser, int64, error)
}

type SynchronizerConfig struct {
	Endpoints   *Service
	Catalogs    SyncCatalogReader
	Artifacts   SyncArtifactReader
	Source      SyncSource
	Destination SyncDestination
}

type Synchronizer struct {
	endpoints   *Service
	catalogs    SyncCatalogReader
	artifacts   SyncArtifactReader
	source      SyncSource
	destination SyncDestination
}

func NewSynchronizer(config SynchronizerConfig) (*Synchronizer, error) {
	if config.Endpoints == nil || config.Catalogs == nil || config.Artifacts == nil || config.Source == nil || config.Destination == nil {
		return nil, ErrSynchronizerConfiguration
	}
	return &Synchronizer{endpoints: config.Endpoints, catalogs: config.Catalogs, artifacts: config.Artifacts, source: config.Source, destination: config.Destination}, nil
}

func (synchronizer *Synchronizer) Handle(ctx context.Context, job jobs.Job) error {
	payload, err := decodeSyncJob(job)
	if err != nil {
		return jobs.NewCodedError("endpoint_sync_job_invalid", err)
	}
	record, err := synchronizer.endpoints.Get(ctx, payload.EndpointID)
	if err != nil || record.ProductID != payload.ProductID || record.Status == StatusDisabled {
		return jobs.NewCodedError("endpoint_sync_endpoint_invalid", errors.Join(ErrSyncJobInvalid, err))
	}
	current, err := synchronizer.catalogs.Current(ctx, payload.ProductID, payload.Channel)
	if err != nil {
		return synchronizer.fail(ctx, job, payload.EndpointID, "endpoint_sync_catalog_unavailable", err)
	}
	if current.ProductID != payload.ProductID || current.Channel != payload.Channel || len(current.Roles) != 5 {
		return synchronizer.fail(ctx, job, payload.EndpointID, "endpoint_sync_catalog_invalid", ErrSyncJobInvalid)
	}
	for _, role := range []catalog.Role{catalog.RoleRoot, catalog.RoleTargets, catalog.RoleSnapshot, catalog.RoleTimestamp, catalog.RoleRevocation} {
		document, exists := current.Roles[role]
		if !exists || document.Role != role || !validSyncDigest(document.EnvelopeSHA256) {
			return synchronizer.fail(ctx, job, payload.EndpointID, "endpoint_sync_catalog_invalid", ErrSyncJobInvalid)
		}
		destinationPath := endpointRolePath(record, payload.ProductID, payload.Channel, role)
		if err := synchronizer.copyAndVerify(ctx, record, document.ObjectKey, destinationPath, "application/json", document.EnvelopeSHA256); err != nil {
			return synchronizer.fail(ctx, job, payload.EndpointID, syncErrorCode(err), err)
		}
	}
	targets := current.Roles[catalog.RoleTargets]
	digests, err := referencedArtifactDigests(targets.Envelope)
	if err != nil {
		return synchronizer.fail(ctx, job, payload.EndpointID, "endpoint_sync_targets_invalid", err)
	}
	for _, digest := range digests {
		item, err := synchronizer.artifacts.GetByDigest(ctx, payload.ProductID, digest)
		if err != nil || item.SHA256 != digest || item.ProductID != payload.ProductID {
			return synchronizer.fail(ctx, job, payload.EndpointID, "endpoint_sync_artifact_unavailable", errors.Join(err, ErrSyncTargetsInvalid))
		}
		destinationPath := endpointArtifactPath(record, payload.ProductID, digest)
		if err := synchronizer.copyAndVerify(ctx, record, item.ObjectKey, destinationPath, item.ContentType, digest); err != nil {
			return synchronizer.fail(ctx, job, payload.EndpointID, syncErrorCode(err), err)
		}
	}
	digestsResult, err := catalogDigests(current)
	if err != nil {
		return synchronizer.fail(ctx, job, payload.EndpointID, "endpoint_sync_catalog_invalid", err)
	}
	if _, err := synchronizer.endpoints.RecordSuccess(ctx, record.ID, digestsResult, job.ID.String()); err != nil {
		return jobs.NewCodedError("endpoint_sync_state_failed", err)
	}
	return nil
}

func (synchronizer *Synchronizer) copyAndVerify(ctx context.Context, endpoint Endpoint, sourceKey, destinationPath, contentType, expectedDigest string) error {
	reader, information, err := synchronizer.source.Open(ctx, sourceKey, 0, -1)
	if err != nil {
		return err
	}
	defer reader.Close()
	if information.Size <= 0 {
		return objectstore.ErrSizeMismatch
	}
	hash := sha256.New()
	buffered := io.TeeReader(reader, hash)
	if err := synchronizer.destination.Put(ctx, endpoint, destinationPath, buffered, information.Size, contentType, expectedDigest); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expectedDigest {
		return ErrSyncDigestMismatch
	}
	readback, readbackSize, err := synchronizer.destination.Open(ctx, endpoint, destinationPath)
	if err != nil {
		return err
	}
	defer readback.Close()
	if readbackSize != information.Size {
		return objectstore.ErrSizeMismatch
	}
	readbackHash := sha256.New()
	written, err := io.CopyBuffer(readbackHash, readback, make([]byte, synchronizationBuffer))
	if err != nil || written != information.Size || hex.EncodeToString(readbackHash.Sum(nil)) != expectedDigest {
		return ErrSyncDigestMismatch
	}
	return nil
}

func (synchronizer *Synchronizer) fail(ctx context.Context, job jobs.Job, endpointID uuid.UUID, code string, cause error) error {
	_, stateErr := synchronizer.endpoints.RecordFailure(ctx, endpointID, code, job.ID.String())
	if stateErr != nil {
		cause = errors.Join(cause, stateErr)
	}
	return jobs.NewCodedError(code, cause)
}

func decodeSyncJob(job jobs.Job) (SyncJobPayload, error) {
	if job.Kind != JobKindEndpointSync || job.ID == uuid.Nil || job.AggregateID == uuid.Nil {
		return SyncJobPayload{}, ErrSyncJobInvalid
	}
	var payload SyncJobPayload
	decoder := json.NewDecoder(strings.NewReader(string(job.Payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil || payload.EndpointID == uuid.Nil || payload.EndpointID != job.AggregateID || !publicProductID(payload.ProductID) || !safeChannel(payload.Channel) {
		return SyncJobPayload{}, ErrSyncJobInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return SyncJobPayload{}, ErrSyncJobInvalid
	}
	return payload, nil
}

func referencedArtifactDigests(envelope []byte) ([]string, error) {
	if len(envelope) == 0 || len(envelope) > maximumTargetsBytes {
		return nil, ErrSyncTargetsInvalid
	}
	var payload struct {
		Signed struct {
			Type    string `json:"_type"`
			Targets map[string]struct {
				Hashes map[string]string `json:"hashes"`
			} `json:"targets"`
		} `json:"signed"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(envelope)))
	if err := decoder.Decode(&payload); err != nil || payload.Signed.Type != string(catalog.RoleTargets) || len(payload.Signed.Targets) > maximumTargetCount {
		return nil, ErrSyncTargetsInvalid
	}
	seen := make(map[string]struct{}, len(payload.Signed.Targets))
	result := make([]string, 0, len(payload.Signed.Targets))
	for _, target := range payload.Signed.Targets {
		digest := strings.ToLower(strings.TrimSpace(target.Hashes["sha256"]))
		if !validSyncDigest(digest) {
			return nil, ErrSyncTargetsInvalid
		}
		if _, exists := seen[digest]; !exists {
			seen[digest] = struct{}{}
			result = append(result, digest)
		}
	}
	return result, nil
}

func endpointRolePath(endpoint Endpoint, productID, channel string, role catalog.Role) string {
	return path.Join(endpoint.PathPrefix, "v1", "products", productID, "channels", channel, "metadata", string(role)+".json")
}

func endpointArtifactPath(endpoint Endpoint, productID, digest string) string {
	return path.Join(endpoint.PathPrefix, "v1", "products", productID, "artifacts", digest)
}

func validSyncDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func safeChannel(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func syncErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrSyncDigestMismatch), errors.Is(err, objectstore.ErrDigestMismatch):
		return "endpoint_sync_digest_mismatch"
	case errors.Is(err, objectstore.ErrSizeMismatch):
		return "endpoint_sync_size_mismatch"
	default:
		return "endpoint_sync_copy_failed"
	}
}

var _ jobs.Handler = (*Synchronizer)(nil)

package catalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/platform/objectstore"
	"xminds-release-platform/internal/release"
)

const (
	JobKindCatalogPublish      = "catalog.publish.v1"
	JobKindCatalogRevoke       = "catalog.revoke.v1"
	maximumRoleEnvelopeBytes   = 4 * 1024 * 1024
	publicationObjectMediaType = "application/json"
)

var publicationRoleOrder = []Role{RoleRoot, RoleTargets, RoleSnapshot, RoleTimestamp, RoleRevocation}

var (
	ErrPublicationConfiguration  = errors.New("catalog publication configuration is invalid")
	ErrPublicationJobInvalid     = errors.New("catalog publication job is invalid")
	ErrPublicationDigestMismatch = errors.New("catalog publication read-back digest does not match")
	ErrPublicationStateInvalid   = errors.New("release is not publishable")
)

type PublicationJobPayload struct {
	ReleaseID uuid.UUID `json:"release_id"`
	AttemptID uuid.UUID `json:"attempt_id"`
}

type PublicationBuilder interface {
	RootVersion() uint64
	Build(ctx context.Context, record release.Release, versions Versions) (Bundle, error)
	BuildRevocation(ctx context.Context, record release.Release, versions Versions) (Bundle, error)
}

type PublicationCatalogRepository interface {
	FindByAttempt(ctx context.Context, attemptID uuid.UUID) (VersionRecord, error)
	ReserveVersions(ctx context.Context, tx pgx.Tx, productID, channel string, rootVersion uint64) (Versions, error)
	Create(ctx context.Context, tx pgx.Tx, record VersionRecord) error
	SetCurrent(ctx context.Context, tx pgx.Tx, productID, channel string, catalogVersionID uuid.UUID, switchedAt time.Time) error
	Current(ctx context.Context, productID, channel string) (VersionRecord, error)
}

type PublicationReleaseRepository interface {
	GetByID(ctx context.Context, releaseID uuid.UUID) (release.Release, error)
	GetAttemptByID(ctx context.Context, attemptID uuid.UUID) (release.Attempt, error)
	CompletePublication(ctx context.Context, tx pgx.Tx, releaseID, attemptID uuid.UUID, completedAt time.Time) error
	CompleteRevocation(ctx context.Context, tx pgx.Tx, releaseID, attemptID uuid.UUID, completedAt time.Time) error
	FailPublication(ctx context.Context, tx pgx.Tx, releaseID, attemptID uuid.UUID, errorCode string, failedAt time.Time) error
	FailRevocation(ctx context.Context, tx pgx.Tx, releaseID, attemptID uuid.UUID, errorCode string, failedAt time.Time) error
}

type PublicationTransactor interface {
	WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error
}

type PublicationAuditor interface {
	Append(ctx context.Context, tx pgx.Tx, command audit.AppendCommand) (audit.Event, error)
}

type PublicationConfig struct {
	Catalogs   PublicationCatalogRepository
	Releases   PublicationReleaseRepository
	Transactor PublicationTransactor
	Builder    PublicationBuilder
	Store      objectstore.Store
	Auditor    PublicationAuditor
	Clock      Clock
}

type PublicationService struct {
	catalogs   PublicationCatalogRepository
	releases   PublicationReleaseRepository
	transactor PublicationTransactor
	builder    PublicationBuilder
	store      objectstore.Store
	auditor    PublicationAuditor
	clock      Clock
}

func (service *PublicationService) Handle(ctx context.Context, job jobs.Job) error {
	var err error
	switch job.Kind {
	case JobKindCatalogPublish:
		err = service.Publish(ctx, job)
	case JobKindCatalogRevoke:
		err = service.Revoke(ctx, job)
	default:
		err = ErrPublicationJobInvalid
	}
	if err == nil {
		return nil
	}
	return jobs.NewCodedError(publicationErrorCode(err), err)
}

func (service *PublicationService) Revoke(ctx context.Context, job jobs.Job) error {
	if service == nil {
		return ErrPublicationConfiguration
	}
	payload, err := decodeCatalogJob(job, JobKindCatalogRevoke)
	if err != nil {
		return err
	}
	releaseRecord, err := service.releases.GetByID(ctx, payload.ReleaseID)
	if err != nil {
		return fmt.Errorf("load revocation release: %w", err)
	}
	attempt, err := service.releases.GetAttemptByID(ctx, payload.AttemptID)
	if err != nil {
		return fmt.Errorf("load revocation attempt: %w", err)
	}
	if attempt.ReleaseID != releaseRecord.ID || attempt.Kind != release.AttemptKindRevoke || releaseRecord.Status != release.StatusPublished ||
		releaseRecord.RevokedAt == nil || strings.TrimSpace(releaseRecord.RevocationReason) == "" {
		return ErrPublicationStateInvalid
	}
	record, err := service.catalogs.FindByAttempt(ctx, payload.AttemptID)
	if errors.Is(err, ErrVersionRecordNotFound) {
		record, err = service.createPublicationRecordWithBuilder(ctx, releaseRecord, payload.AttemptID, service.builder.BuildRevocation)
	}
	if err != nil {
		return err
	}
	if record.ReleaseID != releaseRecord.ID || record.ProductID != releaseRecord.ProductID || record.Channel != releaseRecord.Channel {
		return ErrPublicationJobInvalid
	}
	if attempt.Status == release.AttemptStatusSucceeded {
		current, currentErr := service.catalogs.Current(ctx, record.ProductID, record.Channel)
		if currentErr == nil && current.ID == record.ID {
			return nil
		}
		return ErrPublicationStateInvalid
	}
	if attempt.Status != release.AttemptStatusPending {
		return ErrPublicationStateInvalid
	}
	for _, role := range publicationRoleOrder {
		if err := service.persistRole(ctx, record.ID, record.Roles[role]); err != nil {
			return fmt.Errorf("persist revoked %s catalog role: %w", role, err)
		}
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	return service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if err := service.catalogs.SetCurrent(ctx, tx, record.ProductID, record.Channel, record.ID, now); err != nil {
			return fmt.Errorf("switch revoked current catalog: %w", err)
		}
		if err := service.releases.CompleteRevocation(ctx, tx, releaseRecord.ID, payload.AttemptID, now); err != nil {
			return fmt.Errorf("complete release revocation: %w", err)
		}
		_, err := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: workerPrincipal(record.ProductID), Action: "catalog.revoke.complete",
			ProductID: record.ProductID, ResourceType: "catalog", ResourceID: record.ID.String(),
			Outcome: audit.OutcomeSuccess, RequestID: job.ID.String(),
			Metadata: map[string]any{"release_id": releaseRecord.ID.String(), "attempt_id": payload.AttemptID.String(), "bundle_sha256": record.BundleSHA256},
		})
		return err
	})
}

func (service *PublicationService) HandleDeadLetter(ctx context.Context, job jobs.Job, code string) error {
	if service == nil {
		return ErrPublicationConfiguration
	}
	if job.Kind == JobKindCatalogRevoke {
		return service.handleRevocationDeadLetter(ctx, job, code)
	}
	payload, err := decodePublicationJob(job)
	if err != nil {
		return err
	}
	releaseRecord, err := service.releases.GetByID(ctx, payload.ReleaseID)
	if err != nil {
		return fmt.Errorf("load dead-letter release: %w", err)
	}
	attempt, err := service.releases.GetAttemptByID(ctx, payload.AttemptID)
	if err != nil {
		return fmt.Errorf("load dead-letter attempt: %w", err)
	}
	if attempt.ReleaseID != releaseRecord.ID || attempt.Kind != release.AttemptKindPublish {
		return ErrPublicationJobInvalid
	}
	code = jobs.ErrorCode(jobs.NewCodedError(code, errors.New("publication failed")))
	if releaseRecord.Status == release.StatusFailed && attempt.Status == release.AttemptStatusFailed &&
		releaseRecord.PublicationFailureCode == code && attempt.ErrorCode == code {
		return nil
	}
	if releaseRecord.Status != release.StatusPublishing || attempt.Status != release.AttemptStatusPending {
		return ErrPublicationStateInvalid
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	return service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if err := service.releases.FailPublication(ctx, tx, releaseRecord.ID, attempt.ID, code, now); err != nil {
			return fmt.Errorf("fail release publication: %w", err)
		}
		_, err := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: workerPrincipal(releaseRecord.ProductID), Action: "catalog.publish.failed",
			ProductID: releaseRecord.ProductID, ResourceType: "release", ResourceID: releaseRecord.ID.String(),
			Outcome: audit.OutcomeFailed, RequestID: job.ID.String(),
			Metadata: map[string]any{"attempt_id": attempt.ID.String(), "error_code": code},
		})
		if err != nil {
			return fmt.Errorf("append publication failure audit: %w", err)
		}
		return nil
	})
}

func (service *PublicationService) handleRevocationDeadLetter(ctx context.Context, job jobs.Job, code string) error {
	payload, err := decodeCatalogJob(job, JobKindCatalogRevoke)
	if err != nil {
		return err
	}
	releaseRecord, err := service.releases.GetByID(ctx, payload.ReleaseID)
	if err != nil {
		return err
	}
	attempt, err := service.releases.GetAttemptByID(ctx, payload.AttemptID)
	if err != nil {
		return err
	}
	if attempt.ReleaseID != releaseRecord.ID || attempt.Kind != release.AttemptKindRevoke ||
		releaseRecord.Status != release.StatusPublished || releaseRecord.RevokedAt == nil {
		return ErrPublicationStateInvalid
	}
	code = jobs.ErrorCode(jobs.NewCodedError(code, errors.New("catalog revocation failed")))
	if attempt.Status == release.AttemptStatusFailed && attempt.ErrorCode == code {
		return nil
	}
	if attempt.Status != release.AttemptStatusPending {
		return ErrPublicationStateInvalid
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	return service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if err := service.releases.FailRevocation(ctx, tx, releaseRecord.ID, attempt.ID, code, now); err != nil {
			return err
		}
		_, err := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: workerPrincipal(releaseRecord.ProductID), Action: "catalog.revoke.failed",
			ProductID: releaseRecord.ProductID, ResourceType: "release", ResourceID: releaseRecord.ID.String(),
			Outcome: audit.OutcomeFailed, RequestID: job.ID.String(), Metadata: map[string]any{"attempt_id": attempt.ID.String(), "error_code": code},
		})
		return err
	})
}

func NewPublicationService(config PublicationConfig) (*PublicationService, error) {
	if config.Catalogs == nil || config.Releases == nil || config.Transactor == nil || config.Builder == nil ||
		config.Store == nil || config.Auditor == nil || config.Clock == nil || config.Builder.RootVersion() == 0 {
		return nil, ErrPublicationConfiguration
	}
	return &PublicationService{
		catalogs: config.Catalogs, releases: config.Releases, transactor: config.Transactor,
		builder: config.Builder, store: config.Store, auditor: config.Auditor, clock: config.Clock,
	}, nil
}

func (service *PublicationService) Publish(ctx context.Context, job jobs.Job) error {
	if service == nil {
		return ErrPublicationConfiguration
	}
	payload, err := decodePublicationJob(job)
	if err != nil {
		return err
	}
	releaseRecord, err := service.releases.GetByID(ctx, payload.ReleaseID)
	if err != nil {
		return fmt.Errorf("load publication release: %w", err)
	}
	attempt, err := service.releases.GetAttemptByID(ctx, payload.AttemptID)
	if err != nil {
		return fmt.Errorf("load publication attempt: %w", err)
	}
	if attempt.ReleaseID != releaseRecord.ID || attempt.Kind != release.AttemptKindPublish {
		return ErrPublicationJobInvalid
	}

	record, err := service.catalogs.FindByAttempt(ctx, payload.AttemptID)
	if errors.Is(err, ErrVersionRecordNotFound) {
		if releaseRecord.Status != release.StatusPublishing {
			return ErrPublicationStateInvalid
		}
		record, err = service.createPublicationRecord(ctx, releaseRecord, payload.AttemptID)
	}
	if err != nil {
		return err
	}
	if record.ReleaseID != releaseRecord.ID || record.ProductID != releaseRecord.ProductID || record.Channel != releaseRecord.Channel {
		return ErrPublicationJobInvalid
	}
	if releaseRecord.Status == release.StatusPublished {
		current, currentErr := service.catalogs.Current(ctx, record.ProductID, record.Channel)
		if currentErr == nil && current.ID == record.ID {
			return nil
		}
		return ErrPublicationStateInvalid
	}
	if releaseRecord.Status != release.StatusPublishing {
		return ErrPublicationStateInvalid
	}

	for _, role := range publicationRoleOrder {
		document := record.Roles[role]
		if err := service.persistRole(ctx, record.ID, document); err != nil {
			return fmt.Errorf("persist %s catalog role: %w", role, err)
		}
	}

	now := service.clock().UTC().Truncate(time.Microsecond)
	return service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if err := service.catalogs.SetCurrent(ctx, tx, record.ProductID, record.Channel, record.ID, now); err != nil {
			return fmt.Errorf("switch current catalog: %w", err)
		}
		if err := service.releases.CompletePublication(ctx, tx, releaseRecord.ID, payload.AttemptID, now); err != nil {
			return fmt.Errorf("complete release publication: %w", err)
		}
		_, err := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor:  workerPrincipal(record.ProductID),
			Action: "catalog.publish.complete", ProductID: record.ProductID,
			ResourceType: "catalog", ResourceID: record.ID.String(), Outcome: audit.OutcomeSuccess,
			RequestID: job.ID.String(), Metadata: map[string]any{
				"release_id": releaseRecord.ID.String(), "attempt_id": payload.AttemptID.String(),
				"bundle_sha256": record.BundleSHA256,
			},
		})
		if err != nil {
			return fmt.Errorf("append catalog publication audit: %w", err)
		}
		return nil
	})
}

func publicationErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrPublicationDigestMismatch), errors.Is(err, objectstore.ErrDigestMismatch):
		return "catalog_digest_mismatch"
	case errors.Is(err, objectstore.ErrConfigurationInvalid), errors.Is(err, objectstore.ErrUploadNotFound),
		errors.Is(err, objectstore.ErrObjectNotFound), errors.Is(err, objectstore.ErrSizeMismatch):
		return "catalog_store_failed"
	case errors.Is(err, ErrSignatureThreshold), errors.Is(err, ErrEnvelopeInvalid), errors.Is(err, ErrTargetInvalid),
		errors.Is(err, ErrRoleDigestMismatch), errors.Is(err, ErrRoleVersionMismatch):
		return "catalog_build_failed"
	case errors.Is(err, ErrPublicationJobInvalid):
		return "catalog_job_invalid"
	default:
		return "catalog_publication_failed"
	}
}

func workerPrincipal(productID string) identity.Principal {
	return identity.Principal{
		Subject: "release-worker", Kind: identity.PrincipalKindWorkload,
		Provider: identity.WorkloadProviderAPIToken, Roles: []identity.Role{identity.RolePublisher},
		ProductIDs: []string{productID},
	}
}

func (service *PublicationService) createPublicationRecord(ctx context.Context, releaseRecord release.Release, attemptID uuid.UUID) (VersionRecord, error) {
	return service.createPublicationRecordWithBuilder(ctx, releaseRecord, attemptID, service.builder.Build)
}

func (service *PublicationService) createPublicationRecordWithBuilder(ctx context.Context, releaseRecord release.Release, attemptID uuid.UUID, build func(context.Context, release.Release, Versions) (Bundle, error)) (VersionRecord, error) {
	var record VersionRecord
	err := service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		versions, err := service.catalogs.ReserveVersions(ctx, tx, releaseRecord.ProductID, releaseRecord.Channel, service.builder.RootVersion())
		if err != nil {
			return err
		}
		bundle, err := build(ctx, releaseRecord, versions)
		if err != nil {
			return fmt.Errorf("build signed catalog: %w", err)
		}
		catalogID, err := uuid.NewV7()
		if err != nil {
			return fmt.Errorf("generate catalog version ID: %w", err)
		}
		record, err = newPublicationRecord(catalogID, attemptID, releaseRecord, versions, bundle, service.clock)
		if err != nil {
			return err
		}
		if err := service.catalogs.Create(ctx, tx, record); err != nil {
			return fmt.Errorf("persist catalog publication record: %w", err)
		}
		return nil
	})
	return record, err
}

func newPublicationRecord(id, attemptID uuid.UUID, releaseRecord release.Release, versions Versions, bundle Bundle, clock Clock) (VersionRecord, error) {
	if id == uuid.Nil || attemptID == uuid.Nil || clock == nil {
		return VersionRecord{}, ErrPublicationConfiguration
	}
	roleVersions := map[Role]uint64{
		RoleRoot: versions.Root, RoleTargets: versions.Targets, RoleSnapshot: versions.Snapshot,
		RoleTimestamp: versions.Timestamp, RoleRevocation: versions.Revocation,
	}
	roles := make(map[Role]RoleDocument, len(publicationRoleOrder))
	bundleHash := sha256.New()
	for _, role := range publicationRoleOrder {
		envelope := append([]byte(nil), bundle.Roles()[role]...)
		if len(envelope) == 0 || len(envelope) > maximumRoleEnvelopeBytes {
			return VersionRecord{}, ErrBundleIncomplete
		}
		signatures, err := publicationSignatures(envelope)
		if err != nil {
			return VersionRecord{}, err
		}
		digest := sha256.Sum256(envelope)
		key := path.Join("catalogs", releaseRecord.ProductID, releaseRecord.Channel, id.String(), string(role)+".json")
		roles[role] = RoleDocument{
			Role: role, Version: roleVersions[role], EnvelopeSHA256: hex.EncodeToString(digest[:]),
			ObjectKey: key, Signatures: signatures, Envelope: envelope,
		}
		_, _ = bundleHash.Write([]byte(role))
		_, _ = bundleHash.Write([]byte{0})
		_, _ = bundleHash.Write(digest[:])
	}
	return VersionRecord{
		ID: id, AttemptID: attemptID, ProductID: releaseRecord.ProductID, Channel: releaseRecord.Channel,
		ReleaseID: releaseRecord.ID, Versions: versions, BundleSHA256: hex.EncodeToString(bundleHash.Sum(nil)),
		Roles: roles, CreatedAt: clock().UTC().Truncate(time.Microsecond),
	}, nil
}

func publicationSignatures(envelope []byte) (json.RawMessage, error) {
	value, err := strictJSONValue(envelope)
	if err != nil {
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, ErrEnvelopeInvalid
	}
	signatures, ok := object["signatures"].([]any)
	if !ok || len(signatures) == 0 {
		return nil, ErrEnvelopeInvalid
	}
	encoded, err := json.Marshal(signatures)
	if err != nil {
		return nil, ErrEnvelopeInvalid
	}
	return encoded, nil
}

func (service *PublicationService) persistRole(ctx context.Context, catalogID uuid.UUID, document RoleDocument) error {
	if len(document.Envelope) == 0 || len(document.Envelope) > maximumRoleEnvelopeBytes {
		return ErrEnvelopeInvalid
	}
	if _, err := service.store.Stat(ctx, document.ObjectKey); err == nil {
		return service.verifyRoleObject(ctx, document)
	} else if !errors.Is(err, objectstore.ErrObjectNotFound) {
		return err
	}

	stagingKey := path.Join("uploads", "catalogs", catalogID.String(), string(document.Role)+".json")
	uploadID, err := service.store.BeginMultipart(ctx, stagingKey, publicationObjectMediaType)
	if err != nil {
		return err
	}
	completed := false
	defer func() {
		if completed {
			_ = service.store.Delete(context.WithoutCancel(ctx), stagingKey)
			return
		}
		_ = service.store.AbortMultipart(context.WithoutCancel(ctx), stagingKey, uploadID)
	}()
	part, err := service.store.PutPart(ctx, stagingKey, uploadID, 1, bytes.NewReader(document.Envelope), int64(len(document.Envelope)), document.EnvelopeSHA256)
	if err != nil {
		return err
	}
	if err := service.store.CompleteMultipart(ctx, stagingKey, uploadID, []objectstore.Part{part}); err != nil {
		return err
	}
	completed = true
	if _, err := service.store.Promote(ctx, stagingKey, document.ObjectKey); err != nil && !errors.Is(err, objectstore.ErrObjectAlreadyExists) {
		return err
	}
	return service.verifyRoleObject(ctx, document)
}

func (service *PublicationService) verifyRoleObject(ctx context.Context, document RoleDocument) error {
	reader, information, err := service.store.Open(ctx, document.ObjectKey, 0, -1)
	if err != nil {
		return err
	}
	defer reader.Close()
	if information.Size != int64(len(document.Envelope)) || information.Size > maximumRoleEnvelopeBytes {
		return ErrPublicationDigestMismatch
	}
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(reader, maximumRoleEnvelopeBytes+1))
	if err != nil {
		return err
	}
	if written != information.Size || !strings.EqualFold(hex.EncodeToString(digest.Sum(nil)), document.EnvelopeSHA256) {
		return ErrPublicationDigestMismatch
	}
	return nil
}

func decodePublicationJob(job jobs.Job) (PublicationJobPayload, error) {
	return decodeCatalogJob(job, JobKindCatalogPublish)
}

func decodeCatalogJob(job jobs.Job, expectedKind string) (PublicationJobPayload, error) {
	if job.ID == uuid.Nil || job.Kind != expectedKind || job.AggregateID == uuid.Nil || len(job.Payload) == 0 {
		return PublicationJobPayload{}, ErrPublicationJobInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(job.Payload))
	decoder.DisallowUnknownFields()
	var payload PublicationJobPayload
	if err := decoder.Decode(&payload); err != nil {
		return PublicationJobPayload{}, ErrPublicationJobInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return PublicationJobPayload{}, ErrPublicationJobInvalid
	}
	if payload.ReleaseID == uuid.Nil || payload.AttemptID == uuid.Nil || payload.ReleaseID != job.AggregateID {
		return PublicationJobPayload{}, ErrPublicationJobInvalid
	}
	return payload, nil
}

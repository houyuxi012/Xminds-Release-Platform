package release

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/artifact"
	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/product"
)

const (
	maximumReleaseNotesBytes  = 1024 * 1024
	maximumCompatibilityBytes = 64 * 1024
	maximumReleaseArtifacts   = 64
)

var (
	semverPattern      = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	commitSHAPattern   = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	digestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$`)
)

type ProductReader interface {
	Get(ctx context.Context, productID string) (product.Product, error)
}

type ArtifactReader interface {
	Get(ctx context.Context, principal identity.Principal, productID string, artifactID uuid.UUID) (artifact.Artifact, error)
}

type AuditAppender interface {
	Append(ctx context.Context, tx pgx.Tx, command audit.AppendCommand) (audit.Event, error)
}

type JobEnqueuer interface {
	Enqueue(ctx context.Context, tx pgx.Tx, job jobs.Job) error
}

type Service struct {
	repository Repository
	transactor Transactor
	products   ProductReader
	artifacts  ArtifactReader
	auditor    AuditAppender
	jobs       JobEnqueuer
	authorizer *identity.Authorizer
	now        func() time.Time
}

func NewService(repository Repository, transactor Transactor, products ProductReader, artifacts ArtifactReader, auditor AuditAppender, jobEnqueuer JobEnqueuer) *Service {
	return &Service{
		repository: repository, transactor: transactor, products: products, artifacts: artifacts,
		auditor: auditor, jobs: jobEnqueuer, authorizer: identity.NewAuthorizer(), now: time.Now,
	}
}

func (service *Service) Create(ctx context.Context, principal identity.Principal, command CreateCommand, request RequestContext) (Release, error) {
	if err := service.validateDependencies(); err != nil {
		return Release{}, err
	}
	command.ProductID = strings.TrimSpace(command.ProductID)
	if err := service.authorizer.Require(principal, identity.ActionReleaseCreate, command.ProductID); err != nil {
		return Release{}, err
	}
	productRecord, err := service.products.Get(ctx, command.ProductID)
	if err != nil {
		return Release{}, err
	}
	if err := validateCreateCommand(command, productRecord); err != nil {
		return Release{}, err
	}
	bindings := make([]ArtifactBinding, 0, len(command.ArtifactIDs))
	seenArtifacts := make(map[uuid.UUID]struct{}, len(command.ArtifactIDs))
	for _, artifactID := range command.ArtifactIDs {
		if artifactID == uuid.Nil {
			return Release{}, ErrArtifactsInvalid
		}
		if _, duplicate := seenArtifacts[artifactID]; duplicate {
			return Release{}, ErrArtifactsInvalid
		}
		seenArtifacts[artifactID] = struct{}{}
		artifactRecord, artifactErr := service.artifacts.Get(ctx, principal, command.ProductID, artifactID)
		if errors.Is(artifactErr, artifact.ErrArtifactNotFound) {
			return Release{}, ErrArtifactProductMismatch
		}
		if artifactErr != nil {
			return Release{}, artifactErr
		}
		if artifactRecord.ProductID != command.ProductID {
			return Release{}, ErrArtifactProductMismatch
		}
		bindings = append(bindings, ArtifactBinding{
			ArtifactID: artifactRecord.ID, ArtifactType: artifactRecord.ArtifactType,
			Filename: artifactRecord.Filename, Size: artifactRecord.Size, SHA256: artifactRecord.SHA256,
		})
	}
	releaseID, err := uuid.NewV7()
	if err != nil {
		return Release{}, fmt.Errorf("generate release ID: %w", err)
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	record := Release{
		ID: releaseID, ProductID: command.ProductID, Channel: strings.TrimSpace(command.Channel),
		Version: strings.TrimSpace(command.Version), Status: StatusDraft, LockVersion: 1,
		ReleaseNotes: string(command.ReleaseNotes), ReleaseNotesSHA256: command.ReleaseNotesSHA256,
		Compatibility: append(json.RawMessage(nil), command.Compatibility...), CompatibilitySHA256: command.CompatibilitySHA256,
		Artifacts: bindings, Source: normalizedSource(command.Source), CreatedBy: strings.TrimSpace(principal.Subject),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if createErr := service.repository.Create(ctx, tx, record); createErr != nil {
			return createErr
		}
		_, appendErr := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: principal, Action: "release.create", ProductID: record.ProductID,
			ResourceType: "release", ResourceID: record.ID.String(), Outcome: audit.OutcomeSuccess,
			RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"channel": record.Channel, "version": record.Version, "artifact_count": len(record.Artifacts)},
		})
		return appendErr
	}); err != nil {
		return Release{}, err
	}
	return record, nil
}

func (service *Service) Submit(ctx context.Context, principal identity.Principal, productID string, releaseID uuid.UUID, expectedLockVersion int64, request RequestContext) (Release, error) {
	return service.transition(ctx, principal, identity.ActionReleaseSubmit, productID, releaseID, expectedLockVersion, StatusSubmitted, "", request)
}

func (service *Service) Approve(ctx context.Context, principal identity.Principal, productID string, releaseID uuid.UUID, expectedLockVersion int64, request RequestContext) (Release, error) {
	if err := service.validateDependencies(); err != nil {
		return Release{}, err
	}
	productID = strings.TrimSpace(productID)
	if err := requireExplicitApprover(principal); err != nil {
		return Release{}, err
	}
	if err := service.authorizer.Require(principal, identity.ActionReleaseApprove, productID); err != nil {
		return Release{}, err
	}
	current, err := service.repository.Get(ctx, productID, releaseID)
	if err != nil {
		return Release{}, err
	}
	if strings.TrimSpace(current.SubmittedBy) == strings.TrimSpace(principal.Subject) {
		return Release{}, ErrSelfApprovalForbidden
	}
	return service.transitionAuthorized(ctx, principal, current, expectedLockVersion, StatusApproved, "", request)
}

func (service *Service) Reject(ctx context.Context, principal identity.Principal, productID string, releaseID uuid.UUID, expectedLockVersion int64, reason string, request RequestContext) (Release, error) {
	if err := service.validateDependencies(); err != nil {
		return Release{}, err
	}
	productID = strings.TrimSpace(productID)
	if err := requireExplicitApprover(principal); err != nil {
		return Release{}, err
	}
	if err := service.authorizer.Require(principal, identity.ActionReleaseApprove, productID); err != nil {
		return Release{}, err
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 2048 || containsControl(reason) {
		return Release{}, ErrRejectionReasonRequired
	}
	current, err := service.repository.Get(ctx, productID, releaseID)
	if err != nil {
		return Release{}, err
	}
	if strings.TrimSpace(current.SubmittedBy) == strings.TrimSpace(principal.Subject) {
		return Release{}, ErrSelfApprovalForbidden
	}
	return service.transitionAuthorized(ctx, principal, current, expectedLockVersion, StatusRejected, reason, request)
}

func (service *Service) Publish(ctx context.Context, principal identity.Principal, productID string, releaseID uuid.UUID, expectedLockVersion int64, idempotencyKey string, request RequestContext) (OperationResult, error) {
	return service.startPublication(ctx, principal, identity.ActionReleasePublish, productID, releaseID, expectedLockVersion, AttemptKindPublish, idempotencyKey, request)
}

func (service *Service) Retry(ctx context.Context, principal identity.Principal, productID string, releaseID uuid.UUID, expectedLockVersion int64, idempotencyKey string, request RequestContext) (OperationResult, error) {
	return service.startPublication(ctx, principal, identity.ActionReleaseApprove, productID, releaseID, expectedLockVersion, AttemptKindRetry, idempotencyKey, request)
}

func (service *Service) Revoke(ctx context.Context, principal identity.Principal, productID string, releaseID uuid.UUID, expectedLockVersion int64, reason string, idempotencyKey string, request RequestContext) (OperationResult, error) {
	if err := service.validateDependencies(); err != nil {
		return OperationResult{}, err
	}
	productID = strings.TrimSpace(productID)
	if err := requireExplicitApprover(principal); err != nil {
		return OperationResult{}, err
	}
	if err := service.authorizer.Require(principal, identity.ActionReleaseApprove, productID); err != nil {
		return OperationResult{}, err
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 2048 || containsControl(reason) {
		return OperationResult{}, ErrRevocationReasonRequired
	}
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if !idempotencyPattern.MatchString(idempotencyKey) {
		return OperationResult{}, ErrIdempotencyKeyInvalid
	}
	if existing, err := service.repository.FindAttempt(ctx, nil, releaseID, AttemptKindRevoke, idempotencyKey); err == nil {
		current, getErr := service.repository.Get(ctx, productID, releaseID)
		return OperationResult{Release: current, Attempt: existing}, getErr
	} else if !errors.Is(err, ErrAttemptNotFound) {
		return OperationResult{}, err
	}
	current, err := service.repository.Get(ctx, productID, releaseID)
	if err != nil {
		return OperationResult{}, err
	}
	if current.RevokedAt != nil {
		return OperationResult{}, ErrReleaseAlreadyRevoked
	}
	if current.Status != StatusPublished {
		return OperationResult{}, ErrInvalidTransition
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	attempt, err := newAttempt(releaseID, AttemptKindRevoke, idempotencyKey, principal.Subject, now)
	if err != nil {
		return OperationResult{}, err
	}
	var updated Release
	var replayed bool
	err = service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var operationErr error
		if operationErr = service.repository.LockOperation(ctx, tx, releaseID, AttemptKindRevoke, idempotencyKey); operationErr != nil {
			return operationErr
		}
		if existing, findErr := service.repository.FindAttempt(ctx, tx, releaseID, AttemptKindRevoke, idempotencyKey); findErr == nil {
			attempt = existing
			replayed = true
			return nil
		} else if !errors.Is(findErr, ErrAttemptNotFound) {
			return findErr
		}
		updated, operationErr = service.repository.Revoke(ctx, tx, RevokeCommand{
			ReleaseID: releaseID, ProductID: productID, ExpectedLockVersion: expectedLockVersion,
			Actor: strings.TrimSpace(principal.Subject), Reason: reason, At: now,
		})
		if operationErr != nil {
			return operationErr
		}
		attempt, operationErr = service.repository.CreateAttempt(ctx, tx, attempt)
		if operationErr != nil {
			return operationErr
		}
		if operationErr = service.enqueueReleaseJob(ctx, tx, "catalog.revoke.v1", attempt, now); operationErr != nil {
			return operationErr
		}
		_, operationErr = service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: principal, Action: "release.revoke", ProductID: productID,
			ResourceType: "release", ResourceID: releaseID.String(), Outcome: audit.OutcomeSuccess,
			RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"attempt_id": attempt.ID.String(), "reason": reason, "lock_version": updated.LockVersion},
		})
		return operationErr
	})
	if err != nil {
		return OperationResult{}, err
	}
	if replayed {
		updated, err = service.repository.Get(ctx, productID, releaseID)
		if err != nil {
			return OperationResult{}, err
		}
	}
	return OperationResult{Release: updated, Attempt: attempt}, nil
}

func (service *Service) startPublication(ctx context.Context, principal identity.Principal, action identity.Action, productID string, releaseID uuid.UUID, expectedLockVersion int64, kind AttemptKind, idempotencyKey string, request RequestContext) (OperationResult, error) {
	if err := service.validateDependencies(); err != nil {
		return OperationResult{}, err
	}
	productID = strings.TrimSpace(productID)
	if kind == AttemptKindRetry {
		if err := requireExplicitApprover(principal); err != nil {
			return OperationResult{}, err
		}
	}
	if err := service.authorizer.Require(principal, action, productID); err != nil {
		return OperationResult{}, err
	}
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if !idempotencyPattern.MatchString(idempotencyKey) {
		return OperationResult{}, ErrIdempotencyKeyInvalid
	}
	if existing, err := service.repository.FindAttempt(ctx, nil, releaseID, kind, idempotencyKey); err == nil {
		current, getErr := service.repository.Get(ctx, productID, releaseID)
		return OperationResult{Release: current, Attempt: existing}, getErr
	} else if !errors.Is(err, ErrAttemptNotFound) {
		return OperationResult{}, err
	}
	current, err := service.repository.Get(ctx, productID, releaseID)
	if err != nil {
		return OperationResult{}, err
	}
	if !TransitionAllowed(current.Status, StatusPublishing) {
		return OperationResult{}, ErrInvalidTransition
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	attempt, err := newAttempt(releaseID, kind, idempotencyKey, principal.Subject, now)
	if err != nil {
		return OperationResult{}, err
	}
	var updated Release
	var replayed bool
	err = service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var operationErr error
		if operationErr = service.repository.LockOperation(ctx, tx, releaseID, kind, idempotencyKey); operationErr != nil {
			return operationErr
		}
		if existing, findErr := service.repository.FindAttempt(ctx, tx, releaseID, kind, idempotencyKey); findErr == nil {
			attempt = existing
			replayed = true
			return nil
		} else if !errors.Is(findErr, ErrAttemptNotFound) {
			return findErr
		}
		updated, operationErr = service.repository.Transition(ctx, tx, TransitionCommand{
			ReleaseID: releaseID, ProductID: productID, From: current.Status, To: StatusPublishing,
			ExpectedLockVersion: expectedLockVersion, Actor: strings.TrimSpace(principal.Subject), At: now,
		})
		if operationErr != nil {
			return operationErr
		}
		attempt, operationErr = service.repository.CreateAttempt(ctx, tx, attempt)
		if operationErr != nil {
			return operationErr
		}
		if operationErr = service.enqueueReleaseJob(ctx, tx, "catalog.publish.v1", attempt, now); operationErr != nil {
			return operationErr
		}
		_, operationErr = service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: principal, Action: "release.publish", ProductID: productID,
			ResourceType: "release", ResourceID: releaseID.String(), Outcome: audit.OutcomeSuccess,
			RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"attempt_id": attempt.ID.String(), "attempt_kind": attempt.Kind, "lock_version": updated.LockVersion},
		})
		return operationErr
	})
	if err != nil {
		return OperationResult{}, err
	}
	if replayed {
		updated, err = service.repository.Get(ctx, productID, releaseID)
		if err != nil {
			return OperationResult{}, err
		}
	}
	return OperationResult{Release: updated, Attempt: attempt}, nil
}

func newAttempt(releaseID uuid.UUID, kind AttemptKind, idempotencyKey string, actor string, now time.Time) (Attempt, error) {
	attemptID, err := uuid.NewV7()
	if err != nil {
		return Attempt{}, fmt.Errorf("generate release attempt ID: %w", err)
	}
	return Attempt{
		ID: attemptID, ReleaseID: releaseID, Kind: kind, IdempotencyKey: idempotencyKey,
		Status: AttemptStatusPending, CreatedBy: strings.TrimSpace(actor), CreatedAt: now,
	}, nil
}

func (service *Service) enqueueReleaseJob(ctx context.Context, tx pgx.Tx, kind string, attempt Attempt, now time.Time) error {
	payload, err := json.Marshal(map[string]string{"release_id": attempt.ReleaseID.String(), "attempt_id": attempt.ID.String()})
	if err != nil {
		return fmt.Errorf("encode release job payload: %w", err)
	}
	job, err := jobs.New(kind, attempt.ReleaseID, payload, now)
	if err != nil {
		return err
	}
	return service.jobs.Enqueue(ctx, tx, job)
}

func (service *Service) Get(ctx context.Context, principal identity.Principal, productID string, releaseID uuid.UUID) (Release, error) {
	if err := service.validateDependencies(); err != nil {
		return Release{}, err
	}
	productID = strings.TrimSpace(productID)
	if err := service.authorizer.Require(principal, identity.ActionProductRead, productID); err != nil {
		return Release{}, err
	}
	return service.repository.Get(ctx, productID, releaseID)
}

func (service *Service) transition(ctx context.Context, principal identity.Principal, action identity.Action, productID string, releaseID uuid.UUID, expectedLockVersion int64, target Status, reason string, request RequestContext) (Release, error) {
	if err := service.validateDependencies(); err != nil {
		return Release{}, err
	}
	productID = strings.TrimSpace(productID)
	if err := service.authorizer.Require(principal, action, productID); err != nil {
		return Release{}, err
	}
	current, err := service.repository.Get(ctx, productID, releaseID)
	if err != nil {
		return Release{}, err
	}
	return service.transitionAuthorized(ctx, principal, current, expectedLockVersion, target, reason, request)
}

func (service *Service) transitionAuthorized(ctx context.Context, principal identity.Principal, current Release, expectedLockVersion int64, target Status, reason string, request RequestContext) (Release, error) {
	if !TransitionAllowed(current.Status, target) {
		return Release{}, ErrInvalidTransition
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	var updated Release
	err := service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		var transitionErr error
		updated, transitionErr = service.repository.Transition(ctx, tx, TransitionCommand{
			ReleaseID: current.ID, ProductID: current.ProductID, From: current.Status, To: target,
			ExpectedLockVersion: expectedLockVersion, Actor: strings.TrimSpace(principal.Subject), Reason: reason, At: now,
		})
		if transitionErr != nil {
			return transitionErr
		}
		_, transitionErr = service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: principal, Action: releaseAuditAction(target), ProductID: current.ProductID,
			ResourceType: "release", ResourceID: current.ID.String(), Outcome: audit.OutcomeSuccess,
			RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"from": current.Status, "to": target, "lock_version": updated.LockVersion},
		})
		return transitionErr
	})
	if err != nil {
		return Release{}, err
	}
	return updated, nil
}

func (service *Service) validateDependencies() error {
	switch {
	case service == nil || service.repository == nil:
		return ErrRepositoryRequired
	case service.transactor == nil:
		return ErrTransactorRequired
	case service.products == nil:
		return ErrProductReaderRequired
	case service.artifacts == nil:
		return ErrArtifactReaderRequired
	case service.auditor == nil:
		return ErrAuditAppenderRequired
	case service.jobs == nil:
		return ErrJobEnqueuerRequired
	default:
		return nil
	}
}

func validateCreateCommand(command CreateCommand, productRecord product.Product) error {
	if productRecord.ID != command.ProductID || productRecord.Status != product.ProductStatusActive || productRecord.VersionScheme != "semver" {
		return ErrProductInvalid
	}
	channel := strings.TrimSpace(command.Channel)
	if channel == "" || !productHasChannel(productRecord, channel) {
		return ErrChannelInvalid
	}
	version := strings.TrimSpace(command.Version)
	if version != command.Version || !semverPattern.MatchString(version) {
		return ErrVersionInvalid
	}
	if len(command.ReleaseNotes) == 0 || len(command.ReleaseNotes) > maximumReleaseNotesBytes || !utf8.Valid(command.ReleaseNotes) {
		return ErrReleaseNotesInvalid
	}
	if !validDigest(command.ReleaseNotes, command.ReleaseNotesSHA256) {
		return ErrReleaseNotesMismatch
	}
	if len(command.Compatibility) == 0 || len(command.Compatibility) > maximumCompatibilityBytes {
		return ErrCompatibilityInvalid
	}
	if !validDigest(command.Compatibility, command.CompatibilitySHA256) {
		return ErrCompatibilityMismatch
	}
	if err := validateCompatibility(command.Compatibility, productRecord.CompatibilityKeys); err != nil {
		return err
	}
	if len(command.ArtifactIDs) == 0 || len(command.ArtifactIDs) > maximumReleaseArtifacts {
		return ErrArtifactsInvalid
	}
	if err := validateSource(command.Source); err != nil {
		return err
	}
	return nil
}

func validateCompatibility(payload []byte, requiredKeys []string) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := validateUniqueJSONValue(decoder); err != nil {
		return ErrCompatibilityInvalid
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrCompatibilityInvalid
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(payload, &values); err != nil || values == nil || len(values) != len(requiredKeys) {
		return ErrCompatibilityInvalid
	}
	for _, key := range requiredKeys {
		value, exists := values[key]
		if !exists || len(value) == 0 || string(value) == "null" {
			return ErrCompatibilityInvalid
		}
	}
	return nil
}

func validateUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrCompatibilityInvalid
			}
			if _, duplicate := seen[key]; duplicate {
				return ErrCompatibilityInvalid
			}
			seen[key] = struct{}{}
			if valueErr := validateUniqueJSONValue(decoder); valueErr != nil {
				return valueErr
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return ErrCompatibilityInvalid
		}
	case '[':
		for decoder.More() {
			if valueErr := validateUniqueJSONValue(decoder); valueErr != nil {
				return valueErr
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return ErrCompatibilityInvalid
		}
	default:
		return ErrCompatibilityInvalid
	}
	return nil
}

func validateSource(source Source) error {
	normalized := normalizedSource(source)
	if normalized.Repository == "" || len(normalized.Repository) > 2048 ||
		!commitSHAPattern.MatchString(normalized.CommitSHA) || normalized.Tag == "" || len(normalized.Tag) > 255 ||
		normalized.PipelineRef == "" || len(normalized.PipelineRef) > 512 ||
		containsControl(normalized.Repository) || containsControl(normalized.Tag) || containsControl(normalized.PipelineRef) {
		return ErrSourceInvalid
	}
	return nil
}

func normalizedSource(source Source) Source {
	return Source{
		Repository: strings.TrimSpace(source.Repository), CommitSHA: strings.TrimSpace(source.CommitSHA),
		Tag: strings.TrimSpace(source.Tag), PipelineRef: strings.TrimSpace(source.PipelineRef),
	}
}

func validDigest(payload []byte, declared string) bool {
	if !digestPattern.MatchString(declared) {
		return false
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]) == declared
}

func productHasChannel(record product.Product, channel string) bool {
	for _, candidate := range record.Channels {
		if candidate.ProductID == record.ID && candidate.Name == channel {
			return true
		}
	}
	return false
}

func containsControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}

func releaseAuditAction(target Status) string {
	switch target {
	case StatusSubmitted:
		return "release.submit"
	case StatusApproved:
		return "release.approve"
	case StatusRejected:
		return "release.reject"
	case StatusPublishing:
		return "release.publish"
	case StatusPublished:
		return "release.complete"
	case StatusFailed:
		return "release.fail"
	default:
		return "release.transition"
	}
}

func requireExplicitApprover(principal identity.Principal) error {
	for _, role := range principal.Roles {
		if role == identity.RoleApprover {
			return nil
		}
	}
	return identity.ErrActionDenied
}

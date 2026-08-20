package iam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/jobs"
)

const JobKindDirectorySync = "iam.directory.sync.v1"

type DirectorySyncMode string

const (
	DirectorySyncModePreview DirectorySyncMode = "preview"
	DirectorySyncModeApply   DirectorySyncMode = "apply"
)

type DirectorySyncStatus string

const (
	DirectorySyncStatusPending   DirectorySyncStatus = "pending"
	DirectorySyncStatusRunning   DirectorySyncStatus = "running"
	DirectorySyncStatusCompleted DirectorySyncStatus = "completed"
	DirectorySyncStatusFailed    DirectorySyncStatus = "failed"
)

type DirectorySyncPhase string

const (
	DirectorySyncPhaseFetch         DirectorySyncPhase = "fetch"
	DirectorySyncPhasePrepare       DirectorySyncPhase = "prepare"
	DirectorySyncPhaseUsers         DirectorySyncPhase = "apply_users"
	DirectorySyncPhaseOrganizations DirectorySyncPhase = "apply_organizations"
	DirectorySyncPhaseMemberships   DirectorySyncPhase = "apply_memberships"
	DirectorySyncPhaseFinalize      DirectorySyncPhase = "finalize"
)

var (
	ErrDirectorySyncConfiguration = errors.New("directory synchronization configuration is invalid")
	ErrDirectorySyncActive        = errors.New("an active directory synchronization already exists")
	ErrDirectorySyncNotFound      = errors.New("directory synchronization job was not found")
	ErrDirectoryConflictNotFound  = errors.New("directory synchronization conflict was not found")
	ErrDirectoryApplyUnsupported  = errors.New("directory apply is not supported for this identity source")
	ErrDirectorySourceChanged     = errors.New("identity source changed during directory synchronization")
)

type DirectorySyncJob struct {
	ID                     uuid.UUID           `json:"id"`
	IdentitySourceID       uuid.UUID           `json:"identity_source_id"`
	SourceVersion          int64               `json:"source_version"`
	RunMarker              uuid.UUID           `json:"-"`
	Mode                   DirectorySyncMode   `json:"mode"`
	Status                 DirectorySyncStatus `json:"status"`
	Phase                  DirectorySyncPhase  `json:"-"`
	CreateCount            int                 `json:"create_count"`
	UpdateCount            int                 `json:"update_count"`
	DisableCount           int                 `json:"disable_count"`
	ConflictCount          int                 `json:"conflict_count"`
	ProcessedUsers         int                 `json:"processed_users"`
	ProcessedOrganizations int                 `json:"processed_organizations"`
	ProcessedMemberships   int                 `json:"processed_memberships"`
	ErrorCode              string              `json:"error_code,omitempty"`
	RequestedBy            string              `json:"requested_by"`
	RequestID              uuid.UUID           `json:"request_id"`
	CreatedAt              time.Time           `json:"created_at"`
	UpdatedAt              time.Time           `json:"updated_at"`
	CompletedAt            time.Time           `json:"completed_at,omitempty"`
	Cursor                 string              `json:"-"`
}

type DirectorySyncJobPayload struct {
	JobID    uuid.UUID         `json:"job_id"`
	SourceID uuid.UUID         `json:"source_id"`
	Mode     DirectorySyncMode `json:"mode"`
}

type DirectorySyncConflict struct {
	ID               uuid.UUID       `json:"id"`
	SyncJobID        uuid.UUID       `json:"sync_job_id"`
	IdentitySourceID uuid.UUID       `json:"identity_source_id"`
	ObjectType       string          `json:"object_type"`
	ExternalID       string          `json:"external_id"`
	Code             string          `json:"code"`
	Details          json.RawMessage `json:"details"`
	Status           string          `json:"status"`
	CreatedAt        time.Time       `json:"created_at"`
}

type DirectorySyncConflictPage struct {
	Items      []DirectorySyncConflict `json:"items"`
	NextCursor string                  `json:"next_cursor,omitempty"`
}

type DirectorySyncStore interface {
	WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error
	GetIdentitySource(ctx context.Context, tx pgx.Tx, id uuid.UUID) (IdentitySource, error)
	InsertDirectorySyncJob(ctx context.Context, tx pgx.Tx, job DirectorySyncJob) error
	GetDirectorySyncJob(ctx context.Context, sourceID, jobID uuid.UUID) (DirectorySyncJob, error)
	ListDirectorySyncConflicts(ctx context.Context, sourceID uuid.UUID, page Page) (DirectorySyncConflictPage, error)
}

type DirectorySyncJobEnqueuer interface {
	Enqueue(ctx context.Context, tx pgx.Tx, job jobs.Job) error
}

type DirectorySyncServiceConfig struct {
	Store   DirectorySyncStore
	Jobs    DirectorySyncJobEnqueuer
	Auditor AuditAppender
	Clock   func() time.Time
}

type DirectorySyncService struct {
	store      DirectorySyncStore
	jobs       DirectorySyncJobEnqueuer
	auditor    AuditAppender
	authorizer *identity.Authorizer
	clock      func() time.Time
}

func NewDirectorySyncService(config DirectorySyncServiceConfig) (*DirectorySyncService, error) {
	if config.Store == nil || config.Jobs == nil || config.Auditor == nil || config.Clock == nil {
		return nil, ErrDirectorySyncConfiguration
	}
	return &DirectorySyncService{store: config.Store, jobs: config.Jobs, auditor: config.Auditor, authorizer: identity.NewAuthorizer(), clock: config.Clock}, nil
}

func (service *DirectorySyncService) Start(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, mode DirectorySyncMode, expectedVersion int64, request RequestContext) (DirectorySyncJob, error) {
	if service == nil || service.store == nil || service.jobs == nil || service.auditor == nil || service.authorizer == nil || service.clock == nil {
		return DirectorySyncJob{}, ErrDirectorySyncConfiguration
	}
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return DirectorySyncJob{}, err
	}
	requestID, err := uuid.Parse(strings.TrimSpace(request.RequestID))
	if sourceID == uuid.Nil || expectedVersion < 1 || (mode != DirectorySyncModePreview && mode != DirectorySyncModeApply) || err != nil {
		return DirectorySyncJob{}, ErrIdentitySourceInputInvalid
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	jobID, err := uuid.NewV7()
	if err != nil {
		return DirectorySyncJob{}, fmt.Errorf("generate directory sync job ID: %w", err)
	}
	runMarker, err := uuid.NewV7()
	if err != nil {
		return DirectorySyncJob{}, fmt.Errorf("generate directory sync run marker: %w", err)
	}
	created := DirectorySyncJob{
		ID: jobID, IdentitySourceID: sourceID, SourceVersion: expectedVersion, RunMarker: runMarker,
		Mode: mode, Status: DirectorySyncStatusPending, Phase: DirectorySyncPhaseFetch,
		RequestedBy: actor.Subject, RequestID: requestID, CreatedAt: now, UpdatedAt: now,
	}
	err = service.store.WithinTransaction(ctx, func(tx pgx.Tx) error {
		source, getErr := service.store.GetIdentitySource(ctx, tx, sourceID)
		if getErr != nil {
			return getErr
		}
		if source.Version != expectedVersion {
			return ErrIAMConflict
		}
		if source.Status != IdentitySourceStatusVerified || source.VerifiedAt.IsZero() {
			return ErrIdentitySourceInputInvalid
		}
		if mode == DirectorySyncModeApply && source.Kind != IdentitySourceSCIM {
			return ErrDirectoryApplyUnsupported
		}
		if insertErr := service.store.InsertDirectorySyncJob(ctx, tx, created); insertErr != nil {
			return insertErr
		}
		payload, marshalErr := json.Marshal(DirectorySyncJobPayload{JobID: created.ID, SourceID: sourceID, Mode: mode})
		if marshalErr != nil {
			return fmt.Errorf("encode directory sync job payload: %w", marshalErr)
		}
		outboxJob, jobErr := jobs.New(JobKindDirectorySync, created.ID, payload, now)
		if jobErr != nil {
			return jobErr
		}
		if enqueueErr := service.jobs.Enqueue(ctx, tx, outboxJob); enqueueErr != nil {
			return enqueueErr
		}
		action := "identity.directory_sync." + string(mode) + ".request"
		_, appendErr := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: actor, Action: action, ResourceType: "directory_sync_job", ResourceID: created.ID.String(),
			Outcome: audit.OutcomeSuccess, RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"identity_source_id": sourceID.String(), "source_version": expectedVersion, "mode": mode},
		})
		return appendErr
	})
	if err != nil {
		return DirectorySyncJob{}, err
	}
	return redactDirectorySyncJob(created), nil
}

func (service *DirectorySyncService) GetJob(ctx context.Context, actor identity.Principal, sourceID, jobID uuid.UUID) (DirectorySyncJob, error) {
	if service == nil || service.authorizer == nil || sourceID == uuid.Nil || jobID == uuid.Nil {
		return DirectorySyncJob{}, ErrDirectorySyncNotFound
	}
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return DirectorySyncJob{}, err
	}
	job, err := service.store.GetDirectorySyncJob(ctx, sourceID, jobID)
	if err != nil {
		return DirectorySyncJob{}, err
	}
	return redactDirectorySyncJob(job), nil
}

func (service *DirectorySyncService) ListConflicts(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, page Page) (DirectorySyncConflictPage, error) {
	if service == nil || service.authorizer == nil || sourceID == uuid.Nil {
		return DirectorySyncConflictPage{}, ErrDirectorySyncNotFound
	}
	if err := service.authorizer.Require(actor, identity.ActionIdentityManage, ""); err != nil {
		return DirectorySyncConflictPage{}, err
	}
	if !validIAMPage(page) {
		return DirectorySyncConflictPage{}, ErrPageInvalid
	}
	if _, err := service.store.GetIdentitySource(ctx, nil, sourceID); err != nil {
		return DirectorySyncConflictPage{}, err
	}
	return service.store.ListDirectorySyncConflicts(ctx, sourceID, page)
}

func redactDirectorySyncJob(job DirectorySyncJob) DirectorySyncJob {
	job.Cursor = ""
	job.RunMarker = uuid.Nil
	job.Phase = ""
	return job
}

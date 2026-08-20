package iam

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/platform/strictjson"
)

const (
	defaultDirectorySyncMaximumTransitions = 20_000
	defaultDirectorySyncOperationTimeout   = 10 * time.Second
	maximumDirectorySyncOperationTimeout   = 30 * time.Second
)

var directorySyncErrorCodePattern = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)

type DirectorySyncExecutor interface {
	Load(ctx context.Context, jobID, sourceID uuid.UUID) (DirectorySyncJob, IdentitySource, error)
	Stage(ctx context.Context, job DirectorySyncJob, source IdentitySource, page SyncPage) error
	Advance(ctx context.Context, job DirectorySyncJob, source IdentitySource) (DirectorySyncJob, error)
	Fail(ctx context.Context, jobID, sourceID uuid.UUID, code string) error
}

type DirectorySyncTransactionalFailureExecutor interface {
	FailWithinTransaction(ctx context.Context, tx pgx.Tx, jobID, sourceID uuid.UUID, code string) error
}

type DirectorySyncHandlerConfig struct {
	Executor           DirectorySyncExecutor
	Directory          DirectoryAdapter
	MaximumTransitions int
	OperationTimeout   time.Duration
}

type DirectorySyncHandler struct {
	executor           DirectorySyncExecutor
	directory          DirectoryAdapter
	maximumTransitions int
	operationTimeout   time.Duration
}

func NewDirectorySyncHandler(config DirectorySyncHandlerConfig) (*DirectorySyncHandler, error) {
	if config.MaximumTransitions == 0 {
		config.MaximumTransitions = defaultDirectorySyncMaximumTransitions
	}
	if config.OperationTimeout == 0 {
		config.OperationTimeout = defaultDirectorySyncOperationTimeout
	}
	if config.Executor == nil || config.Directory == nil || config.MaximumTransitions < 5 || config.MaximumTransitions > defaultDirectorySyncMaximumTransitions {
		return nil, ErrDirectorySyncConfiguration
	}
	if config.OperationTimeout <= 0 || config.OperationTimeout > maximumDirectorySyncOperationTimeout {
		return nil, ErrDirectorySyncConfiguration
	}
	return &DirectorySyncHandler{
		executor: config.Executor, directory: config.Directory,
		maximumTransitions: config.MaximumTransitions, operationTimeout: config.OperationTimeout,
	}, nil
}

func (handler *DirectorySyncHandler) Handle(ctx context.Context, outboxJob jobs.Job) error {
	if handler == nil || ctx == nil {
		return jobs.NewCodedError("directory_job_invalid", ErrDirectorySyncConfiguration)
	}
	ctx, cancel := context.WithTimeout(ctx, handler.operationTimeout)
	defer cancel()
	payload, err := decodeDirectorySyncJob(outboxJob)
	if err != nil {
		return jobs.NewCodedError("directory_job_invalid", ErrDirectorySyncConfiguration)
	}
	for transition := 0; transition < handler.maximumTransitions; transition++ {
		job, source, err := handler.executor.Load(ctx, payload.JobID, payload.SourceID)
		if err != nil {
			return jobs.NewCodedError("directory_job_load_failed", ErrDirectorySyncConfiguration)
		}
		if job.Status == DirectorySyncStatusCompleted {
			return nil
		}
		if job.Status == DirectorySyncStatusFailed {
			return jobs.NewCodedError(stableDirectorySyncFailureCode(job.ErrorCode), ErrDirectorySyncConfiguration)
		}
		if job.SourceVersion != source.Version || source.Status != IdentitySourceStatusVerified {
			if err := handler.executor.Fail(ctx, payload.JobID, payload.SourceID, "directory_source_changed"); err != nil {
				return jobs.NewCodedError("directory_job_fail_transition_failed", ErrDirectorySyncConfiguration)
			}
			return nil
		}
		if job.Mode != payload.Mode || job.IdentitySourceID != payload.SourceID || job.ID != payload.JobID {
			return jobs.NewCodedError("directory_job_invalid", ErrDirectorySyncConfiguration)
		}
		if job.Phase == DirectorySyncPhaseFetch {
			var page SyncPage
			if source.Kind == IdentitySourceOIDC {
				if job.Mode != DirectorySyncModePreview {
					if err := handler.executor.Fail(ctx, payload.JobID, payload.SourceID, "directory_apply_unsupported"); err != nil {
						return jobs.NewCodedError("directory_job_fail_transition_failed", ErrDirectorySyncConfiguration)
					}
					return nil
				}
				page.Complete = true
			} else {
				page, err = handler.directory.Sync(ctx, source, job.Cursor)
				if err != nil {
					return jobs.NewCodedError(directoryAdapterJobErrorCode(err), ErrDirectoryUpstreamRejected)
				}
			}
			if err := handler.executor.Stage(ctx, job, source, page); err != nil {
				if errors.Is(err, ErrDirectorySourceChanged) {
					if failErr := handler.executor.Fail(ctx, payload.JobID, payload.SourceID, "directory_source_changed"); failErr != nil {
						return jobs.NewCodedError("directory_job_fail_transition_failed", ErrDirectorySyncConfiguration)
					}
					return nil
				}
				return jobs.NewCodedError("directory_stage_failed", ErrDirectorySyncConfiguration)
			}
			continue
		}
		advanced, err := handler.executor.Advance(ctx, job, source)
		if err != nil {
			if errors.Is(err, ErrDirectorySourceChanged) {
				if failErr := handler.executor.Fail(ctx, payload.JobID, payload.SourceID, "directory_source_changed"); failErr != nil {
					return jobs.NewCodedError("directory_job_fail_transition_failed", ErrDirectorySyncConfiguration)
				}
				return nil
			}
			return jobs.NewCodedError("directory_apply_failed", ErrDirectorySyncConfiguration)
		}
		if advanced.Status == DirectorySyncStatusCompleted || advanced.Status == DirectorySyncStatusFailed {
			return nil
		}
	}
	return jobs.NewCodedError("directory_transition_limit_exceeded", ErrDirectoryLimitExceeded)
}

func (handler *DirectorySyncHandler) HandleDeadLetter(ctx context.Context, outboxJob jobs.Job, code string) error {
	payload, err := decodeDirectorySyncJob(outboxJob)
	if err != nil {
		return ErrDirectorySyncConfiguration
	}
	code = stableDirectorySyncFailureCode(code)
	return handler.executor.Fail(ctx, payload.JobID, payload.SourceID, code)
}

func (handler *DirectorySyncHandler) HandleDeadLetterTx(ctx context.Context, tx pgx.Tx, outboxJob jobs.Job, code string) error {
	if handler == nil {
		return ErrDirectorySyncConfiguration
	}
	payload, err := decodeDirectorySyncJob(outboxJob)
	if err != nil {
		return ErrDirectorySyncConfiguration
	}
	executor, ok := handler.executor.(DirectorySyncTransactionalFailureExecutor)
	if !ok {
		return ErrDirectorySyncConfiguration
	}
	code = stableDirectorySyncFailureCode(code)
	return executor.FailWithinTransaction(ctx, tx, payload.JobID, payload.SourceID, code)
}

func stableDirectorySyncFailureCode(code string) string {
	code = strings.TrimSpace(code)
	if !directorySyncErrorCodePattern.MatchString(code) || len(code) > 128 {
		return "directory_sync_failed"
	}
	return code
}

func decodeDirectorySyncJob(outboxJob jobs.Job) (DirectorySyncJobPayload, error) {
	if outboxJob.ID == uuid.Nil || outboxJob.AggregateID == uuid.Nil || outboxJob.Kind != JobKindDirectorySync || len(outboxJob.Payload) == 0 || len(outboxJob.Payload) > 2048 {
		return DirectorySyncJobPayload{}, ErrDirectorySyncConfiguration
	}
	var payload DirectorySyncJobPayload
	if err := strictjson.DecodeBytes(outboxJob.Payload, 2048, &payload); err != nil {
		return DirectorySyncJobPayload{}, ErrDirectorySyncConfiguration
	}
	if payload.JobID == uuid.Nil || payload.SourceID == uuid.Nil || payload.JobID != outboxJob.AggregateID ||
		(payload.Mode != DirectorySyncModePreview && payload.Mode != DirectorySyncModeApply) {
		return DirectorySyncJobPayload{}, ErrDirectorySyncConfiguration
	}
	return payload, nil
}

func directoryAdapterJobErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrDirectoryConfigurationInvalid):
		return "directory_configuration_invalid"
	case errors.Is(err, ErrDirectoryResponseInvalid):
		return "directory_response_invalid"
	case errors.Is(err, ErrDirectoryLimitExceeded):
		return "directory_limit_exceeded"
	case errors.Is(err, ErrDirectoryCursorInvalid):
		return "directory_cursor_invalid"
	default:
		return "directory_upstream_rejected"
	}
}

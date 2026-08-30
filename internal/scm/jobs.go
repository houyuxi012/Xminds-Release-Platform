package scm

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/release"
)

const StatusWritebackJobKind = "scm.status.writeback.v1"

type StatusWritebackPayload struct {
	ConnectionID uuid.UUID   `json:"connection_id"`
	Repository   string      `json:"repository"`
	SHA          string      `json:"sha"`
	State        CommitState `json:"state"`
	Context      string      `json:"context"`
	Description  string      `json:"description"`
	TargetURL    string      `json:"target_url,omitempty"`
}

type JobEnqueuer interface {
	Enqueue(ctx context.Context, tx pgx.Tx, job jobs.Job) error
}

func EnqueueStatusWriteback(ctx context.Context, tx pgx.Tx, enqueuer JobEnqueuer, aggregateID, connectionID uuid.UUID, status CommitStatus, availableAt time.Time) error {
	if enqueuer == nil || aggregateID == uuid.Nil || connectionID == uuid.Nil || availableAt.IsZero() {
		return ErrProviderRequestFailed
	}
	payload, err := json.Marshal(StatusWritebackPayload{
		ConnectionID: connectionID, Repository: status.Repository, SHA: status.SHA, State: status.State,
		Context: status.Context, Description: status.Description, TargetURL: status.TargetURL,
	})
	if err != nil {
		return errors.Join(ErrProviderRequestFailed, err)
	}
	job, err := jobs.New(StatusWritebackJobKind, aggregateID, payload, availableAt.UTC())
	if err != nil {
		return err
	}
	return enqueuer.Enqueue(ctx, tx, job)
}

func ReleaseSourceFromWebhook(event WebhookEvent) (release.Source, error) {
	if !repositoryPattern.MatchString(event.Repository) || !commitSHAPattern.MatchString(event.CommitSHA) {
		return release.Source{}, ErrWebhookEventInvalid
	}
	return release.Source{
		Repository: event.Repository, CommitSHA: event.CommitSHA, Tag: event.Tag,
		PipelineRef: event.PipelineID,
	}, nil
}

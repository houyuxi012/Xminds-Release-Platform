package scm

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/platform/jobs"
)

func TestEnqueueStatusWritebackCreatesVersionedDurableJob(t *testing.T) {
	t.Parallel()

	recorder := &recordingSCMJobs{}
	aggregateID := uuid.New()
	connectionID := uuid.New()
	err := EnqueueStatusWriteback(context.Background(), nil, recorder, aggregateID, connectionID, CommitStatus{
		Repository: "acme/ngep", SHA: "abcdefabcdefabcdefabcdefabcdefabcdefabcd", State: CommitStateSuccess,
		Context: "xminds/release", Description: "Published", TargetURL: "https://release.example/releases/42",
	}, time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(recorder.jobs) != 1 || recorder.jobs[0].Kind != StatusWritebackJobKind || recorder.jobs[0].AggregateID != aggregateID {
		t.Fatalf("jobs = %#v", recorder.jobs)
	}
	var payload StatusWritebackPayload
	if err := json.Unmarshal(recorder.jobs[0].Payload, &payload); err != nil || payload.ConnectionID != connectionID || payload.State != CommitStateSuccess {
		t.Fatalf("payload = %+v, %v", payload, err)
	}
}

type recordingSCMJobs struct{ jobs []jobs.Job }

func (recorder *recordingSCMJobs) Enqueue(_ context.Context, _ pgx.Tx, job jobs.Job) error {
	recorder.jobs = append(recorder.jobs, job)
	return nil
}

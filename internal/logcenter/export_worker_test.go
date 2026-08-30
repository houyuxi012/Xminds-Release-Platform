package logcenter

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"xminds-release-platform/internal/platform/jobs"
)

func TestDecodeLogExportJobRequiresMatchingAggregate(t *testing.T) {
	exportID := uuid.New()
	job := jobs.Job{
		ID:          uuid.New(),
		Kind:        exportJobKind,
		AggregateID: exportID,
		Payload:     json.RawMessage(`{"export_id":"` + exportID.String() + `"}`),
	}
	payload, err := decodeLogExportJob(job)
	if err != nil || payload.ExportID != exportID {
		t.Fatalf("payload=%+v err=%v", payload, err)
	}
	job.AggregateID = uuid.New()
	if _, err := decodeLogExportJob(job); err == nil {
		t.Fatal("mismatched aggregate was accepted")
	}
	job.AggregateID = exportID
	job.Payload = json.RawMessage(`{"export_id":"` + exportID.String() + `","export_job_id":"` + uuid.NewString() + `"}`)
	if _, err := decodeLogExportJob(job); err == nil {
		t.Fatal("untrusted export job identifier was accepted")
	}
}

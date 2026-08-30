package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/jobs"
)

type memoryRepository struct {
	appended []Event
	exports  map[uuid.UUID]Export
}

func (repository *memoryRepository) Append(_ context.Context, _ pgx.Tx, event Event) (Event, error) {
	event.PreviousHash = zeroHash
	event.EventHash = "1f4e9b4d9f6f972f2df8c3a4d3e672b4c67cce30267b666e471a4e8f70e8c264"
	repository.appended = append(repository.appended, event)
	return event, nil
}

func (repository *memoryRepository) Query(context.Context, QueryFilter) ([]Event, error) {
	return append([]Event(nil), repository.appended...), nil
}

func (repository *memoryRepository) StartExport(_ context.Context, _ pgx.Tx, export Export) error {
	if repository.exports == nil {
		repository.exports = make(map[uuid.UUID]Export)
	}
	repository.exports[export.ID] = export
	return nil
}

func (repository *memoryRepository) GetExport(_ context.Context, id uuid.UUID) (Export, error) {
	export, exists := repository.exports[id]
	if !exists {
		return Export{}, ErrExportNotFound
	}
	return export, nil
}

type memoryJobEnqueuer struct {
	jobs []jobs.Job
}

func (enqueuer *memoryJobEnqueuer) Enqueue(_ context.Context, _ pgx.Tx, job jobs.Job) error {
	enqueuer.jobs = append(enqueuer.jobs, job)
	return nil
}

func TestAppendRedactsSensitiveMetadataAndSnapshotsActor(t *testing.T) {
	t.Parallel()

	repository := &memoryRepository{}
	service := NewService(repository)
	principal := identity.Principal{
		Subject:    "alice",
		Kind:       identity.PrincipalKindHuman,
		Roles:      []identity.Role{identity.RoleApprover},
		ProductIDs: []string{"product-a"},
		TokenID:    "token-1",
	}
	event, err := service.Append(context.Background(), nil, AppendCommand{
		Actor:        principal,
		Action:       "release.approve",
		ProductID:    "product-a",
		ResourceType: "release",
		ResourceID:   "release-2026.08.14",
		Outcome:      OutcomeSuccess,
		RequestID:    "018f835d-7e4b-7abc-9f42-67a2f5f48e01",
		SourceIP:     "192.0.2.10",
		Metadata: map[string]any{
			"channel": "stable",
			"nested": map[string]any{
				"client_secret": "must-not-leak",
			},
		},
	})
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}

	principal.Roles[0] = identity.RolePublisher
	principal.ProductIDs[0] = "product-b"
	if event.ActorRoles[0] != identity.RoleApprover || event.ActorProductIDs[0] != "product-a" {
		t.Fatalf("actor snapshot mutated: %#v", event)
	}
	if string(event.Metadata) != `{"channel":"stable","nested":{"client_secret":"[REDACTED]"}}` {
		t.Fatalf("metadata = %s", event.Metadata)
	}
	if event.ID.Version() != 7 || event.EventHash == "" || event.PreviousHash == "" {
		t.Fatalf("event identity/hash fields = %#v", event)
	}
}

func TestAppendRejectsInvalidRequestID(t *testing.T) {
	t.Parallel()

	service := NewService(&memoryRepository{})
	_, err := service.Append(context.Background(), nil, AppendCommand{
		Actor:        identity.Principal{Subject: "alice", Kind: identity.PrincipalKindHuman},
		Action:       "release.approve",
		ProductID:    "product-a",
		ResourceType: "release",
		ResourceID:   "release-1",
		Outcome:      OutcomeSuccess,
		RequestID:    "not-a-uuid",
		Metadata:     map[string]any{},
	})
	if !errors.Is(err, ErrRequestIDInvalid) {
		t.Fatalf("Append() error = %v, want %v", err, ErrRequestIDInvalid)
	}
}

func TestAppendSnapshotsWorkloadProvider(t *testing.T) {
	t.Parallel()

	service := NewService(&memoryRepository{})
	event, err := service.Append(context.Background(), nil, AppendCommand{
		Actor: identity.Principal{
			Subject:  "ci-release",
			Kind:     identity.PrincipalKindWorkload,
			Provider: identity.WorkloadProviderGitHubActions,
		},
		Action:       "release.submit",
		ProductID:    "product-a",
		ResourceType: "release",
		ResourceID:   "release-1",
		Outcome:      OutcomeSuccess,
		RequestID:    "018f835d-7e4b-7abc-9f42-67a2f5f48e01",
		Metadata:     map[string]any{},
	})
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if event.ActorProvider != identity.WorkloadProviderGitHubActions {
		t.Fatalf("ActorProvider = %q", event.ActorProvider)
	}
}

func TestQueryRejectsAuditorOutsideProductScope(t *testing.T) {
	t.Parallel()

	service := NewService(&memoryRepository{})
	principal := identity.Principal{
		Subject:    "auditor-1",
		Kind:       identity.PrincipalKindHuman,
		Roles:      []identity.Role{identity.RoleAuditor},
		ProductIDs: []string{"product-a"},
	}
	_, err := service.Query(context.Background(), principal, QueryFilter{ProductID: "product-b", Limit: 100})
	if !errors.Is(err, identity.ErrProductScopeDenied) {
		t.Fatalf("Query() error = %v, want %v", err, identity.ErrProductScopeDenied)
	}
}

func TestStartExportPersistsRequestEnqueuesJobAndAuditsAction(t *testing.T) {
	t.Parallel()

	repository := &memoryRepository{}
	jobEnqueuer := &memoryJobEnqueuer{}
	service := NewService(repository, jobEnqueuer)
	principal := identity.Principal{
		Subject:    "auditor-1",
		Kind:       identity.PrincipalKindHuman,
		Roles:      []identity.Role{identity.RoleAuditor},
		ProductIDs: []string{"product-a"},
		TokenID:    "token-auditor-1",
	}
	export, err := service.StartExport(context.Background(), nil, StartExportCommand{
		Actor:     principal,
		ProductID: "product-a",
		Filter: QueryFilter{
			Action: "release.approve",
			Since:  time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
			Until:  time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC),
		},
		RequestID: "018f835d-7e4b-7abc-9f42-67a2f5f48e01",
		SourceIP:  "192.0.2.10",
	})
	if err != nil {
		t.Fatalf("StartExport() error = %v", err)
	}
	if export.Status != ExportStatusPending || export.ID.Version() != 7 {
		t.Fatalf("export = %#v", export)
	}
	if len(jobEnqueuer.jobs) != 1 || jobEnqueuer.jobs[0].Kind != "audit.export.v1" || jobEnqueuer.jobs[0].AggregateID != export.ID {
		t.Fatalf("enqueued jobs = %#v", jobEnqueuer.jobs)
	}
	if len(repository.appended) != 1 || repository.appended[0].Action != "audit.export.start" {
		t.Fatalf("audit events = %#v", repository.appended)
	}
}

func TestGetExportRejectsCrossProductAccess(t *testing.T) {
	t.Parallel()

	exportID := uuid.New()
	repository := &memoryRepository{exports: map[uuid.UUID]Export{
		exportID: {ID: exportID, ProductID: "product-b", Status: ExportStatusPending},
	}}
	service := NewService(repository)
	principal := identity.Principal{
		Subject:    "auditor-1",
		Kind:       identity.PrincipalKindHuman,
		Roles:      []identity.Role{identity.RoleAuditor},
		ProductIDs: []string{"product-a"},
	}

	_, err := service.GetExport(context.Background(), principal, exportID)
	if !errors.Is(err, identity.ErrProductScopeDenied) {
		t.Fatalf("GetExport() error = %v, want %v", err, identity.ErrProductScopeDenied)
	}
}

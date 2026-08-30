package endpoint

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/catalog"
	"xminds-release-platform/internal/identity"
)

const (
	rootDigest      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	timestampDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestUnhealthyEndpointCannotBecomeActiveWhenProbeDigestDiffers(t *testing.T) {
	t.Parallel()

	endpointID := uuid.New()
	repository := &memoryEndpointRepository{records: map[uuid.UUID]Endpoint{endpointID: validEndpoint(endpointID, StatusUnhealthy)}}
	service := newEndpointTestService(t, repository, ProbeResult{RootDigest: rootDigest, TimestampDigest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"})
	err := service.Activate(context.Background(), adminPrincipal(), endpointID, RequestContext{RequestID: uuid.New().String()})
	if !errors.Is(err, ErrCatalogDigestMismatch) {
		t.Fatalf("Activate() error = %v", err)
	}
	if repository.records[endpointID].Status == StatusActive {
		t.Fatal("digest-mismatched endpoint became active")
	}
}

func TestThreeConsecutiveProbeFailuresEjectActiveEndpointAndAuditTransition(t *testing.T) {
	t.Parallel()

	endpointID := uuid.New()
	repository := &memoryEndpointRepository{records: map[uuid.UUID]Endpoint{endpointID: validEndpoint(endpointID, StatusActive)}}
	auditor := &recordingEndpointAuditor{}
	service := newEndpointTestServiceWithAuditor(t, repository, ProbeResult{}, auditor)
	for attempt := 1; attempt <= 3; attempt++ {
		record, err := service.RecordFailure(context.Background(), endpointID, "endpoint_readback_failed", uuid.New().String())
		if err != nil {
			t.Fatal(err)
		}
		if attempt < 3 && record.Status != StatusActive {
			t.Fatalf("attempt %d status = %s", attempt, record.Status)
		}
	}
	if record := repository.records[endpointID]; record.Status != StatusUnhealthy || record.FailureCount != 3 {
		t.Fatalf("record = %+v", record)
	}
	if len(auditor.commands) != 1 || auditor.commands[0].Action != "endpoint.health.unhealthy" || auditor.commands[0].Outcome != audit.OutcomeFailed {
		t.Fatalf("audit commands = %#v", auditor.commands)
	}
}

func TestFailureAuditUsesAtomicTransitionResultInsteadOfStalePreRead(t *testing.T) {
	t.Parallel()

	endpointID := uuid.New()
	base := &memoryEndpointRepository{records: map[uuid.UUID]Endpoint{endpointID: validEndpoint(endpointID, StatusActive)}}
	repository := &staleReadEndpointRepository{memoryEndpointRepository: base}
	auditor := &recordingEndpointAuditor{}
	service, err := NewService(ServiceConfig{
		Repository: repository, Transactor: endpointPassThroughTransactor{}, Catalogs: fixedCurrentCatalog{},
		Probe: fixedEndpointProbe{}, Auditor: auditor, DefaultChannel: "stable", Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 4; attempt++ {
		if _, err := service.RecordFailure(context.Background(), endpointID, "endpoint_readback_failed", uuid.New().String()); err != nil {
			t.Fatal(err)
		}
	}
	if len(auditor.commands) != 1 {
		t.Fatalf("unhealthy audit count = %d, want 1", len(auditor.commands))
	}
}

func TestRegisterRejectsNonHTTPSBaseURL(t *testing.T) {
	t.Parallel()

	repository := &memoryEndpointRepository{records: map[uuid.UUID]Endpoint{}}
	service := newEndpointTestService(t, repository, ProbeResult{})
	_, err := service.Register(context.Background(), adminPrincipal(), RegisterCommand{
		ProductID: "ngep", Name: "unsafe", Type: TypeOrigin, Region: "cn-east-1", Priority: 10,
		BaseURL: "http://download.example", PathPrefix: "/releases", HealthPath: "/health/catalog",
	}, RequestContext{RequestID: uuid.New().String()})
	if !errors.Is(err, ErrEndpointInvalid) {
		t.Fatalf("Register() error = %v", err)
	}
}

func newEndpointTestService(t *testing.T, repository *memoryEndpointRepository, probe ProbeResult) *Service {
	t.Helper()
	return newEndpointTestServiceWithAuditor(t, repository, probe, &recordingEndpointAuditor{})
}

func newEndpointTestServiceWithAuditor(t *testing.T, repository *memoryEndpointRepository, probe ProbeResult, auditor *recordingEndpointAuditor) *Service {
	t.Helper()
	now := time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC)
	service, err := NewService(ServiceConfig{
		Repository: repository, Transactor: endpointPassThroughTransactor{}, Catalogs: fixedCurrentCatalog{},
		Probe: fixedEndpointProbe{result: probe}, Auditor: auditor, DefaultChannel: "stable", Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func validEndpoint(id uuid.UUID, status Status) Endpoint {
	return Endpoint{
		ID: id, ProductID: "ngep", Name: "primary", Type: TypeOrigin, Region: "cn-east-1", Priority: 10,
		BaseURL: "https://download.example", PathPrefix: "/releases", HealthPath: "/health/catalog", Status: status,
	}
}

func adminPrincipal() identity.Principal {
	return identity.Principal{Subject: "admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}, ProductIDs: []string{"ngep"}}
}

type memoryEndpointRepository struct{ records map[uuid.UUID]Endpoint }

type staleReadEndpointRepository struct{ *memoryEndpointRepository }

func (repository *staleReadEndpointRepository) Get(ctx context.Context, id uuid.UUID) (Endpoint, error) {
	record, err := repository.memoryEndpointRepository.Get(ctx, id)
	if err == nil {
		record.Status = StatusActive
	}
	return record, err
}

func (repository *memoryEndpointRepository) Create(_ context.Context, _ pgx.Tx, record Endpoint) error {
	repository.records[record.ID] = record
	return nil
}

func (repository *memoryEndpointRepository) Get(_ context.Context, id uuid.UUID) (Endpoint, error) {
	record, exists := repository.records[id]
	if !exists {
		return Endpoint{}, ErrEndpointNotFound
	}
	return record, nil
}

func (repository *memoryEndpointRepository) MarkHealthy(_ context.Context, _ pgx.Tx, id uuid.UUID, root, timestamp string, at time.Time) (Endpoint, error) {
	record := repository.records[id]
	record.Status, record.FailureCount = StatusActive, 0
	record.LastRootDigest, record.LastTimestampDigest, record.LastCheckedAt = root, timestamp, &at
	repository.records[id] = record
	return record, nil
}

func (repository *memoryEndpointRepository) MarkFailure(_ context.Context, _ pgx.Tx, id uuid.UUID, at time.Time) (Endpoint, error) {
	record := repository.records[id]
	record.FailureCount++
	record.LastCheckedAt = &at
	if record.FailureCount >= 3 {
		record.Status = StatusUnhealthy
	}
	repository.records[id] = record
	return record, nil
}

type endpointPassThroughTransactor struct{}

func (endpointPassThroughTransactor) WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error {
	return function(nil)
}

type fixedCurrentCatalog struct{}

func (fixedCurrentCatalog) Current(context.Context, string, string) (catalog.VersionRecord, error) {
	return catalog.VersionRecord{ProductID: "ngep", Channel: "stable", Roles: map[catalog.Role]catalog.RoleDocument{
		catalog.RoleRoot:      {Role: catalog.RoleRoot, EnvelopeSHA256: rootDigest},
		catalog.RoleTimestamp: {Role: catalog.RoleTimestamp, EnvelopeSHA256: timestampDigest},
	}}, nil
}

type fixedEndpointProbe struct {
	result ProbeResult
	err    error
}

func (probe fixedEndpointProbe) Verify(context.Context, Endpoint, catalog.VersionRecord) (ProbeResult, error) {
	return probe.result, probe.err
}

type recordingEndpointAuditor struct{ commands []audit.AppendCommand }

func (recorder *recordingEndpointAuditor) Append(_ context.Context, _ pgx.Tx, command audit.AppendCommand) (audit.Event, error) {
	recorder.commands = append(recorder.commands, command)
	return audit.Event{}, nil
}

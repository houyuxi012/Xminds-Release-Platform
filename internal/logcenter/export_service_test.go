package logcenter

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

type exportAuthFake struct{ calls int }

func (a *exportAuthFake) AuthorizeExport(context.Context, ExportAuthorization) error {
	a.calls++
	return nil
}

type exportStoreFake struct{ calls int }

func (s *exportStoreFake) CreateExport(context.Context, ExportRecord) error { s.calls++; return nil }

type exportTransactionalFake struct {
	created int
	last    ExportRecord
}

func (s *exportTransactionalFake) CreateExport(context.Context, ExportRecord) error { return nil }
func (s *exportTransactionalFake) CreateOrGetExport(_ context.Context, r ExportRecord, authorize func(context.Context) error) (ExportRecord, error) {
	if err := authorize(context.Background()); err != nil {
		return ExportRecord{}, err
	}
	s.created++
	s.last = r
	return r, nil
}

type exportDedupeFake struct {
	exportTransactionalFake
	existing *ExportRecord
}

func (s *exportDedupeFake) CreateOrGetExport(_ context.Context, r ExportRecord, authorize func(context.Context) error) (ExportRecord, error) {
	if s.existing == nil {
		if err := authorize(context.Background()); err != nil {
			return ExportRecord{}, err
		}
		s.created++
		s.last = r
		copy := r
		s.existing = &copy
		return r, nil
	}
	if s.existing.Requester != r.Requester || s.existing.DedupeKey != r.DedupeKey || s.existing.Scope.Digest != r.Scope.Digest {
		return ExportRecord{}, ErrExportConflict
	}
	return *s.existing, nil
}

func validProofForTest() map[string]any {
	return map[string]any{"challenge_id": uuid.NewString(), "evidence": "xmr_1234567890123456789012345678901234567890123", "confirmed": true}
}

func TestExportInvalidProofDoesNotMutate(t *testing.T) {
	a := &exportAuthFake{}
	s := &exportStoreFake{}
	svc := &ExportService{Authorizer: a, Store: s}
	_, e := svc.Create(context.Background(), ExportRequest{Format: "json"}, LogReadScope{})
	if e == nil || a.calls != 0 || s.calls != 0 {
		t.Fatalf("err=%v auth=%d store=%d", e, a.calls, s.calls)
	}
}

func TestExportServiceRequiresTransactionalStore(t *testing.T) {
	a := &exportAuthFake{}
	svc := &ExportService{Authorizer: a, Store: &exportStoreFake{}}
	_, err := svc.Create(context.Background(), ExportRequest{Requester: "user-1", Format: "ndjson", LogTypes: []ScopeTable{ScopeTableOperations}, Reauthentication: validProofForTest()}, LogReadScope{})
	if !errors.Is(err, ErrExportUnavailable) {
		t.Fatalf("err=%v, want unavailable", err)
	}
	if a.calls != 0 {
		t.Fatalf("authorizer calls=%d, want 0", a.calls)
	}
}

func TestExportServiceDedupeReturnsExistingAndPreservesScope(t *testing.T) {
	a := &exportAuthFake{}
	s := &exportDedupeFake{}
	scope, err := NewLogReadScope(false, false, []string{"product-a"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc := &ExportService{Authorizer: a, Store: s}
	req := ExportRequest{Requester: "user-1", Format: "ndjson", LogTypes: []ScopeTable{ScopeTableOperations}, Reauthentication: validProofForTest(), DedupeKey: "batch-1"}
	first, err := svc.Create(context.Background(), req, scope)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.Create(context.Background(), req, scope)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || s.created != 1 {
		t.Fatalf("first=%s second=%s created=%d", first.ID, second.ID, s.created)
	}
	if a.calls != 1 {
		t.Fatalf("authorizer calls=%d, want exactly one for a deduped retry", a.calls)
	}
	otherScope, err := NewLogReadScope(false, false, []string{"product-b"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(context.Background(), req, otherScope); !errors.Is(err, ErrExportConflict) {
		t.Fatalf("err=%v, want dedupe conflict", err)
	}
	if a.calls != 1 {
		t.Fatalf("authorizer calls=%d, conflict must not consume proof", a.calls)
	}
}

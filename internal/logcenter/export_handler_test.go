package logcenter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type exportHTTPStoreFake struct {
	statusErr error
	created   ExportRecord
}

func (s *exportHTTPStoreFake) CreateExport(context.Context, ExportRecord) error { return nil }
func (s *exportHTTPStoreFake) CreateOrGetExport(_ context.Context, r ExportRecord, authorize func(context.Context) error) (ExportRecord, error) {
	if err := authorize(context.Background()); err != nil {
		return ExportRecord{}, err
	}
	s.created = r
	return r, nil
}
func (s *exportHTTPStoreFake) GetExport(context.Context, uuid.UUID, LogReadScope) (ExportRecord, bool, error) {
	if s.statusErr != nil {
		return ExportRecord{}, false, s.statusErr
	}
	return s.created, true, nil
}
func (s *exportHTTPStoreFake) GrantDownload(context.Context, uuid.UUID, LogReadScope, time.Duration) (string, error) {
	if s.statusErr != nil {
		return "", s.statusErr
	}
	return "/api/v1/log-exports/" + s.created.ID.String() + "/content", nil
}

func TestExportHTTPCreateSetsJSONAndNoStore(t *testing.T) {
	store := &exportHTTPStoreFake{}
	svc := &ExportService{Authorizer: &exportAuthFake{}, Store: store}
	h := &ExportHTTPHandler{Service: svc, ResolveContext: func(context.Context) (string, LogReadScope, error) { return "user-1", LogReadScope{}, nil }}
	body := `{"log_types":["operations"],"format":"ndjson","filters":{"product_id":"product-a","http_status":200},"dedupe_key":"run-1","reauthentication":{"challenge_id":"` + uuid.NewString() + `","evidence":"xmr_1234567890123456789012345678901234567890123","confirmed":true}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/log-exports", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || rec.Header().Get("Content-Type") != "application/json" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d content-type=%q cache=%q body=%s", rec.Code, rec.Header().Get("Content-Type"), rec.Header().Get("Cache-Control"), rec.Body.String())
	}
}

func TestExportHTTPRejectsPaginationFilters(t *testing.T) {
	store := &exportHTTPStoreFake{}
	h := &ExportHTTPHandler{Service: &ExportService{Authorizer: &exportAuthFake{}, Store: store}, ResolveContext: func(context.Context) (string, LogReadScope, error) { return "user-1", LogReadScope{}, nil }}
	body := `{"log_types":["operations"],"format":"ndjson","filters":{"cursor":"forbidden"},"reauthentication":{"challenge_id":"` + uuid.NewString() + `","evidence":"xmr_1234567890123456789012345678901234567890123","confirmed":true}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/log-exports", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestExportHTTPStatusStoreErrorIsUnavailable(t *testing.T) {
	store := &exportHTTPStoreFake{statusErr: errors.New("database unavailable")}
	h := &ExportHTTPHandler{Service: &ExportService{Authorizer: &exportAuthFake{}, Store: store}, ResolveContext: func(context.Context) (string, LogReadScope, error) { return "user-1", LogReadScope{}, nil }}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/log-exports/"+uuid.NewString(), nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestExportHTTPContentStreamsCompletedArchive(t *testing.T) {
	store := &exportHTTPStoreFake{created: ExportRecord{ID: uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e13"), Status: "completed", ArchiveKey: "log-exports/export/archive.ndjson"}}
	archive := &exportObjectStoreFake{objects: map[string][]byte{store.created.ArchiveKey: []byte("{\"event_id\":\"x\"}\n")}}
	h := &ExportHTTPHandler{
		Service:        &ExportService{Authorizer: &exportAuthFake{}, Store: store},
		Archive:        archive,
		ResolveContext: func(context.Context) (string, LogReadScope, error) { return "user-1", LogReadScope{}, nil },
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/log-exports/018f835d-7e4b-7abc-9f42-67a2f5f48e13/content", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/x-ndjson" || rec.Body.String() != "{\"event_id\":\"x\"}\n" {
		t.Fatalf("status=%d content-type=%q body=%q", rec.Code, rec.Header().Get("Content-Type"), rec.Body.String())
	}
}

func TestExportHTTPDownloadReturnsAuthenticatedRelativePath(t *testing.T) {
	id := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e13")
	store := &exportHTTPStoreFake{created: ExportRecord{ID: id, Status: "completed", ArchiveKey: "log-exports/export/archive.ndjson"}}
	h := &ExportHTTPHandler{Service: &ExportService{Authorizer: &exportAuthFake{}, Store: store}, ResolveContext: func(context.Context) (string, LogReadScope, error) { return "user-1", LogReadScope{}, nil }}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/log-exports/"+id.String()+"/download", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "/api/v1/log-exports/"+id.String()+"/content") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

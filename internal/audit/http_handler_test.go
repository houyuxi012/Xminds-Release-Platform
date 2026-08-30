package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/identity"
)

func TestAuditHTTPHandlerQueriesProductScopedEventsWithContractJSON(t *testing.T) {
	t.Parallel()

	eventID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e01")
	requestID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e02")
	application := &recordingAuditHTTPApplication{events: []Event{{
		ID: eventID, OccurredAt: time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC), ProductID: "ngep",
		ActorSubject: "alice", ActorKind: identity.PrincipalKindHuman, ActorRoles: []identity.Role{identity.RoleAuditor},
		ActorProductIDs: []string{"ngep"}, TokenID: "token-1", Action: "release.publish", ResourceType: "release",
		ResourceID: "release-1", Outcome: OutcomeSuccess, RequestID: requestID, Metadata: json.RawMessage(`{"version":"1.0.0"}`),
		PreviousHash: strings.Repeat("0", 64), EventHash: strings.Repeat("a", 64),
	}}}
	handler := authenticatedAuditHandler(t, application)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/audit-events?product_id=ngep&action=release.publish&limit=25", nil)
	request.Header.Set("Authorization", "Bearer signed-token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	for _, marker := range []string{`"id":"` + eventID.String() + `"`, `"actor_subject":"alice"`, `"event_hash":"` + strings.Repeat("a", 64) + `"`} {
		if !strings.Contains(response.Body.String(), marker) {
			t.Fatalf("body = %s, want marker %s", response.Body.String(), marker)
		}
	}
	if strings.Contains(response.Body.String(), "next_before_time") || strings.Contains(response.Body.String(), "next_before_id") {
		t.Fatalf("partial page exposed an empty cursor: %s", response.Body.String())
	}
	if application.queriedBy != "auditor" || application.query.ProductID != "ngep" || application.query.Action != "release.publish" || application.query.Limit != 25 {
		t.Fatalf("query principal/filter = %q, %+v", application.queriedBy, application.query)
	}
}

func TestAuditHTTPHandlerStartsAndReadsExport(t *testing.T) {
	t.Parallel()

	exportID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e03")
	application := &recordingAuditHTTPApplication{export: Export{
		ID: exportID, ProductID: "ngep", RequestedBy: "auditor",
		RequestID: uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e04"), Status: ExportStatusPending,
		CreatedAt: time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC),
	}}
	handler := authenticatedAuditHandler(t, application)
	startRequest := httptest.NewRequest(http.MethodPost, "/api/v1/audit-exports", strings.NewReader(`{"product_id":"ngep","action":"release.publish","outcome":"success"}`))
	startRequest.Header.Set("Authorization", "Bearer signed-token")
	startRequest.Header.Set("Content-Type", "application/json")
	startResponse := httptest.NewRecorder()

	handler.ServeHTTP(startResponse, startRequest)

	if startResponse.Code != http.StatusAccepted || !strings.Contains(startResponse.Body.String(), `"id":"`+exportID.String()+`"`) {
		t.Fatalf("start status = %d, body = %s", startResponse.Code, startResponse.Body.String())
	}
	if strings.Contains(startResponse.Body.String(), "0001-01-01") || strings.Contains(startResponse.Body.String(), "expires_at") {
		t.Fatalf("pending export exposed an unset expiry: %s", startResponse.Body.String())
	}
	if application.start.ProductID != "ngep" || application.start.Filter.Action != "release.publish" || application.start.Filter.Outcome != OutcomeSuccess {
		t.Fatalf("start command = %+v", application.start)
	}

	getRequest := httptest.NewRequest(http.MethodGet, "/api/v1/audit-exports/"+exportID.String(), nil)
	getRequest.Header.Set("Authorization", "Bearer signed-token")
	getResponse := httptest.NewRecorder()
	handler.ServeHTTP(getResponse, getRequest)
	if getResponse.Code != http.StatusOK || !strings.Contains(getResponse.Body.String(), `"status":"pending"`) {
		t.Fatalf("get status = %d, body = %s", getResponse.Code, getResponse.Body.String())
	}
}

func authenticatedAuditHandler(t *testing.T, application *recordingAuditHTTPApplication) http.Handler {
	t.Helper()
	verifier := auditVerifierFunc(func(context.Context, string) (identity.Principal, error) {
		return identity.Principal{
			Subject: "auditor", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAuditor},
			ProductIDs: []string{"ngep"}, TokenID: "token-1",
		}, nil
	})
	return identity.AuthenticationMiddleware(verifier)(NewHTTPHandler(application, auditPassThroughTransactor{}))
}

type auditVerifierFunc func(context.Context, string) (identity.Principal, error)

func (function auditVerifierFunc) Verify(ctx context.Context, token string) (identity.Principal, error) {
	return function(ctx, token)
}

type recordingAuditHTTPApplication struct {
	events    []Event
	export    Export
	queriedBy string
	query     QueryFilter
	start     StartExportCommand
}

func (application *recordingAuditHTTPApplication) Query(_ context.Context, principal identity.Principal, filter QueryFilter) ([]Event, error) {
	application.queriedBy = principal.Subject
	application.query = filter
	return application.events, nil
}

func (application *recordingAuditHTTPApplication) StartExport(_ context.Context, _ pgx.Tx, command StartExportCommand) (Export, error) {
	application.start = command
	return application.export, nil
}

func (application *recordingAuditHTTPApplication) GetExport(_ context.Context, _ identity.Principal, id uuid.UUID) (Export, error) {
	if id != application.export.ID {
		return Export{}, ErrExportNotFound
	}
	return application.export, nil
}

type auditPassThroughTransactor struct{}

func (auditPassThroughTransactor) WithinTransaction(_ context.Context, function func(pgx.Tx) error) error {
	return function(nil)
}

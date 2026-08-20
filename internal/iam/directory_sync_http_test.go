package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/httpx"
)

func TestDirectorySyncHTTPRoutesReturnVersionedRedactedJobContracts(t *testing.T) {
	sourceID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f49001")
	jobID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f49002")
	application := &directoryHTTPApplication{
		stubIAMApplication: &stubIAMApplication{},
		job: DirectorySyncJob{
			ID: jobID, IdentitySourceID: sourceID, SourceVersion: 8, Mode: DirectorySyncModePreview,
			Status: DirectorySyncStatusPending, RunMarker: uuid.New(), Phase: DirectorySyncPhaseFetch, Cursor: "worker-cursor-must-not-leak",
			RequestedBy: "admin", RequestID: uuid.New(), CreatedAt: time.Now(), UpdatedAt: time.Now(),
		},
	}
	handler := authenticatedIAMHandler(application)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/identity-sources/"+sourceID.String()+"/sync-preview", bytes.NewBufferString(`{"version":8}`))
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(httpx.WithRequestID(request.Context(), uuid.NewString()))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted || response.Header().Get("Location") != "/api/v1/identity-sources/"+sourceID.String()+"/sync-jobs/"+jobID.String() {
		t.Fatalf("status=%d Location=%q body=%s", response.Code, response.Header().Get("Location"), response.Body)
	}
	if application.startedMode != DirectorySyncModePreview || application.expectedVersion != 8 || application.startedSourceID != sourceID {
		t.Fatalf("start call mode=%q version=%d source=%s", application.startedMode, application.expectedVersion, application.startedSourceID)
	}
	if strings.Contains(response.Body.String(), "worker-cursor") || strings.Contains(response.Body.String(), "run_marker") || strings.Contains(response.Body.String(), `"phase"`) || strings.Contains(response.Body.String(), "secret") {
		t.Fatalf("job response leaked worker/secret state: %s", response.Body)
	}
}

func TestDirectorySyncHTTPVerifyRequiresExpectedVersionAndReturnsCapabilities(t *testing.T) {
	sourceID := uuid.New()
	application := &directoryHTTPApplication{
		stubIAMApplication: &stubIAMApplication{},
		capabilities: CapabilityReport{
			Reachable: true, RequiredAttributes: []string{"subject", "roles"}, RequiredMappingsComplete: true, SupportsPagination: true,
		},
	}
	handler := authenticatedIAMHandler(application)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/identity-sources/"+sourceID.String()+"/verify", bytes.NewBufferString(`{"version":3}`))
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(httpx.WithRequestID(request.Context(), uuid.NewString()))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || application.expectedVersion != 3 || application.verifiedSourceID != sourceID {
		t.Fatalf("status=%d version=%d source=%s body=%s", response.Code, application.expectedVersion, application.verifiedSourceID, response.Body)
	}
	var report CapabilityReport
	if err := json.Unmarshal(response.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if !report.Reachable || !report.RequiredMappingsComplete || !report.SupportsPagination {
		t.Fatalf("capability report = %#v", report)
	}
}

func TestDirectorySyncHTTPRejectsCaseFoldVersionAlias(t *testing.T) {
	sourceID := uuid.New()
	application := &directoryHTTPApplication{stubIAMApplication: &stubIAMApplication{}}
	handler := authenticatedIAMHandler(application)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/identity-sources/"+sourceID.String()+"/verify", bytes.NewBufferString(`{"version":3,"Version":4}`))
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || application.expectedVersion != 0 {
		t.Fatalf("status=%d decoded_version=%d body=%s", response.Code, application.expectedVersion, response.Body)
	}
}

func TestDirectorySyncHTTPJobOwnershipMismatchIsNotFoundAndConflictCursorIsOpaque(t *testing.T) {
	sourceID, jobID := uuid.New(), uuid.New()
	application := &directoryHTTPApplication{
		stubIAMApplication: &stubIAMApplication{},
		jobError:           ErrDirectorySyncNotFound,
		conflicts: DirectorySyncConflictPage{
			Items:      []DirectorySyncConflict{{ID: uuid.New(), SyncJobID: uuid.New(), IdentitySourceID: sourceID, ObjectType: "user", ExternalID: "external-1", Code: "AMBIGUOUS_EMAIL", Details: json.RawMessage(`{"stable_id":"external-1","field":"email","count":2}`), Status: "open", CreatedAt: time.Now()}},
			NextCursor: "opaque-list-cursor",
		},
	}
	handler := authenticatedIAMHandler(application)
	jobRequest := httptest.NewRequest(http.MethodGet, "/api/v1/identity-sources/"+sourceID.String()+"/sync-jobs/"+jobID.String(), nil)
	jobRequest.Header.Set("Authorization", "Bearer token")
	jobResponse := httptest.NewRecorder()
	handler.ServeHTTP(jobResponse, jobRequest)
	if jobResponse.Code != http.StatusNotFound || !strings.Contains(jobResponse.Body.String(), "DIRECTORY_SYNC_JOB_NOT_FOUND") ||
		!strings.Contains(jobResponse.Body.String(), `"instance":"/api/v1/identity-sources/{source_id}/sync-jobs/{job_id}"`) ||
		strings.Contains(jobResponse.Body.String(), sourceID.String()) || strings.Contains(jobResponse.Body.String(), jobID.String()) {
		t.Fatalf("job status=%d body=%s", jobResponse.Code, jobResponse.Body)
	}

	conflictRequest := httptest.NewRequest(http.MethodGet, "/api/v1/identity-sources/"+sourceID.String()+"/sync-conflicts?limit=25&cursor=opaque-input", nil)
	conflictRequest.Header.Set("Authorization", "Bearer token")
	conflictResponse := httptest.NewRecorder()
	handler.ServeHTTP(conflictResponse, conflictRequest)
	if conflictResponse.Code != http.StatusOK || !strings.Contains(conflictResponse.Body.String(), "opaque-list-cursor") || strings.Contains(conflictResponse.Body.String(), "worker-cursor") {
		t.Fatalf("conflicts status=%d body=%s", conflictResponse.Code, conflictResponse.Body)
	}
	if application.listedPage.Limit != 25 || application.listedPage.Cursor != "opaque-input" || !application.listedPage.BeforeTime.IsZero() || application.listedPage.BeforeID != uuid.Nil {
		t.Fatalf("directory conflict page=%#v", application.listedPage)
	}
}

func TestIAMProblemInstanceTemplatesDirectorySourceJobAndConflictIdentifiers(t *testing.T) {
	sourceID, jobID := uuid.NewString(), uuid.NewString()
	for raw, want := range map[string]string{
		"/api/v1/identity-sources/" + sourceID:                                        "/api/v1/identity-sources/{source_id}",
		"/api/v1/identity-sources/" + sourceID + "/sync-jobs/" + jobID:                "/api/v1/identity-sources/{source_id}/sync-jobs/{job_id}",
		"/api/v1/identity-sources/" + sourceID + "/sync-jobs/" + jobID + "/conflicts": "/api/v1/identity-sources/{source_id}/sync-jobs/{job_id}/conflicts",
		"/api/v1/identity-sources/" + sourceID + "/sync-conflicts":                    "/api/v1/identity-sources/{source_id}/sync-conflicts",
	} {
		if got := iamProblemInstance(raw); got != want {
			t.Errorf("iamProblemInstance(%q)=%q want=%q", raw, got, want)
		}
		if got := iamProblemInstance(raw); strings.Contains(got, sourceID) || strings.Contains(got, jobID) {
			t.Errorf("iamProblemInstance(%q) leaked identifier in %q", raw, got)
		}
	}
}

type directoryHTTPApplication struct {
	*stubIAMApplication
	job              DirectorySyncJob
	jobError         error
	conflicts        DirectorySyncConflictPage
	capabilities     CapabilityReport
	startedMode      DirectorySyncMode
	expectedVersion  int64
	startedSourceID  uuid.UUID
	verifiedSourceID uuid.UUID
	listedPage       Page
}

func (application *directoryHTTPApplication) VerifyIdentitySourceVersioned(_ context.Context, _ identity.Principal, sourceID uuid.UUID, version int64, _ RequestContext) (CapabilityReport, error) {
	application.verifiedSourceID, application.expectedVersion = sourceID, version
	return application.capabilities, nil
}

func (application *directoryHTTPApplication) StartDirectorySync(_ context.Context, _ identity.Principal, sourceID uuid.UUID, mode DirectorySyncMode, version int64, _ RequestContext) (DirectorySyncJob, error) {
	application.startedSourceID, application.startedMode, application.expectedVersion = sourceID, mode, version
	return redactDirectorySyncJob(application.job), nil
}

func (application *directoryHTTPApplication) GetDirectorySyncJob(context.Context, identity.Principal, uuid.UUID, uuid.UUID) (DirectorySyncJob, error) {
	return redactDirectorySyncJob(application.job), application.jobError
}

func (application *directoryHTTPApplication) ListDirectorySyncConflicts(_ context.Context, _ identity.Principal, _ uuid.UUID, page Page) (DirectorySyncConflictPage, error) {
	application.listedPage = page
	return application.conflicts, nil
}

package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

func TestDirectorySyncHTTPListsSourceScopedRedactedJobHistory(t *testing.T) {
	sourceID := uuid.New()
	now := time.Date(2026, 8, 21, 15, 0, 0, 0, time.UTC)
	job := DirectorySyncJob{
		ID: uuid.New(), IdentitySourceID: sourceID, SourceVersion: 5, RunMarker: uuid.New(), Mode: DirectorySyncModeApply,
		Status: DirectorySyncStatusCompleted, Phase: DirectorySyncPhaseFinalize, Cursor: "private-worker-cursor", RequestedBy: "admin",
		RequestID: uuid.New(), CreatedAt: now, UpdatedAt: now, CompletedAt: now,
	}
	application := &directoryHTTPApplication{
		stubIAMApplication: &stubIAMApplication{},
		jobPage:            DirectorySyncJobPage{Items: []DirectorySyncJob{job}, NextCursor: encodeIAMCursor(now, job.ID)},
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/identity-sources/"+sourceID.String()+"/sync-jobs?limit=25", nil)
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()

	authenticatedIAMHandler(application).ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d Cache-Control=%q body=%s", response.Code, response.Header().Get("Cache-Control"), response.Body)
	}
	if application.listedJobSourceID != sourceID || application.listedJobPage.Limit != 25 || application.listJobCalls != 1 {
		t.Fatalf("list calls=%d source=%s page=%+v", application.listJobCalls, application.listedJobSourceID, application.listedJobPage)
	}
	if strings.Contains(response.Body.String(), "private-worker-cursor") || strings.Contains(response.Body.String(), "run_marker") || strings.Contains(response.Body.String(), `"phase"`) {
		t.Fatalf("job history leaked worker state: %s", response.Body)
	}
}

func TestDirectorySyncHTTPRejectsInvalidHistoryCursorBeforeApplication(t *testing.T) {
	sourceID := uuid.New()
	for _, cursor := range []string{strings.Repeat("a", maximumIAMCursorLength+1), canonicalIAMCursor + "="} {
		application := &directoryHTTPApplication{stubIAMApplication: &stubIAMApplication{}}
		request := httptest.NewRequest(http.MethodGet, "/api/v1/identity-sources/"+sourceID.String()+"/sync-jobs?cursor="+cursor, nil)
		request.Header.Set("Authorization", "Bearer token")
		response := httptest.NewRecorder()

		authenticatedIAMHandler(application).ServeHTTP(response, request)

		if response.Code != http.StatusBadRequest || application.listJobCalls != 0 {
			t.Fatalf("cursor_length=%d status=%d calls=%d body=%s", len(cursor), response.Code, application.listJobCalls, response.Body)
		}
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

func TestDirectoryConflictListStatusDefaultsOpenAndRejectsUnknownValues(t *testing.T) {
	status, page, err := parseDirectoryConflictPage(httptest.NewRequest(http.MethodGet, "/api/v1/identity-sources/ignored/sync-conflicts?limit=25", nil))
	if err != nil || status != DirectorySyncConflictStatusOpen || page.Limit != 25 {
		t.Fatalf("default status=%q page=%#v error=%v", status, page, err)
	}
	for _, raw := range []string{"closed", "%20resolved", "ALL"} {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/identity-sources/ignored/sync-conflicts?status="+raw, nil)
		if _, _, err := parseDirectoryConflictPage(request); !errors.Is(err, ErrPageInvalid) {
			t.Fatalf("status %q error=%v", raw, err)
		}
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

	conflictRequest := httptest.NewRequest(http.MethodGet, "/api/v1/identity-sources/"+sourceID.String()+"/sync-conflicts?status=resolved&limit=25&cursor=opaque-input", nil)
	conflictRequest.Header.Set("Authorization", "Bearer token")
	conflictResponse := httptest.NewRecorder()
	handler.ServeHTTP(conflictResponse, conflictRequest)
	if conflictResponse.Code != http.StatusOK || !strings.Contains(conflictResponse.Body.String(), "opaque-list-cursor") || strings.Contains(conflictResponse.Body.String(), "worker-cursor") {
		t.Fatalf("conflicts status=%d body=%s", conflictResponse.Code, conflictResponse.Body)
	}
	for _, absent := range []string{"resolution_decision", "resolution_reason", "resolved_by", "resolved_at"} {
		if strings.Contains(conflictResponse.Body.String(), absent) {
			t.Fatalf("open conflict response included optional %s: %s", absent, conflictResponse.Body)
		}
	}
	if application.listedStatus != DirectorySyncConflictStatusResolved || application.listedPage.Limit != 25 || application.listedPage.Cursor != "opaque-input" || !application.listedPage.BeforeTime.IsZero() || application.listedPage.BeforeID != uuid.Nil {
		t.Fatalf("directory conflict page=%#v", application.listedPage)
	}
}

func TestDirectoryConflictResolutionHTTPIsStrictNoStoreAndDoesNotEchoSensitiveInput(t *testing.T) {
	sourceID, conflictID, challengeID := uuid.New(), uuid.New(), uuid.New()
	resolvedAt := time.Date(2026, 8, 21, 16, 0, 0, 0, time.UTC)
	application := &directoryHTTPApplication{
		stubIAMApplication: &stubIAMApplication{},
		resolvedConflict:   DirectorySyncConflict{ID: conflictID, IdentitySourceID: sourceID, Status: "resolved", Version: 2, ResolutionDecision: DirectoryConflictResolutionKeepLastSafe, ResolutionReason: "confirmed upstream collision", ResolvedBy: uuid.NewString(), ResolvedAt: &resolvedAt},
	}
	handler := authenticatedIAMHandler(application)
	body := `{"version":1,"decision":"keep_last_safe","reason":"confirmed upstream collision","reauthentication":{"challenge_id":"` + challengeID.String() + `","evidence":"xmr_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","confirmed":true}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/identity-sources/"+sourceID.String()+"/sync-conflicts/"+conflictID.String()+"/resolve", bytes.NewBufferString(body))
	request.Header.Set("Authorization", "Bearer token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d cache=%q body=%s", response.Code, response.Header().Get("Cache-Control"), response.Body)
	}
	if application.resolveCommand.Version != 1 || application.resolveCommand.Decision != DirectoryConflictResolutionKeepLastSafe || application.resolveProof.ChallengeID != challengeID.String() || !application.resolveProof.Confirmed {
		t.Fatalf("resolution command=%#v proof=%#v", application.resolveCommand, application.resolveProof)
	}

	malformed := httptest.NewRequest(http.MethodPost, "/api/v1/identity-sources/"+sourceID.String()+"/sync-conflicts/"+conflictID.String()+"/resolve", bytes.NewBufferString(`{"version":1,"decision":"keep_last_safe","reason":"do not echo this reason","unexpected":"secret","reauthentication":{"challenge_id":"`+challengeID.String()+`","evidence":"do-not-echo-evidence","confirmed":true}}`))
	malformed.Header.Set("Authorization", "Bearer token")
	malformed.Header.Set("Content-Type", "application/json")
	malformedResponse := httptest.NewRecorder()
	handler.ServeHTTP(malformedResponse, malformed)
	if malformedResponse.Code != http.StatusBadRequest || strings.Contains(malformedResponse.Body.String(), "do not echo") || strings.Contains(malformedResponse.Body.String(), "do-not-echo") || strings.Contains(malformedResponse.Body.String(), challengeID.String()) {
		t.Fatalf("malformed status=%d body=%s", malformedResponse.Code, malformedResponse.Body)
	}
}

// Mutation caught: resolving a directory conflict with a malformed proof must
// not enter conflict ownership/version validation in the application layer.
func TestDirectoryConflictResolutionHTTPRejectsMalformedProofBeforeApplication(t *testing.T) {
	sourceID, conflictID := uuid.New(), uuid.New()
	validEvidence := "xmr_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
	for _, proof := range []struct {
		name, json string
	}{
		{name: "missing", json: `{}`},
		{name: "invalid challenge", json: `{"challenge_id":"not-a-uuid","evidence":"` + validEvidence + `","confirmed":true}`},
		{name: "invalid evidence", json: `{"challenge_id":"` + uuid.NewString() + `","evidence":"xmr_too-short","confirmed":true}`},
		{name: "unconfirmed", json: `{"challenge_id":"` + uuid.NewString() + `","evidence":"` + validEvidence + `","confirmed":false}`},
	} {
		t.Run(proof.name, func(t *testing.T) {
			application := &directoryHTTPApplication{stubIAMApplication: &stubIAMApplication{}}
			body := `{"version":1,"decision":"keep_last_safe","reason":"confirmed upstream collision","reauthentication":` + proof.json + `}`
			request := httptest.NewRequest(http.MethodPost, "/api/v1/identity-sources/"+sourceID.String()+"/sync-conflicts/"+conflictID.String()+"/resolve", strings.NewReader(body))
			request.Header.Set("Authorization", "Bearer token")
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			authenticatedIAMHandler(application).ServeHTTP(response, request)

			if response.Code != http.StatusBadRequest || application.resolveCommand.Version != 0 {
				t.Fatalf("status=%d command=%#v body=%s", response.Code, application.resolveCommand, response.Body)
			}
		})
	}
}

func TestDirectoryConflictResolutionHTTPAbsentAndCrossSourceResponsesAreExactlyEquivalent(t *testing.T) {
	sourceID, conflictID := uuid.New(), uuid.New()
	path := "/api/v1/identity-sources/" + sourceID.String() + "/sync-conflicts/" + conflictID.String() + "/resolve"
	body := `{"version":1,"decision":"keep_last_safe","reason":"confirmed upstream collision","reauthentication":{"challenge_id":"` + uuid.NewString() + `","evidence":"xmr_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ","confirmed":true}}`
	var canonical string
	for _, testCase := range []struct {
		name string
		err  error
	}{
		{name: "source absent", err: ErrIdentitySourceNotFound},
		{name: "conflict absent", err: ErrDirectoryConflictNotFound},
		{name: "cross source", err: ErrDirectoryConflictNotFound},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			application := &directoryHTTPApplication{stubIAMApplication: &stubIAMApplication{}, resolveError: testCase.err}
			handler := authenticatedIAMHandler(application)
			request := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
			request.Header.Set("Authorization", "Bearer token")
			request.Header.Set("Content-Type", "application/json")
			request = request.WithContext(httpx.WithRequestID(request.Context(), "018f835d-7e4b-7abc-9f42-67a2f5f49999"))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound {
				t.Fatalf("status=%d body=%s", response.Code, response.Body)
			}
			if canonical == "" {
				canonical = response.Body.String()
			}
			if response.Body.String() != canonical {
				t.Fatalf("response differs from invisible canonical\ncanonical=%s\nactual=%s", canonical, response.Body)
			}
		})
	}
}

func TestIAMProblemInstanceTemplatesDirectorySourceJobAndConflictIdentifiers(t *testing.T) {
	sourceID, jobID, conflictID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	for raw, want := range map[string]string{
		"/api/v1/identity-sources/" + sourceID:                                                "/api/v1/identity-sources/{source_id}",
		"/api/v1/identity-sources/" + sourceID + "/sync-jobs/" + jobID:                        "/api/v1/identity-sources/{source_id}/sync-jobs/{job_id}",
		"/api/v1/identity-sources/" + sourceID + "/sync-jobs/" + jobID + "/conflicts":         "/api/v1/identity-sources/{source_id}/sync-jobs/{job_id}/conflicts",
		"/api/v1/identity-sources/" + sourceID + "/sync-conflicts":                            "/api/v1/identity-sources/{source_id}/sync-conflicts",
		"/api/v1/identity-sources/" + sourceID + "/sync-conflicts/" + conflictID + "/resolve": "/api/v1/identity-sources/{source_id}/sync-conflicts/{conflict_id}/resolve",
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
	job               DirectorySyncJob
	jobError          error
	conflicts         DirectorySyncConflictPage
	capabilities      CapabilityReport
	startedMode       DirectorySyncMode
	expectedVersion   int64
	startedSourceID   uuid.UUID
	verifiedSourceID  uuid.UUID
	listedPage        Page
	listedStatus      DirectorySyncConflictStatusFilter
	resolvedConflict  DirectorySyncConflict
	resolveCommand    ResolveDirectorySyncConflictCommand
	resolveProof      HighRiskProof
	resolveError      error
	jobPage           DirectorySyncJobPage
	listedJobPage     Page
	listedJobSourceID uuid.UUID
	listJobCalls      int
}

func (application *directoryHTTPApplication) ListDirectorySyncJobs(_ context.Context, _ identity.Principal, sourceID uuid.UUID, page Page) (DirectorySyncJobPage, error) {
	application.listJobCalls++
	application.listedJobSourceID = sourceID
	application.listedJobPage = page
	return application.jobPage, nil
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

func (application *directoryHTTPApplication) ListDirectorySyncConflicts(_ context.Context, _ identity.Principal, _ uuid.UUID, status DirectorySyncConflictStatusFilter, page Page) (DirectorySyncConflictPage, error) {
	application.listedStatus = status
	application.listedPage = page
	return application.conflicts, nil
}

func (application *directoryHTTPApplication) ResolveDirectorySyncConflict(_ context.Context, _ identity.Principal, _, _ uuid.UUID, command ResolveDirectorySyncConflictCommand, proof HighRiskProof, _ RequestContext) (DirectorySyncConflict, error) {
	application.resolveCommand, application.resolveProof = command, proof
	return application.resolvedConflict, application.resolveError
}

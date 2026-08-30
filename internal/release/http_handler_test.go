package release

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/httpx"
)

func TestReleaseHTTPHandlerCreatesDraftFromPathProduct(t *testing.T) {
	t.Parallel()

	releaseID := uuid.Must(uuid.NewV7())
	application := &stubReleaseApplication{createResult: Release{ID: releaseID, ProductID: "ngep", Status: StatusDraft, LockVersion: 1}}
	handler := authenticatedReleaseHandler(application, releasePrincipal("alice", identity.RolePublisher))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/products/ngep/releases", bytes.NewReader(releaseCreateRequestBody()))
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(httpx.WithRequestID(request.Context(), "019c1547-e880-7831-949c-7302a34724f0"))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body)
	}
	if application.createCommand.ProductID != "ngep" || application.createCommand.Version != "1.2.3" {
		t.Fatalf("create command = %#v", application.createCommand)
	}
	wantLocation := "/api/v1/products/ngep/releases/" + releaseID.String()
	if response.Header().Get("Location") != wantLocation {
		t.Fatalf("Location = %q, want %q", response.Header().Get("Location"), wantLocation)
	}
}

func TestReleaseHTTPHandlerRequiresPublishIdempotencyKey(t *testing.T) {
	t.Parallel()

	application := &stubReleaseApplication{}
	handler := authenticatedReleaseHandler(application, releasePrincipal("alice", identity.RolePublisher))
	releaseID := uuid.Must(uuid.NewV7())
	request := httptest.NewRequest(http.MethodPost, "/api/v1/products/ngep/releases/"+releaseID.String()+"/publish", bytes.NewBufferString(`{"lock_version":3}`))
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnprocessableEntity || application.publishCalls != 0 {
		t.Fatalf("status = %d, publish calls = %d, body = %s", response.Code, application.publishCalls, response.Body)
	}
	var problem httpx.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Code != "RELEASE_IDEMPOTENCY_KEY_INVALID" {
		t.Fatalf("problem = %#v", problem)
	}
}

func TestReleaseHTTPHandlerMapsSelfApprovalToForbidden(t *testing.T) {
	t.Parallel()

	application := &stubReleaseApplication{approveError: ErrSelfApprovalForbidden}
	handler := authenticatedReleaseHandler(application, releasePrincipal("alice", identity.RoleApprover))
	releaseID := uuid.Must(uuid.NewV7())
	request := httptest.NewRequest(http.MethodPost, "/api/v1/products/ngep/releases/"+releaseID.String()+"/approve", bytes.NewBufferString(`{"lock_version":2}`))
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body)
	}
	var problem httpx.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Code != "RELEASE_SELF_APPROVAL_FORBIDDEN" {
		t.Fatalf("problem = %#v", problem)
	}
}

func authenticatedReleaseHandler(application ReleaseApplication, principal identity.Principal) http.Handler {
	return identity.AuthenticationMiddleware(staticReleaseVerifier{principal: principal})(NewHTTPHandler(application))
}

type staticReleaseVerifier struct {
	principal identity.Principal
}

func (verifier staticReleaseVerifier) Verify(context.Context, string) (identity.Principal, error) {
	return verifier.principal, nil
}

type stubReleaseApplication struct {
	createCommand CreateCommand
	createResult  Release
	createError   error
	approveError  error
	publishCalls  int
}

func (application *stubReleaseApplication) Create(_ context.Context, _ identity.Principal, command CreateCommand, _ RequestContext) (Release, error) {
	application.createCommand = command
	return application.createResult, application.createError
}

func (*stubReleaseApplication) Submit(context.Context, identity.Principal, string, uuid.UUID, int64, RequestContext) (Release, error) {
	return Release{}, errors.New("unexpected Submit call")
}

func (application *stubReleaseApplication) Approve(context.Context, identity.Principal, string, uuid.UUID, int64, RequestContext) (Release, error) {
	return Release{}, application.approveError
}

func (*stubReleaseApplication) Reject(context.Context, identity.Principal, string, uuid.UUID, int64, string, RequestContext) (Release, error) {
	return Release{}, errors.New("unexpected Reject call")
}

func (application *stubReleaseApplication) Publish(context.Context, identity.Principal, string, uuid.UUID, int64, string, RequestContext) (OperationResult, error) {
	application.publishCalls++
	return OperationResult{}, errors.New("unexpected Publish call")
}

func (*stubReleaseApplication) Retry(context.Context, identity.Principal, string, uuid.UUID, int64, string, RequestContext) (OperationResult, error) {
	return OperationResult{}, errors.New("unexpected Retry call")
}

func (*stubReleaseApplication) Revoke(context.Context, identity.Principal, string, uuid.UUID, int64, string, string, RequestContext) (OperationResult, error) {
	return OperationResult{}, errors.New("unexpected Revoke call")
}

func (*stubReleaseApplication) Get(context.Context, identity.Principal, string, uuid.UUID) (Release, error) {
	return Release{}, errors.New("unexpected Get call")
}

func releaseCreateRequestBody() []byte {
	command := validCreateCommand()
	payload := map[string]any{
		"channel": command.Channel, "version": command.Version,
		"release_notes": string(command.ReleaseNotes), "release_notes_sha256": command.ReleaseNotesSHA256,
		"compatibility": json.RawMessage(command.Compatibility), "compatibility_sha256": command.CompatibilitySHA256,
		"artifact_ids": command.ArtifactIDs, "source": command.Source,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}
	return encoded
}

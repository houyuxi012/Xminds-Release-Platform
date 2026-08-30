package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/httpx"
)

func TestArtifactHTTPHandlerBeginsUploadFromPathProduct(t *testing.T) {
	t.Parallel()

	uploadID := uuid.Must(uuid.NewV7())
	application := &stubArtifactApplication{beginResult: Upload{ID: uploadID, ProductID: "ngep", Status: UploadStatusUploading}}
	handler := authenticatedArtifactHandler(application, publisherPrincipal("ngep"))
	body := []byte(`{"artifact_type":"desktop","filename":"ngep.tar","content_type":"application/x-tar","size":3,"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/products/ngep/artifact-uploads", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(httpx.WithRequestID(request.Context(), "019c1547-e880-7831-949c-7302a34724e0"))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body)
	}
	if application.beginCommand.ProductID != "ngep" || application.beginCommand.Size != 3 {
		t.Fatalf("begin command = %#v", application.beginCommand)
	}
	wantLocation := "/api/v1/products/ngep/artifact-uploads/" + uploadID.String()
	if response.Header().Get("Location") != wantLocation {
		t.Fatalf("Location = %q, want %q", response.Header().Get("Location"), wantLocation)
	}
}

func TestArtifactHTTPHandlerUploadsPartWithDeclaredDigestAndLength(t *testing.T) {
	t.Parallel()

	uploadID := uuid.Must(uuid.NewV7())
	application := &stubArtifactApplication{partResult: UploadPart{UploadID: uploadID, PartNumber: 7, Size: 3, SHA256: abcSHA256}}
	handler := authenticatedArtifactHandler(application, publisherPrincipal("ngep"))
	request := httptest.NewRequest(http.MethodPut, "/api/v1/products/ngep/artifact-uploads/"+uploadID.String()+"/parts/7", bytes.NewBufferString("abc"))
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Part-SHA256", abcSHA256)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body)
	}
	if application.partProductID != "ngep" || application.partCommand.PartNumber != 7 || application.partCommand.Size != 3 || string(application.partBody) != "abc" {
		t.Fatalf("part request = product %q command %#v body %q", application.partProductID, application.partCommand, application.partBody)
	}
}

func TestArtifactHTTPHandlerMapsDigestMismatchToProblemDetails(t *testing.T) {
	t.Parallel()

	uploadID := uuid.Must(uuid.NewV7())
	application := &stubArtifactApplication{completeError: ErrDigestMismatch}
	handler := authenticatedArtifactHandler(application, publisherPrincipal("ngep"))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/products/ngep/artifact-uploads/"+uploadID.String()+"/complete", nil)
	request.Header.Set("Authorization", "Bearer test-token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnprocessableEntity || response.Header().Get("Content-Type") != httpx.ProblemMediaType {
		t.Fatalf("status = %d, content type = %q, body = %s", response.Code, response.Header().Get("Content-Type"), response.Body)
	}
	var problem httpx.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Code != "ARTIFACT_DIGEST_MISMATCH" {
		t.Fatalf("problem = %#v", problem)
	}
}

func TestArtifactHTTPHandlerDoesNotExposeInternalObjectKey(t *testing.T) {
	t.Parallel()

	artifactID := uuid.Must(uuid.NewV7())
	application := &stubArtifactApplication{getResult: Artifact{
		ID: artifactID, ProductID: "ngep", ArtifactType: "desktop", Filename: "ngep.tar",
		ContentType: "application/x-tar", Size: 3, SHA256: abcSHA256,
		ObjectKey: ArtifactObjectKey(abcSHA256), CreatedBy: "publisher-1",
	}}
	handler := authenticatedArtifactHandler(application, publisherPrincipal("ngep"))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/products/ngep/artifacts/"+artifactID.String(), nil)
	request.Header.Set("Authorization", "Bearer test-token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body)
	}
	if bytes.Contains(response.Body.Bytes(), []byte("artifacts/sha256/")) || bytes.Contains(response.Body.Bytes(), []byte("object_key")) {
		t.Fatalf("response exposed internal object key: %s", response.Body)
	}
}

func authenticatedArtifactHandler(application ArtifactApplication, principal identity.Principal) http.Handler {
	return identity.AuthenticationMiddleware(staticArtifactVerifier{principal: principal})(NewHTTPHandler(application))
}

type staticArtifactVerifier struct {
	principal identity.Principal
}

func (verifier staticArtifactVerifier) Verify(context.Context, string) (identity.Principal, error) {
	return verifier.principal, nil
}

type stubArtifactApplication struct {
	beginCommand  BeginUpload
	beginResult   Upload
	beginError    error
	partProductID string
	partCommand   PutPart
	partBody      []byte
	partResult    UploadPart
	partError     error
	completeError error
	getResult     Artifact
}

func (application *stubArtifactApplication) BeginUpload(_ context.Context, _ identity.Principal, command BeginUpload, _ RequestContext) (Upload, error) {
	application.beginCommand = command
	return application.beginResult, application.beginError
}

func (application *stubArtifactApplication) PutPart(_ context.Context, _ identity.Principal, productID string, _ uuid.UUID, command PutPart, body io.Reader, _ RequestContext) (UploadPart, error) {
	application.partProductID = productID
	application.partCommand = command
	application.partBody, _ = io.ReadAll(body)
	return application.partResult, application.partError
}

func (application *stubArtifactApplication) Complete(context.Context, identity.Principal, string, uuid.UUID, RequestContext) (Artifact, error) {
	return Artifact{}, application.completeError
}

func (application *stubArtifactApplication) Get(context.Context, identity.Principal, string, uuid.UUID) (Artifact, error) {
	if application.getResult.ID == uuid.Nil {
		return Artifact{}, errors.New("unexpected Get call")
	}
	return application.getResult, nil
}

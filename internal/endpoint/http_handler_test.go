package endpoint

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/httpx"
)

func TestEndpointHTTPHandlerRegistersValidatedEndpointForAuthenticatedAdmin(t *testing.T) {
	t.Parallel()

	repository := &memoryEndpointRepository{records: map[uuid.UUID]Endpoint{}}
	service := newEndpointTestService(t, repository, ProbeResult{})
	handler := identity.AuthenticationMiddleware(endpointVerifier{principal: adminPrincipal()})(NewHTTPHandler(service))
	payload := []byte(`{"product_id":"ngep","name":"primary","type":"origin","region":"cn-east-1","priority":10,"base_url":"https://download.example","path_prefix":"/releases","health_path":"/health/catalog"}`)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/endpoints", bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer endpoint-admin-token")
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(httpx.WithRequestID(request.Context(), "019d0000-0000-7000-8000-000000000010"))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("response = %d %s", recorder.Code, recorder.Body.String())
	}
	var response Endpoint
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || response.ProductID != "ngep" || response.Status != StatusPending {
		t.Fatalf("response endpoint = %+v, %v", response, err)
	}
	if repository.records[response.ID].BaseURL != "https://download.example" {
		t.Fatalf("stored endpoint = %+v", repository.records[response.ID])
	}
}

type endpointVerifier struct{ principal identity.Principal }

func (verifier endpointVerifier) Verify(context.Context, string) (identity.Principal, error) {
	return verifier.principal, nil
}

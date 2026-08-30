package product

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/httpx"
)

func TestHTTPHandlerRegistersProduct(t *testing.T) {
	t.Parallel()

	application := &stubProductApplication{registerProduct: Product{ID: "ngep", Status: ProductStatusActive}}
	handler := authenticatedProductHandler(application, adminPrincipal("ngep"))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/products", bytes.NewReader(mustReadFixture(t, "testdata/valid-ngep.json")))
	request.Header.Set("Authorization", "Bearer test-token")
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(httpx.WithRequestID(request.Context(), "019c1547-e880-7831-949c-7302a34724c3"))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body)
	}
	if response.Header().Get("Location") != "/api/v1/products/ngep" {
		t.Fatalf("Location = %q", response.Header().Get("Location"))
	}
	if application.registerRequest.RequestID != "019c1547-e880-7831-949c-7302a34724c3" {
		t.Fatalf("request context = %#v", application.registerRequest)
	}
}

func TestHTTPHandlerMapsProductErrorsToProblemDetails(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{name: "invalid manifest", err: ErrProductIDInvalid, wantStatus: http.StatusUnprocessableEntity, wantCode: "PRODUCT_MANIFEST_INVALID"},
		{name: "duplicate product", err: ErrProductIDExists, wantStatus: http.StatusConflict, wantCode: "PRODUCT_ALREADY_EXISTS"},
		{name: "scope denied", err: identity.ErrProductScopeDenied, wantStatus: http.StatusForbidden, wantCode: "PRODUCT_ACCESS_DENIED"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			application := &stubProductApplication{registerError: testCase.err}
			handler := authenticatedProductHandler(application, adminPrincipal("ngep"))
			request := httptest.NewRequest(http.MethodPost, "/api/v1/products", bytes.NewReader(mustReadFixture(t, "testdata/valid-ngep.json")))
			request.Header.Set("Authorization", "Bearer test-token")
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != testCase.wantStatus {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body)
			}
			if response.Header().Get("Content-Type") != httpx.ProblemMediaType {
				t.Fatalf("Content-Type = %q", response.Header().Get("Content-Type"))
			}
			var problem httpx.Problem
			if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
				t.Fatalf("decode problem: %v", err)
			}
			if problem.Code != testCase.wantCode || problem.Status != testCase.wantStatus {
				t.Fatalf("problem = %#v", problem)
			}
		})
	}
}

func TestHTTPHandlerSerializesEmptyProductPageItemsAsArray(t *testing.T) {
	t.Parallel()

	application := &stubProductApplication{listPage: ProductPage{}}
	handler := authenticatedProductHandler(application, adminPrincipal("ngep"))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/products", nil)
	request.Header.Set("Authorization", "Bearer test-token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Body.String() != "{\"items\":[]}\n" {
		t.Fatalf("response=%d body=%s", response.Code, response.Body)
	}
}

func authenticatedProductHandler(application ProductApplication, principal identity.Principal) http.Handler {
	verifier := staticProductVerifier{principal: principal}
	return identity.AuthenticationMiddleware(verifier)(NewHTTPHandler(application))
}

type staticProductVerifier struct {
	principal identity.Principal
}

func (verifier staticProductVerifier) Verify(context.Context, string) (identity.Principal, error) {
	return verifier.principal, nil
}

type stubProductApplication struct {
	registerProduct Product
	registerError   error
	registerRequest RequestContext
	listPage        ProductPage
	listError       error
}

func (application *stubProductApplication) Register(_ context.Context, _ identity.Principal, _ []byte, request RequestContext) (Product, error) {
	application.registerRequest = request
	return application.registerProduct, application.registerError
}

func (*stubProductApplication) Get(context.Context, identity.Principal, string) (Product, error) {
	return Product{}, errors.New("unexpected Get call")
}

func (application *stubProductApplication) List(context.Context, identity.Principal, Page) (ProductPage, error) {
	return application.listPage, application.listError
}

func (*stubProductApplication) Deactivate(context.Context, identity.Principal, string, RequestContext) (Product, error) {
	return Product{}, errors.New("unexpected Deactivate call")
}

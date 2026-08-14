package httpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"xminds-release-platform/internal/platform/buildinfo"
)

type healthCheckerFunc func(context.Context) error

func (function healthCheckerFunc) Ping(ctx context.Context) error {
	return function(ctx)
}

func TestHandlerPublishesHealthAndVersion(t *testing.T) {
	t.Parallel()

	handler := NewHandler(healthCheckerFunc(func(context.Context) error { return nil }), buildinfo.Info{
		Product: "xminds-release-platform",
		Version: "test-version",
		Commit:  "test-commit",
	})

	for _, testCase := range []struct {
		path       string
		bodyMarker string
	}{
		{path: "/health/live", bodyMarker: `"status":"ok"`},
		{path: "/health/ready", bodyMarker: `"status":"ready"`},
		{path: "/version", bodyMarker: `"version":"test-version"`},
	} {
		testCase := testCase
		t.Run(testCase.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, testCase.path, nil)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), testCase.bodyMarker) {
				t.Fatalf("body = %s, want marker %s", response.Body.String(), testCase.bodyMarker)
			}
			if response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("security response headers are missing")
			}
		})
	}
}

func TestReadinessUsesSafeProblemDetails(t *testing.T) {
	t.Parallel()

	handler := NewHandler(healthCheckerFunc(func(context.Context) error {
		return errors.New("password=must-not-leak")
	}), buildinfo.Current())
	request := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "must-not-leak") {
		t.Fatalf("internal error leaked: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"code":"DATABASE_UNAVAILABLE"`) {
		t.Fatalf("problem code missing: %s", response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"request_id":`) {
		t.Fatalf("request ID missing: %s", response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("Content-Type = %q", response.Header().Get("Content-Type"))
	}
}

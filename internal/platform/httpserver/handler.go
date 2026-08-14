package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"xminds-release-platform/internal/platform/buildinfo"
	"xminds-release-platform/internal/platform/httpx"
)

type HealthChecker interface {
	Ping(ctx context.Context) error
}

func NewHandler(healthChecker HealthChecker, info buildinfo.Info) http.Handler {
	router := chi.NewRouter()
	router.Use(securityHeaders)
	router.Use(requestID)
	router.Use(recoverPanics)

	router.Get("/health/live", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
	})
	router.Get("/health/ready", func(writer http.ResponseWriter, request *http.Request) {
		if healthChecker == nil {
			writeUnavailable(writer, request, errors.New("health checker is not configured"))
			return
		}
		if err := healthChecker.Ping(request.Context()); err != nil {
			writeUnavailable(writer, request, err)
			return
		}
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
	})
	router.Get("/version", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, info)
	})
	router.NotFound(func(writer http.ResponseWriter, request *http.Request) {
		httpx.WriteProblem(writer, httpx.NewProblem(
			http.StatusNotFound,
			"ROUTE_NOT_FOUND",
			"Route not found",
			nil,
		).WithRequestID(httpx.RequestIDFromContext(request.Context())).WithInstance(request.URL.Path))
	})
	router.MethodNotAllowed(func(writer http.ResponseWriter, request *http.Request) {
		httpx.WriteProblem(writer, httpx.NewProblem(
			http.StatusMethodNotAllowed,
			"METHOD_NOT_ALLOWED",
			"Method not allowed",
			nil,
		).WithRequestID(httpx.RequestIDFromContext(request.Context())).WithInstance(request.URL.Path))
	})

	return otelhttp.NewHandler(router, "xminds-release-platform.http")
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("X-Frame-Options", "DENY")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(writer, request)
	})
}

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		identifier := request.Header.Get("X-Request-ID")
		if _, err := uuid.Parse(identifier); err != nil {
			generated, generationErr := uuid.NewV7()
			if generationErr != nil {
				generated = uuid.New()
			}
			identifier = generated.String()
		}
		writer.Header().Set("X-Request-ID", identifier)
		ctx := httpx.WithRequestID(request.Context(), identifier)
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

func recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				httpx.WriteProblem(writer, httpx.NewProblem(
					http.StatusInternalServerError,
					"INTERNAL_ERROR",
					"Internal server error",
					objectAsError(recovered),
				).WithRequestID(httpx.RequestIDFromContext(request.Context())))
			}
		}()
		next.ServeHTTP(writer, request)
	})
}

func writeUnavailable(writer http.ResponseWriter, request *http.Request, cause error) {
	httpx.WriteProblem(writer, httpx.NewProblem(
		http.StatusServiceUnavailable,
		"DATABASE_UNAVAILABLE",
		"Service is not ready",
		cause,
	).WithRequestID(httpx.RequestIDFromContext(request.Context())))
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		httpx.WriteProblem(writer, httpx.NewProblem(
			http.StatusInternalServerError,
			"RESPONSE_SERIALIZATION_FAILED",
			"Internal server error",
			err,
		))
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(payload, '\n'))
}

func objectAsError(value any) error {
	if err, ok := value.(error); ok {
		return err
	}
	return errors.New("panic recovered")
}

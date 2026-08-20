package endpoint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/httpx"
)

const maximumEndpointRequestBytes = 64 * 1024

type EndpointApplication interface {
	Register(ctx context.Context, principal identity.Principal, command RegisterCommand, request RequestContext) (Endpoint, error)
	Activate(ctx context.Context, principal identity.Principal, id uuid.UUID, request RequestContext) error
	GetAuthorized(ctx context.Context, principal identity.Principal, id uuid.UUID) (Endpoint, error)
}

func NewHTTPHandler(application EndpointApplication) http.Handler {
	if application == nil {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writeEndpointProblem(writer, request, http.StatusInternalServerError, "ENDPOINT_SERVICE_UNAVAILABLE", "Distribution endpoint service is unavailable", ErrEndpointRepository)
		})
	}
	router := chi.NewRouter()
	router.Post("/api/v1/endpoints", registerEndpointHandler(application))
	router.Get("/api/v1/endpoints/{endpoint_id}", getEndpointHandler(application))
	router.Post("/api/v1/endpoints/{endpoint_id}/activate", activateEndpointHandler(application))
	return router
}

func registerEndpointHandler(application EndpointApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireEndpointPrincipal(writer, request)
		if !ok {
			return
		}
		var command RegisterCommand
		if !decodeEndpointRequest(writer, request, &command) {
			return
		}
		record, err := application.Register(request.Context(), principal, command, endpointRequestContext(request))
		if err != nil {
			writeEndpointApplicationError(writer, request, err)
			return
		}
		writer.Header().Set("Location", "/api/v1/endpoints/"+record.ID.String())
		writeEndpointJSON(writer, http.StatusCreated, record)
	}
}

func getEndpointHandler(application EndpointApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, endpointID, ok := endpointRouteContext(writer, request)
		if !ok {
			return
		}
		record, err := application.GetAuthorized(request.Context(), principal, endpointID)
		if err != nil {
			writeEndpointApplicationError(writer, request, err)
			return
		}
		writeEndpointJSON(writer, http.StatusOK, record)
	}
}

func activateEndpointHandler(application EndpointApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, endpointID, ok := endpointRouteContext(writer, request)
		if !ok {
			return
		}
		if err := application.Activate(request.Context(), principal, endpointID, endpointRequestContext(request)); err != nil {
			writeEndpointApplicationError(writer, request, err)
			return
		}
		record, err := application.GetAuthorized(request.Context(), principal, endpointID)
		if err != nil {
			writeEndpointApplicationError(writer, request, err)
			return
		}
		writeEndpointJSON(writer, http.StatusOK, record)
	}
}

func decodeEndpointRequest(writer http.ResponseWriter, request *http.Request, destination any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeEndpointProblem(writer, request, http.StatusUnsupportedMediaType, "CONTENT_TYPE_UNSUPPORTED", "Content type must be application/json", err)
		return false
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, maximumEndpointRequestBytes+1))
	if err != nil {
		writeEndpointProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body could not be read", err)
		return false
	}
	if len(payload) > maximumEndpointRequestBytes {
		writeEndpointProblem(writer, request, http.StatusRequestEntityTooLarge, "REQUEST_BODY_TOO_LARGE", "Request body exceeds the size limit", ErrEndpointInvalid)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || !endpointDecoderAtEOF(decoder) {
		writeEndpointProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", err)
		return false
	}
	return true
}

func endpointRouteContext(writer http.ResponseWriter, request *http.Request) (identity.Principal, uuid.UUID, bool) {
	principal, ok := requireEndpointPrincipal(writer, request)
	if !ok {
		return identity.Principal{}, uuid.Nil, false
	}
	endpointID, err := uuid.Parse(chi.URLParam(request, "endpoint_id"))
	if err != nil {
		writeEndpointProblem(writer, request, http.StatusBadRequest, "ENDPOINT_ID_INVALID", "Distribution endpoint ID is invalid", err)
		return identity.Principal{}, uuid.Nil, false
	}
	return principal, endpointID, true
}

func requireEndpointPrincipal(writer http.ResponseWriter, request *http.Request) (identity.Principal, bool) {
	principal, ok := identity.PrincipalFromContext(request.Context())
	if !ok {
		writer.Header().Set("WWW-Authenticate", `Bearer realm="xminds-release-platform"`)
		writeEndpointProblem(writer, request, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Authentication is required", identity.ErrAuthenticationFailed)
		return identity.Principal{}, false
	}
	return principal, true
}

func writeEndpointApplicationError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, identity.ErrActionDenied), errors.Is(err, identity.ErrProductScopeDenied):
		writeEndpointProblem(writer, request, http.StatusForbidden, "ENDPOINT_ACCESS_DENIED", "Distribution endpoint access is denied", err)
	case errors.Is(err, ErrEndpointNotFound):
		writeEndpointProblem(writer, request, http.StatusNotFound, "ENDPOINT_NOT_FOUND", "Distribution endpoint was not found", err)
	case errors.Is(err, ErrCatalogDigestMismatch), errors.Is(err, ErrEndpointProbeFailed):
		writeEndpointProblem(writer, request, http.StatusConflict, "ENDPOINT_ACTIVATION_FAILED", "Distribution endpoint failed catalog verification", err)
	case errors.Is(err, ErrEndpointInvalid):
		writeEndpointProblem(writer, request, http.StatusUnprocessableEntity, "ENDPOINT_REQUEST_INVALID", "Distribution endpoint request is invalid", err)
	default:
		writeEndpointProblem(writer, request, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error", err)
	}
}

func endpointRequestContext(request *http.Request) RequestContext {
	host, _, err := net.SplitHostPort(strings.TrimSpace(request.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(request.RemoteAddr)
	}
	return RequestContext{RequestID: httpx.RequestIDFromContext(request.Context()), SourceIP: host}
}

func endpointDecoderAtEOF(decoder *json.Decoder) bool {
	var extra any
	return errors.Is(decoder.Decode(&extra), io.EOF)
}

func writeEndpointProblem(writer http.ResponseWriter, request *http.Request, status int, code, title string, cause error) {
	httpx.WriteProblem(writer, httpx.NewProblem(status, code, title, cause).
		WithRequestID(httpx.RequestIDFromContext(request.Context())).WithInstance(request.URL.Path))
}

func writeEndpointJSON(writer http.ResponseWriter, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		httpx.WriteProblem(writer, httpx.NewProblem(http.StatusInternalServerError, "RESPONSE_SERIALIZATION_FAILED", "Internal server error", fmt.Errorf("encode response: %w", err)))
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(payload, '\n'))
}

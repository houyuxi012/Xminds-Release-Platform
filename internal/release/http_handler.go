package release

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
	"net/url"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"xminds-release-platform/internal/artifact"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/httpx"
	"xminds-release-platform/internal/product"
)

const maximumReleaseRequestBytes = maximumReleaseNotesBytes + maximumCompatibilityBytes + 128*1024

type ReleaseApplication interface {
	Create(ctx context.Context, principal identity.Principal, command CreateCommand, request RequestContext) (Release, error)
	Submit(ctx context.Context, principal identity.Principal, productID string, releaseID uuid.UUID, expectedLockVersion int64, request RequestContext) (Release, error)
	Approve(ctx context.Context, principal identity.Principal, productID string, releaseID uuid.UUID, expectedLockVersion int64, request RequestContext) (Release, error)
	Reject(ctx context.Context, principal identity.Principal, productID string, releaseID uuid.UUID, expectedLockVersion int64, reason string, request RequestContext) (Release, error)
	Publish(ctx context.Context, principal identity.Principal, productID string, releaseID uuid.UUID, expectedLockVersion int64, idempotencyKey string, request RequestContext) (OperationResult, error)
	Retry(ctx context.Context, principal identity.Principal, productID string, releaseID uuid.UUID, expectedLockVersion int64, idempotencyKey string, request RequestContext) (OperationResult, error)
	Revoke(ctx context.Context, principal identity.Principal, productID string, releaseID uuid.UUID, expectedLockVersion int64, reason string, idempotencyKey string, request RequestContext) (OperationResult, error)
	Get(ctx context.Context, principal identity.Principal, productID string, releaseID uuid.UUID) (Release, error)
}

func NewHTTPHandler(application ReleaseApplication) http.Handler {
	if application == nil {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writeReleaseProblem(writer, request, http.StatusInternalServerError, "RELEASE_SERVICE_UNAVAILABLE", "Release service is unavailable", ErrRepositoryRequired)
		})
	}
	router := chi.NewRouter()
	RegisterRoutes(router, application)
	return router
}

func RegisterRoutes(router chi.Router, application ReleaseApplication) {
	router.Post("/api/v1/products/{product_id}/releases", createReleaseHandler(application))
	router.Post("/api/v1/products/{product_id}/releases/{release_id}/submit", releaseTransitionHandler(application, "submit"))
	router.Post("/api/v1/products/{product_id}/releases/{release_id}/approve", releaseTransitionHandler(application, "approve"))
	router.Post("/api/v1/products/{product_id}/releases/{release_id}/reject", releaseTransitionHandler(application, "reject"))
	router.Post("/api/v1/products/{product_id}/releases/{release_id}/publish", releaseOperationHandler(application, "publish"))
	router.Post("/api/v1/products/{product_id}/releases/{release_id}/retry", releaseOperationHandler(application, "retry"))
	router.Post("/api/v1/products/{product_id}/releases/{release_id}/revoke", releaseOperationHandler(application, "revoke"))
	router.Get("/api/v1/products/{product_id}/releases/{release_id}", getReleaseHandler(application))
}

type createReleaseRequest struct {
	Channel             string          `json:"channel"`
	Version             string          `json:"version"`
	ReleaseNotes        string          `json:"release_notes"`
	ReleaseNotesSHA256  string          `json:"release_notes_sha256"`
	Compatibility       json.RawMessage `json:"compatibility"`
	CompatibilitySHA256 string          `json:"compatibility_sha256"`
	ArtifactIDs         []uuid.UUID     `json:"artifact_ids"`
	Source              Source          `json:"source"`
}

type releaseTransitionRequest struct {
	LockVersion int64  `json:"lock_version"`
	Reason      string `json:"reason,omitempty"`
}

func createReleaseHandler(application ReleaseApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireReleasePrincipal(writer, request)
		if !ok {
			return
		}
		var input createReleaseRequest
		if !decodeReleaseRequest(writer, request, &input) {
			return
		}
		record, err := application.Create(request.Context(), principal, CreateCommand{
			ProductID: chi.URLParam(request, "product_id"), Channel: input.Channel, Version: input.Version,
			ReleaseNotes: []byte(input.ReleaseNotes), ReleaseNotesSHA256: input.ReleaseNotesSHA256,
			Compatibility: input.Compatibility, CompatibilitySHA256: input.CompatibilitySHA256,
			ArtifactIDs: input.ArtifactIDs, Source: input.Source,
		}, releaseRequestContext(request))
		if err != nil {
			writeReleaseApplicationError(writer, request, err)
			return
		}
		writer.Header().Set("Location", "/api/v1/products/"+url.PathEscape(record.ProductID)+"/releases/"+record.ID.String())
		writeReleaseJSON(writer, http.StatusCreated, record)
	}
}

func releaseTransitionHandler(application ReleaseApplication, operation string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, releaseID, ok := releaseRouteContext(writer, request)
		if !ok {
			return
		}
		var input releaseTransitionRequest
		if !decodeReleaseRequest(writer, request, &input) {
			return
		}
		var record Release
		var err error
		productID := chi.URLParam(request, "product_id")
		requestContext := releaseRequestContext(request)
		switch operation {
		case "submit":
			record, err = application.Submit(request.Context(), principal, productID, releaseID, input.LockVersion, requestContext)
		case "approve":
			record, err = application.Approve(request.Context(), principal, productID, releaseID, input.LockVersion, requestContext)
		case "reject":
			record, err = application.Reject(request.Context(), principal, productID, releaseID, input.LockVersion, input.Reason, requestContext)
		default:
			err = ErrInvalidTransition
		}
		if err != nil {
			writeReleaseApplicationError(writer, request, err)
			return
		}
		writeReleaseJSON(writer, http.StatusOK, record)
	}
}

func releaseOperationHandler(application ReleaseApplication, operation string) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, releaseID, ok := releaseRouteContext(writer, request)
		if !ok {
			return
		}
		var input releaseTransitionRequest
		if !decodeReleaseRequest(writer, request, &input) {
			return
		}
		idempotencyKey := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
		if !idempotencyPattern.MatchString(idempotencyKey) {
			writeReleaseApplicationError(writer, request, ErrIdempotencyKeyInvalid)
			return
		}
		var result OperationResult
		var err error
		productID := chi.URLParam(request, "product_id")
		requestContext := releaseRequestContext(request)
		switch operation {
		case "publish":
			result, err = application.Publish(request.Context(), principal, productID, releaseID, input.LockVersion, idempotencyKey, requestContext)
		case "retry":
			result, err = application.Retry(request.Context(), principal, productID, releaseID, input.LockVersion, idempotencyKey, requestContext)
		case "revoke":
			result, err = application.Revoke(request.Context(), principal, productID, releaseID, input.LockVersion, input.Reason, idempotencyKey, requestContext)
		default:
			err = ErrInvalidTransition
		}
		if err != nil {
			writeReleaseApplicationError(writer, request, err)
			return
		}
		writeReleaseJSON(writer, http.StatusOK, result)
	}
}

func getReleaseHandler(application ReleaseApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, releaseID, ok := releaseRouteContext(writer, request)
		if !ok {
			return
		}
		record, err := application.Get(request.Context(), principal, chi.URLParam(request, "product_id"), releaseID)
		if err != nil {
			writeReleaseApplicationError(writer, request, err)
			return
		}
		writeReleaseJSON(writer, http.StatusOK, record)
	}
}

func decodeReleaseRequest(writer http.ResponseWriter, request *http.Request, destination any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeReleaseProblem(writer, request, http.StatusUnsupportedMediaType, "CONTENT_TYPE_UNSUPPORTED", "Content type must be application/json", err)
		return false
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, maximumReleaseRequestBytes+1))
	if err != nil {
		writeReleaseProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body could not be read", err)
		return false
	}
	if len(payload) > maximumReleaseRequestBytes {
		writeReleaseProblem(writer, request, http.StatusRequestEntityTooLarge, "REQUEST_BODY_TOO_LARGE", "Request body exceeds the size limit", ErrReleaseNotesInvalid)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || !releaseDecoderAtEOF(decoder) {
		writeReleaseProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", err)
		return false
	}
	return true
}

func releaseRouteContext(writer http.ResponseWriter, request *http.Request) (identity.Principal, uuid.UUID, bool) {
	principal, ok := requireReleasePrincipal(writer, request)
	if !ok {
		return identity.Principal{}, uuid.Nil, false
	}
	releaseID, err := uuid.Parse(chi.URLParam(request, "release_id"))
	if err != nil {
		writeReleaseProblem(writer, request, http.StatusBadRequest, "RELEASE_ID_INVALID", "Release ID is invalid", err)
		return identity.Principal{}, uuid.Nil, false
	}
	return principal, releaseID, true
}

func requireReleasePrincipal(writer http.ResponseWriter, request *http.Request) (identity.Principal, bool) {
	principal, ok := identity.PrincipalFromContext(request.Context())
	if !ok {
		writer.Header().Set("WWW-Authenticate", `Bearer realm="xminds-release-platform"`)
		writeReleaseProblem(writer, request, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Authentication is required", identity.ErrAuthenticationFailed)
		return identity.Principal{}, false
	}
	return principal, true
}

func writeReleaseApplicationError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, ErrSelfApprovalForbidden):
		writeReleaseProblem(writer, request, http.StatusForbidden, "RELEASE_SELF_APPROVAL_FORBIDDEN", "Release submitter cannot approve or reject own release", err)
	case errors.Is(err, identity.ErrActionDenied), errors.Is(err, identity.ErrProductScopeDenied):
		writeReleaseProblem(writer, request, http.StatusForbidden, "RELEASE_ACCESS_DENIED", "Release access is denied", err)
	case errors.Is(err, ErrReleaseNotFound), errors.Is(err, product.ErrProductNotFound), errors.Is(err, artifact.ErrArtifactNotFound):
		writeReleaseProblem(writer, request, http.StatusNotFound, "RELEASE_RESOURCE_NOT_FOUND", "Release resource was not found", err)
	case errors.Is(err, ErrReleaseVersionExists):
		writeReleaseProblem(writer, request, http.StatusConflict, "RELEASE_VERSION_EXISTS", "Release version already exists in product channel", err)
	case errors.Is(err, ErrStaleRelease):
		writeReleaseProblem(writer, request, http.StatusConflict, "RELEASE_STALE_VERSION", "Release was modified by another request", err)
	case errors.Is(err, ErrInvalidTransition), errors.Is(err, ErrReleaseAlreadyRevoked), errors.Is(err, ErrAttemptAlreadyExists):
		writeReleaseProblem(writer, request, http.StatusConflict, "RELEASE_STATE_CONFLICT", "Release state conflicts with the request", err)
	case errors.Is(err, ErrIdempotencyKeyInvalid):
		writeReleaseProblem(writer, request, http.StatusUnprocessableEntity, "RELEASE_IDEMPOTENCY_KEY_INVALID", "Idempotency-Key is invalid", err)
	case errors.Is(err, ErrProductInvalid), errors.Is(err, ErrChannelInvalid), errors.Is(err, ErrVersionInvalid),
		errors.Is(err, ErrReleaseNotesInvalid), errors.Is(err, ErrReleaseNotesMismatch),
		errors.Is(err, ErrCompatibilityInvalid), errors.Is(err, ErrCompatibilityMismatch),
		errors.Is(err, ErrArtifactsInvalid), errors.Is(err, ErrArtifactProductMismatch), errors.Is(err, ErrSourceInvalid),
		errors.Is(err, ErrRejectionReasonRequired), errors.Is(err, ErrRevocationReasonRequired):
		writeReleaseProblem(writer, request, http.StatusUnprocessableEntity, "RELEASE_REQUEST_INVALID", "Release request is invalid", err)
	default:
		writeReleaseProblem(writer, request, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error", err)
	}
}

func releaseRequestContext(request *http.Request) RequestContext {
	host, _, err := net.SplitHostPort(strings.TrimSpace(request.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(request.RemoteAddr)
	}
	return RequestContext{RequestID: httpx.RequestIDFromContext(request.Context()), SourceIP: host}
}

func releaseDecoderAtEOF(decoder *json.Decoder) bool {
	var extra any
	return errors.Is(decoder.Decode(&extra), io.EOF)
}

func writeReleaseProblem(writer http.ResponseWriter, request *http.Request, status int, code string, title string, cause error) {
	httpx.WriteProblem(writer, httpx.NewProblem(status, code, title, cause).
		WithRequestID(httpx.RequestIDFromContext(request.Context())).WithInstance(request.URL.Path))
}

func writeReleaseJSON(writer http.ResponseWriter, status int, value any) {
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

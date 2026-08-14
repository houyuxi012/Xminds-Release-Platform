package artifact

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
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/httpx"
	"xminds-release-platform/internal/product"
)

const maximumBeginUploadRequestBytes = 64 * 1024

type ArtifactApplication interface {
	BeginUpload(ctx context.Context, principal identity.Principal, command BeginUpload, request RequestContext) (Upload, error)
	PutPart(ctx context.Context, principal identity.Principal, productID string, uploadID uuid.UUID, command PutPart, body io.Reader, request RequestContext) (UploadPart, error)
	Complete(ctx context.Context, principal identity.Principal, productID string, uploadID uuid.UUID, request RequestContext) (Artifact, error)
	Get(ctx context.Context, principal identity.Principal, productID string, artifactID uuid.UUID) (Artifact, error)
}

func NewHTTPHandler(application ArtifactApplication) http.Handler {
	if application == nil {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writeArtifactProblem(writer, request, http.StatusInternalServerError, "ARTIFACT_SERVICE_UNAVAILABLE", "Artifact service is unavailable", ErrRepositoryRequired)
		})
	}
	router := chi.NewRouter()
	router.Post("/api/v1/products/{product_id}/artifact-uploads", beginUploadHandler(application))
	router.Put("/api/v1/products/{product_id}/artifact-uploads/{upload_id}/parts/{part_number}", putPartHandler(application))
	router.Post("/api/v1/products/{product_id}/artifact-uploads/{upload_id}/complete", completeUploadHandler(application))
	router.Get("/api/v1/products/{product_id}/artifacts/{artifact_id}", getArtifactHandler(application))
	return router
}

type beginUploadRequest struct {
	ArtifactType string `json:"artifact_type"`
	Filename     string `json:"filename"`
	ContentType  string `json:"content_type"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
}

func beginUploadHandler(application ArtifactApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireArtifactPrincipal(writer, request)
		if !ok {
			return
		}
		mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			writeArtifactProblem(writer, request, http.StatusUnsupportedMediaType, "CONTENT_TYPE_UNSUPPORTED", "Content type must be application/json", err)
			return
		}
		payload, err := io.ReadAll(io.LimitReader(request.Body, maximumBeginUploadRequestBytes+1))
		if err != nil {
			writeArtifactProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body could not be read", err)
			return
		}
		if len(payload) > maximumBeginUploadRequestBytes {
			writeArtifactProblem(writer, request, http.StatusRequestEntityTooLarge, "REQUEST_BODY_TOO_LARGE", "Request body exceeds the size limit", ErrObjectSizeInvalid)
			return
		}
		var input beginUploadRequest
		decoder := json.NewDecoder(bytes.NewReader(payload))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil || !decoderAtEOF(decoder) {
			writeArtifactProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", err)
			return
		}
		upload, err := application.BeginUpload(request.Context(), principal, BeginUpload{
			ProductID: chi.URLParam(request, "product_id"), ArtifactType: input.ArtifactType,
			Filename: input.Filename, ContentType: input.ContentType, Size: input.Size, SHA256: input.SHA256,
		}, artifactRequestContext(request))
		if err != nil {
			writeArtifactApplicationError(writer, request, err)
			return
		}
		writer.Header().Set("Location", "/api/v1/products/"+url.PathEscape(upload.ProductID)+"/artifact-uploads/"+upload.ID.String())
		writeArtifactJSON(writer, http.StatusCreated, upload)
	}
}

func putPartHandler(application ArtifactApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireArtifactPrincipal(writer, request)
		if !ok {
			return
		}
		mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/octet-stream" {
			writeArtifactProblem(writer, request, http.StatusUnsupportedMediaType, "CONTENT_TYPE_UNSUPPORTED", "Content type must be application/octet-stream", err)
			return
		}
		uploadID, err := uuid.Parse(chi.URLParam(request, "upload_id"))
		if err != nil {
			writeArtifactProblem(writer, request, http.StatusBadRequest, "UPLOAD_ID_INVALID", "Upload ID is invalid", err)
			return
		}
		partNumber, err := strconv.Atoi(chi.URLParam(request, "part_number"))
		if err != nil || partNumber < 1 || partNumber > MaximumPartCount {
			writeArtifactProblem(writer, request, http.StatusBadRequest, "PART_NUMBER_INVALID", "Part number is invalid", ErrPartNumberInvalid)
			return
		}
		if request.ContentLength < 0 {
			writeArtifactProblem(writer, request, http.StatusLengthRequired, "CONTENT_LENGTH_REQUIRED", "Content-Length is required", ErrPartSizeInvalid)
			return
		}
		if request.ContentLength == 0 {
			writeArtifactProblem(writer, request, http.StatusUnprocessableEntity, "PART_SIZE_INVALID", "Part size is invalid", ErrPartSizeInvalid)
			return
		}
		if request.ContentLength > MaximumPartSize {
			writeArtifactProblem(writer, request, http.StatusRequestEntityTooLarge, "PART_TOO_LARGE", "Part exceeds the size limit", ErrPartSizeInvalid)
			return
		}
		part, err := application.PutPart(request.Context(), principal, chi.URLParam(request, "product_id"), uploadID, PutPart{
			PartNumber: partNumber,
			Size:       request.ContentLength,
			SHA256:     strings.TrimSpace(request.Header.Get("X-Part-SHA256")),
		}, request.Body, artifactRequestContext(request))
		if err != nil {
			writeArtifactApplicationError(writer, request, err)
			return
		}
		writeArtifactJSON(writer, http.StatusOK, part)
	}
}

func completeUploadHandler(application ArtifactApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireArtifactPrincipal(writer, request)
		if !ok {
			return
		}
		uploadID, err := uuid.Parse(chi.URLParam(request, "upload_id"))
		if err != nil {
			writeArtifactProblem(writer, request, http.StatusBadRequest, "UPLOAD_ID_INVALID", "Upload ID is invalid", err)
			return
		}
		item, err := application.Complete(request.Context(), principal, chi.URLParam(request, "product_id"), uploadID, artifactRequestContext(request))
		if err != nil {
			writeArtifactApplicationError(writer, request, err)
			return
		}
		writeArtifactJSON(writer, http.StatusOK, item)
	}
}

func getArtifactHandler(application ArtifactApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireArtifactPrincipal(writer, request)
		if !ok {
			return
		}
		artifactID, err := uuid.Parse(chi.URLParam(request, "artifact_id"))
		if err != nil {
			writeArtifactProblem(writer, request, http.StatusBadRequest, "ARTIFACT_ID_INVALID", "Artifact ID is invalid", err)
			return
		}
		item, err := application.Get(request.Context(), principal, chi.URLParam(request, "product_id"), artifactID)
		if err != nil {
			writeArtifactApplicationError(writer, request, err)
			return
		}
		writeArtifactJSON(writer, http.StatusOK, item)
	}
}

func requireArtifactPrincipal(writer http.ResponseWriter, request *http.Request) (identity.Principal, bool) {
	principal, ok := identity.PrincipalFromContext(request.Context())
	if !ok {
		writer.Header().Set("WWW-Authenticate", `Bearer realm="xminds-release-platform"`)
		writeArtifactProblem(writer, request, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Authentication is required", identity.ErrAuthenticationFailed)
		return identity.Principal{}, false
	}
	return principal, true
}

func decoderAtEOF(decoder *json.Decoder) bool {
	var extra any
	return errors.Is(decoder.Decode(&extra), io.EOF)
}

func artifactRequestContext(request *http.Request) RequestContext {
	return RequestContext{RequestID: httpx.RequestIDFromContext(request.Context()), SourceIP: artifactSourceIP(request.RemoteAddr)}
}

func artifactSourceIP(remoteAddress string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddress))
	if err == nil {
		return host
	}
	return strings.TrimSpace(remoteAddress)
}

func writeArtifactApplicationError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, identity.ErrActionDenied), errors.Is(err, identity.ErrProductScopeDenied):
		writeArtifactProblem(writer, request, http.StatusForbidden, "ARTIFACT_ACCESS_DENIED", "Artifact access is denied", err)
	case errors.Is(err, ErrUploadNotFound), errors.Is(err, ErrUploadProductMismatch), errors.Is(err, ErrArtifactNotFound), errors.Is(err, product.ErrProductNotFound):
		writeArtifactProblem(writer, request, http.StatusNotFound, "ARTIFACT_RESOURCE_NOT_FOUND", "Artifact resource was not found", err)
	case errors.Is(err, ErrUploadExpired):
		writeArtifactProblem(writer, request, http.StatusGone, "ARTIFACT_UPLOAD_EXPIRED", "Artifact upload has expired", err)
	case errors.Is(err, ErrDigestMismatch):
		writeArtifactProblem(writer, request, http.StatusUnprocessableEntity, "ARTIFACT_DIGEST_MISMATCH", "Artifact digest does not match uploaded content", err)
	case errors.Is(err, ErrPartDigestMismatch):
		writeArtifactProblem(writer, request, http.StatusUnprocessableEntity, "ARTIFACT_PART_DIGEST_MISMATCH", "Artifact part digest does not match uploaded content", err)
	case errors.Is(err, ErrPartSizeMismatch), errors.Is(err, ErrPartSizeInvalid), errors.Is(err, ErrPartNumberInvalid),
		errors.Is(err, ErrProductRequired), errors.Is(err, ErrArtifactTypeInvalid), errors.Is(err, ErrFilenameInvalid),
		errors.Is(err, ErrContentTypeInvalid), errors.Is(err, ErrObjectSizeInvalid), errors.Is(err, ErrDigestInvalid):
		writeArtifactProblem(writer, request, http.StatusUnprocessableEntity, "ARTIFACT_REQUEST_INVALID", "Artifact request is invalid", err)
	case errors.Is(err, ErrPartsIncomplete), errors.Is(err, ErrUploadStateInvalid), errors.Is(err, ErrObjectConflict):
		writeArtifactProblem(writer, request, http.StatusConflict, "ARTIFACT_STATE_CONFLICT", "Artifact state conflicts with the request", err)
	default:
		writeArtifactProblem(writer, request, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error", err)
	}
}

func writeArtifactProblem(writer http.ResponseWriter, request *http.Request, status int, code string, title string, cause error) {
	httpx.WriteProblem(writer, httpx.NewProblem(status, code, title, cause).
		WithRequestID(httpx.RequestIDFromContext(request.Context())).WithInstance(request.URL.Path))
}

func writeArtifactJSON(writer http.ResponseWriter, status int, value any) {
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

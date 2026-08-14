package product

import (
	"context"
	"encoding/base64"
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
	"time"

	"github.com/go-chi/chi/v5"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/httpx"
)

const maximumProductRequestBytes = maximumManifestBytes + 1

type ProductApplication interface {
	Register(ctx context.Context, principal identity.Principal, rawManifest []byte, request RequestContext) (Product, error)
	Get(ctx context.Context, principal identity.Principal, productID string) (Product, error)
	List(ctx context.Context, principal identity.Principal, page Page) (ProductPage, error)
	Deactivate(ctx context.Context, principal identity.Principal, productID string, request RequestContext) (Product, error)
}

func NewHTTPHandler(application ProductApplication) http.Handler {
	if application == nil {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writeProductProblem(writer, request, http.StatusInternalServerError, "PRODUCT_SERVICE_UNAVAILABLE", "Product service is unavailable", ErrRepositoryRequired)
		})
	}
	router := chi.NewRouter()
	router.Route("/api/v1/products", func(router chi.Router) {
		router.Post("/", registerProductHandler(application))
		router.Get("/", listProductsHandler(application))
		router.Get("/{product_id}", getProductHandler(application))
		router.Post("/{product_id}/deactivate", deactivateProductHandler(application))
	})
	return router
}

func registerProductHandler(application ProductApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requirePrincipal(writer, request)
		if !ok {
			return
		}
		mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			writeProductProblem(writer, request, http.StatusUnsupportedMediaType, "CONTENT_TYPE_UNSUPPORTED", "Content type must be application/json", err)
			return
		}
		payload, err := io.ReadAll(io.LimitReader(request.Body, maximumProductRequestBytes))
		if err != nil {
			writeProductProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body could not be read", err)
			return
		}
		if len(payload) > maximumManifestBytes {
			writeProductProblem(writer, request, http.StatusRequestEntityTooLarge, "REQUEST_BODY_TOO_LARGE", "Request body exceeds the size limit", ErrManifestTooLarge)
			return
		}
		product, err := application.Register(request.Context(), principal, payload, requestContext(request))
		if err != nil {
			writeProductApplicationError(writer, request, err)
			return
		}
		writer.Header().Set("Location", "/api/v1/products/"+url.PathEscape(product.ID))
		writeJSON(writer, http.StatusCreated, product)
	}
}

func getProductHandler(application ProductApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requirePrincipal(writer, request)
		if !ok {
			return
		}
		product, err := application.Get(request.Context(), principal, chi.URLParam(request, "product_id"))
		if err != nil {
			writeProductApplicationError(writer, request, err)
			return
		}
		writeJSON(writer, http.StatusOK, product)
	}
}

func listProductsHandler(application ProductApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requirePrincipal(writer, request)
		if !ok {
			return
		}
		page, err := parseProductPage(request)
		if err != nil {
			writeProductProblem(writer, request, http.StatusBadRequest, "PAGE_INVALID", "Product page parameters are invalid", err)
			return
		}
		result, err := application.List(request.Context(), principal, page)
		if err != nil {
			writeProductApplicationError(writer, request, err)
			return
		}
		writeJSON(writer, http.StatusOK, result)
	}
}

func deactivateProductHandler(application ProductApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requirePrincipal(writer, request)
		if !ok {
			return
		}
		product, err := application.Deactivate(request.Context(), principal, chi.URLParam(request, "product_id"), requestContext(request))
		if err != nil {
			writeProductApplicationError(writer, request, err)
			return
		}
		writeJSON(writer, http.StatusOK, product)
	}
}

func requirePrincipal(writer http.ResponseWriter, request *http.Request) (identity.Principal, bool) {
	principal, ok := identity.PrincipalFromContext(request.Context())
	if !ok {
		writer.Header().Set("WWW-Authenticate", `Bearer realm="xminds-release-platform"`)
		writeProductProblem(writer, request, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Authentication is required", identity.ErrAuthenticationFailed)
		return identity.Principal{}, false
	}
	return principal, true
}

func requestContext(request *http.Request) RequestContext {
	return RequestContext{
		RequestID: httpx.RequestIDFromContext(request.Context()),
		SourceIP:  sourceIP(request.RemoteAddr),
	}
}

func sourceIP(remoteAddress string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddress))
	if err == nil {
		return host
	}
	return strings.TrimSpace(remoteAddress)
}

func parseProductPage(request *http.Request) (Page, error) {
	page := Page{}
	if rawLimit := strings.TrimSpace(request.URL.Query().Get("limit")); rawLimit != "" {
		limit, err := strconv.Atoi(rawLimit)
		if err != nil {
			return Page{}, ErrPageInvalid
		}
		if limit <= 0 {
			return Page{}, ErrPageInvalid
		}
		page.Limit = limit
	}
	if rawCursor := strings.TrimSpace(request.URL.Query().Get("cursor")); rawCursor != "" {
		createdAt, productID, err := decodePageCursor(rawCursor)
		if err != nil {
			return Page{}, err
		}
		page.BeforeTime = createdAt
		page.BeforeID = productID
	}
	if page.Limit < 0 || page.Limit > maximumPageLimit {
		return Page{}, ErrPageInvalid
	}
	return page, nil
}

func encodePageCursor(createdAt time.Time, productID string) string {
	payload := createdAt.UTC().Format(time.RFC3339Nano) + "\n" + strings.TrimSpace(productID)
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

func decodePageCursor(cursor string) (time.Time, string, error) {
	payload, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", ErrPageInvalid
	}
	parts := strings.Split(string(payload), "\n")
	if len(parts) != 2 || !productIDPattern.MatchString(parts[1]) {
		return time.Time{}, "", ErrPageInvalid
	}
	createdAt, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", ErrPageInvalid
	}
	return createdAt.UTC(), parts[1], nil
}

func writeProductApplicationError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case isManifestError(err):
		writeProductProblem(writer, request, http.StatusUnprocessableEntity, "PRODUCT_MANIFEST_INVALID", "Product manifest is invalid", err)
	case errors.Is(err, ErrProductIDExists):
		writeProductProblem(writer, request, http.StatusConflict, "PRODUCT_ALREADY_EXISTS", "Product ID already exists", err)
	case errors.Is(err, ErrManifestDigestExists):
		writeProductProblem(writer, request, http.StatusConflict, "PRODUCT_MANIFEST_ALREADY_EXISTS", "Product manifest already exists", err)
	case errors.Is(err, identity.ErrActionDenied), errors.Is(err, identity.ErrProductScopeDenied):
		writeProductProblem(writer, request, http.StatusForbidden, "PRODUCT_ACCESS_DENIED", "Product access is denied", err)
	case errors.Is(err, ErrProductNotFound):
		writeProductProblem(writer, request, http.StatusNotFound, "PRODUCT_NOT_FOUND", "Product was not found", err)
	case errors.Is(err, ErrPageInvalid):
		writeProductProblem(writer, request, http.StatusBadRequest, "PAGE_INVALID", "Product page parameters are invalid", err)
	default:
		writeProductProblem(writer, request, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error", err)
	}
}

func isManifestError(err error) bool {
	manifestErrors := []error{
		ErrManifestInvalid,
		ErrManifestTooLarge,
		ErrManifestDuplicateField,
		ErrSchemaVersionUnsupported,
		ErrProductIDInvalid,
		ErrDisplayNameInvalid,
		ErrArtifactTypeInvalid,
		ErrArtifactTypeDuplicate,
		ErrVersionSchemeUnsupported,
		ErrCompatibilityKeyInvalid,
		ErrCompatibilityKeyDuplicate,
		ErrCatalogFormatUnsupported,
		ErrChannelInvalid,
		ErrChannelDuplicate,
	}
	for _, candidate := range manifestErrors {
		if errors.Is(err, candidate) {
			return true
		}
	}
	return false
}

func writeProductProblem(writer http.ResponseWriter, request *http.Request, status int, code string, title string, cause error) {
	httpx.WriteProblem(writer, httpx.NewProblem(status, code, title, cause).
		WithRequestID(httpx.RequestIDFromContext(request.Context())).
		WithInstance(request.URL.Path))
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
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

package catalog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"xminds-release-platform/internal/artifact"
	"xminds-release-platform/internal/platform/objectstore"
)

const (
	timestampCacheControl = "public, max-age=30, must-revalidate"
	immutableCacheControl = "public, max-age=31536000, immutable"
)

var (
	publicProductPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	publicChannelPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	publicDigestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type PublicCatalogReader interface {
	Current(ctx context.Context, productID, channel string) (VersionRecord, error)
}

type PublicArtifactReader interface {
	GetByDigest(ctx context.Context, productID, digest string) (artifact.Artifact, error)
}

type PublicObjectStore interface {
	Open(ctx context.Context, key string, offset, length int64) (io.ReadCloser, objectstore.ObjectInfo, error)
	Stat(ctx context.Context, key string) (objectstore.ObjectInfo, error)
}

type PublicHTTPConfig struct {
	DefaultProductID string
	DefaultChannel   string
	Catalogs         PublicCatalogReader
	Artifacts        PublicArtifactReader
	Store            PublicObjectStore
}

var ErrPublicHTTPConfiguration = errors.New("public catalog HTTP configuration is invalid")

func NewPublicHTTPHandler(config PublicHTTPConfig) (http.Handler, error) {
	config.DefaultProductID = strings.TrimSpace(config.DefaultProductID)
	config.DefaultChannel = strings.TrimSpace(config.DefaultChannel)
	if !publicProductPattern.MatchString(config.DefaultProductID) || !publicChannelPattern.MatchString(config.DefaultChannel) || config.Catalogs == nil || config.Artifacts == nil || config.Store == nil {
		return nil, ErrPublicHTTPConfiguration
	}
	router := chi.NewRouter()
	router.Use(publicSecurityHeaders)
	router.Get("/metadata/{role}.json", func(writer http.ResponseWriter, request *http.Request) {
		servePublicRole(writer, request, config, config.DefaultProductID, config.DefaultChannel, chi.URLParam(request, "role"))
	})
	router.Get("/v1/products/{product}/channels/{channel}/metadata/{role}.json", func(writer http.ResponseWriter, request *http.Request) {
		servePublicRole(writer, request, config, chi.URLParam(request, "product"), chi.URLParam(request, "channel"), chi.URLParam(request, "role"))
	})
	router.Get("/v1/products/{product}/artifacts/{sha256}", func(writer http.ResponseWriter, request *http.Request) {
		servePublicArtifact(writer, request, config, chi.URLParam(request, "product"), chi.URLParam(request, "sha256"))
	})
	return router, nil
}

func servePublicRole(writer http.ResponseWriter, request *http.Request, config PublicHTTPConfig, productID, channel, roleText string) {
	role, valid := publicRole(roleText)
	if !valid || !publicProductPattern.MatchString(productID) || !publicChannelPattern.MatchString(channel) {
		http.NotFound(writer, request)
		return
	}
	record, err := config.Catalogs.Current(request.Context(), productID, channel)
	if err != nil || record.ProductID != productID || record.Channel != channel {
		http.NotFound(writer, request)
		return
	}
	document, exists := record.Roles[role]
	if !exists || document.Role != role || !publicDigestPattern.MatchString(document.EnvelopeSHA256) {
		http.NotFound(writer, request)
		return
	}
	etag := quoteETag(document.EnvelopeSHA256)
	setPublicSecurityHeaders(writer)
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("ETag", etag)
	if role == RoleTimestamp {
		writer.Header().Set("Cache-Control", timestampCacheControl)
	} else {
		writer.Header().Set("Cache-Control", immutableCacheControl)
	}
	if etagMatches(request.Header.Get("If-None-Match"), etag) {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	reader, information, err := config.Store.Open(request.Context(), document.ObjectKey, 0, -1)
	if err != nil {
		writePublicStoreError(writer, request, err)
		return
	}
	defer reader.Close()
	if information.Size > 0 {
		writer.Header().Set("Content-Length", strconv.FormatInt(information.Size, 10))
	}
	writer.WriteHeader(http.StatusOK)
	_, _ = io.Copy(writer, reader)
}

func servePublicArtifact(writer http.ResponseWriter, request *http.Request, config PublicHTTPConfig, productID, digest string) {
	if !publicProductPattern.MatchString(productID) || !publicDigestPattern.MatchString(digest) {
		http.NotFound(writer, request)
		return
	}
	item, err := config.Artifacts.GetByDigest(request.Context(), productID, digest)
	if err != nil || item.ProductID != productID || item.SHA256 != digest || item.Size <= 0 || item.ObjectKey == "" {
		http.NotFound(writer, request)
		return
	}
	etag := quoteETag(digest)
	setPublicSecurityHeaders(writer)
	writer.Header().Set("Accept-Ranges", "bytes")
	writer.Header().Set("Cache-Control", immutableCacheControl)
	writer.Header().Set("Content-Disposition", "attachment")
	writer.Header().Set("Content-Type", safeArtifactContentType(item.ContentType))
	writer.Header().Set("ETag", etag)
	if etagMatches(request.Header.Get("If-None-Match"), etag) {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	offset, length, partial, err := parseSingleRange(request.Header.Get("Range"), item.Size)
	if err != nil {
		writer.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", item.Size))
		writer.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		return
	}
	reader, information, err := config.Store.Open(request.Context(), item.ObjectKey, offset, length)
	if err != nil || information.Size != item.Size {
		writePublicStoreError(writer, request, err)
		return
	}
	defer reader.Close()
	if partial {
		writer.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, offset+length-1, item.Size))
		writer.Header().Set("Content-Length", strconv.FormatInt(length, 10))
		writer.WriteHeader(http.StatusPartialContent)
	} else {
		writer.Header().Set("Content-Length", strconv.FormatInt(item.Size, 10))
		writer.WriteHeader(http.StatusOK)
	}
	_, _ = io.Copy(writer, reader)
}

func publicRole(value string) (Role, bool) {
	role := Role(strings.TrimSpace(value))
	switch role {
	case RoleRoot, RoleTargets, RoleSnapshot, RoleTimestamp, RoleRevocation:
		return role, true
	default:
		return "", false
	}
}

func parseSingleRange(header string, size int64) (offset, length int64, partial bool, err error) {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0, -1, false, nil
	}
	if !strings.HasPrefix(header, "bytes=") || strings.Contains(header, ",") || size <= 0 {
		return 0, 0, false, objectstore.ErrRangeInvalid
	}
	value := strings.TrimPrefix(header, "bytes=")
	startText, endText, found := strings.Cut(value, "-")
	if !found || (startText == "" && endText == "") {
		return 0, 0, false, objectstore.ErrRangeInvalid
	}
	if startText == "" {
		suffix, parseErr := strconv.ParseInt(endText, 10, 64)
		if parseErr != nil || suffix <= 0 {
			return 0, 0, false, objectstore.ErrRangeInvalid
		}
		if suffix > size {
			suffix = size
		}
		return size - suffix, suffix, true, nil
	}
	start, parseErr := strconv.ParseInt(startText, 10, 64)
	if parseErr != nil || start < 0 || start >= size {
		return 0, 0, false, objectstore.ErrRangeInvalid
	}
	end := size - 1
	if endText != "" {
		end, parseErr = strconv.ParseInt(endText, 10, 64)
		if parseErr != nil || end < start {
			return 0, 0, false, objectstore.ErrRangeInvalid
		}
		if end >= size {
			end = size - 1
		}
	}
	return start, end - start + 1, true, nil
}

func etagMatches(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == etag || strings.TrimPrefix(candidate, "W/") == etag {
			return true
		}
	}
	return false
}

func quoteETag(digest string) string { return `"` + digest + `"` }

func safeArtifactContentType(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "application/octet-stream"
	}
	return value
}

func setPublicSecurityHeaders(writer http.ResponseWriter) {
	writer.Header().Set("X-Content-Type-Options", "nosniff")
}

func publicSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		writer.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		setPublicSecurityHeaders(writer)
		next.ServeHTTP(writer, request)
	})
}

func writePublicStoreError(writer http.ResponseWriter, request *http.Request, err error) {
	_ = err
	writer.Header().Del("Content-Length")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.Error(writer, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
}

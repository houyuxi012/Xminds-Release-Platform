package logcenter

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"xminds-release-platform/internal/platform/objectstore"
)

type ExportHTTPHandler struct {
	Service        *ExportService
	ResolveContext ExportContextResolver
	Archive        objectstore.Store
}

func (h *ExportHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path != "/api/v1/log-exports" && !strings.HasPrefix(r.URL.Path, "/api/v1/log-exports/") {
		writeMiddlewareProblem(w, 404, "NOT_FOUND", "resource not found")
		return
	}
	if r.Method == "GET" || r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/download") {
		if h == nil || h.Service == nil {
			writeMiddlewareProblem(w, 503, "LOG_CENTER_UNAVAILABLE", "export service unavailable")
			return
		}
		_, scope, err := h.resolveContext(r)
		if err != nil {
			writeExportStoreError(w, err)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if (r.Method == http.MethodGet && len(parts) != 4 && !(len(parts) == 5 && parts[4] == "content")) || (r.Method == http.MethodPost && (len(parts) != 5 || parts[4] != "download")) {
			writeMiddlewareProblem(w, 404, "NOT_FOUND", "resource not found")
			return
		}
		if len(parts) < 4 {
			writeMiddlewareProblem(w, 404, "NOT_FOUND", "resource not found")
			return
		}
		id, e := uuid.Parse(parts[3])
		if e != nil {
			writeMiddlewareProblem(w, 404, "NOT_FOUND", "resource not found")
			return
		}
		store, ok := h.Service.Store.(ExportStatusStore)
		if !ok {
			writeMiddlewareProblem(w, 503, "LOG_CENTER_UNAVAILABLE", "export store unavailable")
			return
		}
		if r.Method == http.MethodGet && len(parts) == 5 && parts[4] == "content" {
			if h.Archive == nil {
				writeMiddlewareProblem(w, 503, "LOG_CENTER_UNAVAILABLE", "archive store unavailable")
				return
			}
			rec, found, e := store.GetExport(r.Context(), id, scope)
			if e != nil {
				writeExportStoreError(w, e)
				return
			}
			if !found || rec.Status != "completed" || strings.TrimSpace(rec.ArchiveKey) == "" {
				writeMiddlewareProblem(w, 404, "NOT_FOUND", "export not found")
				return
			}
			reader, info, e := h.Archive.Open(r.Context(), rec.ArchiveKey, 0, -1)
			if e != nil {
				writeExportStoreError(w, e)
				return
			}
			defer reader.Close()
			w.Header().Set("Content-Type", "application/x-ndjson")
			w.Header().Set("Content-Length", strconv.FormatInt(info.Size, 10))
			if _, e := io.Copy(w, reader); e != nil {
				slog.Error("write log export content", "error", e)
			}
			return
		}
		if r.Method == http.MethodGet {
			rec, found, e := store.GetExport(r.Context(), id, scope)
			if e != nil {
				writeExportStoreError(w, e)
				return
			}
			if !found {
				writeMiddlewareProblem(w, 404, "NOT_FOUND", "export not found")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(map[string]any{"id": rec.ID.String(), "status": rec.Status}); err != nil {
				slog.Error("write export status response", "error", err)
				return
			}
			return
		}
		url, e := store.GrantDownload(r.Context(), id, scope, 5*time.Minute)
		if e != nil {
			writeExportStoreError(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"url": url}); err != nil {
			slog.Error("write export download response", "error", err)
			return
		}
		return
	}
	if r.Method != "POST" {
		writeMiddlewareProblem(w, 405, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	if r.URL.Path != "/api/v1/log-exports" {
		writeMiddlewareProblem(w, 404, "NOT_FOUND", "resource not found")
		return
	}
	if h == nil || h.Service == nil {
		writeMiddlewareProblem(w, 503, "LOG_CENTER_UNAVAILABLE", "export service unavailable")
		return
	}
	var req ExportRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if dec.Decode(&req) != nil || req.Format != "ndjson" || len(req.LogTypes) == 0 || strings.TrimSpace(req.DedupeKey) != req.DedupeKey || !validExportLogTypes(req.LogTypes) || !validExportProof(req.Reauthentication) {
		writeMiddlewareProblem(w, 400, "INVALID_EXPORT_REQUEST", "invalid export request")
		return
	}
	var trailing any
	if dec.Decode(&trailing) != io.EOF {
		writeMiddlewareProblem(w, 400, "INVALID_EXPORT_REQUEST", "trailing JSON is not allowed")
		return
	}
	requester, scope, err := h.resolveContext(r)
	if err != nil {
		writeExportStoreError(w, err)
		return
	}
	req.Requester = requester
	rec, err := h.Service.Create(r.Context(), req, scope)
	if err != nil {
		switch {
		case errors.Is(err, ErrExportUnavailable), errors.Is(err, ErrRepositoryUnavailable):
			writeMiddlewareProblem(w, 503, "LOG_CENTER_UNAVAILABLE", "export service unavailable")
		case errors.Is(err, ErrExportForbidden):
			writeMiddlewareProblem(w, 403, "FORBIDDEN", "export is not permitted")
		case errors.Is(err, ErrExportConflict):
			writeMiddlewareProblem(w, 409, "EXPORT_CONFLICT", "export dedupe key conflicts with an existing request")
		default:
			writeMiddlewareProblem(w, 400, "INVALID_EXPORT_REQUEST", "invalid export request")
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if err := json.NewEncoder(w).Encode(map[string]any{"id": rec.ID.String(), "status": rec.Status}); err != nil {
		slog.Error("write export response", "error", err)
		return
	}
}

func (h *ExportHTTPHandler) resolveContext(r *http.Request) (string, LogReadScope, error) {
	if h == nil || h.ResolveContext == nil {
		return "", LogReadScope{}, ErrExportUnavailable
	}
	requester, scope, err := h.ResolveContext(r.Context())
	if err != nil {
		return "", LogReadScope{}, err
	}
	if strings.TrimSpace(requester) == "" {
		return "", LogReadScope{}, ErrExportForbidden
	}
	return requester, scope, nil
}

func validExportLogTypes(v []ScopeTable) bool {
	if len(v) == 0 {
		return false
	}
	seen := map[ScopeTable]bool{}
	for _, t := range v {
		if seen[t] || (t != ScopeTableOperations && t != ScopeTableAuthentications && t != ScopeTableApplicationRequests && t != ScopeTableGitSyncs) {
			return false
		}
		seen[t] = true
	}
	return true
}
func validExportProof(v any) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 3 {
		return false
	}
	c, ok := m["challenge_id"].(string)
	e, _ := m["evidence"].(string)
	confirmed, _ := m["confirmed"].(bool)
	_, err := uuid.Parse(c)
	return err == nil && confirmed && exportEvidencePattern.MatchString(e)
}

var exportEvidencePattern = regexp.MustCompile(`^xmr_[A-Za-z0-9_-]{43}$`)

func writeExportStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrExportNotFound):
		writeMiddlewareProblem(w, 404, "NOT_FOUND", "export not found")
	case errors.Is(err, ErrExportForbidden):
		writeMiddlewareProblem(w, 403, "FORBIDDEN", "export is not permitted")
	case errors.Is(err, ErrRepositoryUnavailable), errors.Is(err, ErrExportUnavailable):
		writeMiddlewareProblem(w, 503, "LOG_CENTER_UNAVAILABLE", "export service unavailable")
	default:
		writeMiddlewareProblem(w, 503, "LOG_CENTER_UNAVAILABLE", "export service unavailable")
	}
}

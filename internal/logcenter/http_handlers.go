package logcenter

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
)

type LogHTTPHandler struct {
	Repo          *QueryRepository
	Scope         LogReadScope
	ScopeResolver func(*http.Request) (LogReadScope, bool)
}

func (h *LogHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if h == nil {
		writeMiddlewareProblem(w, 503, "LOG_CENTER_UNAVAILABLE", "log center is unavailable")
		return
	}
	if r.Method != "GET" {
		writeMiddlewareProblem(w, 405, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	scope := h.Scope
	if h.ScopeResolver != nil {
		resolved, ok := h.ScopeResolver(r)
		if !ok {
			writeMiddlewareProblem(w, 403, "FORBIDDEN", "audit read scope unavailable")
			return
		}
		scope = resolved
	}
	table := ScopeTable("")
	path := r.URL.EscapedPath()
	switch path {
	case "/api/v1/logs/related":
		f, err := parseLogQuery(r)
		if err != nil || (f.RequestID == "" && f.CorrelationID == "") {
			writeMiddlewareProblem(w, 400, "INVALID_LOG_QUERY", "related lookup requires request_id or correlation_id")
			return
		}
		if h.Repo == nil {
			writeMiddlewareProblem(w, 503, "LOG_CENTER_UNAVAILABLE", "log center is unavailable")
			return
		}
		page, err := h.Repo.QueryRelated(r.Context(), scope, f)
		if err != nil {
			if errors.Is(err, ErrRepositoryUnavailable) {
				writeMiddlewareProblem(w, 503, "LOG_CENTER_UNAVAILABLE", "log center is unavailable")
			} else {
				writeMiddlewareProblem(w, 400, "INVALID_LOG_QUERY", "invalid log query")
			}
			return
		}
		items := make([]map[string]any, 0, len(page.Items))
		for _, row := range page.Items {
			m := map[string]any{}
			for k, v := range row.Values {
				if k == "event_id" || k == "occurred_at" || k == "request_id" || k == "correlation_id" || k == "result" || k == "product_id" || k == "log_type" {
					m[k] = v
				}
			}
			items = append(items, m)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"items": items, "next_cursor": page.NextCursor}); err != nil {
			slog.Error("write related log response", "error", err)
		}
		return
	case "/api/v1/logs/operations":
		table = ScopeTableOperations
	case "/api/v1/logs/authentications":
		table = ScopeTableAuthentications
	case "/api/v1/logs/application-requests":
		table = ScopeTableApplicationRequests
	case "/api/v1/logs/git-syncs":
		table = ScopeTableGitSyncs
	default:
		writeMiddlewareProblem(w, 404, "NOT_FOUND", "log resource not found")
		return
	}
	f, err := parseLogQuery(r)
	if err != nil {
		if errors.Is(err, ErrRepositoryUnavailable) {
			writeMiddlewareProblem(w, 503, "LOG_CENTER_UNAVAILABLE", "log center is unavailable")
		} else {
			writeMiddlewareProblem(w, 400, "INVALID_LOG_QUERY", "invalid log query")
		}
		return
	}
	if h.Repo == nil {
		writeMiddlewareProblem(w, 503, "LOG_CENTER_UNAVAILABLE", "log center is unavailable")
		return
	}
	page, err := h.Repo.Query(r.Context(), scope, table, f)
	if err != nil {
		if errors.Is(err, ErrRepositoryUnavailable) {
			writeMiddlewareProblem(w, 503, "LOG_CENTER_UNAVAILABLE", "log center is unavailable")
		} else {
			writeMiddlewareProblem(w, 400, "INVALID_LOG_QUERY", "invalid log query")
		}
		return
	}
	items := make([]map[string]any, 0, len(page.Items))
	allowed := map[string]bool{"event_id": true, "occurred_at": true, "product_id": true, "request_id": true, "correlation_id": true, "trace_id": true, "result": true, "decision": true, "reason_code": true, "http_status": true, "client_app_id": true, "client_app_version": true, "customer_id": true, "customer_name": true, "authorization_name": true, "license_id": true, "license_status": true, "provider": true, "repository_id": true, "repository_name": true, "stage": true}
	for _, row := range page.Items {
		m := map[string]any{}
		for k, v := range row.Values {
			if allowed[k] {
				m[k] = v
			}
		}
		items = append(items, m)
	}
	out := map[string]any{"items": items, "next_cursor": page.NextCursor}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(out); err != nil {
		slog.Error("write log query response", "error", err)
		return
	}
}
func parseLogQuery(r *http.Request) (LogQueryFilters, error) {
	q := r.URL.Query()
	for key := range q {
		switch key {
		case "from", "to", "product_id", "customer_id", "authorization_name", "client_app_id", "client_app_version", "license_id", "license_status", "decision", "result", "request_id", "correlation_id", "http_status", "limit", "cursor":
		default:
			return LogQueryFilters{}, ErrInvalidLogQuery
		}
		if len(q[key]) > 1 {
			return LogQueryFilters{}, ErrInvalidLogQuery
		}
	}
	f := LogQueryFilters{ProductID: q.Get("product_id"), CustomerID: q.Get("customer_id"), AuthorizationName: q.Get("authorization_name"), ClientAppID: q.Get("client_app_id"), ClientAppVersion: q.Get("client_app_version"), LicenseID: q.Get("license_id"), LicenseStatus: q.Get("license_status"), Decision: q.Get("decision"), Result: q.Get("result"), RequestID: q.Get("request_id"), CorrelationID: q.Get("correlation_id"), Cursor: q.Get("cursor")}
	f.Limit = 50
	if v := q.Get("limit"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil {
			return f, ErrInvalidLogQuery
		}
		f.Limit = n
	}
	if v := q.Get("http_status"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil {
			return f, ErrInvalidLogQuery
		}
		f.HTTPStatus = &n
	}
	for _, v := range []string{f.RequestID, f.CorrelationID} {
		if v != "" {
			if _, e := uuid.Parse(v); e != nil {
				return f, ErrInvalidLogQuery
			}
		}
	}
	if f.LicenseStatus != "" && f.LicenseStatus != "valid" && f.LicenseStatus != "expiring" && f.LicenseStatus != "expired" && f.LicenseStatus != "revoked" && f.LicenseStatus != "unknown" {
		return f, ErrInvalidLogQuery
	}
	if f.Decision != "" && f.Decision != "allow" && f.Decision != "deny" {
		return f, ErrInvalidLogQuery
	}
	if f.Result != "" && f.Result != "success" && f.Result != "denied" && f.Result != "failed" {
		return f, ErrInvalidLogQuery
	}
	var e error
	if v := q.Get("from"); v != "" {
		f.From, e = time.Parse(time.RFC3339Nano, v)
		if e != nil {
			return f, ErrInvalidLogQuery
		}
	}
	if v := q.Get("to"); v != "" {
		f.To, e = time.Parse(time.RFC3339Nano, v)
		if e != nil {
			return f, ErrInvalidLogQuery
		}
	}
	return f, nil
}

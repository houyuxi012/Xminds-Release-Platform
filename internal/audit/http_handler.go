package audit

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
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/database"
	"xminds-release-platform/internal/platform/httpx"
)

const maximumAuditRequestBytes = 64 * 1024

type HTTPApplication interface {
	Query(ctx context.Context, principal identity.Principal, filter QueryFilter) ([]Event, error)
	StartExport(ctx context.Context, tx pgx.Tx, command StartExportCommand) (Export, error)
	GetExport(ctx context.Context, principal identity.Principal, id uuid.UUID) (Export, error)
}

type HTTPTransactor interface {
	WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error
}

type PoolTransactor struct {
	Pool *pgxpool.Pool
}

func (transactor PoolTransactor) WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error {
	if transactor.Pool == nil {
		return ErrTransactionRequired
	}
	return database.WithTx(ctx, transactor.Pool, function)
}

func NewHTTPHandler(application HTTPApplication, transactor HTTPTransactor) http.Handler {
	if application == nil || transactor == nil {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writeAuditProblem(writer, request, http.StatusInternalServerError, "AUDIT_SERVICE_UNAVAILABLE", "Audit service is unavailable", ErrRepositoryRequired)
		})
	}
	router := chi.NewRouter()
	RegisterRoutes(router, application, transactor)
	return router
}

func RegisterRoutes(router chi.Router, application HTTPApplication, transactor HTTPTransactor) {
	router.Get("/api/v1/audit-events", queryAuditEventsHandler(application))
	router.Post("/api/v1/audit-exports", startAuditExportHandler(application, transactor))
	router.Get("/api/v1/audit-exports/{export_id}", getAuditExportHandler(application))
}

func queryAuditEventsHandler(application HTTPApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireAuditPrincipal(writer, request)
		if !ok {
			return
		}
		filter, err := parseAuditQuery(request)
		if err != nil {
			writeAuditProblem(writer, request, http.StatusBadRequest, "AUDIT_FILTER_INVALID", "Audit filter is invalid", err)
			return
		}
		events, err := application.Query(request.Context(), principal, filter)
		if err != nil {
			writeAuditApplicationError(writer, request, err)
			return
		}
		page := auditEventPage{Items: events}
		limit := filter.Limit
		if limit == 0 {
			limit = 100
		}
		if len(events) == limit && len(events) > 0 {
			last := events[len(events)-1]
			page.NextBeforeTime = &last.OccurredAt
			page.NextBeforeID = &last.ID
		}
		writeAuditJSON(writer, http.StatusOK, page)
	}
}

type auditExportRequest struct {
	ProductID string    `json:"product_id"`
	Action    string    `json:"action"`
	Outcome   Outcome   `json:"outcome"`
	Since     time.Time `json:"since"`
	Until     time.Time `json:"until"`
}

func startAuditExportHandler(application HTTPApplication, transactor HTTPTransactor) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireAuditPrincipal(writer, request)
		if !ok {
			return
		}
		var input auditExportRequest
		if !decodeAuditRequest(writer, request, &input) {
			return
		}
		input.ProductID = strings.TrimSpace(input.ProductID)
		if input.ProductID == "" || len(input.ProductID) > 128 || len(strings.TrimSpace(input.Action)) > 128 ||
			(!input.Since.IsZero() && !input.Until.IsZero() && input.Since.After(input.Until)) || !validAuditOutcome(input.Outcome, true) {
			writeAuditProblem(writer, request, http.StatusUnprocessableEntity, "AUDIT_EXPORT_INVALID", "Audit export request is invalid", ErrExportFilterInvalid)
			return
		}
		command := StartExportCommand{
			Actor: principal, ProductID: input.ProductID, RequestID: httpx.RequestIDFromContext(request.Context()), SourceIP: auditSourceIP(request.RemoteAddr),
			Filter: QueryFilter{ProductID: input.ProductID, Action: strings.TrimSpace(input.Action), Outcome: input.Outcome, Since: input.Since, Until: input.Until},
		}
		var result Export
		err := transactor.WithinTransaction(request.Context(), func(tx pgx.Tx) error {
			var startErr error
			result, startErr = application.StartExport(request.Context(), tx, command)
			return startErr
		})
		if err != nil {
			writeAuditApplicationError(writer, request, err)
			return
		}
		writer.Header().Set("Location", "/api/v1/audit-exports/"+result.ID.String())
		writeAuditJSON(writer, http.StatusAccepted, toAuditExportResponse(result))
	}
}

func getAuditExportHandler(application HTTPApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireAuditPrincipal(writer, request)
		if !ok {
			return
		}
		exportID, err := uuid.Parse(chi.URLParam(request, "export_id"))
		if err != nil {
			writeAuditProblem(writer, request, http.StatusBadRequest, "AUDIT_EXPORT_ID_INVALID", "Audit export ID is invalid", err)
			return
		}
		result, err := application.GetExport(request.Context(), principal, exportID)
		if err != nil {
			writeAuditApplicationError(writer, request, err)
			return
		}
		writeAuditJSON(writer, http.StatusOK, toAuditExportResponse(result))
	}
}

func parseAuditQuery(request *http.Request) (QueryFilter, error) {
	query := request.URL.Query()
	filter := QueryFilter{
		ProductID: strings.TrimSpace(query.Get("product_id")), ActorSubject: strings.TrimSpace(query.Get("actor_subject")),
		Action: strings.TrimSpace(query.Get("action")), Outcome: Outcome(strings.TrimSpace(query.Get("outcome"))),
	}
	if filter.ProductID == "" || len(filter.ProductID) > 128 || len(filter.ActorSubject) > 512 || len(filter.Action) > 128 || !validAuditOutcome(filter.Outcome, true) {
		return QueryFilter{}, ErrQueryFilterInvalid
	}
	var err error
	if filter.Since, err = parseAuditTime(query.Get("since")); err != nil {
		return QueryFilter{}, err
	}
	if filter.Until, err = parseAuditTime(query.Get("until")); err != nil {
		return QueryFilter{}, err
	}
	if filter.BeforeTime, err = parseAuditTime(query.Get("before_time")); err != nil {
		return QueryFilter{}, err
	}
	beforeID := strings.TrimSpace(query.Get("before_id"))
	if beforeID != "" {
		if filter.BeforeID, err = uuid.Parse(beforeID); err != nil {
			return QueryFilter{}, ErrQueryFilterInvalid
		}
	}
	if filter.BeforeTime.IsZero() != (filter.BeforeID == uuid.Nil) || (!filter.Since.IsZero() && !filter.Until.IsZero() && filter.Since.After(filter.Until)) {
		return QueryFilter{}, ErrQueryFilterInvalid
	}
	if rawLimit := strings.TrimSpace(query.Get("limit")); rawLimit != "" {
		filter.Limit, err = strconv.Atoi(rawLimit)
		if err != nil || filter.Limit <= 0 || filter.Limit > 500 {
			return QueryFilter{}, ErrQueryFilterInvalid
		}
	}
	return filter, nil
}

func parseAuditTime(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	value, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, ErrQueryFilterInvalid
	}
	return value.UTC(), nil
}

func validAuditOutcome(outcome Outcome, allowEmpty bool) bool {
	if outcome == "" {
		return allowEmpty
	}
	return outcome == OutcomeSuccess || outcome == OutcomeDenied || outcome == OutcomeFailed
}

func decodeAuditRequest(writer http.ResponseWriter, request *http.Request, destination any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeAuditProblem(writer, request, http.StatusUnsupportedMediaType, "CONTENT_TYPE_UNSUPPORTED", "Content type must be application/json", err)
		return false
	}
	payload, err := io.ReadAll(io.LimitReader(request.Body, maximumAuditRequestBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumAuditRequestBytes {
		writeAuditProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", err)
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || !auditDecoderAtEOF(decoder) {
		writeAuditProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", err)
		return false
	}
	return true
}

func auditDecoderAtEOF(decoder *json.Decoder) bool {
	var extra any
	return errors.Is(decoder.Decode(&extra), io.EOF)
}

func requireAuditPrincipal(writer http.ResponseWriter, request *http.Request) (identity.Principal, bool) {
	principal, ok := identity.PrincipalFromContext(request.Context())
	if !ok {
		writer.Header().Set("WWW-Authenticate", `Bearer realm="xminds-release-platform"`)
		writeAuditProblem(writer, request, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Authentication is required", identity.ErrAuthenticationFailed)
		return identity.Principal{}, false
	}
	return principal, true
}

func writeAuditApplicationError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, identity.ErrActionDenied), errors.Is(err, identity.ErrProductScopeDenied):
		writeAuditProblem(writer, request, http.StatusForbidden, "AUDIT_ACCESS_DENIED", "Audit access is denied", err)
	case errors.Is(err, ErrExportNotFound):
		writeAuditProblem(writer, request, http.StatusNotFound, "AUDIT_EXPORT_NOT_FOUND", "Audit export was not found", err)
	case errors.Is(err, ErrQueryFilterInvalid), errors.Is(err, ErrExportFilterInvalid):
		writeAuditProblem(writer, request, http.StatusBadRequest, "AUDIT_FILTER_INVALID", "Audit filter is invalid", err)
	default:
		writeAuditProblem(writer, request, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error", err)
	}
}

func writeAuditProblem(writer http.ResponseWriter, request *http.Request, status int, code, title string, cause error) {
	httpx.WriteProblem(writer, httpx.NewProblem(status, code, title, cause).
		WithRequestID(httpx.RequestIDFromContext(request.Context())).WithInstance(request.URL.Path))
}

func writeAuditJSON(writer http.ResponseWriter, status int, value any) {
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

func auditSourceIP(remoteAddress string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddress))
	if err == nil {
		return host
	}
	return strings.TrimSpace(remoteAddress)
}

type auditEventPage struct {
	Items          []Event    `json:"items"`
	NextBeforeTime *time.Time `json:"next_before_time,omitempty"`
	NextBeforeID   *uuid.UUID `json:"next_before_id,omitempty"`
}

type auditExportResponse struct {
	ID          uuid.UUID    `json:"id"`
	ProductID   string       `json:"product_id"`
	RequestedBy string       `json:"requested_by"`
	RequestID   uuid.UUID    `json:"request_id"`
	Status      ExportStatus `json:"status"`
	ObjectKey   string       `json:"object_key,omitempty"`
	ErrorCode   string       `json:"error_code,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

func toAuditExportResponse(export Export) auditExportResponse {
	return auditExportResponse{
		ID: export.ID, ProductID: export.ProductID, RequestedBy: export.RequestedBy, RequestID: export.RequestID,
		Status: export.Status, ObjectKey: export.ObjectKey, ErrorCode: export.ErrorCode, CreatedAt: export.CreatedAt, UpdatedAt: export.UpdatedAt,
	}
}

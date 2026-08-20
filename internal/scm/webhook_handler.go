package scm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"xminds-release-platform/internal/platform/httpx"
)

type WebhookApplication interface {
	Handle(ctx context.Context, connectionID uuid.UUID, headers http.Header, body []byte) (Delivery, error)
}

func NewWebhookHTTPHandler(application WebhookApplication) http.Handler {
	router := chi.NewRouter()
	router.Post("/api/v1/scm/webhooks/{connection_id}", func(writer http.ResponseWriter, request *http.Request) {
		if application == nil {
			writeSCMProblem(writer, request, http.StatusServiceUnavailable, "SCM_WEBHOOK_UNAVAILABLE", "SCM webhook service is unavailable", ErrWebhookServiceConfig)
			return
		}
		connectionID, err := uuid.Parse(strings.TrimSpace(chi.URLParam(request, "connection_id")))
		if err != nil {
			writeSCMProblem(writer, request, http.StatusBadRequest, "SCM_CONNECTION_ID_INVALID", "SCM connection ID is invalid", err)
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, maximumWebhookPayloadBytes+1))
		if err != nil {
			writeSCMProblem(writer, request, http.StatusBadRequest, "SCM_WEBHOOK_BODY_INVALID", "Webhook body could not be read", err)
			return
		}
		if len(body) > maximumWebhookPayloadBytes {
			writeSCMProblem(writer, request, http.StatusRequestEntityTooLarge, "SCM_WEBHOOK_TOO_LARGE", "Webhook body exceeds the size limit", ErrWebhookPayloadTooLarge)
			return
		}
		delivery, err := application.Handle(request.Context(), connectionID, request.Header.Clone(), body)
		if err != nil {
			writeWebhookError(writer, request, err)
			return
		}
		writeSCMJSON(writer, http.StatusAccepted, struct {
			DeliveryID uuid.UUID `json:"delivery_id"`
			EventID    string    `json:"event_id"`
		}{DeliveryID: delivery.ID, EventID: delivery.EventID})
	})
	return router
}

func writeWebhookError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, ErrConnectionNotFound):
		writeSCMProblem(writer, request, http.StatusNotFound, "SCM_CONNECTION_NOT_FOUND", "SCM connection was not found", err)
	case errors.Is(err, ErrConnectionInactive):
		writeSCMProblem(writer, request, http.StatusGone, "SCM_CONNECTION_INACTIVE", "SCM connection is inactive", err)
	case errors.Is(err, ErrWebhookSignatureInvalid):
		writeSCMProblem(writer, request, http.StatusUnauthorized, "SCM_WEBHOOK_SIGNATURE_INVALID", "Webhook signature is invalid", err)
	case errors.Is(err, ErrDeliveryReplayConflict):
		writeSCMProblem(writer, request, http.StatusConflict, "SCM_WEBHOOK_REPLAY_CONFLICT", "Webhook delivery payload conflicts with an existing event", err)
	case errors.Is(err, ErrWebhookEventInvalid):
		writeSCMProblem(writer, request, http.StatusUnprocessableEntity, "SCM_WEBHOOK_INVALID", "Webhook event is invalid", err)
	default:
		writeSCMProblem(writer, request, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error", err)
	}
}

func writeSCMProblem(writer http.ResponseWriter, request *http.Request, status int, code, title string, cause error) {
	httpx.WriteProblem(writer, httpx.NewProblem(status, code, title, cause).
		WithRequestID(httpx.RequestIDFromContext(request.Context())).WithInstance(request.URL.Path))
}

func writeSCMJSON(writer http.ResponseWriter, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		httpx.WriteProblem(writer, httpx.NewProblem(http.StatusInternalServerError, "RESPONSE_SERIALIZATION_FAILED", "Internal server error", err))
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(payload, '\n'))
}

package scm

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestWebhookHandlerReturnsStableDeliveryAndNeverEchoesPayload(t *testing.T) {
	t.Parallel()

	delivery := Delivery{ID: uuid.New(), ConnectionID: uuid.New(), EventID: "event-42"}
	application := &fixedWebhookApplication{delivery: delivery}
	handler := NewWebhookHTTPHandler(application)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/scm/webhooks/"+delivery.ConnectionID.String(), bytes.NewBufferString(`{"secret":"never-return"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	if bytes.Contains(recorder.Body.Bytes(), []byte("never-return")) {
		t.Fatal("webhook payload leaked in response")
	}
	var response struct {
		DeliveryID uuid.UUID `json:"delivery_id"`
		EventID    string    `json:"event_id"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || response.DeliveryID != delivery.ID || response.EventID != delivery.EventID {
		t.Fatalf("response = %+v, %v", response, err)
	}
}

type fixedWebhookApplication struct {
	delivery Delivery
	err      error
}

func (application *fixedWebhookApplication) Handle(_ context.Context, _ uuid.UUID, _ http.Header, _ []byte) (Delivery, error) {
	return application.delivery, application.err
}

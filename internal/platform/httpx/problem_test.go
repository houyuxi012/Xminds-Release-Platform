package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProblemNeverSerializesInternalCause(t *testing.T) {
	t.Parallel()

	problem := NewProblem(
		http.StatusBadRequest,
		"PRODUCT_MANIFEST_INVALID",
		"Invalid product manifest",
		errors.New("secret=abc"),
	)
	raw, err := json.Marshal(problem)
	if err != nil {
		t.Fatalf("marshal problem: %v", err)
	}
	if bytes.Contains(raw, []byte("secret=abc")) {
		t.Fatal("internal cause leaked")
	}
	if !bytes.Contains(raw, []byte(`"code":"PRODUCT_MANIFEST_INVALID"`)) {
		t.Fatalf("stable code missing: %s", raw)
	}
}

func TestWriteProblemUsesRFC9457MediaTypeAndStatus(t *testing.T) {
	t.Parallel()

	recorder := httptest.NewRecorder()
	problem := NewProblem(
		http.StatusServiceUnavailable,
		"DATABASE_UNAVAILABLE",
		"Database unavailable",
		errors.New("postgres://user:password@database/internal"),
	).WithRequestID("0198a3b1-6c00-7f11-8000-000000000001")

	WriteProblem(recorder, problem)

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", recorder.Code)
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if bytes.Contains(recorder.Body.Bytes(), []byte("password")) {
		t.Fatalf("internal cause leaked in response: %s", recorder.Body.Bytes())
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte(`"request_id":"0198a3b1-6c00-7f11-8000-000000000001"`)) {
		t.Fatalf("request ID missing: %s", recorder.Body.Bytes())
	}
}

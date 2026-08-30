package logcenter

import (
	"net/http/httptest"
	"testing"
)

func TestLogHTTPHandlerContract(t *testing.T) {
	cases := []struct {
		name, path string
		status     int
	}{{"path traversal", "/api/v1/logs/operations/extra", 404}, {"unknown param", "/api/v1/logs/operations?evil=x", 400}, {"duplicate", "/api/v1/logs/operations?limit=1&limit=2", 400}, {"bad uuid", "/api/v1/logs/operations?request_id=bad", 400}, {"related missing key", "/api/v1/logs/related", 400}, {"nil repo", "/api/v1/logs/operations", 503}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &LogHTTPHandler{}
			r := httptest.NewRequest("GET", tc.path, nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d", w.Code, tc.status)
			}
			if w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing no-store")
			}
		})
	}
}

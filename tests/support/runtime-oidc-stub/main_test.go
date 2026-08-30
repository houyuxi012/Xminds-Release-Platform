package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateListenAddressRejectsNonLoopback(t *testing.T) {
	t.Parallel()

	for _, address := range []string{"0.0.0.0:15556", "192.0.2.10:15556", ":15556"} {
		if err := validateListenAddress(address); err == nil {
			t.Fatalf("validateListenAddress(%q) error = nil, want rejection", address)
		}
	}
	if err := validateListenAddress("127.0.0.1:15556"); err != nil {
		t.Fatalf("validateListenAddress(loopback) error = %v", err)
	}
}

func TestOIDCStubPublishesDiscoveryAndEmptyJWKS(t *testing.T) {
	t.Parallel()

	issuer := "http://127.0.0.1:15556"
	handler, err := newOIDCStubHandler(issuer)
	if err != nil {
		t.Fatal(err)
	}

	discoveryRequest := httptest.NewRequest(http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	discoveryResponse := httptest.NewRecorder()
	handler.ServeHTTP(discoveryResponse, discoveryRequest)
	if discoveryResponse.Code != http.StatusOK {
		t.Fatalf("discovery status = %d", discoveryResponse.Code)
	}
	var discovery map[string]any
	if err := json.Unmarshal(discoveryResponse.Body.Bytes(), &discovery); err != nil {
		t.Fatal(err)
	}
	if discovery["issuer"] != issuer || discovery["jwks_uri"] != issuer+"/keys" {
		t.Fatalf("unexpected discovery document: %v", discovery)
	}
	if got := discoveryResponse.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("discovery Cache-Control = %q, want no-store", got)
	}

	keysRequest := httptest.NewRequest(http.MethodGet, issuer+"/keys", nil)
	keysResponse := httptest.NewRecorder()
	handler.ServeHTTP(keysResponse, keysRequest)
	if keysResponse.Code != http.StatusOK || keysResponse.Body.String() != "{\"keys\":[]}\n" {
		t.Fatalf("JWKS response = %d %q", keysResponse.Code, keysResponse.Body.String())
	}
}

func TestOIDCStubRejectsUnsupportedMethodsAndPaths(t *testing.T) {
	t.Parallel()

	handler, err := newOIDCStubHandler("http://127.0.0.1:15556")
	if err != nil {
		t.Fatal(err)
	}
	post := httptest.NewRecorder()
	handler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/keys", nil))
	if post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /keys status = %d, want 405", post.Code)
	}
	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/unknown", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("GET /unknown status = %d, want 404", missing.Code)
	}
}

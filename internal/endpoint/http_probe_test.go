package endpoint

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/google/uuid"

	"xminds-release-platform/internal/catalog"
)

func TestHTTPProbeVerifiesCurrentRootAndTimestampOverPinnedTLS(t *testing.T) {
	t.Parallel()

	root := []byte(`{"signed":{"_type":"root"}}`)
	timestamp := []byte(`{"signed":{"_type":"timestamp"}}`)
	wantedPaths := map[string][]byte{
		"/releases/v1/products/ngep/channels/stable/metadata/root.json":      root,
		"/releases/v1/products/ngep/channels/stable/metadata/timestamp.json": timestamp,
	}
	var mutex sync.Mutex
	seen := make(map[string]int)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mutex.Lock()
		seen[request.URL.Path]++
		mutex.Unlock()
		payload, exists := wantedPaths[request.URL.Path]
		if !exists {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(payload)
	}))
	defer server.Close()

	certificate := server.Certificate()
	caBundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	probe, err := NewHTTPProbe(HTTPProbeConfig{
		CABundles: CABundleLoaderFunc(func(context.Context, string) ([]byte, error) {
			return caBundle, nil
		}),
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewHTTPProbe() error = %v", err)
	}
	rootHash := sha256.Sum256(root)
	timestampHash := sha256.Sum256(timestamp)
	current := catalog.VersionRecord{
		ProductID: "ngep",
		Channel:   "stable",
		Roles: map[catalog.Role]catalog.RoleDocument{
			catalog.RoleRoot:      {Role: catalog.RoleRoot, EnvelopeSHA256: hex.EncodeToString(rootHash[:])},
			catalog.RoleTimestamp: {Role: catalog.RoleTimestamp, EnvelopeSHA256: hex.EncodeToString(timestampHash[:])},
		},
	}
	record := Endpoint{
		ID: uuid.New(), ProductID: "ngep", BaseURL: server.URL, PathPrefix: "/releases", TLSCARef: "private-ca",
	}

	result, err := probe.Verify(context.Background(), record, current)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if result.RootDigest != hex.EncodeToString(rootHash[:]) || result.TimestampDigest != hex.EncodeToString(timestampHash[:]) {
		t.Fatalf("Verify() result = %+v", result)
	}
	mutex.Lock()
	defer mutex.Unlock()
	for path := range wantedPaths {
		if seen[path] != 1 {
			t.Fatalf("request count for %s = %d", path, seen[path])
		}
	}
}

func TestHTTPProbeRejectsRedirectedMetadata(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "https://example.com/metadata.json", http.StatusFound)
	}))
	defer server.Close()
	certificate := server.Certificate()
	if _, err := x509.ParseCertificate(certificate.Raw); err != nil {
		t.Fatal(err)
	}
	caBundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	probe, err := NewHTTPProbe(HTTPProbeConfig{
		CABundles:     CABundleLoaderFunc(func(context.Context, string) ([]byte, error) { return caBundle, nil }),
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"signed":{"_type":"root"}}`)
	digest := sha256.Sum256(payload)
	current := catalog.VersionRecord{ProductID: "ngep", Channel: "stable", Roles: map[catalog.Role]catalog.RoleDocument{
		catalog.RoleRoot:      {Role: catalog.RoleRoot, EnvelopeSHA256: hex.EncodeToString(digest[:])},
		catalog.RoleTimestamp: {Role: catalog.RoleTimestamp, EnvelopeSHA256: hex.EncodeToString(digest[:])},
	}}
	record := Endpoint{ID: uuid.New(), ProductID: "ngep", BaseURL: server.URL, PathPrefix: "/releases", TLSCARef: "private-ca"}

	if _, err := probe.Verify(context.Background(), record, current); err == nil {
		t.Fatal("redirected metadata was accepted")
	}
}

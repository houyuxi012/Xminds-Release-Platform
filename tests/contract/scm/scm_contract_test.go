package scm_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	platformscm "xminds-release-platform/internal/scm"
)

const contractSHA = "abcdefabcdefabcdefabcdefabcdefabcdefabcd"

func TestGitHubEnterpriseContractOverPrivateTLSWithoutPublicDNS(t *testing.T) {
	var statusBody map[string]any
	server, caPEM := newPrivateTLSServer(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v3/meta":
			writer.WriteHeader(http.StatusOK)
		case "/api/v3/repos/acme/ngep/commits/" + contractSHA:
			writeJSON(writer, http.StatusOK, map[string]any{"sha": contractSHA, "html_url": "https://github.corp/acme/ngep/commit/" + contractSHA, "commit": map[string]any{"message": "release", "author": map[string]any{"name": "Alice", "date": "2026-08-20T08:00:00Z"}}})
		case "/api/v3/repos/acme/ngep/statuses/" + contractSHA:
			_ = json.NewDecoder(request.Body).Decode(&statusBody)
			writeJSON(writer, http.StatusCreated, map[string]any{"id": 42})
		default:
			http.NotFound(writer, request)
		}
	})
	connection := contractConnection(t, server, caPEM, platformscm.ProviderGitHub, "/api/v3")
	credentialID := uuid.New()
	connection.CredentialID = credentialID
	connection.Capabilities.CommitStatuses = true
	adapter, err := platformscm.NewGitHubAdapter(platformscm.AdapterConfig{
		Clients: contractClientFactory{}, Credentials: contractCredentialStore{id: credentialID, kind: platformscm.CredentialKindGitHubToken}, Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := adapter.VerifyConnection(context.Background(), connection)
	if err != nil || !capabilities.CommitStatuses || capabilities.CertificateSHA256 == "" {
		t.Fatalf("capabilities = %+v, %v", capabilities, err)
	}
	commit, err := adapter.GetCommit(context.Background(), connection, "acme/ngep", contractSHA)
	if err != nil || commit.Author != "Alice" {
		t.Fatalf("commit = %+v, %v", commit, err)
	}
	if err := adapter.WriteStatus(context.Background(), connection, platformscm.CommitStatus{Repository: "acme/ngep", SHA: contractSHA, State: platformscm.CommitStateSuccess, Context: "xminds/release", Description: "Published"}); err != nil {
		t.Fatal(err)
	}
	if statusBody["state"] != "success" {
		t.Fatalf("status body = %#v", statusBody)
	}
}

func TestGitLabSelfManagedContractOverPrivateTLSWithoutPublicDNS(t *testing.T) {
	var statusBody string
	server, caPEM := newPrivateTLSServer(t, func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v4/version":
			writer.WriteHeader(http.StatusOK)
		case "/api/v4/projects/acme/ngep/repository/commits/" + contractSHA:
			// Go's server decodes %2F in URL.Path; RawPath remains encoded on the client.
			writeJSON(writer, http.StatusOK, map[string]any{"id": contractSHA, "web_url": "https://gitlab.corp/acme/ngep/-/commit/" + contractSHA, "message": "release", "author_name": "Alice", "committed_date": "2026-08-20T08:00:00Z"})
		case "/api/v4/projects/acme/ngep/statuses/" + contractSHA:
			buffer, _ := io.ReadAll(request.Body)
			statusBody = string(buffer)
			writeJSON(writer, http.StatusCreated, map[string]any{"id": 42})
		default:
			http.NotFound(writer, request)
		}
	})
	connection := contractConnection(t, server, caPEM, platformscm.ProviderGitLab, "/api/v4")
	credentialID := uuid.New()
	connection.CredentialID = credentialID
	connection.Capabilities.CommitStatuses = true
	adapter, err := platformscm.NewGitLabAdapter(platformscm.AdapterConfig{
		Clients: contractClientFactory{}, Credentials: contractCredentialStore{id: credentialID, kind: platformscm.CredentialKindGitLabAccessToken}, Clock: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := adapter.VerifyConnection(context.Background(), connection)
	if err != nil || !capabilities.CommitStatuses || capabilities.CertificateSHA256 == "" {
		t.Fatalf("capabilities = %+v, %v", capabilities, err)
	}
	commit, err := adapter.GetCommit(context.Background(), connection, "acme/ngep", contractSHA)
	if err != nil || commit.Author != "Alice" {
		t.Fatalf("commit = %+v, %v", commit, err)
	}
	if err := adapter.WriteStatus(context.Background(), connection, platformscm.CommitStatus{Repository: "acme/ngep", SHA: contractSHA, State: platformscm.CommitStateSuccess, Context: "xminds/release", Description: "Published"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(statusBody, "state=success") {
		t.Fatalf("status body = %q", statusBody)
	}
}

type contractClientFactory struct{}

func (contractClientFactory) ClientFor(connection platformscm.Connection) (platformscm.HTTPDoer, error) {
	return platformscm.NewHTTPClient(connection, platformscm.HTTPClientOptions{AllowLoopback: true})
}

type contractCredentialStore struct {
	id   uuid.UUID
	kind platformscm.CredentialKind
}

func (store contractCredentialStore) UseCredential(_ context.Context, id uuid.UUID, use func(platformscm.SecretCredential) error) error {
	if id != store.id {
		return platformscm.ErrCredentialUnavailable
	}
	secret := []byte("contract-provider-token")
	defer func() {
		for index := range secret {
			secret[index] = 0
		}
	}()
	return use(platformscm.SecretCredential{ID: id, Kind: store.kind, Secret: secret})
}

func contractConnection(t *testing.T, server *httptest.Server, caPEM []byte, provider platformscm.ProviderKind, apiPath string) platformscm.Connection {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	return platformscm.Connection{
		ID: uuid.New(), ProductID: "ngep", Provider: provider, Status: platformscm.ConnectionStatusActive,
		APIBaseURL: "https://scm.test:" + parsed.Port() + apiPath, ResolvedAddresses: []string{"127.0.0.1"},
		EnterpriseCABundlePEM: caPEM,
	}
}

func newPrivateTLSServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Xminds Contract CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "scm.test"}, DNSNames: []string{"scm.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertificate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tlsCertificate(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER}))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}

var tlsCertificate = func(certificatePEM, keyPEM []byte) (tls.Certificate, error) {
	return tls.X509KeyPair(certificatePEM, keyPEM)
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

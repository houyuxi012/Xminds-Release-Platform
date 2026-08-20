package scm

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func TestBuildTLSConfigRejectsInvalidEnterpriseCAAndNeverSkipsVerification(t *testing.T) {
	t.Parallel()

	if _, err := BuildTLSConfig("gitlab.corp.example", []byte("not a certificate")); !errors.Is(err, ErrTLSConfigurationInvalid) {
		t.Fatalf("BuildTLSConfig() error = %v, want %v", err, ErrTLSConfigurationInvalid)
	}
	configuration, err := BuildTLSConfig("gitlab.corp.example", nil)
	if err != nil {
		t.Fatal(err)
	}
	if configuration.InsecureSkipVerify || configuration.ServerName != "gitlab.corp.example" || configuration.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS configuration = %+v", configuration)
	}
}

func TestHTTPClientDialsPinnedAddressInsteadOfResolvingRegisteredHostname(t *testing.T) {
	t.Parallel()

	dialer := &recordingDialer{err: errors.New("stop after observing dial")}
	client, err := NewHTTPClient(Connection{
		ID: uuid.New(), Provider: ProviderGitLab, Status: ConnectionStatusActive,
		APIBaseURL: "https://gitlab.corp.example/api/v4", ResolvedAddresses: []string{"10.20.30.40"},
	}, HTTPClientOptions{Dialer: dialer})
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://gitlab.corp.example/api/v4/version", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(request); err == nil {
		t.Fatal("client request unexpectedly succeeded")
	}
	if dialer.address != "10.20.30.40:443" {
		t.Fatalf("dial address = %q, want pinned address", dialer.address)
	}
}

func TestHTTPClientIgnoresAmbientProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://ambient-proxy.invalid:3128")

	client, err := NewHTTPClient(Connection{
		ID: uuid.New(), Provider: ProviderGitHub, Status: ConnectionStatusActive,
		APIBaseURL: "https://github.corp.example/api/v3", ResolvedAddresses: []string{"192.0.2.10"},
	}, HTTPClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	request, _ := http.NewRequest(http.MethodGet, "https://github.corp.example/api/v3", nil)
	proxy, err := transport.Proxy(request)
	if err != nil {
		t.Fatal(err)
	}
	if proxy != nil {
		t.Fatalf("ambient proxy was used: %s", proxy)
	}
}

type recordingDialer struct {
	address string
	err     error
}

func (dialer *recordingDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	dialer.address = address
	return nil, dialer.err
}

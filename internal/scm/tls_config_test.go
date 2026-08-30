package scm

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
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
	}, HTTPClientOptions{Dialer: dialer, AllowedPrivatePrefixes: []netip.Prefix{netip.MustParsePrefix("10.20.30.0/24")}})
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

func TestHTTPClientDialsPinnedExplicitProxyAddress(t *testing.T) {
	t.Parallel()

	dialer := &recordingDialer{err: errors.New("stop after observing proxy dial")}
	client, err := NewHTTPClient(Connection{
		ID: uuid.New(), Provider: ProviderGitLab, Status: ConnectionStatusActive,
		APIBaseURL: "https://gitlab.corp.example/api/v4", ResolvedAddresses: []string{"10.20.30.40"},
		ProxyURL: "http://proxy.corp.example:3128", ProxyResolvedAddresses: []string{"10.20.30.50"},
	}, HTTPClientOptions{Dialer: dialer, AllowedPrivatePrefixes: []netip.Prefix{netip.MustParsePrefix("10.20.30.0/24")}})
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://gitlab.corp.example/api/v4/version", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(request); err == nil {
		t.Fatal("client proxy request unexpectedly succeeded")
	}
	if dialer.address != "10.20.30.50:3128" {
		t.Fatalf("proxy dial address = %q, want pinned proxy address", dialer.address)
	}
}

func TestHTTPClientIgnoresAmbientProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://ambient-proxy.invalid:3128")

	client, err := NewHTTPClient(Connection{
		ID: uuid.New(), Provider: ProviderGitHub, Status: ConnectionStatusActive,
		APIBaseURL: "https://github.corp.example/api/v3", ResolvedAddresses: []string{"8.8.8.8"},
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

func TestHTTPClientCompletesPinnedCONNECTWithOriginTLSAndNoProxyBypass(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v4/version" {
			http.NotFound(writer, request)
			return
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte(`{"version":"test"}`))
	}))
	t.Cleanup(origin.Close)
	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	var connects atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect || request.Host != originURL.Host {
			http.Error(writer, "denied", http.StatusForbidden)
			return
		}
		upstream, dialErr := net.Dial("tcp", request.Host)
		if dialErr != nil {
			http.Error(writer, "unavailable", http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			t.Error("proxy response writer does not support hijacking")
			return
		}
		client, buffered, hijackErr := hijacker.Hijack()
		if hijackErr != nil {
			t.Error(hijackErr)
			return
		}
		defer client.Close()
		connects.Add(1)
		_, _ = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
		_ = buffered.Flush()
		copyDone := make(chan struct{})
		go func() {
			_, _ = io.Copy(upstream, client)
			_ = upstream.(*net.TCPConn).CloseWrite()
			close(copyDone)
		}()
		_, _ = io.Copy(client, upstream)
		<-copyDone
	}))
	t.Cleanup(proxy.Close)
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	caBundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: origin.Certificate().Raw})
	connection := Connection{
		ID: uuid.New(), Provider: ProviderGitLab, Status: ConnectionStatusActive,
		APIBaseURL: origin.URL + "/api/v4", ResolvedAddresses: []string{originURL.Hostname()}, EnterpriseCABundlePEM: caBundle,
		ProxyURL: proxy.URL, ProxyResolvedAddresses: []string{proxyURL.Hostname()},
	}
	client, err := NewHTTPClient(connection, HTTPClientOptions{AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*http.Transport)
	if transport.TLSClientConfig.ServerName != originURL.Hostname() || transport.TLSClientConfig.RootCAs == nil {
		t.Fatalf("origin TLS server_name=%q roots=%v", transport.TLSClientConfig.ServerName, transport.TLSClientConfig.RootCAs)
	}
	response, err := client.Get(origin.URL + "/api/v4/version")
	if err != nil {
		t.Fatalf("proxied request: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || connects.Load() != 1 {
		t.Fatalf("proxied status=%d CONNECTs=%d", response.StatusCode, connects.Load())
	}

	connection.NoProxy = []string{strings.ToLower(originURL.Hostname())}
	bypassClient, err := NewHTTPClient(connection, HTTPClientOptions{AllowLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	response, err = bypassClient.Get(origin.URL + "/api/v4/version")
	if err != nil {
		t.Fatalf("NO_PROXY request: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || connects.Load() != 1 {
		t.Fatalf("NO_PROXY status=%d CONNECTs=%d", response.StatusCode, connects.Load())
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

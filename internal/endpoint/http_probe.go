package endpoint

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strings"
	"time"

	"xminds-release-platform/internal/catalog"
	"xminds-release-platform/internal/platform/egress"
)

const maximumProbeMetadataBytes = 8 * 1024 * 1024

var (
	ErrHTTPProbeConfiguration = errors.New("distribution endpoint HTTP probe configuration is invalid")
	ErrHTTPProbeDestination   = errors.New("distribution endpoint probe destination is invalid")
	ErrHTTPProbeResponse      = errors.New("distribution endpoint probe response is invalid")
	ErrHTTPProbeRedirect      = errors.New("distribution endpoint probe redirect is forbidden")
)

type ProbeIPResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

type ProbeDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type CABundleLoader interface {
	Load(ctx context.Context, reference string) ([]byte, error)
}

type CABundleLoaderFunc func(context.Context, string) ([]byte, error)

func (function CABundleLoaderFunc) Load(ctx context.Context, reference string) ([]byte, error) {
	return function(ctx, reference)
}

type HTTPProbeConfig struct {
	Resolver      ProbeIPResolver
	Dialer        ProbeDialer
	CABundles     CABundleLoader
	AllowLoopback bool
}

type HTTPProbe struct {
	resolver      ProbeIPResolver
	dialer        ProbeDialer
	caBundles     CABundleLoader
	allowLoopback bool
}

func NewHTTPProbe(config HTTPProbeConfig) (*HTTPProbe, error) {
	if config.Resolver == nil {
		config.Resolver = net.DefaultResolver
	}
	if config.Dialer == nil {
		config.Dialer = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	}
	if config.Resolver == nil || config.Dialer == nil {
		return nil, ErrHTTPProbeConfiguration
	}
	return &HTTPProbe{
		resolver: config.Resolver, dialer: config.Dialer, caBundles: config.CABundles, allowLoopback: config.AllowLoopback,
	}, nil
}

func (probe *HTTPProbe) Verify(ctx context.Context, endpoint Endpoint, current catalog.VersionRecord) (ProbeResult, error) {
	if probe == nil || probe.resolver == nil || probe.dialer == nil || endpoint.ProductID != current.ProductID || current.ProductID == "" || current.Channel == "" {
		return ProbeResult{}, ErrHTTPProbeConfiguration
	}
	root, rootExists := current.Roles[catalog.RoleRoot]
	timestamp, timestampExists := current.Roles[catalog.RoleTimestamp]
	if !rootExists || !timestampExists || !validSyncDigest(root.EnvelopeSHA256) || !validSyncDigest(timestamp.EnvelopeSHA256) {
		return ProbeResult{}, ErrHTTPProbeConfiguration
	}
	baseURL, err := parseProbeBaseURL(endpoint.BaseURL)
	if err != nil {
		return ProbeResult{}, err
	}
	client, err := probe.client(ctx, baseURL, endpoint.TLSCARef)
	if err != nil {
		return ProbeResult{}, err
	}
	for role, expected := range map[catalog.Role]string{
		catalog.RoleRoot: root.EnvelopeSHA256, catalog.RoleTimestamp: timestamp.EnvelopeSHA256,
	} {
		roleURL := *baseURL
		roleURL.Path = path.Join(baseURL.Path, endpoint.PathPrefix, "v1", "products", endpoint.ProductID, "channels", current.Channel, "metadata", string(role)+".json")
		if err := verifyProbeDocument(ctx, client, roleURL.String(), expected); err != nil {
			return ProbeResult{}, err
		}
	}
	return ProbeResult{RootDigest: root.EnvelopeSHA256, TimestampDigest: timestamp.EnvelopeSHA256}, nil
}

func (probe *HTTPProbe) client(ctx context.Context, baseURL *url.URL, caReference string) (*http.Client, error) {
	addresses, err := resolveProbeAddresses(ctx, probe.resolver, baseURL.Hostname(), probe.allowLoopback)
	if err != nil {
		return nil, err
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system CA pool: %w", ErrHTTPProbeConfiguration)
	}
	if roots == nil {
		roots = x509.NewCertPool()
	}
	caReference = strings.TrimSpace(caReference)
	if caReference != "" {
		if probe.caBundles == nil {
			return nil, ErrHTTPProbeConfiguration
		}
		bundle, loadErr := probe.caBundles.Load(ctx, caReference)
		if loadErr != nil || len(bundle) == 0 || len(bundle) > 1024*1024 || !roots.AppendCertsFromPEM(bundle) {
			return nil, errors.Join(ErrHTTPProbeConfiguration, loadErr)
		}
	}
	wantedHost := strings.ToLower(strings.TrimSuffix(baseURL.Hostname(), "."))
	pinnedDialContext, err := egress.NewPinnedDialContext(wantedHost, addresses, probe.dialer)
	if err != nil {
		return nil, errors.Join(ErrHTTPProbeDestination, err)
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			connection, dialErr := pinnedDialContext(ctx, network, address)
			if dialErr != nil {
				return nil, errors.Join(ErrHTTPProbeDestination, dialErr)
			}
			return connection, nil
		},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: wantedHost,
			RootCAs:    roots,
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       30 * time.Second,
		MaxIdleConns:          4,
		MaxIdleConnsPerHost:   2,
		ForceAttemptHTTP2:     true,
		DisableCompression:    true,
	}
	return &http.Client{
		Transport:     transport,
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrHTTPProbeRedirect },
	}, nil
}

func resolveProbeAddresses(ctx context.Context, resolver ProbeIPResolver, host string, allowLoopback bool) ([]netip.Addr, error) {
	addresses, err := egress.ResolvePinnedAddresses(ctx, resolver, host, egress.Policy{AllowLoopback: allowLoopback, AllowPrivate: true})
	if err != nil {
		return nil, errors.Join(ErrHTTPProbeDestination, err)
	}
	return addresses, nil
}

func parseProbeBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrHTTPProbeDestination
	}
	return parsed, nil
}

func verifyProbeDocument(ctx context.Context, client *http.Client, rawURL, expectedDigest string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return errors.Join(ErrHTTPProbeDestination, err)
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errors.Join(ErrHTTPProbeResponse, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > maximumProbeMetadataBytes {
		return ErrHTTPProbeResponse
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maximumProbeMetadataBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumProbeMetadataBytes {
		return errors.Join(ErrHTTPProbeResponse, err)
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != expectedDigest {
		return ErrCatalogDigestMismatch
	}
	return nil
}

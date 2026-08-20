package scm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	platformegress "xminds-release-platform/internal/platform/egress"
)

const maximumEnterpriseCABundleBytes = 1024 * 1024

var ErrTLSConfigurationInvalid = errors.New("SCM TLS configuration is invalid")

type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type HTTPClientOptions struct {
	Dialer        ContextDialer
	AllowLoopback bool
}

func BuildTLSConfig(serverName string, enterpriseCABundlePEM []byte) (*tls.Config, error) {
	serverName = strings.TrimSuffix(strings.TrimSpace(serverName), ".")
	if serverName == "" || strings.ContainsAny(serverName, "/\\") || len(enterpriseCABundlePEM) > maximumEnterpriseCABundleBytes {
		return nil, ErrTLSConfigurationInvalid
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load system certificate roots: %w", err)
	}
	if roots == nil {
		roots = x509.NewCertPool()
	}
	if len(enterpriseCABundlePEM) > 0 && !roots.AppendCertsFromPEM(enterpriseCABundlePEM) {
		return nil, ErrTLSConfigurationInvalid
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		RootCAs:    roots,
	}, nil
}

func NewHTTPClient(connection Connection, options HTTPClientOptions) (*http.Client, error) {
	baseURL, err := parseConnectionAPIBaseURL(connection.APIBaseURL)
	if err != nil || connection.ID == [16]byte{} || connection.Status != ConnectionStatusActive {
		return nil, ErrEgressConfigurationInvalid
	}
	pinned, err := validatePinnedAddresses(connection.ResolvedAddresses, options.AllowLoopback)
	if err != nil {
		return nil, err
	}
	tlsConfiguration, err := BuildTLSConfig(baseURL.Hostname(), connection.EnterpriseCABundlePEM)
	if err != nil {
		return nil, err
	}
	if options.Dialer == nil {
		options.Dialer = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	}
	baseHost := strings.ToLower(strings.TrimSuffix(baseURL.Hostname(), "."))
	baseDialContext, err := platformegress.NewPinnedDialContext(baseHost, pinned, options.Dialer)
	if err != nil {
		return nil, errors.Join(ErrEgressConfigurationInvalid, err)
	}

	var proxyURL *url.URL
	proxyPinned := []netip.Addr(nil)
	proxyHost := ""
	var proxyDialContext func(context.Context, string, string) (net.Conn, error)
	if strings.TrimSpace(connection.ProxyURL) != "" {
		proxyURL, err = parseExplicitProxyURL(connection.ProxyURL)
		if err != nil {
			return nil, err
		}
		proxyHost = strings.ToLower(strings.TrimSuffix(proxyURL.Hostname(), "."))
		proxyPinned, err = validatePinnedAddresses(connection.ProxyResolvedAddresses, options.AllowLoopback)
		if err != nil {
			return nil, err
		}
		proxyDialContext, err = platformegress.NewPinnedDialContext(proxyHost, proxyPinned, options.Dialer)
		if err != nil {
			return nil, errors.Join(ErrEgressConfigurationInvalid, err)
		}
	}
	noProxy := make(map[string]struct{}, len(connection.NoProxy))
	for _, host := range connection.NoProxy {
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
		if host == "" || strings.ContainsAny(host, "/: ") {
			return nil, ErrEgressConfigurationInvalid
		}
		noProxy[host] = struct{}{}
	}

	transport := &http.Transport{
		Proxy: func(request *http.Request) (*url.URL, error) {
			if !sameAuthority(request.URL, baseURL) {
				return nil, ErrEgressDestinationDenied
			}
			if proxyURL == nil {
				return nil, nil
			}
			if _, bypass := noProxy[strings.ToLower(request.URL.Hostname())]; bypass {
				return nil, nil
			}
			return proxyURL, nil
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, ErrEgressDestinationDenied
			}
			host = strings.ToLower(strings.TrimSuffix(host, "."))
			dialContext := baseDialContext
			if proxyURL != nil && host == proxyHost {
				dialContext = proxyDialContext
			} else if host != baseHost {
				return nil, ErrEgressDestinationDenied
			}
			connection, dialErr := dialContext(ctx, network, address)
			if dialErr != nil {
				return nil, errors.Join(ErrEgressDestinationDenied, dialErr)
			}
			return connection, nil
		},
		TLSClientConfig:       tlsConfiguration,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   10,
		ForceAttemptHTTP2:     true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return ErrRedirectDenied
		},
	}, nil
}

func parseConnectionAPIBaseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrEgressConfigurationInvalid
	}
	return parsed, nil
}

func parseExplicitProxyURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, ErrEgressConfigurationInvalid
	}
	return parsed, nil
}

func validatePinnedAddresses(raw []string, allowLoopback bool) ([]netip.Addr, error) {
	if len(raw) == 0 {
		return nil, ErrEgressConfigurationInvalid
	}
	parsed := make([]netip.Addr, 0, len(raw))
	for _, item := range raw {
		address, err := netip.ParseAddr(strings.TrimSpace(item))
		if err != nil {
			return nil, ErrEgressConfigurationInvalid
		}
		parsed = append(parsed, address)
	}
	result, err := platformegress.NormalizeAddresses(parsed, platformegress.Policy{AllowLoopback: allowLoopback, AllowPrivate: true})
	if err != nil || len(result) != len(raw) {
		return nil, ErrEgressConfigurationInvalid
	}
	return result, nil
}

func sameAuthority(left, right *url.URL) bool {
	if left == nil || right == nil || !strings.EqualFold(left.Scheme, right.Scheme) {
		return false
	}
	return strings.EqualFold(left.Hostname(), right.Hostname()) && effectivePort(left) == effectivePort(right)
}

func effectivePort(parsed *url.URL) string {
	if port := parsed.Port(); port != "" {
		return port
	}
	if parsed.Scheme == "https" {
		return "443"
	}
	return "80"
}

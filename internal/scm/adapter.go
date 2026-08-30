package scm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"xminds-release-platform/internal/identity"
)

var (
	commitSHAPattern  = regexp.MustCompile(`^[0-9a-f]{40}(?:[0-9a-f]{24})?$`)
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
)

type HTTPDoer interface {
	Do(request *http.Request) (*http.Response, error)
}

type SCMClientFactory interface {
	ClientFor(connection Connection) (HTTPDoer, error)
}

type WorkloadVerifierResolver interface {
	VerifierFor(ctx context.Context, connection Connection) (identity.Verifier, error)
}

type AdapterConfig struct {
	Clients     SCMClientFactory
	Credentials CredentialUser
	Workloads   WorkloadVerifierResolver
	Clock       func() time.Time
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func providerProbeEndpoint(baseURL, resource string) (string, error) {
	parsed, err := parseConnectionAPIBaseURL(baseURL)
	if err != nil || strings.TrimSpace(resource) == "" {
		return "", ErrConnectionInvalid
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/") + "/" + url.PathEscape(resource)
	return parsed.String(), nil
}

func peerCertificateFingerprint(response *http.Response) (string, error) {
	if response == nil || response.TLS == nil || len(response.TLS.PeerCertificates) == 0 || len(response.TLS.PeerCertificates[0].Raw) == 0 {
		return "", ErrProviderResponseInvalid
	}
	digest := sha256.Sum256(response.TLS.PeerCertificates[0].Raw)
	return hex.EncodeToString(digest[:]), nil
}

func verifyProviderWorkload(ctx context.Context, resolver WorkloadVerifierResolver, connection Connection, provider ProviderKind, token string) (identity.Principal, error) {
	if resolver == nil {
		return identity.Principal{}, ErrWorkloadVerifierRequired
	}
	if connection.ID == [16]byte{} || connection.Provider != provider || connection.Status != ConnectionStatusActive || token == "" {
		return identity.Principal{}, ErrWorkloadIdentityInvalid
	}
	verifier, err := resolver.VerifierFor(ctx, connection)
	if err != nil || verifier == nil {
		return identity.Principal{}, ErrWorkloadVerifierRequired
	}
	principal, err := verifier.Verify(ctx, token)
	if err != nil || principal.Kind != identity.PrincipalKindWorkload {
		return identity.Principal{}, ErrWorkloadIdentityInvalid
	}
	return principal, nil
}

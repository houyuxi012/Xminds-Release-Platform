package scm

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
)

func TestAdaptersImplementProviderAndProbeCapabilitiesWithCertificateEvidence(t *testing.T) {
	t.Parallel()

	certificate := []byte("verified-peer-certificate")
	credentialID := uuid.New()
	for _, test := range []struct {
		name       string
		provider   ProviderKind
		credential CredentialKind
		baseURL    string
		new        func(AdapterConfig) (Provider, error)
		wantChecks bool
	}{
		{name: "github app", provider: ProviderGitHub, credential: CredentialKindGitHubAppToken, baseURL: "https://github.corp/api/v3", new: func(config AdapterConfig) (Provider, error) { return NewGitHubAdapter(config) }, wantChecks: true},
		{name: "gitlab", provider: ProviderGitLab, credential: CredentialKindGitLabAccessToken, baseURL: "https://gitlab.corp/api/v4", new: func(config AdapterConfig) (Provider, error) { return NewGitLabAdapter(config) }},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			doer := &recordingDoer{response: &http.Response{
				StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}},
				Body: http.NoBody, TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: certificate}}},
			}}
			adapter, err := test.new(AdapterConfig{
				Clients: fixedClientFactory{client: doer}, Credentials: fixedCredentialStore{credentials: map[uuid.UUID]SecretCredential{
					credentialID: {ID: credentialID, Kind: test.credential, Secret: []byte("provider-secret")},
				}}, Clock: time.Now,
			})
			if err != nil {
				t.Fatal(err)
			}
			capabilities, err := adapter.VerifyConnection(context.Background(), Connection{
				ID: uuid.New(), Provider: test.provider, Status: ConnectionStatusActive, APIBaseURL: test.baseURL, CredentialID: credentialID,
			})
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(certificate)
			if !capabilities.CommitStatuses || capabilities.CheckRuns != test.wantChecks || capabilities.CertificateSHA256 != hex.EncodeToString(digest[:]) {
				t.Fatalf("capabilities = %+v", capabilities)
			}
		})
	}
}

func TestAdaptersRejectWorkloadFromWrongProvider(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name       string
		provider   ProviderKind
		principal  identity.Principal
		newAdapter func(AdapterConfig) (Provider, error)
	}{
		{name: "github", provider: ProviderGitHub, principal: workloadPrincipal(identity.WorkloadProviderGitLabCI), newAdapter: func(config AdapterConfig) (Provider, error) { return NewGitHubAdapter(config) }},
		{name: "gitlab", provider: ProviderGitLab, principal: workloadPrincipal(identity.WorkloadProviderGitHubActions), newAdapter: func(config AdapterConfig) (Provider, error) { return NewGitLabAdapter(config) }},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			adapter, err := test.newAdapter(AdapterConfig{Credentials: fixedCredentialStore{}, Workloads: fixedWorkloadResolver{principal: test.principal}, Clock: time.Now})
			if err != nil {
				t.Fatal(err)
			}
			_, err = adapter.VerifyWorkload(context.Background(), Connection{ID: uuid.New(), Provider: test.provider, Status: ConnectionStatusActive}, "signed-token")
			if err != ErrWorkloadIdentityInvalid {
				t.Fatalf("wrong provider error = %v", err)
			}
		})
	}
}

func workloadPrincipal(provider identity.WorkloadProvider) identity.Principal {
	return identity.Principal{Subject: "ci-job", Kind: identity.PrincipalKindWorkload, Provider: provider, Roles: []identity.Role{identity.RolePublisher}, ProductIDs: []string{"ngep"}, TokenID: "job-42"}
}

type verifierFunc func(context.Context, string) (identity.Principal, error)

func (function verifierFunc) Verify(ctx context.Context, token string) (identity.Principal, error) {
	return function(ctx, token)
}

type fixedWorkloadResolver struct{ principal identity.Principal }

func (resolver fixedWorkloadResolver) VerifierFor(context.Context, Connection) (identity.Verifier, error) {
	return verifierFunc(func(context.Context, string) (identity.Principal, error) { return resolver.principal, nil }), nil
}

package identity

import (
	"context"
	"strings"
)

const workloadTokenUse = "workload"

func NewWorkloadVerifier(ctx context.Context, config OIDCVerifierConfig) (*OIDCVerifier, error) {
	return newTokenVerifier(ctx, config, PrincipalKindWorkload, workloadTokenUse)
}

type WorkloadIdentityVerifier struct {
	federated Verifier
	apiToken  Verifier
}

func NewWorkloadIdentityVerifier(federated Verifier, apiToken Verifier) *WorkloadIdentityVerifier {
	return &WorkloadIdentityVerifier{federated: federated, apiToken: apiToken}
}

func (verifier *WorkloadIdentityVerifier) Verify(ctx context.Context, rawToken string) (Principal, error) {
	if strings.HasPrefix(rawToken, apiTokenPrefix+".") {
		if verifier == nil || verifier.apiToken == nil {
			return Principal{}, ErrAPITokenStoreRequired
		}
		return verifier.apiToken.Verify(ctx, rawToken)
	}
	if verifier == nil || verifier.federated == nil {
		return Principal{}, ErrOIDCConfigurationInvalid
	}
	return verifier.federated.Verify(ctx, rawToken)
}

package identity

import (
	"context"
	"errors"
	"strings"
)

var ErrManagementVerifierConfiguration = errors.New("management identity verifier configuration is invalid")

// ManagementVerifier accepts human OIDC identities, federated workload
// identities, and hashed API-token credentials without weakening the failure
// semantics of one identity type into an implicit fallback to another.
type ManagementVerifier struct {
	human    Verifier
	workload Verifier
	apiToken Verifier
	local    Verifier
}

func NewManagementVerifier(human, workload, apiToken, local Verifier) (*ManagementVerifier, error) {
	if human == nil || workload == nil || apiToken == nil || local == nil {
		return nil, ErrManagementVerifierConfiguration
	}
	return &ManagementVerifier{human: human, workload: workload, apiToken: apiToken, local: local}, nil
}

func (verifier *ManagementVerifier) Verify(ctx context.Context, rawToken string) (Principal, error) {
	if verifier == nil || verifier.human == nil || verifier.workload == nil || verifier.apiToken == nil || verifier.local == nil {
		return Principal{}, ErrManagementVerifierConfiguration
	}
	if strings.HasPrefix(rawToken, "xms_") {
		return verifier.local.Verify(ctx, rawToken)
	}
	if strings.HasPrefix(rawToken, apiTokenPrefix+".") {
		return verifier.apiToken.Verify(ctx, rawToken)
	}
	principal, err := verifier.human.Verify(ctx, rawToken)
	if err == nil {
		return principal, nil
	}
	if !errors.Is(err, ErrTokenUseInvalid) {
		return Principal{}, err
	}
	return verifier.workload.Verify(ctx, rawToken)
}

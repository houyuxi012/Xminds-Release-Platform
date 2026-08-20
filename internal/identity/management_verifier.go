package identity

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"

	"xminds-release-platform/internal/platform/strictjson"
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
	tokenUse, err := managementTokenUse(rawToken)
	if err != nil {
		return Principal{}, err
	}
	switch tokenUse {
	case defaultHumanTokenUse:
		return verifier.human.Verify(ctx, rawToken)
	case workloadTokenUse:
		return verifier.workload.Verify(ctx, rawToken)
	default:
		return Principal{}, ErrTokenUseInvalid
	}
}

func managementTokenUse(rawToken string) (string, error) {
	if rawToken == "" || len(rawToken) > maximumBearerTokenLength {
		return "", ErrTokenUseInvalid
	}
	segments := strings.Split(rawToken, ".")
	if len(segments) != 3 || segments[0] == "" || segments[1] == "" || segments[2] == "" {
		return "", ErrTokenUseInvalid
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(segments[1])
	if err != nil || len(payload) == 0 || len(payload) > maximumBearerTokenLength {
		return "", ErrTokenUseInvalid
	}
	claims := struct {
		TokenUse string `json:"token_use"`
	}{}
	if err := strictjson.DecodeKnownBytes(payload, maximumBearerTokenLength, &claims); err != nil {
		return "", ErrTokenUseInvalid
	}
	if claims.TokenUse != defaultHumanTokenUse && claims.TokenUse != workloadTokenUse {
		return "", ErrTokenUseInvalid
	}
	return claims.TokenUse, nil
}

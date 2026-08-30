package main

import (
	"context"
	"errors"
	"strings"

	"xminds-release-platform/internal/iam"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/logcenter"
	"xminds-release-platform/internal/platform/httpx"
)

type logExportAuthorizer struct {
	service *iam.ReauthenticationService
}

func (authorizer logExportAuthorizer) AuthorizeExport(ctx context.Context, authorization logcenter.ExportAuthorization) error {
	if authorizer.service == nil {
		return logcenter.ErrExportUnavailable
	}
	principal, ok := identity.PrincipalFromContext(ctx)
	if !ok || strings.TrimSpace(principal.Subject) == "" || strings.TrimSpace(authorization.Requester) != principal.Subject {
		return logcenter.ErrExportForbidden
	}
	proof, ok := decodeLogExportProof(authorization.Proof)
	if !ok {
		return iam.ErrHighRiskConfirmationRequired
	}
	request := iam.RequestContext{RequestID: httpx.RequestIDFromContext(ctx)}
	if tx, inTransaction := logcenter.ExportAuthorizationTxFromContext(ctx); inTransaction {
		err := authorizer.service.AuthorizeInTransaction(ctx, tx, principal, string(iam.ReauthenticationOperationLogExport), proof, request)
		if errors.Is(err, iam.ErrHighRiskConfirmationRequired) {
			return logcenter.ErrExportForbidden
		}
		return err
	}
	err := authorizer.service.Authorize(ctx, principal, string(iam.ReauthenticationOperationLogExport), proof, request)
	if errors.Is(err, iam.ErrHighRiskConfirmationRequired) {
		return logcenter.ErrExportForbidden
	}
	return err
}

func decodeLogExportProof(value any) (iam.HighRiskProof, bool) {
	fields, ok := value.(map[string]any)
	if !ok || len(fields) != 3 {
		return iam.HighRiskProof{}, false
	}
	challengeID, idOK := fields["challenge_id"].(string)
	evidence, evidenceOK := fields["evidence"].(string)
	confirmed, confirmedOK := fields["confirmed"].(bool)
	if !idOK || !evidenceOK || !confirmedOK || !confirmed || strings.TrimSpace(challengeID) == "" || strings.TrimSpace(evidence) == "" {
		return iam.HighRiskProof{}, false
	}
	return iam.HighRiskProof{ChallengeID: challengeID, Evidence: evidence, Confirmed: true}, true
}

var _ logcenter.ExportAuthorizer = logExportAuthorizer{}

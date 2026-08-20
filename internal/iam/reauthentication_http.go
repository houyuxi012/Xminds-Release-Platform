package iam

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
)

type ReauthenticationApplication interface {
	CreateChallenge(ctx context.Context, actor identity.Principal, operation ReauthenticationOperation, request RequestContext) (ReauthenticationChallengeResult, error)
	CompleteChallenge(ctx context.Context, actor identity.Principal, challengeID uuid.UUID, command CompleteReauthenticationCommand, request RequestContext) (ReauthenticationEvidence, error)
}

func RegisterReauthenticationRoutes(router chi.Router, application ReauthenticationApplication) {
	if application == nil {
		return
	}
	router.Post("/api/v1/auth/reauth-challenges", createReauthenticationChallengeHandler(application))
	router.Post("/api/v1/auth/reauth-challenges/{challenge_id}/complete", completeReauthenticationChallengeHandler(application))
}

func createReauthenticationChallengeHandler(application ReauthenticationApplication) http.HandlerFunc {
	type input struct {
		Operation ReauthenticationOperation `json:"operation"`
	}
	type response struct {
		ID        uuid.UUID                 `json:"id"`
		Operation ReauthenticationOperation `json:"operation"`
		Status    ReauthenticationStatus    `json:"status"`
		ExpiresAt time.Time                 `json:"expires_at"`
	}
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireIAMPrincipal(writer, request)
		if !ok {
			return
		}
		var body input
		if err := decodeIAMJSON(request, &body); err != nil {
			writeIAMProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", err)
			return
		}
		result, err := application.CreateChallenge(request.Context(), principal, body.Operation, iamRequestContext(request))
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("Location", "/api/v1/auth/reauth-challenges/"+result.ID.String())
		writeIAMJSON(writer, http.StatusCreated, response{ID: result.ID, Operation: result.Operation, Status: result.Status, ExpiresAt: result.ExpiresAt})
	}
}

func completeReauthenticationChallengeHandler(application ReauthenticationApplication) http.HandlerFunc {
	type input struct {
		Password string `json:"password"`
		MFAProof string `json:"mfa_proof"`
	}
	type response struct {
		ChallengeID uuid.UUID `json:"challenge_id"`
		Evidence    string    `json:"evidence"`
		ExpiresAt   time.Time `json:"expires_at"`
	}
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireIAMPrincipal(writer, request)
		if !ok {
			return
		}
		challengeID, err := uuid.Parse(chi.URLParam(request, "challenge_id"))
		if err != nil || challengeID == uuid.Nil || challengeID.Version() != 7 {
			writeIAMApplicationError(writer, request, ErrHighRiskConfirmationRequired)
			return
		}
		var body input
		if err := decodeIAMJSON(request, &body); err != nil {
			writeIAMProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", err)
			return
		}
		if len(body.Password) > 1024 || !validOptionalMFAProof(body.MFAProof) ||
			(principal.Kind == identity.PrincipalKindHuman && (body.Password != "" || body.MFAProof != "")) {
			writeIAMProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", ErrUserInputInvalid)
			return
		}
		result, err := application.CompleteChallenge(request.Context(), principal, challengeID, CompleteReauthenticationCommand{Password: body.Password, MFAProof: body.MFAProof}, iamRequestContext(request))
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writeIAMJSON(writer, http.StatusOK, response{ChallengeID: result.ChallengeID, Evidence: result.Evidence, ExpiresAt: result.ExpiresAt})
	}
}

func validOptionalMFAProof(proof string) bool {
	if proof == "" {
		return true
	}
	if len(proof) < 6 || len(proof) > 8 {
		return false
	}
	for _, character := range proof {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

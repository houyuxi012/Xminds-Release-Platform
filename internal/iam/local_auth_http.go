package iam

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"xminds-release-platform/internal/platform/httpx"
)

type LocalAuthApplication interface {
	Activate(ctx context.Context, command ActivateLocalAccountCommand, request RequestContext) error
	LoginLocal(ctx context.Context, command LocalLoginCommand, request RequestContext) (LoginResult, error)
	LoginEmergency(ctx context.Context, command LocalLoginCommand, request RequestContext) (LoginResult, error)
}

func RegisterPublicAuthRoutes(router chi.Router, application LocalAuthApplication) {
	if application == nil {
		return
	}
	router.Post("/api/v1/auth/local/activate", activateLocalAccountHandler(application))
	router.Post("/api/v1/auth/local/login", localLoginHandler(application, false))
	router.Post("/api/v1/auth/emergency/login", localLoginHandler(application, true))
}

func activateLocalAccountHandler(application LocalAuthApplication) http.HandlerFunc {
	type input struct {
		ActivationToken    string `json:"activation_token"`
		NewPassword        string `json:"new_password"`
		MFASecretReference string `json:"mfa_secret_reference"`
		MFAProof           string `json:"mfa_proof"`
	}
	return func(writer http.ResponseWriter, request *http.Request) {
		var body input
		if err := decodeIAMJSON(request, &body); err != nil {
			writeIAMProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", err)
			return
		}
		err := application.Activate(request.Context(), ActivateLocalAccountCommand{
			ActivationToken: body.ActivationToken, NewPassword: body.NewPassword,
			MFASecretReference: body.MFASecretReference, MFAProof: body.MFAProof,
		}, iamRequestContext(request))
		if err != nil {
			writeLocalAuthError(writer, request, err)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusNoContent)
	}
}

func localLoginHandler(application LocalAuthApplication, emergency bool) http.HandlerFunc {
	type input struct {
		Username string `json:"username"`
		Password string `json:"password"`
		MFAProof string `json:"mfa_proof"`
	}
	type response struct {
		AccessToken string               `json:"access_token"`
		TokenType   string               `json:"token_type"`
		ExpiresAt   time.Time            `json:"expires_at"`
		Subject     AuthenticatedSubject `json:"subject"`
	}
	return func(writer http.ResponseWriter, request *http.Request) {
		var body input
		if err := decodeIAMJSON(request, &body); err != nil {
			writeIAMProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", err)
			return
		}
		command := LocalLoginCommand{Username: body.Username, Password: body.Password, MFAProof: body.MFAProof}
		var result LoginResult
		var err error
		if emergency {
			result, err = application.LoginEmergency(request.Context(), command, iamRequestContext(request))
		} else {
			result, err = application.LoginLocal(request.Context(), command, iamRequestContext(request))
		}
		if err != nil {
			writeLocalAuthError(writer, request, err)
			return
		}
		writeIAMJSON(writer, http.StatusOK, response{
			AccessToken: result.AccessToken, TokenType: result.TokenType, ExpiresAt: result.ExpiresAt, Subject: result.Subject,
		})
	}
}

func writeLocalAuthError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, ErrLocalAuthenticationLimited):
		writer.Header().Set("Retry-After", "300")
		writeIAMProblem(writer, request, http.StatusTooManyRequests, "AUTHENTICATION_RATE_LIMITED", "Authentication rate limit exceeded", err)
	case errors.Is(err, ErrLocalAuthenticationFailed), errors.Is(err, ErrMFAProofInvalid):
		writer.Header().Set("WWW-Authenticate", `Bearer realm="xminds-release-platform"`)
		writeIAMProblem(writer, request, http.StatusUnauthorized, "AUTHENTICATION_FAILED", "Authentication failed", err)
	case errors.Is(err, ErrPasswordInvalid), errors.Is(err, ErrPasswordBreached), errors.Is(err, ErrPasswordRecentlyUsed):
		writeIAMProblem(writer, request, http.StatusBadRequest, "PASSWORD_POLICY_REJECTED", "Password does not satisfy policy", err)
	default:
		httpx.WriteProblem(writer, httpx.NewProblem(http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error", err).
			WithRequestID(httpx.RequestIDFromContext(request.Context())).WithInstance(request.URL.Path))
	}
}

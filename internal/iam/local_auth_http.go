package iam

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/httpx"
)

type LocalAuthApplication interface {
	ActivateWithResult(ctx context.Context, command ActivateLocalAccountCommand, request RequestContext) (LocalActivationResult, error)
	LoginLocal(ctx context.Context, command LocalLoginCommand, request RequestContext) (LoginResult, error)
	LoginEmergency(ctx context.Context, command LocalLoginCommand, request RequestContext) (LoginResult, error)
}

type PublicLoginStateApplication interface {
	GetPublicLoginState(ctx context.Context) (PublicLoginState, error)
}

type CurrentSessionLogoutApplication interface {
	LogoutCurrentSession(ctx context.Context, principal identity.Principal, request RequestContext) error
}

type MFAActivationEnrollmentApplication interface {
	BeginActivationEnrollment(ctx context.Context, activationToken string, request RequestContext) (MFAEnrollmentStart, error)
}

func RegisterPublicAuthRoutes(router chi.Router, application LocalAuthApplication) {
	if application == nil {
		return
	}
	router.Post("/api/v1/auth/local/activate", activateLocalAccountHandler(application))
	router.Post("/api/v1/auth/local/login", localLoginHandler(application, false))
	router.Post("/api/v1/auth/emergency/login", localLoginHandler(application, true))
	if loginState, ok := application.(PublicLoginStateApplication); ok {
		router.Get("/api/v1/auth/login-state", publicLoginStateHandler(loginState))
	}
}

func publicLoginStateHandler(application PublicLoginStateApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		state, err := application.GetPublicLoginState(request.Context())
		if err != nil {
			writeIAMProblem(writer, request, http.StatusServiceUnavailable, "LOGIN_STATE_UNAVAILABLE", "Login state is unavailable", err)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writeIAMJSON(writer, http.StatusOK, state)
	}
}

func RegisterPublicMFAEnrollmentRoutes(router chi.Router, application MFAActivationEnrollmentApplication) {
	if application == nil {
		return
	}
	router.Post("/api/v1/auth/local/mfa-enrollments", beginActivationMFAEnrollmentHandler(application))
}

func RegisterCurrentSessionLogoutRoute(router chi.Router, application CurrentSessionLogoutApplication) {
	if application == nil {
		return
	}
	router.Post("/api/v1/auth/logout", currentSessionLogoutHandler(application))
}

func currentSessionLogoutHandler(application CurrentSessionLogoutApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireIAMPrincipal(writer, request)
		if !ok {
			return
		}
		if err := application.LogoutCurrentSession(request.Context(), principal, iamRequestContext(request)); err != nil {
			writeLocalAuthError(writer, request, err)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusNoContent)
	}
}

func beginActivationMFAEnrollmentHandler(application MFAActivationEnrollmentApplication) http.HandlerFunc {
	type input struct {
		ActivationToken string `json:"activation_token"`
	}
	return func(writer http.ResponseWriter, request *http.Request) {
		var body input
		if err := decodeIAMJSON(request, &body); err != nil || len(body.ActivationToken) < 32 || body.ActivationToken != strings.TrimSpace(body.ActivationToken) || len(body.ActivationToken) > 1024 {
			writeIAMProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", ErrUserInputInvalid)
			return
		}
		result, err := application.BeginActivationEnrollment(request.Context(), body.ActivationToken, iamRequestContext(request))
		if err != nil {
			writeLocalAuthError(writer, request, err)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writeIAMJSON(writer, http.StatusCreated, result)
	}
}

func activateLocalAccountHandler(application LocalAuthApplication) http.HandlerFunc {
	type input struct {
		ActivationToken string    `json:"activation_token"`
		NewPassword     string    `json:"new_password"`
		MFAEnrollmentID uuid.UUID `json:"mfa_enrollment_id"`
		MFAProof        string    `json:"mfa_proof"`
	}
	return func(writer http.ResponseWriter, request *http.Request) {
		var body input
		if err := decodeIAMJSON(request, &body); err != nil {
			writeIAMProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", err)
			return
		}
		result, err := application.ActivateWithResult(request.Context(), ActivateLocalAccountCommand{
			ActivationToken: body.ActivationToken, NewPassword: body.NewPassword,
			MFAEnrollmentID: body.MFAEnrollmentID, MFAProof: body.MFAProof,
		}, iamRequestContext(request))
		if err != nil {
			writeLocalAuthError(writer, request, err)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writeIAMJSON(writer, http.StatusOK, result)
	}
}

func localLoginHandler(application LocalAuthApplication, emergency bool) http.HandlerFunc {
	type input struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		MFAProof     string `json:"mfa_proof"`
		RecoveryCode string `json:"recovery_code"`
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
		command := LocalLoginCommand{Username: body.Username, Password: body.Password, MFAProof: body.MFAProof, RecoveryCode: body.RecoveryCode}
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
		writer.Header().Set("Cache-Control", "no-store")
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

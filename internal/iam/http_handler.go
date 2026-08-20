package iam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/httpx"
)

const maximumIAMRequestBytes = 16 * 1024

type IAMApplication interface {
	CreateLocalUser(ctx context.Context, actor identity.Principal, command CreateLocalUserCommand, request RequestContext) (LocalUserProvisioning, error)
	GetUser(ctx context.Context, actor identity.Principal, userID uuid.UUID) (UserPrincipal, error)
	ListUsers(ctx context.Context, actor identity.Principal, page Page) (UserPage, error)
}

func NewHTTPHandler(application IAMApplication) http.Handler {
	if application == nil {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writeIAMProblem(writer, request, http.StatusInternalServerError, "IAM_SERVICE_UNAVAILABLE", "Identity service is unavailable", ErrIAMConfiguration)
		})
	}
	router := chi.NewRouter()
	RegisterRoutes(router, application)
	return router
}

func RegisterRoutes(router chi.Router, application IAMApplication) {
	router.Post("/api/v1/local-users", createLocalUserHandler(application))
	router.Route("/api/v1/users", func(router chi.Router) {
		router.Get("/", listUsersHandler(application))
		router.Get("/{user_id}", getUserHandler(application))
	})
}

func createLocalUserHandler(application IAMApplication) http.HandlerFunc {
	type input struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Email       string `json:"email"`
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
		result, err := application.CreateLocalUser(request.Context(), principal, CreateLocalUserCommand{
			Username: body.Username, DisplayName: body.DisplayName, Email: body.Email,
		}, iamRequestContext(request))
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writer.Header().Set("Location", "/api/v1/users/"+result.User.ID.String())
		writeIAMJSON(writer, http.StatusCreated, localUserProvisioningResponse{
			User: toUserResponse(result.User), ActivationToken: result.ActivationToken, ActivationExpiresAt: result.ActivationExpires,
		})
	}
}

func listUsersHandler(application IAMApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireIAMPrincipal(writer, request)
		if !ok {
			return
		}
		page, err := parseIAMPage(request)
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		result, err := application.ListUsers(request.Context(), principal, page)
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		items := make([]userResponse, 0, len(result.Items))
		for _, item := range result.Items {
			items = append(items, toUserResponse(item))
		}
		writeIAMJSON(writer, http.StatusOK, userPageResponse{Items: items, NextCursor: result.NextCursor})
	}
}

func getUserHandler(application IAMApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireIAMPrincipal(writer, request)
		if !ok {
			return
		}
		userID, err := uuid.Parse(chi.URLParam(request, "user_id"))
		if err != nil || userID == uuid.Nil {
			writeIAMProblem(writer, request, http.StatusBadRequest, "USER_ID_INVALID", "User ID is invalid", ErrUserInputInvalid)
			return
		}
		user, err := application.GetUser(request.Context(), principal, userID)
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writeIAMJSON(writer, http.StatusOK, toUserResponse(user))
	}
}

func parseIAMPage(request *http.Request) (Page, error) {
	page := Page{}
	if rawLimit := strings.TrimSpace(request.URL.Query().Get("limit")); rawLimit != "" {
		limit, err := strconv.Atoi(rawLimit)
		if err != nil || limit < 1 || limit > 200 {
			return Page{}, ErrPageInvalid
		}
		page.Limit = limit
	}
	if cursor := strings.TrimSpace(request.URL.Query().Get("cursor")); cursor != "" {
		createdAt, id, err := decodeIAMCursor(cursor)
		if err != nil {
			return Page{}, err
		}
		page.BeforeTime = createdAt
		page.BeforeID = id
	}
	return page, nil
}

func decodeIAMJSON(request *http.Request, target any) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("content type must be application/json")
	}
	decoder := json.NewDecoder(io.LimitReader(request.Body, maximumIAMRequestBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func requireIAMPrincipal(writer http.ResponseWriter, request *http.Request) (identity.Principal, bool) {
	principal, ok := identity.PrincipalFromContext(request.Context())
	if !ok {
		writer.Header().Set("WWW-Authenticate", `Bearer realm="xminds-release-platform"`)
		writeIAMProblem(writer, request, http.StatusUnauthorized, "AUTHENTICATION_REQUIRED", "Authentication is required", identity.ErrAuthenticationFailed)
		return identity.Principal{}, false
	}
	return principal, true
}

func iamRequestContext(request *http.Request) RequestContext {
	host, _, err := net.SplitHostPort(strings.TrimSpace(request.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(request.RemoteAddr)
	}
	return RequestContext{RequestID: httpx.RequestIDFromContext(request.Context()), SourceIP: host}
}

func writeIAMApplicationError(writer http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, ErrUserInputInvalid), errors.Is(err, ErrPageInvalid):
		writeIAMProblem(writer, request, http.StatusBadRequest, "IAM_INPUT_INVALID", "Identity request is invalid", err)
	case errors.Is(err, identity.ErrActionDenied):
		writeIAMProblem(writer, request, http.StatusForbidden, "IAM_ACCESS_DENIED", "Identity access is denied", err)
	case errors.Is(err, ErrUserNotFound):
		writeIAMProblem(writer, request, http.StatusNotFound, "USER_NOT_FOUND", "User was not found", err)
	case errors.Is(err, ErrIAMConflict):
		writeIAMProblem(writer, request, http.StatusConflict, "IAM_RECORD_CONFLICT", "Identity record conflicts with current state", err)
	default:
		writeIAMProblem(writer, request, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error", err)
	}
}

func writeIAMProblem(writer http.ResponseWriter, request *http.Request, status int, code, title string, cause error) {
	httpx.WriteProblem(writer, httpx.NewProblem(status, code, title, cause).
		WithRequestID(httpx.RequestIDFromContext(request.Context())).WithInstance(request.URL.Path))
}

func writeIAMJSON(writer http.ResponseWriter, status int, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		httpx.WriteProblem(writer, httpx.NewProblem(http.StatusInternalServerError, "RESPONSE_SERIALIZATION_FAILED", "Internal server error", fmt.Errorf("encode IAM response: %w", err)))
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_, _ = writer.Write(append(payload, '\n'))
}

type userResponse struct {
	ID                  uuid.UUID  `json:"id"`
	IdentitySourceID    *uuid.UUID `json:"identity_source_id,omitempty"`
	ExternalSubject     string     `json:"external_subject,omitempty"`
	Username            string     `json:"username"`
	DisplayName         string     `json:"display_name"`
	Email               string     `json:"email,omitempty"`
	Kind                UserKind   `json:"kind"`
	Status              UserStatus `json:"status"`
	MFAEnrolled         bool       `json:"mfa_enrolled"`
	CredentialRotatedAt *time.Time `json:"credential_rotated_at,omitempty"`
	Version             int64      `json:"version"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	DisabledAt          *time.Time `json:"disabled_at,omitempty"`
	DisabledReason      string     `json:"disabled_reason,omitempty"`
}

type localUserProvisioningResponse struct {
	User                userResponse `json:"user"`
	ActivationToken     string       `json:"activation_token"`
	ActivationExpiresAt time.Time    `json:"activation_expires_at"`
}

type userPageResponse struct {
	Items      []userResponse `json:"items"`
	NextCursor string         `json:"next_cursor,omitempty"`
}

func toUserResponse(user UserPrincipal) userResponse {
	result := userResponse{
		ID: user.ID, ExternalSubject: user.ExternalSubject, Username: user.Username, DisplayName: user.DisplayName,
		Email: user.Email, Kind: user.Kind, Status: user.Status, MFAEnrolled: user.MFAEnrolled, Version: user.Version,
		CreatedAt: user.CreatedAt, UpdatedAt: user.UpdatedAt, DisabledReason: user.DisabledReason,
	}
	if user.IdentitySourceID != uuid.Nil {
		value := user.IdentitySourceID
		result.IdentitySourceID = &value
	}
	if !user.CredentialRotatedAt.IsZero() {
		value := user.CredentialRotatedAt
		result.CredentialRotatedAt = &value
	}
	if !user.DisabledAt.IsZero() {
		value := user.DisabledAt
		result.DisabledAt = &value
	}
	return result
}

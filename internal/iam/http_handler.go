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
	CreateOrganization(ctx context.Context, actor identity.Principal, command CreateOrganizationCommand, request RequestContext) (OrganizationUnit, error)
	ListOrganizations(ctx context.Context, actor identity.Principal, page Page) (OrganizationPage, error)
	ListRoleBindings(ctx context.Context, actor identity.Principal, page Page) (RoleBindingPage, error)
	CreateIdentitySource(ctx context.Context, actor identity.Principal, command CreateIdentitySourceCommand, request RequestContext) (IdentitySource, error)
	ListIdentitySources(ctx context.Context, actor identity.Principal, page Page) (IdentitySourcePage, error)
	PatchIdentitySourceDraft(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, command PatchIdentitySourceCommand, request RequestContext) (IdentitySource, error)
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
	router.Route("/api/v1/organizations", func(router chi.Router) {
		router.Get("/", listOrganizationsHandler(application))
		router.Post("/", createOrganizationHandler(application))
	})
	router.Get("/api/v1/role-bindings", listRoleBindingsHandler(application))
	router.Route("/api/v1/identity-sources", func(router chi.Router) {
		router.Get("/", listIdentitySourcesHandler(application))
		router.Post("/", createIdentitySourceHandler(application))
		router.Patch("/{source_id}", patchIdentitySourceHandler(application))
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

func createOrganizationHandler(application IAMApplication) http.HandlerFunc {
	type input struct {
		Name     string `json:"name"`
		ParentID string `json:"parent_id"`
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
		var parentID uuid.UUID
		var err error
		if strings.TrimSpace(body.ParentID) != "" {
			parentID, err = uuid.Parse(body.ParentID)
			if err != nil || parentID == uuid.Nil {
				writeIAMProblem(writer, request, http.StatusBadRequest, "ORGANIZATION_INPUT_INVALID", "Organization request is invalid", ErrUserInputInvalid)
				return
			}
		}
		organization, err := application.CreateOrganization(request.Context(), principal, CreateOrganizationCommand{Name: body.Name, ParentID: parentID}, iamRequestContext(request))
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writer.Header().Set("Location", "/api/v1/organizations/"+organization.ID.String())
		writeIAMJSON(writer, http.StatusCreated, toOrganizationResponse(organization))
	}
}

func listOrganizationsHandler(application IAMApplication) http.HandlerFunc {
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
		result, err := application.ListOrganizations(request.Context(), principal, page)
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		items := make([]organizationResponse, 0, len(result.Items))
		for _, item := range result.Items {
			items = append(items, toOrganizationResponse(item))
		}
		writeIAMJSON(writer, http.StatusOK, organizationPageResponse{Items: items, NextCursor: result.NextCursor})
	}
}

func listRoleBindingsHandler(application IAMApplication) http.HandlerFunc {
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
		result, err := application.ListRoleBindings(request.Context(), principal, page)
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		items := make([]roleBindingResponse, 0, len(result.Items))
		for _, item := range result.Items {
			items = append(items, toRoleBindingResponse(item))
		}
		writeIAMJSON(writer, http.StatusOK, roleBindingPageResponse{Items: items, NextCursor: result.NextCursor})
	}
}

func createIdentitySourceHandler(application IAMApplication) http.HandlerFunc {
	type input struct {
		Name                     string             `json:"name"`
		Kind                     IdentitySourceKind `json:"kind"`
		SecretReference          string             `json:"secret_reference"`
		RequiredMappingsComplete bool               `json:"required_mappings_complete"`
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
		source, err := application.CreateIdentitySource(request.Context(), principal, CreateIdentitySourceCommand{Name: body.Name, Kind: body.Kind, SecretReference: body.SecretReference, RequiredMappingsComplete: body.RequiredMappingsComplete}, iamRequestContext(request))
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writer.Header().Set("Location", "/api/v1/identity-sources/"+source.ID.String())
		writeIAMJSON(writer, http.StatusCreated, toIdentitySourceResponse(source))
	}
}

func listIdentitySourcesHandler(application IAMApplication) http.HandlerFunc {
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
		result, err := application.ListIdentitySources(request.Context(), principal, page)
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		items := make([]identitySourceResponse, 0, len(result.Items))
		for _, item := range result.Items {
			items = append(items, toIdentitySourceResponse(item))
		}
		writeIAMJSON(writer, http.StatusOK, identitySourcePageResponse{Items: items, NextCursor: result.NextCursor})
	}
}

func patchIdentitySourceHandler(application IAMApplication) http.HandlerFunc {
	type input struct {
		Name                     *string `json:"name"`
		SecretReference          *string `json:"secret_reference"`
		RequiredMappingsComplete *bool   `json:"required_mappings_complete"`
		Version                  int64   `json:"version"`
	}
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireIAMPrincipal(writer, request)
		if !ok {
			return
		}
		sourceID, err := uuid.Parse(chi.URLParam(request, "source_id"))
		if err != nil || sourceID == uuid.Nil {
			writeIAMProblem(writer, request, http.StatusBadRequest, "IDENTITY_SOURCE_ID_INVALID", "Identity source ID is invalid", ErrIdentitySourceInputInvalid)
			return
		}
		var body input
		if err := decodeIAMJSON(request, &body); err != nil {
			writeIAMProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", err)
			return
		}
		source, err := application.PatchIdentitySourceDraft(request.Context(), principal, sourceID, PatchIdentitySourceCommand{Name: body.Name, SecretReference: body.SecretReference, RequiredMappingsComplete: body.RequiredMappingsComplete, Version: body.Version}, iamRequestContext(request))
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writeIAMJSON(writer, http.StatusOK, toIdentitySourceResponse(source))
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
	case errors.Is(err, ErrUserInputInvalid), errors.Is(err, ErrPageInvalid), errors.Is(err, ErrRoleBindingInvalid), errors.Is(err, ErrIdentitySourceInputInvalid):
		writeIAMProblem(writer, request, http.StatusBadRequest, "IAM_INPUT_INVALID", "Identity request is invalid", err)
	case errors.Is(err, identity.ErrActionDenied):
		writeIAMProblem(writer, request, http.StatusForbidden, "IAM_ACCESS_DENIED", "Identity access is denied", err)
	case errors.Is(err, ErrUserNotFound):
		writeIAMProblem(writer, request, http.StatusNotFound, "USER_NOT_FOUND", "User was not found", err)
	case errors.Is(err, ErrOrganizationNotFound):
		writeIAMProblem(writer, request, http.StatusNotFound, "ORGANIZATION_NOT_FOUND", "Organization was not found", err)
	case errors.Is(err, ErrRoleBindingNotFound):
		writeIAMProblem(writer, request, http.StatusNotFound, "ROLE_BINDING_NOT_FOUND", "Role binding was not found", err)
	case errors.Is(err, ErrIdentitySourceNotFound):
		writeIAMProblem(writer, request, http.StatusNotFound, "IDENTITY_SOURCE_NOT_FOUND", "Identity source was not found", err)
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

type organizationResponse struct {
	ID               uuid.UUID          `json:"id"`
	IdentitySourceID *uuid.UUID         `json:"identity_source_id,omitempty"`
	ExternalID       string             `json:"external_id,omitempty"`
	ParentID         *uuid.UUID         `json:"parent_id,omitempty"`
	Name             string             `json:"name"`
	SourceOwned      bool               `json:"source_owned"`
	Status           OrganizationStatus `json:"status"`
	Version          int64              `json:"version"`
	CreatedAt        time.Time          `json:"created_at"`
	UpdatedAt        time.Time          `json:"updated_at"`
}

type organizationPageResponse struct {
	Items      []organizationResponse `json:"items"`
	NextCursor string                 `json:"next_cursor,omitempty"`
}

type roleBindingResponse struct {
	ID          uuid.UUID     `json:"id"`
	SubjectType SubjectType   `json:"subject_type"`
	SubjectID   uuid.UUID     `json:"subject_id"`
	Role        identity.Role `json:"role"`
	ScopeType   ScopeType     `json:"scope_type"`
	ProductID   string        `json:"product_id,omitempty"`
	ChannelName string        `json:"channel_name,omitempty"`
	Effect      BindingEffect `json:"effect"`
	ValidFrom   time.Time     `json:"valid_from"`
	ValidUntil  *time.Time    `json:"valid_until,omitempty"`
	CreatedBy   string        `json:"created_by"`
	Version     int64         `json:"version"`
	CreatedAt   time.Time     `json:"created_at"`
	UpdatedAt   time.Time     `json:"updated_at"`
}
type roleBindingPageResponse struct {
	Items      []roleBindingResponse `json:"items"`
	NextCursor string                `json:"next_cursor,omitempty"`
}

type identitySourceResponse struct {
	ID                       uuid.UUID            `json:"id"`
	Name                     string               `json:"name"`
	Kind                     IdentitySourceKind   `json:"kind"`
	Status                   IdentitySourceStatus `json:"status"`
	RequiredMappingsComplete bool                 `json:"required_mappings_complete"`
	VerifiedAt               *time.Time           `json:"verified_at,omitempty"`
	PreviewedAt              *time.Time           `json:"previewed_at,omitempty"`
	FaultCode                string               `json:"fault_code,omitempty"`
	Version                  int64                `json:"version"`
	CreatedAt                time.Time            `json:"created_at"`
	UpdatedAt                time.Time            `json:"updated_at"`
}
type identitySourcePageResponse struct {
	Items      []identitySourceResponse `json:"items"`
	NextCursor string                   `json:"next_cursor,omitempty"`
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

func toOrganizationResponse(organization OrganizationUnit) organizationResponse {
	result := organizationResponse{ID: organization.ID, ExternalID: organization.ExternalID, Name: organization.Name, SourceOwned: organization.SourceOwned, Status: organization.Status, Version: organization.Version, CreatedAt: organization.CreatedAt, UpdatedAt: organization.UpdatedAt}
	if organization.IdentitySourceID != uuid.Nil {
		value := organization.IdentitySourceID
		result.IdentitySourceID = &value
	}
	if organization.ParentID != uuid.Nil {
		value := organization.ParentID
		result.ParentID = &value
	}
	return result
}

func toRoleBindingResponse(binding RoleBinding) roleBindingResponse {
	result := roleBindingResponse{ID: binding.ID, SubjectType: binding.SubjectType, SubjectID: binding.SubjectID, Role: binding.Role, ScopeType: binding.ScopeType, ProductID: binding.ProductID, ChannelName: binding.ChannelName, Effect: binding.Effect, ValidFrom: binding.ValidFrom, CreatedBy: binding.CreatedBy, Version: binding.Version, CreatedAt: binding.CreatedAt, UpdatedAt: binding.UpdatedAt}
	if !binding.ValidUntil.IsZero() {
		value := binding.ValidUntil
		result.ValidUntil = &value
	}
	return result
}

func toIdentitySourceResponse(source IdentitySource) identitySourceResponse {
	result := identitySourceResponse{ID: source.ID, Name: source.Name, Kind: source.Kind, Status: source.Status, RequiredMappingsComplete: source.RequiredMappingsComplete, FaultCode: source.FaultCode, Version: source.Version, CreatedAt: source.CreatedAt, UpdatedAt: source.UpdatedAt}
	if !source.VerifiedAt.IsZero() {
		value := source.VerifiedAt
		result.VerifiedAt = &value
	}
	if !source.PreviewedAt.IsZero() {
		value := source.PreviewedAt
		result.PreviewedAt = &value
	}
	return result
}

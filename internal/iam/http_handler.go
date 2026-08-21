package iam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"xminds-release-platform/internal/platform/strictjson"
)

const maximumIAMRequestBytes = 16 * 1024

type IAMApplication interface {
	CreateLocalUser(ctx context.Context, actor identity.Principal, command CreateLocalUserCommand, request RequestContext) (LocalUserProvisioning, error)
	GetUser(ctx context.Context, actor identity.Principal, userID uuid.UUID) (UserPrincipal, error)
	ListUsers(ctx context.Context, actor identity.Principal, page Page) (UserPage, error)
	CreateOrganization(ctx context.Context, actor identity.Principal, command CreateOrganizationCommand, request RequestContext) (OrganizationUnit, error)
	ListOrganizations(ctx context.Context, actor identity.Principal, page Page) (OrganizationPage, error)
	GetOrganization(ctx context.Context, actor identity.Principal, organizationID uuid.UUID) (OrganizationUnit, error)
	ListOrganizationChildren(ctx context.Context, actor identity.Principal, organizationID uuid.UUID, page Page) (OrganizationPage, error)
	ListOrganizationMemberships(ctx context.Context, actor identity.Principal, organizationID uuid.UUID, page Page) (OrganizationMembershipPage, error)
	CreateOrganizationMembership(ctx context.Context, actor identity.Principal, organizationID uuid.UUID, command CreateOrganizationMembershipCommand, proof HighRiskProof, request RequestContext) (OrganizationMembership, error)
	DeleteOrganizationMembership(ctx context.Context, actor identity.Principal, organizationID, userID uuid.UUID, command DeleteOrganizationMembershipCommand, proof HighRiskProof, request RequestContext) error
	ListRoleBindings(ctx context.Context, actor identity.Principal, page Page) (RoleBindingPage, error)
	CreateRoleBinding(ctx context.Context, actor identity.Principal, command CreateRoleBindingCommand, proof HighRiskProof, request RequestContext) (RoleBinding, error)
	DeleteRoleBinding(ctx context.Context, actor identity.Principal, bindingID uuid.UUID, expectedVersion int64, proof HighRiskProof, request RequestContext) error
	DisableUser(ctx context.Context, actor identity.Principal, userID uuid.UUID, expectedVersion int64, reason string, proof HighRiskProof, request RequestContext) error
	EnableUser(ctx context.Context, actor identity.Principal, userID uuid.UUID, expectedVersion int64, reason string, proof HighRiskProof, request RequestContext) error
	RevokeUserSessions(ctx context.Context, actor identity.Principal, userID uuid.UUID, expectedVersion int64, reason string, proof HighRiskProof, request RequestContext) error
	CreateIdentitySource(ctx context.Context, actor identity.Principal, command CreateIdentitySourceCommand, request RequestContext) (IdentitySource, error)
	ListIdentitySources(ctx context.Context, actor identity.Principal, page Page) (IdentitySourcePage, error)
	PatchIdentitySourceDraft(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, command PatchIdentitySourceCommand, request RequestContext) (IdentitySource, error)
	EnableSSO(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, expectedVersion int64, proof HighRiskProof, request RequestContext) error
	DisableSSO(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, expectedVersion int64, proof HighRiskProof, request RequestContext) error
}

type DirectorySyncApplication interface {
	VerifyIdentitySourceVersioned(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, expectedVersion int64, request RequestContext) (CapabilityReport, error)
	StartDirectorySync(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, mode DirectorySyncMode, expectedVersion int64, request RequestContext) (DirectorySyncJob, error)
	GetDirectorySyncJob(ctx context.Context, actor identity.Principal, sourceID, jobID uuid.UUID) (DirectorySyncJob, error)
	ListDirectorySyncConflicts(ctx context.Context, actor identity.Principal, sourceID uuid.UUID, status DirectorySyncConflictStatusFilter, page Page) (DirectorySyncConflictPage, error)
	ResolveDirectorySyncConflict(ctx context.Context, actor identity.Principal, sourceID, conflictID uuid.UUID, command ResolveDirectorySyncConflictCommand, proof HighRiskProof, request RequestContext) (DirectorySyncConflict, error)
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
		router.Post("/{user_id}/disable", userLifecycleHandler(application, "disable"))
		router.Post("/{user_id}/enable", userLifecycleHandler(application, "enable"))
		router.Post("/{user_id}/revoke-sessions", userLifecycleHandler(application, "revoke_sessions"))
	})
	router.Route("/api/v1/organizations", func(router chi.Router) {
		router.Get("/", listOrganizationsHandler(application))
		router.Post("/", createOrganizationHandler(application))
		router.Get("/{organization_id}", getOrganizationHandler(application))
		router.Get("/{organization_id}/children", listOrganizationChildrenHandler(application))
		router.Get("/{organization_id}/memberships", listOrganizationMembershipsHandler(application))
		router.Post("/{organization_id}/memberships", createOrganizationMembershipHandler(application))
		router.Delete("/{organization_id}/memberships/{user_id}", deleteOrganizationMembershipHandler(application))
	})
	router.Route("/api/v1/role-bindings", func(router chi.Router) {
		router.Get("/", listRoleBindingsHandler(application))
		router.Post("/", createRoleBindingHandler(application))
		router.Delete("/{binding_id}", deleteRoleBindingHandler(application))
	})
	router.Route("/api/v1/identity-sources", func(router chi.Router) {
		router.Get("/", listIdentitySourcesHandler(application))
		router.Post("/", createIdentitySourceHandler(application))
		router.Patch("/{source_id}", patchIdentitySourceHandler(application))
		router.Post("/{source_id}/enable", identitySourceLifecycleHandler(application, true))
		router.Post("/{source_id}/disable", identitySourceLifecycleHandler(application, false))
	})
	if directory, ok := application.(DirectorySyncApplication); ok {
		registerDirectorySyncRoutes(router, directory)
	}
}

func registerDirectorySyncRoutes(router chi.Router, application DirectorySyncApplication) {
	router.Post("/api/v1/identity-sources/{source_id}/verify", verifyIdentitySourceHandler(application))
	router.Post("/api/v1/identity-sources/{source_id}/sync-preview", startDirectorySyncHandler(application, DirectorySyncModePreview))
	router.Post("/api/v1/identity-sources/{source_id}/sync", startDirectorySyncHandler(application, DirectorySyncModeApply))
	router.Get("/api/v1/identity-sources/{source_id}/sync-jobs/{job_id}", getDirectorySyncJobHandler(application))
	router.Get("/api/v1/identity-sources/{source_id}/sync-conflicts", listDirectorySyncConflictsHandler(application))
	router.Post("/api/v1/identity-sources/{source_id}/sync-conflicts/{conflict_id}/resolve", resolveDirectorySyncConflictHandler(application))
}

func verifyIdentitySourceHandler(application DirectorySyncApplication) http.HandlerFunc {
	type input struct {
		Version int64 `json:"version"`
	}
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireIAMPrincipal(writer, request)
		if !ok {
			return
		}
		sourceID, ok := parseDirectoryPathID(writer, request, "source_id", "IDENTITY_SOURCE_ID_INVALID")
		if !ok {
			return
		}
		var body input
		if err := decodeIAMJSON(request, &body); err != nil || body.Version < 1 {
			writeIAMProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", ErrIdentitySourceInputInvalid)
			return
		}
		report, err := application.VerifyIdentitySourceVersioned(request.Context(), principal, sourceID, body.Version, iamRequestContext(request))
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writeIAMJSON(writer, http.StatusOK, report)
	}
}

func startDirectorySyncHandler(application DirectorySyncApplication, mode DirectorySyncMode) http.HandlerFunc {
	type input struct {
		Version int64 `json:"version"`
	}
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireIAMPrincipal(writer, request)
		if !ok {
			return
		}
		sourceID, ok := parseDirectoryPathID(writer, request, "source_id", "IDENTITY_SOURCE_ID_INVALID")
		if !ok {
			return
		}
		var body input
		if err := decodeIAMJSON(request, &body); err != nil || body.Version < 1 {
			writeIAMProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", ErrIdentitySourceInputInvalid)
			return
		}
		job, err := application.StartDirectorySync(request.Context(), principal, sourceID, mode, body.Version, iamRequestContext(request))
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writer.Header().Set("Location", "/api/v1/identity-sources/"+sourceID.String()+"/sync-jobs/"+job.ID.String())
		writeIAMJSON(writer, http.StatusAccepted, toDirectorySyncJobResponse(job))
	}
}

func getDirectorySyncJobHandler(application DirectorySyncApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireIAMPrincipal(writer, request)
		if !ok {
			return
		}
		sourceID, ok := parseDirectoryPathID(writer, request, "source_id", "IDENTITY_SOURCE_ID_INVALID")
		if !ok {
			return
		}
		jobID, ok := parseDirectoryPathID(writer, request, "job_id", "DIRECTORY_SYNC_JOB_ID_INVALID")
		if !ok {
			return
		}
		job, err := application.GetDirectorySyncJob(request.Context(), principal, sourceID, jobID)
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writeIAMJSON(writer, http.StatusOK, toDirectorySyncJobResponse(job))
	}
}

func listDirectorySyncConflictsHandler(application DirectorySyncApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireIAMPrincipal(writer, request)
		if !ok {
			return
		}
		sourceID, ok := parseDirectoryPathID(writer, request, "source_id", "IDENTITY_SOURCE_ID_INVALID")
		if !ok {
			return
		}
		status, page, err := parseDirectoryConflictPage(request)
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		result, err := application.ListDirectorySyncConflicts(request.Context(), principal, sourceID, status, page)
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writeIAMJSON(writer, http.StatusOK, result)
	}
}

func resolveDirectorySyncConflictHandler(application DirectorySyncApplication) http.HandlerFunc {
	type input struct {
		Version          int64                               `json:"version"`
		Decision         DirectoryConflictResolutionDecision `json:"decision"`
		Reason           string                              `json:"reason"`
		Reauthentication reauthenticationProofInput          `json:"reauthentication"`
	}
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireIAMPrincipal(writer, request)
		if !ok {
			return
		}
		sourceID, ok := parseDirectoryPathID(writer, request, "source_id", "IDENTITY_SOURCE_ID_INVALID")
		if !ok {
			return
		}
		conflictID, ok := parseDirectoryPathID(writer, request, "conflict_id", "DIRECTORY_SYNC_CONFLICT_ID_INVALID")
		if !ok {
			return
		}
		var body input
		if err := decodeIAMJSON(request, &body); err != nil {
			writeIAMProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", ErrIdentitySourceInputInvalid)
			return
		}
		result, err := application.ResolveDirectorySyncConflict(request.Context(), principal, sourceID, conflictID, ResolveDirectorySyncConflictCommand{
			Version: body.Version, Decision: body.Decision, Reason: body.Reason,
		}, body.Reauthentication.proof(), iamRequestContext(request))
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writeIAMJSON(writer, http.StatusOK, result)
	}
}

func parseDirectoryConflictPage(request *http.Request) (DirectorySyncConflictStatusFilter, Page, error) {
	page := Page{}
	rawStatus := request.URL.Query().Get("status")
	status := DirectorySyncConflictStatusFilter(strings.TrimSpace(rawStatus))
	if status == "" {
		status = DirectorySyncConflictStatusOpen
	}
	if !validDirectoryConflictStatusFilter(status) || (rawStatus != "" && string(status) != rawStatus) {
		return "", Page{}, ErrPageInvalid
	}
	if rawLimit := strings.TrimSpace(request.URL.Query().Get("limit")); rawLimit != "" {
		limit, err := strconv.Atoi(rawLimit)
		if err != nil || limit < 1 || limit > 200 {
			return "", Page{}, ErrPageInvalid
		}
		page.Limit = limit
	}
	if cursor := request.URL.Query().Get("cursor"); cursor != "" {
		if strings.TrimSpace(cursor) != cursor || len(cursor) > 512 {
			return "", Page{}, ErrPageInvalid
		}
		page.Cursor = cursor
	}
	return status, page, nil
}

func parseDirectoryPathID(writer http.ResponseWriter, request *http.Request, parameter, code string) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(request, parameter))
	if err != nil || id == uuid.Nil {
		writeIAMProblem(writer, request, http.StatusBadRequest, code, "Directory identifier is invalid", ErrIdentitySourceInputInvalid)
		return uuid.Nil, false
	}
	return id, true
}

type reauthenticationProofInput struct {
	ChallengeID string `json:"challenge_id"`
	Evidence    string `json:"evidence"`
	Confirmed   bool   `json:"confirmed"`
}

func (input reauthenticationProofInput) proof() HighRiskProof {
	return HighRiskProof{ChallengeID: input.ChallengeID, Evidence: input.Evidence, Confirmed: input.Confirmed}
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
		command, err := validateCreateLocalUserCommand(CreateLocalUserCommand{
			Username: body.Username, DisplayName: body.DisplayName, Email: body.Email,
		})
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		result, err := application.CreateLocalUser(request.Context(), principal, command, iamRequestContext(request))
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

func getOrganizationHandler(application IAMApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireIAMPrincipal(writer, request)
		if !ok {
			return
		}
		organizationID, ok := parseIAMPathUUID(writer, request, "organization_id", "ORGANIZATION_ID_INVALID", ErrOrganizationMembershipInvalid)
		if !ok {
			return
		}
		organization, err := application.GetOrganization(request.Context(), principal, organizationID)
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writeIAMJSON(writer, http.StatusOK, toOrganizationResponse(organization))
	}
}

func listOrganizationChildrenHandler(application IAMApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireIAMPrincipal(writer, request)
		if !ok {
			return
		}
		organizationID, ok := parseIAMPathUUID(writer, request, "organization_id", "ORGANIZATION_ID_INVALID", ErrOrganizationMembershipInvalid)
		if !ok {
			return
		}
		page, err := parseIAMPage(request)
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		result, err := application.ListOrganizationChildren(request.Context(), principal, organizationID, page)
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

func listOrganizationMembershipsHandler(application IAMApplication) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireIAMPrincipal(writer, request)
		if !ok {
			return
		}
		organizationID, ok := parseIAMPathUUID(writer, request, "organization_id", "ORGANIZATION_ID_INVALID", ErrOrganizationMembershipInvalid)
		if !ok {
			return
		}
		page, err := parseOrganizationMembershipPage(request)
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		result, err := application.ListOrganizationMemberships(request.Context(), principal, organizationID, page)
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		items := make([]organizationMembershipResponse, 0, len(result.Items))
		for _, item := range result.Items {
			items = append(items, toOrganizationMembershipResponse(item))
		}
		writeIAMJSON(writer, http.StatusOK, organizationMembershipPageResponse{Items: items, NextCursor: result.NextCursor})
	}
}

func createOrganizationMembershipHandler(application IAMApplication) http.HandlerFunc {
	type input struct {
		OrganizationVersion int64                      `json:"organization_version"`
		UserID              uuid.UUID                  `json:"user_id"`
		UserVersion         int64                      `json:"user_version"`
		Reason              string                     `json:"reason"`
		Reauthentication    reauthenticationProofInput `json:"reauthentication"`
	}
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireIAMPrincipal(writer, request)
		if !ok {
			return
		}
		organizationID, ok := parseIAMPathUUID(writer, request, "organization_id", "ORGANIZATION_ID_INVALID", ErrOrganizationMembershipInvalid)
		if !ok {
			return
		}
		var body input
		if err := decodeIAMJSON(request, &body); err != nil {
			writeIAMProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", err)
			return
		}
		if _, valid := canonicalOrganizationMembershipReason(body.Reason); !valid {
			writeIAMApplicationError(writer, request, ErrOrganizationMembershipInvalid)
			return
		}
		membership, err := application.CreateOrganizationMembership(request.Context(), principal, organizationID, CreateOrganizationMembershipCommand{
			OrganizationVersion: body.OrganizationVersion, UserID: body.UserID, UserVersion: body.UserVersion, Reason: body.Reason,
		}, body.Reauthentication.proof(), iamRequestContext(request))
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writer.Header().Set("Location", "/api/v1/organizations/"+organizationID.String()+"/memberships/"+body.UserID.String())
		writeIAMJSON(writer, http.StatusCreated, toOrganizationMembershipResponse(membership))
	}
}

func deleteOrganizationMembershipHandler(application IAMApplication) http.HandlerFunc {
	type input struct {
		OrganizationVersion int64                      `json:"organization_version"`
		UserVersion         int64                      `json:"user_version"`
		MembershipVersion   int64                      `json:"membership_version"`
		Reason              string                     `json:"reason"`
		Reauthentication    reauthenticationProofInput `json:"reauthentication"`
	}
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireIAMPrincipal(writer, request)
		if !ok {
			return
		}
		organizationID, ok := parseIAMPathUUID(writer, request, "organization_id", "ORGANIZATION_ID_INVALID", ErrOrganizationMembershipInvalid)
		if !ok {
			return
		}
		userID, ok := parseIAMPathUUID(writer, request, "user_id", "USER_ID_INVALID", ErrOrganizationMembershipInvalid)
		if !ok {
			return
		}
		var body input
		if err := decodeIAMJSON(request, &body); err != nil {
			writeIAMProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", err)
			return
		}
		if _, valid := canonicalOrganizationMembershipReason(body.Reason); !valid {
			writeIAMApplicationError(writer, request, ErrOrganizationMembershipInvalid)
			return
		}
		err := application.DeleteOrganizationMembership(request.Context(), principal, organizationID, userID, DeleteOrganizationMembershipCommand{
			OrganizationVersion: body.OrganizationVersion, UserVersion: body.UserVersion, MembershipVersion: body.MembershipVersion, Reason: body.Reason,
		}, body.Reauthentication.proof(), iamRequestContext(request))
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}
}

func parseIAMPathUUID(writer http.ResponseWriter, request *http.Request, parameter, code string, cause error) (uuid.UUID, bool) {
	id, err := uuid.Parse(chi.URLParam(request, parameter))
	if err != nil || id == uuid.Nil {
		writeIAMProblem(writer, request, http.StatusBadRequest, code, "Identity identifier is invalid", cause)
		return uuid.Nil, false
	}
	return id, true
}

func parseOrganizationMembershipPage(request *http.Request) (Page, error) {
	page := Page{}
	if rawLimit := strings.TrimSpace(request.URL.Query().Get("limit")); rawLimit != "" {
		limit, err := strconv.Atoi(rawLimit)
		if err != nil || limit < 1 || limit > 200 {
			return Page{}, ErrPageInvalid
		}
		page.Limit = limit
	}
	if cursor := strings.TrimSpace(request.URL.Query().Get("cursor")); cursor != "" {
		createdAt, userID, sourceOwned, err := decodeOrganizationMembershipCursor(cursor)
		if err != nil {
			return Page{}, err
		}
		page.BeforeTime, page.BeforeID, page.BeforeSourceOwned = createdAt, userID, &sourceOwned
	}
	return page, nil
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

func createRoleBindingHandler(application IAMApplication) http.HandlerFunc {
	type input struct {
		SubjectType      SubjectType                `json:"subject_type"`
		SubjectID        uuid.UUID                  `json:"subject_id"`
		SubjectVersion   int64                      `json:"subject_version"`
		Role             identity.Role              `json:"role"`
		ScopeType        ScopeType                  `json:"scope_type"`
		ProductID        string                     `json:"product_id"`
		ChannelName      string                     `json:"channel_name"`
		Effect           BindingEffect              `json:"effect"`
		ValidFrom        time.Time                  `json:"valid_from"`
		ValidUntil       time.Time                  `json:"valid_until"`
		Reauthentication reauthenticationProofInput `json:"reauth"`
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
		binding, err := application.CreateRoleBinding(request.Context(), principal, CreateRoleBindingCommand{
			SubjectType: body.SubjectType, SubjectID: body.SubjectID, SubjectVersion: body.SubjectVersion, Role: body.Role,
			ScopeType: body.ScopeType, ProductID: body.ProductID, ChannelName: body.ChannelName, Effect: body.Effect,
			ValidFrom: body.ValidFrom, ValidUntil: body.ValidUntil,
		}, body.Reauthentication.proof(), iamRequestContext(request))
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writer.Header().Set("Location", "/api/v1/role-bindings/"+binding.ID.String())
		writeIAMJSON(writer, http.StatusCreated, toRoleBindingResponse(binding))
	}
}

func deleteRoleBindingHandler(application IAMApplication) http.HandlerFunc {
	type input struct {
		Version          int64                      `json:"version"`
		Reauthentication reauthenticationProofInput `json:"reauth"`
	}
	return func(writer http.ResponseWriter, request *http.Request) {
		principal, ok := requireIAMPrincipal(writer, request)
		if !ok {
			return
		}
		bindingID, err := uuid.Parse(chi.URLParam(request, "binding_id"))
		if err != nil || bindingID == uuid.Nil {
			writeIAMProblem(writer, request, http.StatusBadRequest, "ROLE_BINDING_ID_INVALID", "Role binding ID is invalid", ErrRoleBindingInvalid)
			return
		}
		var body input
		if err := decodeIAMJSON(request, &body); err != nil {
			writeIAMProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", err)
			return
		}
		if err := application.DeleteRoleBinding(request.Context(), principal, bindingID, body.Version, body.Reauthentication.proof(), iamRequestContext(request)); err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}
}

func userLifecycleHandler(application IAMApplication, action string) http.HandlerFunc {
	type input struct {
		Version          int64                      `json:"version"`
		Reason           string                     `json:"reason"`
		Reauthentication reauthenticationProofInput `json:"reauth"`
	}
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
		var body input
		if err := decodeIAMJSON(request, &body); err != nil {
			writeIAMProblem(writer, request, http.StatusBadRequest, "REQUEST_BODY_INVALID", "Request body is invalid", err)
			return
		}
		proof, requestContext := body.Reauthentication.proof(), iamRequestContext(request)
		switch action {
		case "disable":
			err = application.DisableUser(request.Context(), principal, userID, body.Version, body.Reason, proof, requestContext)
		case "enable":
			err = application.EnableUser(request.Context(), principal, userID, body.Version, body.Reason, proof, requestContext)
		case "revoke_sessions":
			err = application.RevokeUserSessions(request.Context(), principal, userID, body.Version, body.Reason, proof, requestContext)
		default:
			err = ErrIAMConfiguration
		}
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}
}

func identitySourceLifecycleHandler(application IAMApplication, enable bool) http.HandlerFunc {
	type input struct {
		Version          int64                      `json:"version"`
		Reauthentication reauthenticationProofInput `json:"reauth"`
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
		if enable {
			err = application.EnableSSO(request.Context(), principal, sourceID, body.Version, body.Reauthentication.proof(), iamRequestContext(request))
		} else {
			err = application.DisableSSO(request.Context(), principal, sourceID, body.Version, body.Reauthentication.proof(), iamRequestContext(request))
		}
		if err != nil {
			writeIAMApplicationError(writer, request, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
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
	return strictjson.Decode(request.Body, maximumIAMRequestBytes, target)
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
	case errors.Is(err, ErrUserInputInvalid), errors.Is(err, ErrPageInvalid), errors.Is(err, ErrRoleBindingInvalid), errors.Is(err, ErrIdentitySourceInputInvalid),
		errors.Is(err, ErrOrganizationMembershipInvalid), errors.Is(err, ErrDisableReasonRequired), errors.Is(err, ErrEnableReasonRequired), errors.Is(err, ErrRevokeReasonRequired):
		writeIAMProblem(writer, request, http.StatusBadRequest, "IAM_INPUT_INVALID", "Identity request is invalid", err)
	case errors.Is(err, identity.ErrActionDenied):
		writeIAMProblem(writer, request, http.StatusForbidden, "IAM_ACCESS_DENIED", "Identity access is denied", err)
	case errors.Is(err, ErrUserNotFound):
		writeIAMProblem(writer, request, http.StatusNotFound, "USER_NOT_FOUND", "User was not found", err)
	case errors.Is(err, ErrOrganizationNotFound):
		writeIAMProblem(writer, request, http.StatusNotFound, "ORGANIZATION_NOT_FOUND", "Organization was not found", err)
	case errors.Is(err, ErrOrganizationMembershipNotFound):
		writeIAMProblem(writer, request, http.StatusNotFound, "ORGANIZATION_MEMBERSHIP_NOT_FOUND", "Organization membership was not found", err)
	case errors.Is(err, ErrRoleBindingNotFound):
		writeIAMProblem(writer, request, http.StatusNotFound, "ROLE_BINDING_NOT_FOUND", "Role binding was not found", err)
	case errors.Is(err, ErrIdentitySourceNotFound) && iamProblemInstance(request.URL.Path) == "/api/v1/identity-sources/{source_id}/sync-conflicts/{conflict_id}/resolve":
		writeIAMProblem(writer, request, http.StatusNotFound, "DIRECTORY_SYNC_CONFLICT_NOT_FOUND", "Directory synchronization conflict was not found", ErrDirectoryConflictNotFound)
	case errors.Is(err, ErrIdentitySourceNotFound):
		writeIAMProblem(writer, request, http.StatusNotFound, "IDENTITY_SOURCE_NOT_FOUND", "Identity source was not found", err)
	case errors.Is(err, ErrDirectoryConflictNotFound):
		writeIAMProblem(writer, request, http.StatusNotFound, "DIRECTORY_SYNC_CONFLICT_NOT_FOUND", "Directory synchronization conflict was not found", err)
	case errors.Is(err, ErrIAMConflict):
		writeIAMProblem(writer, request, http.StatusConflict, "IAM_RECORD_CONFLICT", "Identity record conflicts with current state", err)
	case errors.Is(err, ErrDirectorySyncActive):
		writeIAMProblem(writer, request, http.StatusConflict, "DIRECTORY_SYNC_ACTIVE", "A directory synchronization is already active", err)
	case errors.Is(err, ErrDirectoryApplyUnsupported):
		writeIAMProblem(writer, request, http.StatusConflict, "DIRECTORY_APPLY_UNSUPPORTED", "Directory apply is not supported for this source", err)
	case errors.Is(err, ErrDirectorySyncNotFound):
		writeIAMProblem(writer, request, http.StatusNotFound, "DIRECTORY_SYNC_JOB_NOT_FOUND", "Directory synchronization job was not found", err)
	case errors.Is(err, ErrDirectoryConfigurationInvalid):
		writeIAMProblem(writer, request, http.StatusUnprocessableEntity, "IDENTITY_SOURCE_CONFIGURATION_INVALID", "Identity source configuration is invalid", err)
	case errors.Is(err, ErrDirectoryUpstreamRejected), errors.Is(err, ErrDirectoryResponseInvalid):
		writeIAMProblem(writer, request, http.StatusBadGateway, "IDENTITY_SOURCE_UPSTREAM_INVALID", "Identity source verification failed", err)
	case errors.Is(err, ErrSSOPreconditionFailed), errors.Is(err, ErrLoginModeTransitionInvalid), errors.Is(err, ErrLastEmergencyAdministrator),
		errors.Is(err, ErrUserAlreadyDisabled), errors.Is(err, ErrUserAlreadyEnabled), errors.Is(err, ErrUserCannotBeEnabled):
		writeIAMProblem(writer, request, http.StatusConflict, "IAM_STATE_PRECONDITION_FAILED", "Identity state precondition failed", err)
	case errors.Is(err, ErrHighRiskConfirmationRequired):
		writeIAMProblem(writer, request, http.StatusForbidden, "HIGH_RISK_CONFIRMATION_REQUIRED", "Fresh reauthentication and explicit confirmation are required", err)
	case errors.Is(err, ErrLocalAuthenticationLimited):
		writer.Header().Set("Retry-After", "300")
		writeIAMProblem(writer, request, http.StatusTooManyRequests, "AUTHENTICATION_RATE_LIMITED", "Authentication rate limit exceeded", err)
	case errors.Is(err, ErrLocalAuthenticationFailed):
		writeIAMProblem(writer, request, http.StatusUnauthorized, "AUTHENTICATION_FAILED", "Authentication failed", err)
	default:
		writeIAMProblem(writer, request, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error", err)
	}
}

func writeIAMProblem(writer http.ResponseWriter, request *http.Request, status int, code, title string, cause error) {
	httpx.WriteProblem(writer, httpx.NewProblem(status, code, title, cause).
		WithRequestID(httpx.RequestIDFromContext(request.Context())).WithInstance(iamProblemInstance(request.URL.Path)))
}

func iamProblemInstance(path string) string {
	const challengePrefix = "/api/v1/auth/reauth-challenges/"
	if strings.HasPrefix(path, challengePrefix) {
		return challengePrefix + "{challenge_id}/complete"
	}
	const sourcePrefix = "/api/v1/identity-sources/"
	if strings.HasPrefix(path, sourcePrefix) {
		segments := strings.Split(strings.TrimPrefix(path, sourcePrefix), "/")
		if len(segments) > 0 && segments[0] != "" {
			segments[0] = "{source_id}"
		}
		if len(segments) >= 3 && segments[1] == "sync-jobs" && segments[2] != "" {
			segments[2] = "{job_id}"
		}
		if len(segments) >= 4 && segments[1] == "sync-conflicts" && segments[2] != "" && segments[3] == "resolve" {
			segments[2] = "{conflict_id}"
		}
		return sourcePrefix + strings.Join(segments, "/")
	}
	const organizationPrefix = "/api/v1/organizations/"
	if strings.HasPrefix(path, organizationPrefix) {
		segments := strings.Split(strings.TrimPrefix(path, organizationPrefix), "/")
		if len(segments) > 0 && segments[0] != "" {
			segments[0] = "{organization_id}"
		}
		if len(segments) >= 3 && segments[1] == "memberships" && segments[2] != "" {
			segments[2] = "{user_id}"
		}
		return organizationPrefix + strings.Join(segments, "/")
	}
	return path
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

type organizationMembershipResponse struct {
	OrganizationID uuid.UUID                    `json:"organization_id"`
	UserID         uuid.UUID                    `json:"user_id"`
	SourceOwned    bool                         `json:"source_owned"`
	Status         OrganizationMembershipStatus `json:"status"`
	Version        int64                        `json:"version"`
	CreatedAt      time.Time                    `json:"created_at"`
	UpdatedAt      time.Time                    `json:"updated_at"`
}

type organizationMembershipPageResponse struct {
	Items      []organizationMembershipResponse `json:"items"`
	NextCursor string                           `json:"next_cursor,omitempty"`
}

func toOrganizationMembershipResponse(membership OrganizationMembership) organizationMembershipResponse {
	return organizationMembershipResponse{
		OrganizationID: membership.OrganizationID, UserID: membership.UserID, SourceOwned: membership.SourceOwned,
		Status: membership.Status, Version: membership.Version, CreatedAt: membership.CreatedAt, UpdatedAt: membership.UpdatedAt,
	}
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

type directorySyncJobResponse struct {
	ID                     uuid.UUID           `json:"id"`
	IdentitySourceID       uuid.UUID           `json:"identity_source_id"`
	SourceVersion          int64               `json:"source_version"`
	Mode                   DirectorySyncMode   `json:"mode"`
	Status                 DirectorySyncStatus `json:"status"`
	CreateCount            int                 `json:"create_count"`
	UpdateCount            int                 `json:"update_count"`
	DisableCount           int                 `json:"disable_count"`
	ConflictCount          int                 `json:"conflict_count"`
	ProcessedUsers         int                 `json:"processed_users"`
	ProcessedOrganizations int                 `json:"processed_organizations"`
	ProcessedMemberships   int                 `json:"processed_memberships"`
	ErrorCode              string              `json:"error_code,omitempty"`
	RequestedBy            string              `json:"requested_by"`
	RequestID              uuid.UUID           `json:"request_id"`
	CreatedAt              time.Time           `json:"created_at"`
	UpdatedAt              time.Time           `json:"updated_at"`
	CompletedAt            *time.Time          `json:"completed_at,omitempty"`
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

func toDirectorySyncJobResponse(job DirectorySyncJob) directorySyncJobResponse {
	result := directorySyncJobResponse{
		ID:                     job.ID,
		IdentitySourceID:       job.IdentitySourceID,
		SourceVersion:          job.SourceVersion,
		Mode:                   job.Mode,
		Status:                 job.Status,
		CreateCount:            job.CreateCount,
		UpdateCount:            job.UpdateCount,
		DisableCount:           job.DisableCount,
		ConflictCount:          job.ConflictCount,
		ProcessedUsers:         job.ProcessedUsers,
		ProcessedOrganizations: job.ProcessedOrganizations,
		ProcessedMemberships:   job.ProcessedMemberships,
		ErrorCode:              job.ErrorCode,
		RequestedBy:            job.RequestedBy,
		RequestID:              job.RequestID,
		CreatedAt:              job.CreatedAt,
		UpdatedAt:              job.UpdatedAt,
	}
	if !job.CompletedAt.IsZero() {
		value := job.CompletedAt
		result.CompletedAt = &value
	}
	return result
}

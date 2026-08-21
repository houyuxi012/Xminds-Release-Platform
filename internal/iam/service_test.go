package iam

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
)

func TestEnableSSORequiresVerifiedSourceMappingPreviewAndEmergencyAccount(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	harness.repository.sources[harness.sourceID] = IdentitySource{
		ID: harness.sourceID, Kind: IdentitySourceOIDC, Status: IdentitySourceStatusDraft,
		RequiredMappingsComplete: false, Version: 1,
	}

	err := harness.service.EnableSSO(context.Background(), harness.admin, harness.sourceID, 1, harness.proof(), harness.request)

	if !errors.Is(err, ErrSSOPreconditionFailed) {
		t.Fatalf("EnableSSO() error = %v", err)
	}
	if harness.repository.login.Mode != LoginModeLocal {
		t.Fatalf("login mode = %q", harness.repository.login.Mode)
	}
	if len(harness.highRisk.operations) != 1 || harness.highRisk.operations[0] != string(ReauthenticationOperationSSOEnable) {
		t.Fatalf("business precondition did not consume proof: %+v", harness.highRisk.operations)
	}
}

func TestEnableSSORejectsSCIMSourceBeforeConsumingProof(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	source := harness.repository.sources[harness.sourceID]
	source.Kind = IdentitySourceSCIM
	harness.repository.sources[harness.sourceID] = source

	err := harness.service.EnableSSO(context.Background(), harness.admin, harness.sourceID, 1, harness.proof(), harness.request)

	if !errors.Is(err, ErrSSOPreconditionFailed) {
		t.Fatalf("EnableSSO(SCIM) error = %v, want %v", err, ErrSSOPreconditionFailed)
	}
	if len(harness.highRisk.operations) != 0 {
		t.Fatalf("SCIM static type rejection consumed proof: %+v", harness.highRisk.operations)
	}
	if harness.repository.login.Mode != LoginModeLocal || harness.repository.sources[harness.sourceID].Status != IdentitySourceStatusVerified {
		t.Fatalf("SCIM rejection changed state: login=%+v source=%+v", harness.repository.login, harness.repository.sources[harness.sourceID])
	}
}

func TestFaultDoesNotEnableRegularLocalLogin(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	if err := harness.service.EnableSSO(context.Background(), harness.admin, harness.sourceID, 1, harness.proof(), harness.request); err != nil {
		t.Fatalf("EnableSSO() error = %v", err)
	}
	if err := harness.service.MarkIdentitySourceFault(context.Background(), harness.system, harness.sourceID, "OIDC_UNREACHABLE", harness.request); err != nil {
		t.Fatalf("MarkIdentitySourceFault() error = %v", err)
	}

	_, err := harness.service.AuthenticateLocal(context.Background(), "member", "correct horse battery staple")

	if !errors.Is(err, ErrLocalLoginDisabled) {
		t.Fatalf("AuthenticateLocal() error = %v", err)
	}
	if harness.repository.login.Mode != LoginModeFault {
		t.Fatalf("login mode = %q", harness.repository.login.Mode)
	}
	if harness.sessions.regularRevocations != 2 {
		t.Fatalf("regular local session revocations = %d", harness.sessions.regularRevocations)
	}
}

func TestCannotDisableLastUsableEmergencyAdministrator(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)

	err := harness.service.DisableUser(context.Background(), harness.admin, harness.emergencyAdminID, 1, "rotation", harness.proof(), harness.request)

	if !errors.Is(err, ErrLastEmergencyAdministrator) {
		t.Fatalf("DisableUser() error = %v", err)
	}
	if harness.repository.users[harness.emergencyAdminID].Status != UserStatusActive {
		t.Fatal("last emergency administrator was disabled")
	}
}

func TestEnableSSORejectsEmergencyAccountWithoutCredentialAndEffectiveAdministratorBinding(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	delete(harness.repository.credentials, harness.emergencyAdminID)
	harness.repository.roleBindings = make(map[uuid.UUID]RoleBinding)

	err := harness.service.EnableSSO(context.Background(), harness.admin, harness.sourceID, 1, harness.proof(), harness.request)

	if !errors.Is(err, ErrSSOPreconditionFailed) {
		t.Fatalf("EnableSSO() error = %v", err)
	}
	if harness.repository.login.Mode != LoginModeLocal {
		t.Fatalf("login mode = %q", harness.repository.login.Mode)
	}
}

func TestDisableSSORequiresFreshConfirmationAndReturnsToLocalMode(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	if err := harness.service.EnableSSO(context.Background(), harness.admin, harness.sourceID, 1, harness.proof(), harness.request); err != nil {
		t.Fatal(err)
	}
	if err := harness.service.DisableSSO(context.Background(), harness.admin, harness.sourceID, 2, HighRiskProof{Confirmed: true, ChallengeID: "wrong", Evidence: "bad"}, harness.request); !errors.Is(err, ErrHighRiskConfirmationRequired) {
		t.Fatalf("DisableSSO(unverified proof) error = %v", err)
	}
	if harness.repository.login.Mode != LoginModeSSO {
		t.Fatalf("login mode after rejected disable = %q", harness.repository.login.Mode)
	}

	if err := harness.service.DisableSSO(context.Background(), harness.admin, harness.sourceID, 2, harness.proof(), harness.request); err != nil {
		t.Fatalf("DisableSSO() error = %v", err)
	}
	if harness.repository.login.Mode != LoginModeLocal || harness.repository.login.ActiveSourceID != uuid.Nil || harness.repository.login.FaultCode != "" {
		t.Fatalf("login state = %+v", harness.repository.login)
	}
	if harness.repository.sources[harness.sourceID].Status != IdentitySourceStatusDisabled {
		t.Fatalf("identity source = %+v", harness.repository.sources[harness.sourceID])
	}
}

func TestCreateLocalUserStoresOnlyActivationDigestAndAuditsProvisioning(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	provisioning, err := harness.service.CreateLocalUser(context.Background(), harness.admin, CreateLocalUserCommand{
		Username: "release.operator", DisplayName: "Release Operator", Email: "operator@example.com",
	}, harness.request)
	if err != nil {
		t.Fatalf("CreateLocalUser() error = %v", err)
	}
	if provisioning.ActivationToken == "" || provisioning.User.Status != UserStatusPending || provisioning.User.Username != "release.operator" {
		t.Fatalf("provisioning = %+v", provisioning)
	}
	if provisioning.User.ID.Version() != 7 {
		t.Fatalf("local user ID version = %d, want UUIDv7", provisioning.User.ID.Version())
	}
	credential := harness.repository.credentials[provisioning.User.ID]
	wantDigest := sha256.Sum256([]byte(provisioning.ActivationToken))
	if credential.ActivationDigest != hex.EncodeToString(wantDigest[:]) {
		t.Fatalf("activation digest = %q", credential.ActivationDigest)
	}
	if credential.ActivationDigest == provisioning.ActivationToken {
		t.Fatal("activation token was stored in plaintext")
	}
	if credential.Password.Algorithm != "" || len(credential.Password.Salt) != 0 || len(credential.Password.DerivedKey) != 0 || !credential.PasswordChangedAt.IsZero() {
		t.Fatalf("pending credential contains a login password: %+v", credential)
	}
	if len(harness.auditor.commands) != 1 || harness.auditor.commands[0].Action != "identity.local_user.create" {
		t.Fatalf("audit commands = %+v", harness.auditor.commands)
	}
	if _, leaked := harness.auditor.commands[0].Metadata["activation_token"]; leaked {
		t.Fatal("activation token leaked into audit metadata")
	}
}

func TestCreateLocalUserRejectsInvalidIdentityFields(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	for name, command := range map[string]CreateLocalUserCommand{
		"username": {Username: "../admin", DisplayName: "Admin"},
		"display":  {Username: "valid.user", DisplayName: ""},
		"email":    {Username: "valid.user", DisplayName: "Valid User", Email: "not-an-email"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := harness.service.CreateLocalUser(context.Background(), harness.admin, command, harness.request); !errors.Is(err, ErrUserInputInvalid) {
				t.Fatalf("CreateLocalUser() error = %v", err)
			}
		})
	}
}

func TestCreateLocalUserUsesUnicodeCharacterLimits(t *testing.T) {
	t.Parallel()

	validEmail := strings.Repeat("é", 308) + "@example.com"
	validDisplayName := strings.Repeat("界", 256)
	validUsername := strings.Repeat("a", 128)
	harness := newIAMHarness(t)
	provisioning, err := harness.service.CreateLocalUser(context.Background(), harness.admin, CreateLocalUserCommand{
		Username: validUsername, DisplayName: validDisplayName, Email: validEmail,
	}, harness.request)
	if err != nil {
		t.Fatalf("CreateLocalUser() error = %v", err)
	}
	if provisioning.User.Username != validUsername || provisioning.User.DisplayName != validDisplayName || provisioning.User.Email != validEmail {
		t.Fatalf("provisioning user = %+v", provisioning.User)
	}

	for _, testCase := range []struct {
		name    string
		command CreateLocalUserCommand
	}{
		{name: "username 129 characters", command: CreateLocalUserCommand{Username: strings.Repeat("a", 129), DisplayName: "Release Operator", Email: "operator@example.com"}},
		{name: "display 257 characters", command: CreateLocalUserCommand{Username: "release.operator", DisplayName: strings.Repeat("界", 257), Email: "operator@example.com"}},
		{name: "email 321 characters", command: CreateLocalUserCommand{Username: "release.operator", DisplayName: "Release Operator", Email: strings.Repeat("é", 309) + "@example.com"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			invalid := newIAMHarness(t)
			if _, err := invalid.service.CreateLocalUser(context.Background(), invalid.admin, testCase.command, invalid.request); !errors.Is(err, ErrUserInputInvalid) {
				t.Fatalf("CreateLocalUser() error = %v, want ErrUserInputInvalid", err)
			}
			if invalid.repository.withinTransactionCalls != 0 {
				t.Fatalf("over-limit input reached repository transaction %d times", invalid.repository.withinTransactionCalls)
			}
		})
	}
}

func TestCreateLocalUserAcceptsCanonicalUsernamesThrough128Characters(t *testing.T) {
	t.Parallel()

	for _, username := range []string{strings.Repeat("a", 65), strings.Repeat("a", 128)} {
		t.Run(strconv.Itoa(len(username)), func(t *testing.T) {
			harness := newIAMHarness(t)
			provisioning, err := harness.service.CreateLocalUser(context.Background(), harness.admin, CreateLocalUserCommand{
				Username: username, DisplayName: "Release Operator", Email: "operator@example.com",
			}, harness.request)
			if err != nil {
				t.Fatalf("CreateLocalUser() error = %v", err)
			}
			if provisioning.User.Username != username {
				t.Fatalf("username = %q, want %q", provisioning.User.Username, username)
			}
		})
	}
}

func TestCreateOrganizationPersistsLocalUnitAndAuditsInOneTransaction(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	organization, err := harness.service.CreateOrganization(context.Background(), harness.admin, CreateOrganizationCommand{
		Name: "Release Engineering",
	}, harness.request)

	if err != nil {
		t.Fatalf("CreateOrganization() error = %v", err)
	}
	if organization.ID == uuid.Nil || organization.SourceOwned || organization.Status != OrganizationStatusActive || organization.Version != 1 {
		t.Fatalf("organization = %+v", organization)
	}
	if got := harness.repository.organizations[organization.ID]; got.Name != "Release Engineering" {
		t.Fatalf("stored organization = %+v", got)
	}
	if len(harness.auditor.commands) != 1 || harness.auditor.commands[0].Action != "identity.organization.create" {
		t.Fatalf("audit commands = %+v", harness.auditor.commands)
	}
}

func TestRoleBindingCreateAndDeleteAreAuditedAndOptimistic(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	binding, err := harness.service.CreateRoleBinding(context.Background(), harness.admin, CreateRoleBindingCommand{
		SubjectType:    SubjectTypeUser,
		SubjectID:      harness.emergencyAdminID,
		SubjectVersion: 1,
		Role:           identity.RoleAdmin,
		ScopeType:      ScopeTypePlatform,
		Effect:         BindingEffectAllow,
	}, harness.proof(), harness.request)
	if err != nil {
		t.Fatalf("CreateRoleBinding() error = %v", err)
	}
	if binding.ID == uuid.Nil || binding.Version != 1 {
		t.Fatalf("binding = %+v", binding)
	}
	if err := harness.service.DeleteRoleBinding(context.Background(), harness.admin, binding.ID, binding.Version, harness.proof(), harness.request); err != nil {
		t.Fatalf("DeleteRoleBinding() error = %v", err)
	}
	if _, exists := harness.repository.roleBindings[binding.ID]; exists {
		t.Fatal("role binding was not deleted")
	}
	if len(harness.auditor.commands) != 2 || harness.auditor.commands[1].Action != "identity.role_binding.delete" {
		t.Fatalf("audit commands = %+v", harness.auditor.commands)
	}
	if len(harness.sessions.subjects) != 2 || harness.sessions.subjects[0] != harness.emergencyAdminID || harness.sessions.subjects[1] != harness.emergencyAdminID {
		t.Fatalf("revoked session subjects = %+v", harness.sessions.subjects)
	}
}

func TestCreateRoleBindingRejectsUnknownOrOversizedCatalogScopeBeforeProofConsumption(t *testing.T) {
	t.Parallel()

	for name, scope := range map[string]struct {
		scopeType   ScopeType
		productID   string
		channelName string
	}{
		"unknown product":   {scopeType: ScopeTypeProduct, productID: "missing-product"},
		"unknown channel":   {scopeType: ScopeTypeChannel, productID: "ngep", channelName: "missing-channel"},
		"oversized product": {scopeType: ScopeTypeProduct, productID: strings.Repeat("p", 129)},
		"oversized channel": {scopeType: ScopeTypeChannel, productID: "ngep", channelName: strings.Repeat("c", 65)},
	} {
		t.Run(name, func(t *testing.T) {
			harness := newIAMHarness(t)
			initialBindingCount := len(harness.repository.roleBindings)
			_, err := harness.service.CreateRoleBinding(context.Background(), harness.admin, CreateRoleBindingCommand{
				SubjectType: SubjectTypeUser, SubjectID: harness.emergencyAdminID, SubjectVersion: 1,
				Role: identity.RoleViewer, ScopeType: scope.scopeType, ProductID: scope.productID,
				ChannelName: scope.channelName, Effect: BindingEffectAllow,
			}, harness.proof(), harness.request)
			if !errors.Is(err, ErrRoleBindingInvalid) {
				t.Fatalf("CreateRoleBinding() error = %v", err)
			}
			if len(harness.highRisk.operations) != 0 {
				t.Fatalf("invalid catalog scope consumed proof: %+v", harness.highRisk.operations)
			}
			if len(harness.repository.roleBindings) != initialBindingCount {
				t.Fatalf("invalid catalog scope persisted binding: %+v", harness.repository.roleBindings)
			}
		})
	}
}

func TestDeleteLastEffectiveEmergencyAdministratorBindingRollsBack(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	bindingID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e14")
	harness.repository.roleBindings = map[uuid.UUID]RoleBinding{bindingID: {
		ID: bindingID, SubjectType: SubjectTypeUser, SubjectID: harness.emergencyAdminID,
		Role: identity.RoleAdmin, ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow,
		ValidFrom: harness.now.Add(-time.Hour), Version: 1,
	}}

	err := harness.service.DeleteRoleBinding(context.Background(), harness.admin, bindingID, 1, harness.proof(), harness.request)

	if !errors.Is(err, ErrLastEmergencyAdministrator) {
		t.Fatalf("DeleteRoleBinding() error = %v", err)
	}
	if _, exists := harness.repository.roleBindings[bindingID]; !exists {
		t.Fatal("last emergency administrator binding was deleted")
	}
	if len(harness.highRisk.operations) != 1 {
		t.Fatalf("business invariant did not consume proof: %+v", harness.highRisk.operations)
	}
}

func TestCreateFutureDenyCannotScheduleBreakGlassGap(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	initialBindings := len(harness.repository.roleBindings)
	_, err := harness.service.CreateRoleBinding(context.Background(), harness.admin, CreateRoleBindingCommand{
		SubjectType: SubjectTypeUser, SubjectID: harness.emergencyAdminID, SubjectVersion: 1,
		Role: identity.RoleAdmin, ScopeType: ScopeTypePlatform, Effect: BindingEffectDeny,
		ValidFrom: harness.now.Add(time.Hour),
	}, harness.proof(), harness.request)

	if !errors.Is(err, ErrLastEmergencyAdministrator) {
		t.Fatalf("CreateRoleBinding(future deny) error = %v", err)
	}
	if len(harness.repository.roleBindings) != initialBindings {
		t.Fatalf("scheduled break-glass gap committed: %+v", harness.repository.roleBindings)
	}
	if len(harness.highRisk.operations) != 1 || harness.highRisk.operations[0] != string(ReauthenticationOperationRoleBindingCreate) {
		t.Fatalf("scheduled invariant did not consume proof: %+v", harness.highRisk.operations)
	}
}

func TestDeletePermanentAllowCannotLeaveOnlyExpiringBreakGlassAccess(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	var permanentBindingID uuid.UUID
	for id := range harness.repository.roleBindings {
		permanentBindingID = id
	}
	expiringBindingID := uuid.New()
	harness.repository.roleBindings[expiringBindingID] = RoleBinding{
		ID: expiringBindingID, SubjectType: SubjectTypeUser, SubjectID: harness.emergencyAdminID,
		Role: identity.RoleAdmin, ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow,
		ValidFrom: harness.now.Add(-time.Hour), ValidUntil: harness.now.Add(time.Hour), Version: 1,
	}

	err := harness.service.DeleteRoleBinding(context.Background(), harness.admin, permanentBindingID, 1, harness.proof(), harness.request)

	if !errors.Is(err, ErrLastEmergencyAdministrator) {
		t.Fatalf("DeleteRoleBinding(permanent allow) error = %v", err)
	}
	if _, exists := harness.repository.roleBindings[permanentBindingID]; !exists {
		t.Fatal("permanent break-glass allow was deleted")
	}
	if len(harness.highRisk.operations) != 1 || harness.highRisk.operations[0] != string(ReauthenticationOperationRoleBindingDelete) {
		t.Fatalf("scheduled invariant did not consume proof: %+v", harness.highRisk.operations)
	}
}

func TestFutureDenyAllowsContinuousBackupEmergencyAdministrator(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	backupID := uuid.New()
	harness.repository.seedUsableEmergencyAdministrator(backupID, "future-deny-backup")

	binding, err := harness.service.CreateRoleBinding(context.Background(), harness.admin, CreateRoleBindingCommand{
		SubjectType: SubjectTypeUser, SubjectID: harness.emergencyAdminID, SubjectVersion: 1,
		Role: identity.RoleAdmin, ScopeType: ScopeTypePlatform, Effect: BindingEffectDeny,
		ValidFrom: harness.now.Add(365 * 24 * time.Hour),
	}, harness.proof(), harness.request)

	if err != nil {
		t.Fatalf("CreateRoleBinding(future deny with backup) error = %v", err)
	}
	if _, exists := harness.repository.roleBindings[binding.ID]; !exists {
		t.Fatal("safe future deny was not committed")
	}
}

func TestOrganizationAdministratorContinuityHonorsFutureDenyPrecedence(t *testing.T) {
	for _, test := range []struct {
		name       string
		allow      SubjectType
		futureDeny SubjectType
	}{
		{name: "organization allow direct deny", allow: SubjectTypeOrganization, futureDeny: SubjectTypeUser},
		{name: "direct allow organization deny", allow: SubjectTypeUser, futureDeny: SubjectTypeOrganization},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newIAMHarness(t)
			organizationID := uuid.New()
			allowBindingID := uuid.New()
			harness.repository.organizations[organizationID] = OrganizationUnit{
				ID: organizationID, Name: "Emergency Administrators", Status: OrganizationStatusActive, Version: 1,
			}
			harness.repository.memberships[harness.emergencyAdminID] = []uuid.UUID{organizationID}
			allowSubjectID := harness.emergencyAdminID
			if test.allow == SubjectTypeOrganization {
				allowSubjectID = organizationID
			}
			harness.repository.roleBindings = map[uuid.UUID]RoleBinding{allowBindingID: {
				ID: allowBindingID, SubjectType: test.allow, SubjectID: allowSubjectID,
				Role: identity.RoleAdmin, ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow,
				ValidFrom: harness.now.Add(-time.Hour), Version: 1,
			}}
			denySubjectID, denySubjectVersion := harness.emergencyAdminID, int64(1)
			if test.futureDeny == SubjectTypeOrganization {
				denySubjectID = organizationID
			}

			_, err := harness.service.CreateRoleBinding(context.Background(), harness.admin, CreateRoleBindingCommand{
				SubjectType: test.futureDeny, SubjectID: denySubjectID, SubjectVersion: denySubjectVersion,
				Role: identity.RoleAdmin, ScopeType: ScopeTypePlatform, Effect: BindingEffectDeny,
				ValidFrom: harness.now.Add(time.Hour),
			}, harness.proof(), harness.request)

			if !errors.Is(err, ErrLastEmergencyAdministrator) {
				t.Fatalf("CreateRoleBinding(future deny) error = %v", err)
			}
			if len(harness.highRisk.operations) != 1 {
				t.Fatalf("scheduled invariant did not consume proof: %+v", harness.highRisk.operations)
			}
		})
	}
}

func TestBreakGlassContinuityAllowsAdjacentBindingsAtSameTimestamp(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	boundary := harness.now.Add(time.Hour)
	for id, binding := range harness.repository.roleBindings {
		binding.ValidUntil = boundary
		harness.repository.roleBindings[id] = binding
	}
	successorID := uuid.New()
	harness.repository.roleBindings[successorID] = RoleBinding{
		ID: successorID, SubjectType: SubjectTypeUser, SubjectID: harness.emergencyAdminID,
		Role: identity.RoleAdmin, ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow,
		ValidFrom: boundary, Version: 1,
	}

	if err := harness.service.EnableSSO(context.Background(), harness.admin, harness.sourceID, 1, harness.proof(), harness.request); err != nil {
		t.Fatalf("EnableSSO(adjacent break-glass bindings) error = %v", err)
	}
}

func TestEnableSSOFailsClosedOnExistingScheduledBreakGlassGap(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	for id, binding := range harness.repository.roleBindings {
		binding.ValidUntil = harness.now.Add(time.Hour)
		harness.repository.roleBindings[id] = binding
	}

	err := harness.service.EnableSSO(context.Background(), harness.admin, harness.sourceID, 1, harness.proof(), harness.request)

	if !errors.Is(err, ErrSSOPreconditionFailed) {
		t.Fatalf("EnableSSO(scheduled break-glass gap) error = %v", err)
	}
	if harness.repository.login.Mode != LoginModeLocal {
		t.Fatalf("login mode = %s", harness.repository.login.Mode)
	}
	if len(harness.highRisk.operations) != 1 {
		t.Fatalf("scheduled invariant did not consume proof: %+v", harness.highRisk.operations)
	}
}

func TestDisableUserFailsClosedOnExistingScheduledBreakGlassGap(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	backupID := uuid.New()
	harness.repository.seedUsableEmergencyAdministrator(backupID, "expiring-backup")
	for id, binding := range harness.repository.roleBindings {
		if binding.SubjectID == backupID {
			binding.ValidUntil = harness.now.Add(time.Hour)
			harness.repository.roleBindings[id] = binding
		}
	}

	err := harness.service.DisableUser(context.Background(), harness.admin, harness.emergencyAdminID, 1, "scheduled continuity", harness.proof(), harness.request)

	if !errors.Is(err, ErrLastEmergencyAdministrator) {
		t.Fatalf("DisableUser(scheduled break-glass gap) error = %v", err)
	}
	if harness.repository.users[harness.emergencyAdminID].Status != UserStatusActive {
		t.Fatal("emergency administrator was disabled despite scheduled gap")
	}
	if len(harness.highRisk.operations) != 1 {
		t.Fatalf("scheduled invariant did not consume proof: %+v", harness.highRisk.operations)
	}
}

func TestHighRiskWritesFailClosedWithoutServerSideAuthority(t *testing.T) {
	t.Parallel()
	harness := newIAMHarness(t)
	harness.service.highRisk = nil
	_, err := harness.service.CreateRoleBinding(context.Background(), harness.admin, CreateRoleBindingCommand{
		SubjectType: SubjectTypeUser, SubjectID: harness.emergencyAdminID, SubjectVersion: 1, Role: identity.RoleAuditor, ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow,
	}, harness.proof(), harness.request)
	if !errors.Is(err, ErrIAMConfiguration) {
		t.Fatalf("CreateRoleBinding() error = %v", err)
	}
}

func TestEveryHighRiskWriteChecksPermissionBeforeResourceOrProof(t *testing.T) {
	unauthorized := identity.Principal{Subject: "viewer", Kind: identity.PrincipalKindHuman, TokenID: "viewer-token"}
	for name, invoke := range map[string]func(*iamHarness) error{
		"create role binding": func(harness *iamHarness) error {
			_, err := harness.service.CreateRoleBinding(context.Background(), unauthorized, CreateRoleBindingCommand{}, HighRiskProof{}, harness.request)
			return err
		},
		"delete role binding": func(harness *iamHarness) error {
			return harness.service.DeleteRoleBinding(context.Background(), unauthorized, uuid.Nil, 0, HighRiskProof{}, harness.request)
		},
		"disable user": func(harness *iamHarness) error {
			return harness.service.DisableUser(context.Background(), unauthorized, uuid.Nil, 0, "", HighRiskProof{}, harness.request)
		},
		"enable user": func(harness *iamHarness) error {
			return harness.service.EnableUser(context.Background(), unauthorized, uuid.Nil, 0, "", HighRiskProof{}, harness.request)
		},
		"revoke user sessions": func(harness *iamHarness) error {
			return harness.service.RevokeUserSessions(context.Background(), unauthorized, uuid.Nil, 0, "", HighRiskProof{}, harness.request)
		},
		"enable sso": func(harness *iamHarness) error {
			return harness.service.EnableSSO(context.Background(), unauthorized, uuid.Nil, 0, HighRiskProof{}, harness.request)
		},
		"disable sso": func(harness *iamHarness) error {
			return harness.service.DisableSSO(context.Background(), unauthorized, uuid.Nil, 0, HighRiskProof{}, harness.request)
		},
	} {
		t.Run(name, func(t *testing.T) {
			harness := newIAMHarness(t)
			if err := invoke(harness); !errors.Is(err, identity.ErrActionDenied) {
				t.Fatalf("unauthorized write error = %v", err)
			}
			if len(harness.highRisk.operations) != 0 {
				t.Fatalf("unauthorized write consumed proof: %+v", harness.highRisk.operations)
			}
		})
	}
}

func TestUserDisableAndRoleRemovalRollBackWhenSessionRevocationFails(t *testing.T) {
	revocationFailure := errors.New("session store unavailable")
	t.Run("disable user", func(t *testing.T) {
		harness := newIAMHarness(t)
		backupID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e15")
		harness.repository.seedUsableEmergencyAdministrator(backupID, "backup-break-glass")
		harness.sessions.err = revocationFailure
		err := harness.service.DisableUser(context.Background(), harness.admin, harness.emergencyAdminID, 1, "security response", harness.proof(), harness.request)
		if !errors.Is(err, revocationFailure) {
			t.Fatalf("DisableUser() error = %v", err)
		}
		if harness.repository.users[harness.emergencyAdminID].Status != UserStatusActive {
			t.Fatalf("revocation failure committed disabled user: %+v", harness.repository.users[harness.emergencyAdminID])
		}
	})
	t.Run("delete role binding", func(t *testing.T) {
		harness := newIAMHarness(t)
		binding, err := harness.service.CreateRoleBinding(context.Background(), harness.admin, CreateRoleBindingCommand{
			SubjectType: SubjectTypeUser, SubjectID: harness.emergencyAdminID, SubjectVersion: 1, Role: identity.RoleAdmin,
			ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow,
		}, harness.proof(), harness.request)
		if err != nil {
			t.Fatal(err)
		}
		harness.sessions.err = revocationFailure
		err = harness.service.DeleteRoleBinding(context.Background(), harness.admin, binding.ID, binding.Version, harness.proof(), harness.request)
		if !errors.Is(err, revocationFailure) {
			t.Fatalf("DeleteRoleBinding() error = %v", err)
		}
		if _, exists := harness.repository.roleBindings[binding.ID]; !exists {
			t.Fatal("revocation failure committed role-binding deletion")
		}
	})
}

func TestSessionRevocationDependentWritesFailClosedWithoutRevoker(t *testing.T) {
	harness := newIAMHarness(t)
	harness.service.sessions = nil
	localUserID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e18")
	harness.repository.users[localUserID] = UserPrincipal{ID: localUserID, Username: "local.user", Kind: UserKindLocal, Status: UserStatusActive, Version: 1}
	if err := harness.service.DisableUser(context.Background(), harness.admin, localUserID, 1, "security response", harness.proof(), harness.request); !errors.Is(err, ErrIAMConfiguration) {
		t.Fatalf("DisableUser() error = %v", err)
	}
	bindingID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e19")
	harness.repository.roleBindings[bindingID] = RoleBinding{
		ID: bindingID, SubjectType: SubjectTypeUser, SubjectID: localUserID, Role: identity.RoleViewer,
		ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow, Version: 1,
	}
	if err := harness.service.DeleteRoleBinding(context.Background(), harness.admin, bindingID, 1, harness.proof(), harness.request); !errors.Is(err, ErrIAMConfiguration) {
		t.Fatalf("DeleteRoleBinding() error = %v", err)
	}
}

func TestOrganizationRoleRemovalRevokesCurrentMemberSessions(t *testing.T) {
	harness := newIAMHarness(t)
	organization, err := harness.service.CreateOrganization(context.Background(), harness.admin, CreateOrganizationCommand{Name: "Release Administrators"}, harness.request)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := harness.service.CreateRoleBinding(context.Background(), harness.admin, CreateRoleBindingCommand{
		SubjectType: SubjectTypeOrganization, SubjectID: organization.ID, SubjectVersion: organization.Version, Role: identity.RoleAdmin,
		ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow,
	}, harness.proof(), harness.request)
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.service.DeleteRoleBinding(context.Background(), harness.admin, binding.ID, binding.Version, harness.proof(), harness.request); err != nil {
		t.Fatalf("DeleteRoleBinding() error = %v", err)
	}
	if len(harness.sessions.organizations) != 2 || harness.sessions.organizations[0] != organization.ID || harness.sessions.organizations[1] != organization.ID {
		t.Fatalf("revoked organizations = %+v", harness.sessions.organizations)
	}
}

func TestDirectLocalAdministratorGrantRequiresMFAEnrollment(t *testing.T) {
	harness := newIAMHarness(t)
	initialBindingCount := len(harness.repository.roleBindings)
	localID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e16")
	harness.repository.users[localID] = UserPrincipal{
		ID: localID, Username: "local.operator", Kind: UserKindLocal, Status: UserStatusActive, MFAEnrolled: false, Version: 1,
	}
	_, err := harness.service.CreateRoleBinding(context.Background(), harness.admin, CreateRoleBindingCommand{
		SubjectType: SubjectTypeUser, SubjectID: localID, SubjectVersion: 1, Role: identity.RoleAdmin,
		ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow,
	}, harness.proof(), harness.request)
	if !errors.Is(err, ErrRoleBindingInvalid) {
		t.Fatalf("CreateRoleBinding(local admin without MFA) error = %v", err)
	}
	if len(harness.repository.roleBindings) != initialBindingCount {
		t.Fatalf("unsafe administrator binding persisted: %+v", harness.repository.roleBindings)
	}
	if len(harness.highRisk.operations) != 1 || harness.highRisk.operations[0] != string(ReauthenticationOperationRoleBindingCreate) {
		t.Fatalf("administrator safety validation did not consume proof: %+v", harness.highRisk.operations)
	}
}

func TestAdministratorElevationRevokesExistingSubjectSessions(t *testing.T) {
	harness := newIAMHarness(t)
	localID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e17")
	harness.repository.users[localID] = UserPrincipal{
		ID: localID, Username: "local.mfa.operator", Kind: UserKindLocal, Status: UserStatusActive, MFAEnrolled: true, Version: 1,
	}
	if _, err := harness.service.CreateRoleBinding(context.Background(), harness.admin, CreateRoleBindingCommand{
		SubjectType: SubjectTypeUser, SubjectID: localID, SubjectVersion: 1, Role: identity.RoleAdmin,
		ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow,
	}, harness.proof(), harness.request); err != nil {
		t.Fatalf("CreateRoleBinding() error = %v", err)
	}
	if len(harness.sessions.subjects) != 1 || harness.sessions.subjects[0] != localID {
		t.Fatalf("elevated subject session revocations = %+v", harness.sessions.subjects)
	}
}

func TestIdentitySourceDraftVerifyAndPreviewDoNotExposeSecretReference(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	source, err := harness.service.CreateIdentitySource(context.Background(), harness.admin, CreateIdentitySourceCommand{
		Name: "Corporate SCIM", Kind: IdentitySourceSCIM, SecretReference: "secret://iam/corporate-scim",
	}, harness.request)
	if err != nil {
		t.Fatalf("CreateIdentitySource() error = %v", err)
	}
	if source.SecretReference != "" || source.Status != IdentitySourceStatusDraft || source.ID == uuid.Nil {
		t.Fatalf("source = %+v", source)
	}
	if harness.repository.sources[source.ID].SecretReference != "secret://iam/corporate-scim" {
		t.Fatal("identity source secret reference was not persisted internally")
	}
	if _, err := harness.service.VerifyIdentitySource(context.Background(), harness.admin, source.ID, harness.request); err != nil {
		t.Fatalf("VerifyIdentitySource() error = %v", err)
	}
	if _, err := harness.service.PreviewIdentitySource(context.Background(), harness.admin, source.ID, harness.request); err != nil {
		t.Fatalf("PreviewIdentitySource() error = %v", err)
	}
	stored := harness.repository.sources[source.ID]
	if stored.Status != IdentitySourceStatusVerified || stored.VerifiedAt.IsZero() || stored.PreviewedAt.IsZero() {
		t.Fatalf("stored source = %+v", stored)
	}
	if len(harness.auditor.commands) != 3 || harness.auditor.commands[0].Metadata["secret_reference"] != nil {
		t.Fatalf("audit commands = %+v", harness.auditor.commands)
	}
}

func TestHighRiskWritesValidateVersionBeforeProofAndConsumeBeforeBusinessTransaction(t *testing.T) {
	harness := newIAMHarness(t)
	userID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e30")
	harness.repository.users[userID] = UserPrincipal{
		ID: userID, Username: "release.operator", Kind: UserKindLocal, Status: UserStatusActive,
		Version: 3, CreatedAt: harness.now.Add(-time.Hour), UpdatedAt: harness.now.Add(-time.Hour),
	}
	harness.repository.credentials[userID] = LocalCredential{UserID: userID, Password: PasswordDigest{Algorithm: "argon2id", Parameters: "m=65536,t=3,p=2,l=32", Salt: make([]byte, 16), DerivedKey: make([]byte, 32)}, PasswordChangedAt: harness.now.Add(-time.Hour)}

	if err := harness.service.DisableUser(context.Background(), harness.admin, userID, 2, "security response", harness.proof(), harness.request); !errors.Is(err, ErrIAMConflict) {
		t.Fatalf("DisableUser(stale version) error = %v", err)
	}
	if len(harness.highRisk.operations) != 0 {
		t.Fatalf("stale request consumed proof: %+v", harness.highRisk.operations)
	}
	if err := harness.service.DisableUser(context.Background(), harness.admin, userID, 3, "security response", harness.proof(), harness.request); err != nil {
		t.Fatalf("DisableUser() error = %v", err)
	}
	if harness.repository.users[userID].Version != 4 || harness.repository.users[userID].Status != UserStatusDisabled || len(harness.highRisk.operations) != 1 {
		t.Fatalf("disabled user or proof calls = user:%+v calls:%+v", harness.repository.users[userID], harness.highRisk.operations)
	}

	if err := harness.service.EnableUser(context.Background(), harness.admin, userID, 4, "incident closed", harness.proof(), harness.request); err != nil {
		t.Fatalf("EnableUser() error = %v", err)
	}
	if harness.repository.users[userID].Version != 5 || harness.repository.users[userID].Status != UserStatusActive {
		t.Fatalf("enabled user = %+v", harness.repository.users[userID])
	}
	if err := harness.service.RevokeUserSessions(context.Background(), harness.admin, userID, 5, "credential rotation", harness.proof(), harness.request); err != nil {
		t.Fatalf("RevokeUserSessions() error = %v", err)
	}
	if harness.repository.users[userID].Version != 5 || len(harness.sessions.subjects) != 2 {
		t.Fatalf("revoke sessions changed user version or missed revocation: user=%+v sessions=%+v", harness.repository.users[userID], harness.sessions.subjects)
	}
	if got := harness.highRisk.operations; len(got) != 3 || got[0] != string(ReauthenticationOperationUserDisable) || got[1] != string(ReauthenticationOperationUserEnable) || got[2] != string(ReauthenticationOperationUserRevokeSessions) {
		t.Fatalf("high-risk operations = %+v", got)
	}
}

func TestCreateRoleBindingRequiresCurrentSubjectVersionBeforeProofConsumption(t *testing.T) {
	harness := newIAMHarness(t)
	_, err := harness.service.CreateRoleBinding(context.Background(), harness.admin, CreateRoleBindingCommand{
		SubjectType: SubjectTypeUser, SubjectID: harness.emergencyAdminID, SubjectVersion: 99,
		Role: identity.RoleViewer, ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow,
	}, harness.proof(), harness.request)
	if !errors.Is(err, ErrIAMConflict) {
		t.Fatalf("CreateRoleBinding(stale subject) error = %v", err)
	}
	if len(harness.highRisk.operations) != 0 {
		t.Fatalf("stale subject consumed proof: %+v", harness.highRisk.operations)
	}
}

func TestCreateRoleBindingValidatesEffectiveTimeWindowBeforeProofConsumption(t *testing.T) {
	harness := newIAMHarness(t)
	_, err := harness.service.CreateRoleBinding(context.Background(), harness.admin, CreateRoleBindingCommand{
		SubjectType: SubjectTypeUser, SubjectID: harness.emergencyAdminID, SubjectVersion: 1,
		Role: identity.RoleViewer, ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow,
		ValidUntil: harness.now.Add(-time.Minute),
	}, harness.proof(), harness.request)
	if !errors.Is(err, ErrRoleBindingInvalid) {
		t.Fatalf("CreateRoleBinding(invalid time window) error = %v", err)
	}
	if len(harness.highRisk.operations) != 0 {
		t.Fatalf("invalid time window consumed proof: %+v", harness.highRisk.operations)
	}
}

func TestEveryHighRiskWriteRejectsStaleVersionBeforeProofConsumption(t *testing.T) {
	for name, invoke := range map[string]func(*iamHarness) error{
		"create role binding": func(harness *iamHarness) error {
			_, err := harness.service.CreateRoleBinding(context.Background(), harness.admin, CreateRoleBindingCommand{
				SubjectType: SubjectTypeUser, SubjectID: harness.emergencyAdminID, SubjectVersion: 2,
				Role: identity.RoleViewer, ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow,
			}, harness.proof(), harness.request)
			return err
		},
		"delete role binding": func(harness *iamHarness) error {
			bindingID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e41")
			harness.repository.roleBindings[bindingID] = RoleBinding{ID: bindingID, SubjectType: SubjectTypeUser, SubjectID: harness.emergencyAdminID, Role: identity.RoleViewer, ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow, Version: 2}
			return harness.service.DeleteRoleBinding(context.Background(), harness.admin, bindingID, 1, harness.proof(), harness.request)
		},
		"disable user": func(harness *iamHarness) error {
			return harness.service.DisableUser(context.Background(), harness.admin, harness.emergencyAdminID, 2, "security response", harness.proof(), harness.request)
		},
		"enable user": func(harness *iamHarness) error {
			user := harness.repository.users[harness.emergencyAdminID]
			user.Status, user.DisabledAt, user.DisabledReason = UserStatusDisabled, harness.now.Add(-time.Hour), "test"
			harness.repository.users[user.ID] = user
			return harness.service.EnableUser(context.Background(), harness.admin, user.ID, 2, "restore", harness.proof(), harness.request)
		},
		"revoke user sessions": func(harness *iamHarness) error {
			return harness.service.RevokeUserSessions(context.Background(), harness.admin, harness.emergencyAdminID, 2, "rotation", harness.proof(), harness.request)
		},
		"enable sso": func(harness *iamHarness) error {
			return harness.service.EnableSSO(context.Background(), harness.admin, harness.sourceID, 2, harness.proof(), harness.request)
		},
		"disable sso": func(harness *iamHarness) error {
			harness.repository.login.Mode, harness.repository.login.ActiveSourceID = LoginModeSSO, harness.sourceID
			source := harness.repository.sources[harness.sourceID]
			source.Status = IdentitySourceStatusEnabled
			harness.repository.sources[source.ID] = source
			return harness.service.DisableSSO(context.Background(), harness.admin, harness.sourceID, 2, harness.proof(), harness.request)
		},
	} {
		t.Run(name, func(t *testing.T) {
			harness := newIAMHarness(t)
			if err := invoke(harness); !errors.Is(err, ErrIAMConflict) {
				t.Fatalf("stale version error = %v", err)
			}
			if len(harness.highRisk.operations) != 0 {
				t.Fatalf("stale version consumed proof: %+v", harness.highRisk.operations)
			}
		})
	}
}

func TestEveryHighRiskWriteRejectsMissingOrUnconfirmedProof(t *testing.T) {
	for name, invoke := range map[string]func(*iamHarness, HighRiskProof) error{
		"create role binding": func(harness *iamHarness, proof HighRiskProof) error {
			_, err := harness.service.CreateRoleBinding(context.Background(), harness.admin, CreateRoleBindingCommand{
				SubjectType: SubjectTypeUser, SubjectID: harness.emergencyAdminID, SubjectVersion: 1,
				Role: identity.RoleViewer, ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow,
			}, proof, harness.request)
			return err
		},
		"delete role binding": func(harness *iamHarness, proof HighRiskProof) error {
			bindingID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e42")
			harness.repository.roleBindings[bindingID] = RoleBinding{ID: bindingID, SubjectType: SubjectTypeUser, SubjectID: harness.emergencyAdminID, Role: identity.RoleViewer, ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow, Version: 1}
			return harness.service.DeleteRoleBinding(context.Background(), harness.admin, bindingID, 1, proof, harness.request)
		},
		"disable user": func(harness *iamHarness, proof HighRiskProof) error {
			return harness.service.DisableUser(context.Background(), harness.admin, harness.emergencyAdminID, 1, "security response", proof, harness.request)
		},
		"enable user": func(harness *iamHarness, proof HighRiskProof) error {
			localID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e43")
			harness.repository.users[localID] = UserPrincipal{ID: localID, Username: "disabled.local", Kind: UserKindLocal, Status: UserStatusDisabled, Version: 1, DisabledAt: harness.now.Add(-time.Hour), DisabledReason: "test"}
			harness.repository.credentials[localID] = LocalCredential{UserID: localID, Password: PasswordDigest{Algorithm: "argon2id", Parameters: "m=65536,t=3,p=2,l=32", Salt: make([]byte, 16), DerivedKey: make([]byte, 32)}, PasswordChangedAt: harness.now.Add(-time.Hour)}
			return harness.service.EnableUser(context.Background(), harness.admin, localID, 1, "restore", proof, harness.request)
		},
		"revoke user sessions": func(harness *iamHarness, proof HighRiskProof) error {
			return harness.service.RevokeUserSessions(context.Background(), harness.admin, harness.emergencyAdminID, 1, "rotation", proof, harness.request)
		},
		"enable sso": func(harness *iamHarness, proof HighRiskProof) error {
			return harness.service.EnableSSO(context.Background(), harness.admin, harness.sourceID, 1, proof, harness.request)
		},
		"disable sso": func(harness *iamHarness, proof HighRiskProof) error {
			harness.repository.login.Mode, harness.repository.login.ActiveSourceID = LoginModeSSO, harness.sourceID
			source := harness.repository.sources[harness.sourceID]
			source.Status = IdentitySourceStatusEnabled
			harness.repository.sources[source.ID] = source
			return harness.service.DisableSSO(context.Background(), harness.admin, harness.sourceID, 1, proof, harness.request)
		},
	} {
		t.Run(name, func(t *testing.T) {
			for proofName, proof := range map[string]HighRiskProof{
				"missing":     {},
				"unconfirmed": {ChallengeID: "server-challenge", Evidence: "server-evidence", Confirmed: false},
			} {
				t.Run(proofName, func(t *testing.T) {
					harness := newIAMHarness(t)
					if err := invoke(harness, proof); !errors.Is(err, ErrHighRiskConfirmationRequired) {
						t.Fatalf("proof rejection error = %v", err)
					}
					if len(harness.highRisk.operations) != 0 {
						t.Fatalf("unconfirmed proof reached authority: %+v", harness.highRisk.operations)
					}
				})
			}
		})
	}
}

func TestEnableUserConsumesProofButOnlyTransitionsDisabledAccounts(t *testing.T) {
	for name, status := range map[string]UserStatus{"pending": UserStatusPending, "locked": UserStatusLocked} {
		t.Run(name, func(t *testing.T) {
			harness := newIAMHarness(t)
			userID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e44")
			harness.repository.users[userID] = UserPrincipal{ID: userID, Username: "non-disabled.local", Kind: UserKindLocal, Status: status, Version: 1}
			harness.repository.credentials[userID] = LocalCredential{UserID: userID, Password: PasswordDigest{Algorithm: "argon2id", Parameters: "m=65536,t=3,p=2,l=32", Salt: make([]byte, 16), DerivedKey: make([]byte, 32)}, PasswordChangedAt: harness.now.Add(-time.Hour)}
			err := harness.service.EnableUser(context.Background(), harness.admin, userID, 1, "manual enable", harness.proof(), harness.request)
			if !errors.Is(err, ErrUserCannotBeEnabled) {
				t.Fatalf("EnableUser(%s) error = %v", status, err)
			}
			if len(harness.highRisk.operations) != 1 || harness.highRisk.operations[0] != string(ReauthenticationOperationUserEnable) || harness.repository.users[userID].Status != status {
				t.Fatalf("invalid transition changed state or consumed proof: user=%+v operations=%+v", harness.repository.users[userID], harness.highRisk.operations)
			}
		})
	}
}

type iamHarness struct {
	service          *Service
	repository       *memoryIAMRepository
	now              time.Time
	sourceID         uuid.UUID
	emergencyAdminID uuid.UUID
	admin            identity.Principal
	system           identity.Principal
	request          RequestContext
	auditor          *iamAuditRecorder
	sessions         *iamSessionRecorder
	highRisk         *recordingHighRiskAuthorizer
}

func newIAMHarness(t *testing.T) *iamHarness {
	t.Helper()
	now := time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC)
	sourceID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e11")
	emergencyID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e12")
	emergencyBindingID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e10")
	repository := &memoryIAMRepository{
		login: LoginState{Mode: LoginModeLocal, Version: 1, UpdatedAt: now},
		sources: map[uuid.UUID]IdentitySource{sourceID: {
			ID: sourceID, Kind: IdentitySourceOIDC, Status: IdentitySourceStatusVerified,
			VerifiedAt: now.Add(-time.Minute), RequiredMappingsComplete: true, PreviewedAt: now.Add(-30 * time.Second), Version: 1,
		}},
		users: map[uuid.UUID]UserPrincipal{emergencyID: {
			ID: emergencyID, Username: "break-glass", Kind: UserKindEmergency, Status: UserStatusActive,
			MFAEnrolled: true, CredentialRotatedAt: now.Add(-24 * time.Hour), Version: 1,
		}},
		credentials: map[uuid.UUID]LocalCredential{emergencyID: {
			UserID: emergencyID, Password: PasswordDigest{
				Algorithm: "argon2id", Parameters: "m=19456,t=1,p=1,l=32", Salt: make([]byte, 16), DerivedKey: make([]byte, 32),
			}, PasswordChangedAt: now.Add(-24 * time.Hour), MFASecretReference: "secret://mfa/break-glass",
		}},
		organizations: make(map[uuid.UUID]OrganizationUnit),
		roleBindings: map[uuid.UUID]RoleBinding{emergencyBindingID: {
			ID: emergencyBindingID, SubjectType: SubjectTypeUser, SubjectID: emergencyID, Role: identity.RoleAdmin,
			ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow, ValidFrom: now.Add(-24 * time.Hour), Version: 1,
		}},
		catalogScopes: map[string]map[string]bool{"ngep": {"stable": true}},
		memberships:   make(map[uuid.UUID][]uuid.UUID),
	}
	auditor := &iamAuditRecorder{}
	sessions := &iamSessionRecorder{}
	highRisk := &recordingHighRiskAuthorizer{}
	service, err := NewService(ServiceConfig{
		Repository: repository, ScopeCatalog: repository, BreakGlass: NewBreakGlassInvariantAuthority(repository), Auditor: auditor, Sessions: sessions, Passwords: deterministicPasswordManager{}, Directory: iamDirectoryAdapter{}, HighRisk: highRisk,
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return &iamHarness{
		service: service, repository: repository, now: now, sourceID: sourceID, emergencyAdminID: emergencyID,
		auditor: auditor, sessions: sessions, highRisk: highRisk,
		admin:   identity.Principal{Subject: "admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}, TokenID: "admin-token"},
		system:  identity.Principal{Subject: "identity-monitor", Kind: identity.PrincipalKindWorkload, Roles: []identity.Role{identity.RoleAdmin}, TokenID: "monitor-token", Provider: identity.WorkloadProviderAPIToken},
		request: RequestContext{RequestID: "018f835d-7e4b-7abc-9f42-67a2f5f48e13", SourceIP: "127.0.0.1"},
	}
}

func (harness *iamHarness) proof() HighRiskProof {
	return HighRiskProof{Confirmed: true, ChallengeID: "server-challenge", Evidence: "server-evidence"}
}

type memoryIAMRepository struct {
	withinTransactionCalls int
	login                  LoginState
	sources                map[uuid.UUID]IdentitySource
	users                  map[uuid.UUID]UserPrincipal
	credentials            map[uuid.UUID]LocalCredential
	organizations          map[uuid.UUID]OrganizationUnit
	roleBindings           map[uuid.UUID]RoleBinding
	catalogScopes          map[string]map[string]bool
	memberships            map[uuid.UUID][]uuid.UUID
}

func (repository *memoryIAMRepository) WithinTransaction(_ context.Context, function func(pgx.Tx) error) error {
	repository.withinTransactionCalls++
	login := repository.login
	users := cloneIAMUsers(repository.users)
	sources := cloneIAMSources(repository.sources)
	bindings := cloneIAMRoleBindings(repository.roleBindings)
	err := function(nil)
	if err != nil {
		repository.login = login
		repository.users = users
		repository.sources = sources
		repository.roleBindings = bindings
	}
	return err
}

func cloneIAMUsers(source map[uuid.UUID]UserPrincipal) map[uuid.UUID]UserPrincipal {
	result := make(map[uuid.UUID]UserPrincipal, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneIAMSources(source map[uuid.UUID]IdentitySource) map[uuid.UUID]IdentitySource {
	result := make(map[uuid.UUID]IdentitySource, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneIAMRoleBindings(source map[uuid.UUID]RoleBinding) map[uuid.UUID]RoleBinding {
	result := make(map[uuid.UUID]RoleBinding, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func (repository *memoryIAMRepository) GetLoginState(context.Context, pgx.Tx) (LoginState, error) {
	return repository.login, nil
}

func (repository *memoryIAMRepository) SetLoginState(_ context.Context, _ pgx.Tx, state LoginState, expectedVersion int64) error {
	if repository.login.Version != expectedVersion {
		return ErrIAMConflict
	}
	repository.login = state
	return nil
}

func (repository *memoryIAMRepository) GetIdentitySource(_ context.Context, _ pgx.Tx, id uuid.UUID) (IdentitySource, error) {
	source, exists := repository.sources[id]
	if !exists {
		return IdentitySource{}, ErrIdentitySourceNotFound
	}
	return source, nil
}

func (repository *memoryIAMRepository) SaveIdentitySource(_ context.Context, _ pgx.Tx, source IdentitySource, expectedVersion int64) error {
	current, exists := repository.sources[source.ID]
	if !exists {
		return ErrIdentitySourceNotFound
	}
	if current.Version != expectedVersion {
		return ErrIAMConflict
	}
	repository.sources[source.ID] = source
	return nil
}

func (repository *memoryIAMRepository) LockBreakGlassInvariant(context.Context, pgx.Tx) error {
	return nil
}

func (repository *memoryIAMRepository) EvaluateBreakGlassInvariant(_ context.Context, _ pgx.Tx, at time.Time) (BreakGlassInvariantEvaluation, error) {
	at = at.UTC()
	evaluation := BreakGlassInvariantEvaluation{}
	bindings := make([]RoleBinding, 0, len(repository.roleBindings))
	boundaries := make(map[time.Time]struct{})
	for _, binding := range repository.roleBindings {
		bindings = append(bindings, binding)
		if binding.Role != identity.RoleAdmin || binding.ScopeType != ScopeTypePlatform {
			continue
		}
		if binding.ValidFrom.After(at) {
			boundaries[binding.ValidFrom.UTC()] = struct{}{}
		}
		if !binding.ValidUntil.IsZero() && binding.ValidUntil.After(at) {
			boundaries[binding.ValidUntil.UTC()] = struct{}{}
		}
	}
	structuralCandidates := make([]UserPrincipal, 0, len(repository.users))
	for id, user := range repository.users {
		credential, exists := repository.credentials[id]
		if !exists || user.Kind != UserKindEmergency || user.Status != UserStatusActive || !user.MFAEnrolled ||
			credential.PasswordChangedAt.IsZero() || credential.ActivationDigest != "" || credential.MFASecretReference == "" {
			continue
		}
		if _, _, _, _, err := parsePasswordDigest(credential.Password); err != nil {
			continue
		}
		structuralCandidates = append(structuralCandidates, user)
		if !user.CredentialRotatedAt.IsZero() && !user.CredentialRotatedAt.Before(at.Add(-emergencyCredentialMaximumAge)) &&
			(credential.LockedUntil.IsZero() || !credential.LockedUntil.After(at)) &&
			ResolveAccess(user, repository.memberships[id], bindings, at).Allowed(identity.RoleAdmin, "", "") {
			evaluation.CurrentUsableAdministrators++
		}
	}
	for boundary := range boundaries {
		available := false
		for _, user := range structuralCandidates {
			if ResolveAccess(user, repository.memberships[user.ID], bindings, boundary).Allowed(identity.RoleAdmin, "", "") {
				available = true
				break
			}
		}
		if !available && (evaluation.FirstScheduledPermissionGap.IsZero() || boundary.Before(evaluation.FirstScheduledPermissionGap)) {
			evaluation.FirstScheduledPermissionGap = boundary
		}
	}
	return evaluation, nil
}

func (repository *memoryIAMRepository) seedUsableEmergencyAdministrator(id uuid.UUID, username string) {
	repository.users[id] = UserPrincipal{
		ID: id, Username: username, Kind: UserKindEmergency, Status: UserStatusActive, MFAEnrolled: true,
		CredentialRotatedAt: time.Date(2026, 8, 19, 8, 0, 0, 0, time.UTC), Version: 1,
	}
	repository.credentials[id] = LocalCredential{
		UserID: id, Password: PasswordDigest{
			Algorithm: "argon2id", Parameters: "m=19456,t=1,p=1,l=32", Salt: make([]byte, 16), DerivedKey: make([]byte, 32),
		}, PasswordChangedAt: time.Date(2026, 8, 19, 8, 0, 0, 0, time.UTC), MFASecretReference: "secret://mfa/" + username,
	}
	bindingID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("test-break-glass:"+id.String()))
	repository.roleBindings[bindingID] = RoleBinding{
		ID: bindingID, SubjectType: SubjectTypeUser, SubjectID: id, Role: identity.RoleAdmin,
		ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow,
		ValidFrom: time.Date(2026, 8, 19, 8, 0, 0, 0, time.UTC), Version: 1,
	}
}

func (repository *memoryIAMRepository) GetUser(_ context.Context, _ pgx.Tx, id uuid.UUID) (UserPrincipal, error) {
	user, exists := repository.users[id]
	if !exists {
		return UserPrincipal{}, ErrUserNotFound
	}
	return user, nil
}

func (repository *memoryIAMRepository) SaveUser(_ context.Context, _ pgx.Tx, user UserPrincipal, expectedVersion int64) error {
	current, exists := repository.users[user.ID]
	if !exists {
		return ErrUserNotFound
	}
	if current.Version != expectedVersion {
		return ErrIAMConflict
	}
	repository.users[user.ID] = user
	return nil
}

func (repository *memoryIAMRepository) UserCanBeEnabled(_ context.Context, _ pgx.Tx, user UserPrincipal) (bool, error) {
	if user.Kind == UserKindExternal {
		source, exists := repository.sources[user.IdentitySourceID]
		return exists && source.Status == IdentitySourceStatusEnabled, nil
	}
	credential, exists := repository.credentials[user.ID]
	if !exists || credential.Password.Algorithm != "argon2id" || credential.PasswordChangedAt.IsZero() || credential.ActivationDigest != "" {
		return false, nil
	}
	if user.Kind == UserKindEmergency && (!user.MFAEnrolled || credential.MFASecretReference == "") {
		return false, nil
	}
	return true, nil
}

func (repository *memoryIAMRepository) FindLocalAuthentication(context.Context, string) (LoginState, UserPrincipal, LocalCredential, error) {
	return repository.login, UserPrincipal{}, LocalCredential{}, ErrLocalCredentialInvalid
}

func (repository *memoryIAMRepository) InsertLocalUser(_ context.Context, _ pgx.Tx, user UserPrincipal, credential LocalCredential) error {
	if repository.credentials == nil {
		repository.credentials = make(map[uuid.UUID]LocalCredential)
	}
	for _, existing := range repository.users {
		if existing.Username == user.Username {
			return ErrIAMConflict
		}
	}
	repository.users[user.ID] = user
	repository.credentials[user.ID] = credential
	return nil
}

func (repository *memoryIAMRepository) ListUsers(context.Context, Page) (UserPage, error) {
	items := make([]UserPrincipal, 0, len(repository.users))
	for _, user := range repository.users {
		items = append(items, user)
	}
	return UserPage{Items: items}, nil
}

func (repository *memoryIAMRepository) InsertOrganization(_ context.Context, _ pgx.Tx, organization OrganizationUnit) error {
	repository.organizations[organization.ID] = organization
	return nil
}

func (repository *memoryIAMRepository) GetOrganization(_ context.Context, _ pgx.Tx, id uuid.UUID) (OrganizationUnit, error) {
	organization, exists := repository.organizations[id]
	if !exists {
		return OrganizationUnit{}, ErrOrganizationNotFound
	}
	return organization, nil
}

func (repository *memoryIAMRepository) ListOrganizations(context.Context, Page) (OrganizationPage, error) {
	items := make([]OrganizationUnit, 0, len(repository.organizations))
	for _, organization := range repository.organizations {
		items = append(items, organization)
	}
	return OrganizationPage{Items: items}, nil
}

func (repository *memoryIAMRepository) InsertRoleBinding(_ context.Context, _ pgx.Tx, binding RoleBinding) error {
	repository.roleBindings[binding.ID] = binding
	return nil
}

func (repository *memoryIAMRepository) GetRoleBinding(_ context.Context, _ pgx.Tx, id uuid.UUID) (RoleBinding, error) {
	binding, exists := repository.roleBindings[id]
	if !exists {
		return RoleBinding{}, ErrRoleBindingNotFound
	}
	return binding, nil
}

func (repository *memoryIAMRepository) ListRoleBindings(context.Context, Page) (RoleBindingPage, error) {
	items := make([]RoleBinding, 0, len(repository.roleBindings))
	for _, binding := range repository.roleBindings {
		items = append(items, binding)
	}
	return RoleBindingPage{Items: items}, nil
}

func (repository *memoryIAMRepository) DeleteRoleBinding(_ context.Context, _ pgx.Tx, id uuid.UUID, expectedVersion int64) error {
	binding, exists := repository.roleBindings[id]
	if !exists {
		return ErrRoleBindingNotFound
	}
	if binding.Version != expectedVersion {
		return ErrIAMConflict
	}
	delete(repository.roleBindings, id)
	return nil
}

func (repository *memoryIAMRepository) ValidateRoleBindingScope(_ context.Context, _ pgx.Tx, scope CatalogScope) error {
	if scope.Type == ScopeTypePlatform {
		return nil
	}
	channels, exists := repository.catalogScopes[scope.ProductID]
	if !exists {
		return ErrRoleBindingInvalid
	}
	if scope.Type == ScopeTypeProduct {
		return nil
	}
	if scope.Type != ScopeTypeChannel || !channels[scope.ChannelName] {
		return ErrRoleBindingInvalid
	}
	return nil
}

func (repository *memoryIAMRepository) InsertIdentitySource(_ context.Context, _ pgx.Tx, source IdentitySource) error {
	repository.sources[source.ID] = source
	return nil
}

func (repository *memoryIAMRepository) ListIdentitySources(context.Context, Page) (IdentitySourcePage, error) {
	items := make([]IdentitySource, 0, len(repository.sources))
	for _, source := range repository.sources {
		items = append(items, source)
	}
	return IdentitySourcePage{Items: items}, nil
}

func (repository *memoryIAMRepository) UpdateIdentitySourceDraft(_ context.Context, _ pgx.Tx, source IdentitySource, expectedVersion int64) error {
	return repository.SaveIdentitySource(context.Background(), nil, source, expectedVersion)
}

type iamAuditRecorder struct {
	commands []audit.AppendCommand
}

func (recorder *iamAuditRecorder) Append(_ context.Context, _ pgx.Tx, command audit.AppendCommand) (audit.Event, error) {
	recorder.commands = append(recorder.commands, command)
	return audit.Event{}, nil
}

type iamSessionRecorder struct {
	subjects           []uuid.UUID
	organizations      []uuid.UUID
	err                error
	regularRevocations int
}

func (recorder *iamSessionRecorder) RevokeRegularLocalSessions(_ context.Context, _ pgx.Tx, _ string) error {
	if recorder.err != nil {
		return recorder.err
	}
	recorder.regularRevocations++
	return nil
}

func (recorder *iamSessionRecorder) RevokeSubject(_ context.Context, _ pgx.Tx, subject uuid.UUID, _ string) error {
	if recorder.err != nil {
		return recorder.err
	}
	recorder.subjects = append(recorder.subjects, subject)
	return nil
}

func (recorder *iamSessionRecorder) RevokeOrganizationMembers(_ context.Context, _ pgx.Tx, organization uuid.UUID, _ string) error {
	if recorder.err != nil {
		return recorder.err
	}
	recorder.organizations = append(recorder.organizations, organization)
	return nil
}

type iamHighRiskAuthorizer struct{}

func (iamHighRiskAuthorizer) Authorize(_ context.Context, _ identity.Principal, _ string, proof HighRiskProof, _ RequestContext) error {
	if proof.ChallengeID != "server-challenge" || proof.Evidence != "server-evidence" {
		return ErrHighRiskConfirmationRequired
	}
	return nil
}

type recordingHighRiskAuthorizer struct {
	operations []string
	err        error
}

func (authorizer *recordingHighRiskAuthorizer) Authorize(_ context.Context, _ identity.Principal, operation string, proof HighRiskProof, _ RequestContext) error {
	if authorizer.err != nil {
		return authorizer.err
	}
	if proof.ChallengeID != "server-challenge" || proof.Evidence != "server-evidence" {
		return ErrHighRiskConfirmationRequired
	}
	authorizer.operations = append(authorizer.operations, operation)
	return nil
}

type iamDirectoryAdapter struct{}

func (iamDirectoryAdapter) Verify(context.Context, IdentitySource) (CapabilityReport, error) {
	return CapabilityReport{Reachable: true, SupportsIncremental: true}, nil
}

func (iamDirectoryAdapter) Preview(context.Context, IdentitySource) (SyncDiff, error) {
	return SyncDiff{CreateCount: 1}, nil
}

func (iamDirectoryAdapter) Sync(context.Context, IdentitySource, string) (SyncPage, error) {
	return SyncPage{}, nil
}

type deterministicPasswordManager struct{}

func (deterministicPasswordManager) Hash(_ context.Context, password string) (PasswordDigest, error) {
	digest := sha256.Sum256([]byte("password-digest:" + password))
	return PasswordDigest{Algorithm: "argon2id", Parameters: "m=65536,t=3,p=2,l=32", Salt: make([]byte, 16), DerivedKey: digest[:]}, nil
}

func (deterministicPasswordManager) Verify(string, PasswordDigest) error {
	return ErrLocalCredentialInvalid
}

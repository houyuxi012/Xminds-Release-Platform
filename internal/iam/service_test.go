package iam

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
		RequiredMappingsComplete: false,
	}

	err := harness.service.EnableSSO(context.Background(), harness.admin, harness.sourceID, harness.proof(), harness.request)

	if !errors.Is(err, ErrSSOPreconditionFailed) {
		t.Fatalf("EnableSSO() error = %v", err)
	}
	if harness.repository.login.Mode != LoginModeLocal {
		t.Fatalf("login mode = %q", harness.repository.login.Mode)
	}
}

func TestFaultDoesNotEnableRegularLocalLogin(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	if err := harness.service.EnableSSO(context.Background(), harness.admin, harness.sourceID, harness.proof(), harness.request); err != nil {
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
}

func TestCannotDisableLastUsableEmergencyAdministrator(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)

	err := harness.service.DisableUser(context.Background(), harness.admin, harness.emergencyAdminID, "rotation", harness.proof(), harness.request)

	if !errors.Is(err, ErrLastEmergencyAdministrator) {
		t.Fatalf("DisableUser() error = %v", err)
	}
	if harness.repository.users[harness.emergencyAdminID].Status != UserStatusActive {
		t.Fatal("last emergency administrator was disabled")
	}
}

func TestDisableSSORequiresFreshConfirmationAndReturnsToLocalMode(t *testing.T) {
	t.Parallel()

	harness := newIAMHarness(t)
	if err := harness.service.EnableSSO(context.Background(), harness.admin, harness.sourceID, harness.proof(), harness.request); err != nil {
		t.Fatal(err)
	}
	if err := harness.service.DisableSSO(context.Background(), harness.admin, HighRiskProof{Confirmed: true, ChallengeID: "wrong", Evidence: "bad"}, harness.request); !errors.Is(err, ErrHighRiskConfirmationRequired) {
		t.Fatalf("DisableSSO(unverified proof) error = %v", err)
	}
	if harness.repository.login.Mode != LoginModeSSO {
		t.Fatalf("login mode after rejected disable = %q", harness.repository.login.Mode)
	}

	if err := harness.service.DisableSSO(context.Background(), harness.admin, harness.proof(), harness.request); err != nil {
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
		Username: "  Release.Operator ", DisplayName: "Release Operator", Email: "OPERATOR@example.com",
	}, harness.request)
	if err != nil {
		t.Fatalf("CreateLocalUser() error = %v", err)
	}
	if provisioning.ActivationToken == "" || provisioning.User.Status != UserStatusPending || provisioning.User.Username != "release.operator" {
		t.Fatalf("provisioning = %+v", provisioning)
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
		SubjectType: SubjectTypeUser,
		SubjectID:   harness.emergencyAdminID,
		Role:        identity.RoleAdmin,
		ScopeType:   ScopeTypePlatform,
		Effect:      BindingEffectAllow,
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
	if len(harness.sessions.subjects) != 1 || harness.sessions.subjects[0] != harness.emergencyAdminID {
		t.Fatalf("revoked session subjects = %+v", harness.sessions.subjects)
	}
}

func TestHighRiskWritesFailClosedWithoutServerSideAuthority(t *testing.T) {
	t.Parallel()
	harness := newIAMHarness(t)
	harness.service.highRisk = nil
	_, err := harness.service.CreateRoleBinding(context.Background(), harness.admin, CreateRoleBindingCommand{
		SubjectType: SubjectTypeUser, SubjectID: harness.emergencyAdminID, Role: identity.RoleAuditor, ScopeType: ScopeTypePlatform, Effect: BindingEffectAllow,
	}, harness.proof(), harness.request)
	if !errors.Is(err, ErrIAMConfiguration) {
		t.Fatalf("CreateRoleBinding() error = %v", err)
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
}

func newIAMHarness(t *testing.T) *iamHarness {
	t.Helper()
	now := time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC)
	sourceID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e11")
	emergencyID := uuid.MustParse("018f835d-7e4b-7abc-9f42-67a2f5f48e12")
	repository := &memoryIAMRepository{
		login: LoginState{Mode: LoginModeLocal, Version: 1, UpdatedAt: now},
		sources: map[uuid.UUID]IdentitySource{sourceID: {
			ID: sourceID, Kind: IdentitySourceOIDC, Status: IdentitySourceStatusVerified,
			VerifiedAt: now.Add(-time.Minute), RequiredMappingsComplete: true, PreviewedAt: now.Add(-30 * time.Second),
		}},
		users: map[uuid.UUID]UserPrincipal{emergencyID: {
			ID: emergencyID, Username: "break-glass", Kind: UserKindEmergency, Status: UserStatusActive,
			MFAEnrolled: true, CredentialRotatedAt: now.Add(-24 * time.Hour),
		}},
		organizations: make(map[uuid.UUID]OrganizationUnit),
		roleBindings:  make(map[uuid.UUID]RoleBinding),
	}
	auditor := &iamAuditRecorder{}
	sessions := &iamSessionRecorder{}
	service, err := NewService(ServiceConfig{
		Repository: repository, Auditor: auditor, Sessions: sessions, Passwords: deterministicPasswordManager{}, Directory: iamDirectoryAdapter{}, HighRisk: iamHighRiskAuthorizer{},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return &iamHarness{
		service: service, repository: repository, now: now, sourceID: sourceID, emergencyAdminID: emergencyID,
		auditor: auditor, sessions: sessions,
		admin:   identity.Principal{Subject: "admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}, TokenID: "admin-token"},
		system:  identity.Principal{Subject: "identity-monitor", Kind: identity.PrincipalKindWorkload, Roles: []identity.Role{identity.RoleAdmin}, TokenID: "monitor-token", Provider: identity.WorkloadProviderAPIToken},
		request: RequestContext{RequestID: "018f835d-7e4b-7abc-9f42-67a2f5f48e13", SourceIP: "127.0.0.1"},
	}
}

func (harness *iamHarness) proof() HighRiskProof {
	return HighRiskProof{Confirmed: true, ChallengeID: "server-challenge", Evidence: "server-evidence"}
}

type memoryIAMRepository struct {
	login         LoginState
	sources       map[uuid.UUID]IdentitySource
	users         map[uuid.UUID]UserPrincipal
	credentials   map[uuid.UUID]LocalCredential
	organizations map[uuid.UUID]OrganizationUnit
	roleBindings  map[uuid.UUID]RoleBinding
}

func (repository *memoryIAMRepository) WithinTransaction(_ context.Context, function func(pgx.Tx) error) error {
	return function(nil)
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

func (repository *memoryIAMRepository) CountUsableEmergencyAdministrators(_ context.Context, _ pgx.Tx, excluding uuid.UUID, _ time.Time) (int, error) {
	count := 0
	for id, user := range repository.users {
		if id != excluding && user.Kind == UserKindEmergency && user.Status == UserStatusActive && user.MFAEnrolled {
			count++
		}
	}
	return count, nil
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
	subjects []uuid.UUID
}

func (recorder *iamSessionRecorder) RevokeSubject(_ context.Context, subject uuid.UUID, _ string) error {
	recorder.subjects = append(recorder.subjects, subject)
	return nil
}

type iamHighRiskAuthorizer struct{}

func (iamHighRiskAuthorizer) Authorize(_ context.Context, _ identity.Principal, _ string, proof HighRiskProof) error {
	if proof.ChallengeID != "server-challenge" || proof.Evidence != "server-evidence" {
		return ErrHighRiskConfirmationRequired
	}
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

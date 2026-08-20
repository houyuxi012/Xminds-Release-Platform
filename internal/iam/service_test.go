package iam

import (
	"context"
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

	err := harness.service.EnableSSO(context.Background(), harness.admin, harness.sourceID, harness.confirmation(), harness.request)

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
	if err := harness.service.EnableSSO(context.Background(), harness.admin, harness.sourceID, harness.confirmation(), harness.request); err != nil {
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

	err := harness.service.DisableUser(context.Background(), harness.admin, harness.emergencyAdminID, "rotation", harness.confirmation(), harness.request)

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
	if err := harness.service.EnableSSO(context.Background(), harness.admin, harness.sourceID, harness.confirmation(), harness.request); err != nil {
		t.Fatal(err)
	}
	stale := HighRiskConfirmation{Confirmed: true, ReauthenticatedAt: harness.now.Add(-10 * time.Minute)}
	if err := harness.service.DisableSSO(context.Background(), harness.admin, stale, harness.request); !errors.Is(err, ErrHighRiskConfirmationRequired) {
		t.Fatalf("DisableSSO(stale) error = %v", err)
	}
	if harness.repository.login.Mode != LoginModeSSO {
		t.Fatalf("login mode after rejected disable = %q", harness.repository.login.Mode)
	}

	if err := harness.service.DisableSSO(context.Background(), harness.admin, harness.confirmation(), harness.request); err != nil {
		t.Fatalf("DisableSSO() error = %v", err)
	}
	if harness.repository.login.Mode != LoginModeLocal || harness.repository.login.ActiveSourceID != uuid.Nil || harness.repository.login.FaultCode != "" {
		t.Fatalf("login state = %+v", harness.repository.login)
	}
	if harness.repository.sources[harness.sourceID].Status != IdentitySourceStatusDisabled {
		t.Fatalf("identity source = %+v", harness.repository.sources[harness.sourceID])
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
	}
	service, err := NewService(ServiceConfig{
		Repository: repository, Auditor: iamAuditRecorder{}, Sessions: iamSessionRecorder{}, Passwords: rejectingPasswordVerifier{},
		Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return &iamHarness{
		service: service, repository: repository, now: now, sourceID: sourceID, emergencyAdminID: emergencyID,
		admin:   identity.Principal{Subject: "admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}, TokenID: "admin-token"},
		system:  identity.Principal{Subject: "identity-monitor", Kind: identity.PrincipalKindWorkload, Roles: []identity.Role{identity.RoleAdmin}, TokenID: "monitor-token", Provider: identity.WorkloadProviderAPIToken},
		request: RequestContext{RequestID: "018f835d-7e4b-7abc-9f42-67a2f5f48e13", SourceIP: "127.0.0.1"},
	}
}

func (harness *iamHarness) confirmation() HighRiskConfirmation {
	return HighRiskConfirmation{Confirmed: true, ReauthenticatedAt: harness.now.Add(-time.Minute)}
}

type memoryIAMRepository struct {
	login   LoginState
	sources map[uuid.UUID]IdentitySource
	users   map[uuid.UUID]UserPrincipal
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

type iamAuditRecorder struct{}

func (iamAuditRecorder) Append(context.Context, pgx.Tx, audit.AppendCommand) (audit.Event, error) {
	return audit.Event{}, nil
}

type iamSessionRecorder struct{}

func (iamSessionRecorder) RevokeSubject(context.Context, uuid.UUID, string) error { return nil }

type rejectingPasswordVerifier struct{}

func (rejectingPasswordVerifier) Verify(string, PasswordDigest) error {
	return ErrLocalCredentialInvalid
}

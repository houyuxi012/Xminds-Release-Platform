package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/artifact"
	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
	"xminds-release-platform/internal/platform/jobs"
	"xminds-release-platform/internal/product"
)

func TestSubmitterCannotApproveOwnRelease(t *testing.T) {
	t.Parallel()

	service := newTestReleaseService()
	creator := releasePrincipal("alice", identity.RolePublisher)
	created, err := service.Create(context.Background(), creator, validCreateCommand(), testRequestContext())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	submitted, err := service.Submit(context.Background(), creator, created.ProductID, created.ID, created.LockVersion, testRequestContext())
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	selfApprover := releasePrincipal("alice", identity.RoleApprover)
	_, err = service.Approve(context.Background(), selfApprover, submitted.ProductID, submitted.ID, submitted.LockVersion, testRequestContext())
	if !errors.Is(err, ErrSelfApprovalForbidden) {
		t.Fatalf("Approve() error = %v, want %v", err, ErrSelfApprovalForbidden)
	}
	stored, getErr := service.Get(context.Background(), releasePrincipal("reader", identity.RoleAuditor), submitted.ProductID, submitted.ID)
	if getErr != nil {
		t.Fatalf("Get() error = %v", getErr)
	}
	if stored.Status != StatusSubmitted || stored.LockVersion != submitted.LockVersion {
		t.Fatalf("release after denied self-approval = %#v", stored)
	}
}

func TestApprovalRequiresExplicitApproverRole(t *testing.T) {
	t.Parallel()

	service := newTestReleaseService()
	publisher := releasePrincipal("alice", identity.RolePublisher)
	created, err := service.Create(context.Background(), publisher, validCreateCommand(), testRequestContext())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	submitted, err := service.Submit(context.Background(), publisher, created.ProductID, created.ID, created.LockVersion, testRequestContext())
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	adminOnly := releasePrincipal("platform-admin", identity.RoleAdmin)
	_, err = service.Approve(context.Background(), adminOnly, submitted.ProductID, submitted.ID, submitted.LockVersion, testRequestContext())
	if !errors.Is(err, identity.ErrActionDenied) {
		t.Fatalf("admin-only Approve() error = %v, want %v", err, identity.ErrActionDenied)
	}
}

func TestCreateRejectsInvalidImmutableReleaseInputs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*CreateCommand)
		want   error
	}{
		{name: "unknown channel", mutate: func(command *CreateCommand) { command.Channel = "nightly" }, want: ErrChannelInvalid},
		{name: "non canonical semver", mutate: func(command *CreateCommand) { command.Version = "01.2.3" }, want: ErrVersionInvalid},
		{name: "numeric prerelease leading zero", mutate: func(command *CreateCommand) { command.Version = "1.2.3-01" }, want: ErrVersionInvalid},
		{name: "notes digest mismatch", mutate: func(command *CreateCommand) {
			command.ReleaseNotesSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
		}, want: ErrReleaseNotesMismatch},
		{name: "duplicate compatibility key", mutate: func(command *CreateCommand) {
			command.Compatibility = []byte(`{"os":["darwin"],"os":["linux"],"arch":["arm64"]}`)
			command.CompatibilitySHA256 = digestForReleaseTest(command.Compatibility)
		}, want: ErrCompatibilityInvalid},
		{name: "missing artifact", mutate: func(command *CreateCommand) { command.ArtifactIDs = nil }, want: ErrArtifactsInvalid},
		{name: "missing pipeline provenance", mutate: func(command *CreateCommand) { command.Source.PipelineRef = "" }, want: ErrSourceInvalid},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			command := validCreateCommand()
			test.mutate(&command)
			_, err := newTestReleaseService().Create(context.Background(), releasePrincipal("alice", identity.RolePublisher), command, testRequestContext())
			if !errors.Is(err, test.want) {
				t.Fatalf("Create() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestGovernedExplicitDenyBlocksProtectedReleaseCreate(t *testing.T) {
	t.Parallel()

	principal := releasePrincipal("governed-publisher", identity.RolePublisher)
	principal.Governed = true
	principal.RoleScopes = []identity.RoleScope{
		{Role: identity.RolePublisher, Effect: "allow", ScopeType: "product", ProductID: "ngep"},
		{Role: identity.RolePublisher, Effect: "deny", ScopeType: "platform"},
	}
	_, err := newTestReleaseService().Create(context.Background(), principal, validCreateCommand(), testRequestContext())
	if !errors.Is(err, identity.ErrActionDenied) {
		t.Fatalf("Create() error = %v, want governed explicit deny", err)
	}
}

func TestGovernedChannelScopesControlProtectedReleaseCreate(t *testing.T) {
	t.Parallel()
	command := validCreateCommand()
	principal := releasePrincipal("governed-publisher", identity.RolePublisher)
	principal.Governed = true
	principal.RoleScopes = []identity.RoleScope{
		{Role: identity.RolePublisher, Effect: "allow", ScopeType: "product", ProductID: "ngep"},
		{Role: identity.RolePublisher, Effect: "deny", ScopeType: "channel", ProductID: "ngep", ChannelName: command.Channel},
	}
	if _, err := newTestReleaseService().Create(context.Background(), principal, command, testRequestContext()); !errors.Is(err, identity.ErrActionDenied) {
		t.Fatalf("Create() product allow + channel deny error = %v", err)
	}

	principal.RoleScopes = []identity.RoleScope{{Role: identity.RolePublisher, Effect: "allow", ScopeType: "channel", ProductID: "ngep", ChannelName: command.Channel}}
	if _, err := newTestReleaseService().Create(context.Background(), principal, command, testRequestContext()); err != nil {
		t.Fatalf("Create() matching channel allow error = %v", err)
	}
	command.Channel = "beta"
	if _, err := newTestReleaseService().Create(context.Background(), principal, command, testRequestContext()); !errors.Is(err, identity.ErrActionDenied) {
		t.Fatalf("Create() different channel error = %v", err)
	}
}

func TestGovernedReleaseOperationsFilterRoleScopesByTargetAction(t *testing.T) {
	t.Parallel()

	type operationResult struct {
		release Release
		attempt Attempt
		err     error
	}
	tests := []struct {
		name               string
		initialStatus      Status
		allowedRole        identity.Role
		call               func(*Service, identity.Principal, Release) operationResult
		wantStatus         Status
		wantAttemptKind    AttemptKind
		wantRevoked        bool
		wantErr            error
		wantRepositoryRead int
	}{
		{
			name: "get", initialStatus: StatusDraft, allowedRole: identity.RolePublisher,
			call: func(service *Service, principal identity.Principal, record Release) operationResult {
				result, err := service.Get(context.Background(), principal, record.ProductID, record.ID)
				return operationResult{release: result, err: err}
			},
			wantErr: ErrReleaseNotFound,
		},
		{
			name: "create", allowedRole: identity.RolePublisher,
			call: func(service *Service, principal identity.Principal, _ Release) operationResult {
				result, err := service.Create(context.Background(), principal, validCreateCommand(), testRequestContext())
				return operationResult{release: result, err: err}
			},
			wantStatus: StatusDraft,
		},
		{
			name: "submit", initialStatus: StatusDraft, allowedRole: identity.RolePublisher,
			call: func(service *Service, principal identity.Principal, record Release) operationResult {
				result, err := service.Submit(context.Background(), principal, record.ProductID, record.ID, record.LockVersion, testRequestContext())
				return operationResult{release: result, err: err}
			},
			wantStatus: StatusSubmitted, wantRepositoryRead: 1,
		},
		{
			name: "approve", initialStatus: StatusSubmitted, allowedRole: identity.RoleApprover,
			call: func(service *Service, principal identity.Principal, record Release) operationResult {
				result, err := service.Approve(context.Background(), principal, record.ProductID, record.ID, record.LockVersion, testRequestContext())
				return operationResult{release: result, err: err}
			},
			wantStatus: StatusApproved, wantRepositoryRead: 1,
		},
		{
			name: "reject", initialStatus: StatusSubmitted, allowedRole: identity.RoleApprover,
			call: func(service *Service, principal identity.Principal, record Release) operationResult {
				result, err := service.Reject(context.Background(), principal, record.ProductID, record.ID, record.LockVersion, "policy rejection", testRequestContext())
				return operationResult{release: result, err: err}
			},
			wantStatus: StatusRejected, wantRepositoryRead: 1,
		},
		{
			name: "publish", initialStatus: StatusApproved, allowedRole: identity.RolePublisher,
			call: func(service *Service, principal identity.Principal, record Release) operationResult {
				result, err := service.Publish(context.Background(), principal, record.ProductID, record.ID, record.LockVersion, "publish-cross-role-12345678", testRequestContext())
				return operationResult{release: result.Release, attempt: result.Attempt, err: err}
			},
			wantStatus: StatusPublishing, wantAttemptKind: AttemptKindPublish, wantRepositoryRead: 1,
		},
		{
			name: "retry", initialStatus: StatusFailed, allowedRole: identity.RoleApprover,
			call: func(service *Service, principal identity.Principal, record Release) operationResult {
				result, err := service.Retry(context.Background(), principal, record.ProductID, record.ID, record.LockVersion, "retry-cross-role-12345678", testRequestContext())
				return operationResult{release: result.Release, attempt: result.Attempt, err: err}
			},
			wantStatus: StatusPublishing, wantAttemptKind: AttemptKindRetry, wantRepositoryRead: 1,
		},
		{
			name: "revoke", initialStatus: StatusPublished, allowedRole: identity.RoleApprover,
			call: func(service *Service, principal identity.Principal, record Release) operationResult {
				result, err := service.Revoke(context.Background(), principal, record.ProductID, record.ID, record.LockVersion, "security revocation", "revoke-cross-role-12345678", testRequestContext())
				return operationResult{release: result.Release, attempt: result.Attempt, err: err}
			},
			wantStatus: StatusPublished, wantAttemptKind: AttemptKindRevoke, wantRevoked: true, wantRepositoryRead: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := newTestReleaseService()
			repository := service.repository.(*memoryReleaseRepository)
			record := Release{
				ID: uuid.New(), ProductID: "ngep", Channel: "stable", Status: test.initialStatus, LockVersion: 4,
				SubmittedBy: "original-publisher",
			}
			if test.initialStatus != "" {
				repository.releases[record.ID] = record
			}
			principal := identity.Principal{
				Subject: "governed-operator", Kind: identity.PrincipalKindHuman, Governed: true,
				RoleScopes: []identity.RoleScope{
					{Role: identity.RoleViewer, Effect: "deny", ScopeType: "product", ProductID: "ngep"},
					{Role: test.allowedRole, Effect: "allow", ScopeType: "channel", ProductID: "ngep", ChannelName: "stable"},
				},
			}

			outcome := test.call(service, principal, record)
			if test.wantErr != nil {
				if !errors.Is(outcome.err, test.wantErr) {
					t.Fatalf("%s error = %v, want %v", test.name, outcome.err, test.wantErr)
				}
				if !reflect.DeepEqual(outcome.release, Release{}) || !reflect.DeepEqual(outcome.attempt, Attempt{}) {
					t.Fatalf("%s leaked release=%#v attempt=%#v", test.name, outcome.release, outcome.attempt)
				}
			} else {
				if outcome.err != nil {
					t.Fatalf("%s error = %v", test.name, outcome.err)
				}
				if outcome.release.Status != test.wantStatus {
					t.Fatalf("%s status = %s, want %s", test.name, outcome.release.Status, test.wantStatus)
				}
				if test.wantAttemptKind != "" && outcome.attempt.Kind != test.wantAttemptKind {
					t.Fatalf("%s attempt kind = %s, want %s", test.name, outcome.attempt.Kind, test.wantAttemptKind)
				}
				if test.wantRevoked && outcome.release.RevokedAt == nil {
					t.Fatalf("%s did not revoke release", test.name)
				}
			}
			if repository.getCalls != test.wantRepositoryRead {
				t.Fatalf("%s repository reads = %d, want %d", test.name, repository.getCalls, test.wantRepositoryRead)
			}
		})
	}
}

func TestGovernedPublisherTargetActionDenyWinsOverChannelAllow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		initialStatus Status
		call          func(*Service, identity.Principal, Release) error
	}{
		{
			name: "submit", initialStatus: StatusDraft,
			call: func(service *Service, principal identity.Principal, record Release) error {
				_, err := service.Submit(context.Background(), principal, record.ProductID, record.ID, record.LockVersion, testRequestContext())
				return err
			},
		},
		{
			name: "publish", initialStatus: StatusApproved,
			call: func(service *Service, principal identity.Principal, record Release) error {
				_, err := service.Publish(context.Background(), principal, record.ProductID, record.ID, record.LockVersion, "publish-target-deny-12345678", testRequestContext())
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := newTestReleaseService()
			repository := service.repository.(*memoryReleaseRepository)
			record := Release{ID: uuid.New(), ProductID: "ngep", Channel: "stable", Status: test.initialStatus, LockVersion: 4}
			repository.releases[record.ID] = record
			principal := identity.Principal{
				Subject: "governed-publisher", Kind: identity.PrincipalKindHuman, Governed: true,
				RoleScopes: []identity.RoleScope{
					{Role: identity.RolePublisher, Effect: "allow", ScopeType: "channel", ProductID: "ngep", ChannelName: "stable"},
					{Role: identity.RolePublisher, Effect: "deny", ScopeType: "product", ProductID: "ngep"},
				},
			}

			if err := test.call(service, principal, record); !errors.Is(err, ErrReleaseNotFound) {
				t.Fatalf("%s error = %v, want %v", test.name, err, ErrReleaseNotFound)
			}
			if repository.getCalls != 0 {
				t.Fatalf("%s queried denied release %d times", test.name, repository.getCalls)
			}
			if stored := repository.releases[record.ID]; !reflect.DeepEqual(stored, record) {
				t.Fatalf("%s changed denied release: got=%#v want=%#v", test.name, stored, record)
			}
		})
	}
}

func TestGovernedSubjectWithoutProductOrChannelPermissionCannotReplayPublication(t *testing.T) {
	t.Parallel()

	operations := []struct {
		name string
		kind AttemptKind
		call func(*Service, identity.Principal, Release, string) (OperationResult, error)
	}{
		{
			name: "publish",
			kind: AttemptKindPublish,
			call: func(service *Service, principal identity.Principal, record Release, key string) (OperationResult, error) {
				return service.Publish(context.Background(), principal, record.ProductID, record.ID, record.LockVersion, key, testRequestContext())
			},
		},
		{
			name: "retry",
			kind: AttemptKindRetry,
			call: func(service *Service, principal identity.Principal, record Release, key string) (OperationResult, error) {
				return service.Retry(context.Background(), principal, record.ProductID, record.ID, record.LockVersion, key, testRequestContext())
			},
		},
	}
	authorizations := []struct {
		name         string
		principal    identity.Principal
		wantGetCalls int
	}{
		{
			name: "no product permission",
			principal: identity.Principal{
				Subject: "governed-outsider", Kind: identity.PrincipalKindHuman, Governed: true,
			},
			wantGetCalls: 0,
		},
		{
			name: "product permission but channel denied",
			principal: identity.Principal{
				Subject: "governed-channel-denied", Kind: identity.PrincipalKindHuman, Governed: true,
				RoleScopes: []identity.RoleScope{
					{Role: identity.RolePublisher, Effect: "allow", ScopeType: "product", ProductID: "ngep"},
					{Role: identity.RoleApprover, Effect: "allow", ScopeType: "product", ProductID: "ngep"},
					{Role: identity.RolePublisher, Effect: "deny", ScopeType: "channel", ProductID: "ngep", ChannelName: "stable"},
					{Role: identity.RoleApprover, Effect: "deny", ScopeType: "channel", ProductID: "ngep", ChannelName: "stable"},
				},
			},
			wantGetCalls: 1,
		},
	}

	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()
			for _, authorization := range authorizations {
				t.Run(authorization.name, func(t *testing.T) {
					t.Parallel()
					service := newTestReleaseService()
					repository := service.repository.(*memoryReleaseRepository)
					releaseID := uuid.New()
					key := operation.name + "-replay-request-12345678"
					record := Release{
						ID: releaseID, ProductID: "ngep", Channel: "stable", Status: StatusPublishing, LockVersion: 8,
					}
					repository.releases[releaseID] = record
					repository.attempts[releaseAttemptKey(releaseID, operation.kind, key)] = Attempt{
						ID: uuid.New(), ReleaseID: releaseID, Kind: operation.kind, IdempotencyKey: key, Status: AttemptStatusPending,
					}

					result, err := operation.call(service, authorization.principal, record, key)
					if !errors.Is(err, ErrReleaseNotFound) {
						t.Fatalf("%s replay error = %v, want %v", operation.name, err, ErrReleaseNotFound)
					}
					if !reflect.DeepEqual(result, OperationResult{}) {
						t.Fatalf("%s replay result = %#v, want empty result", operation.name, result)
					}
					if repository.getCalls != authorization.wantGetCalls || repository.findAttemptCalls != 0 {
						t.Fatalf("%s replay queried release=%d attempt=%d, want release=%d attempt=0", operation.name, repository.getCalls, repository.findAttemptCalls, authorization.wantGetCalls)
					}
				})
			}
		})
	}
}

func TestGovernedChannelDeniedAndMissingReleaseAreExternallyEquivalent(t *testing.T) {
	t.Parallel()

	type operationResult struct {
		release Release
		attempt Attempt
		err     error
	}
	tests := []struct {
		name   string
		status Status
		call   func(*Service, identity.Principal, Release, uuid.UUID) operationResult
	}{
		{name: "get", status: StatusDraft, call: func(service *Service, principal identity.Principal, record Release, releaseID uuid.UUID) operationResult {
			releaseRecord, err := service.Get(context.Background(), principal, record.ProductID, releaseID)
			return operationResult{release: releaseRecord, err: err}
		}},
		{name: "submit", status: StatusDraft, call: func(service *Service, principal identity.Principal, record Release, releaseID uuid.UUID) operationResult {
			releaseRecord, err := service.Submit(context.Background(), principal, record.ProductID, releaseID, record.LockVersion, testRequestContext())
			return operationResult{release: releaseRecord, err: err}
		}},
		{name: "approve", status: StatusSubmitted, call: func(service *Service, principal identity.Principal, record Release, releaseID uuid.UUID) operationResult {
			releaseRecord, err := service.Approve(context.Background(), principal, record.ProductID, releaseID, record.LockVersion, testRequestContext())
			return operationResult{release: releaseRecord, err: err}
		}},
		{name: "reject", status: StatusSubmitted, call: func(service *Service, principal identity.Principal, record Release, releaseID uuid.UUID) operationResult {
			releaseRecord, err := service.Reject(context.Background(), principal, record.ProductID, releaseID, record.LockVersion, "policy rejection", testRequestContext())
			return operationResult{release: releaseRecord, err: err}
		}},
		{name: "publish", status: StatusApproved, call: func(service *Service, principal identity.Principal, record Release, releaseID uuid.UUID) operationResult {
			result, err := service.Publish(context.Background(), principal, record.ProductID, releaseID, record.LockVersion, "publish-invisible-12345678", testRequestContext())
			return operationResult{release: result.Release, attempt: result.Attempt, err: err}
		}},
		{name: "retry", status: StatusFailed, call: func(service *Service, principal identity.Principal, record Release, releaseID uuid.UUID) operationResult {
			result, err := service.Retry(context.Background(), principal, record.ProductID, releaseID, record.LockVersion, "retry-invisible-12345678", testRequestContext())
			return operationResult{release: result.Release, attempt: result.Attempt, err: err}
		}},
		{name: "revoke", status: StatusPublished, call: func(service *Service, principal identity.Principal, record Release, releaseID uuid.UUID) operationResult {
			result, err := service.Revoke(context.Background(), principal, record.ProductID, releaseID, record.LockVersion, "security revocation", "revoke-invisible-12345678", testRequestContext())
			return operationResult{release: result.Release, attempt: result.Attempt, err: err}
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service := newTestReleaseService()
			repository := service.repository.(*memoryReleaseRepository)
			record := Release{
				ID: uuid.New(), ProductID: "ngep", Channel: "stable", Status: test.status, LockVersion: 4,
				SubmittedBy: "original-publisher",
			}
			repository.releases[record.ID] = record
			principal := identity.Principal{
				Subject: "governed-channel-denied", Kind: identity.PrincipalKindHuman, Governed: true,
				RoleScopes: []identity.RoleScope{
					{Role: identity.RolePublisher, Effect: "allow", ScopeType: "product", ProductID: "ngep"},
					{Role: identity.RoleApprover, Effect: "allow", ScopeType: "product", ProductID: "ngep"},
					{Role: identity.RolePublisher, Effect: "deny", ScopeType: "channel", ProductID: "ngep", ChannelName: "stable"},
					{Role: identity.RoleApprover, Effect: "deny", ScopeType: "channel", ProductID: "ngep", ChannelName: "stable"},
				},
			}

			existing := test.call(service, principal, record, record.ID)
			missing := test.call(service, principal, record, uuid.New())
			for outcomeName, outcome := range map[string]operationResult{"existing": existing, "missing": missing} {
				if !errors.Is(outcome.err, ErrReleaseNotFound) {
					t.Errorf("%s %s error = %v, want %v", test.name, outcomeName, outcome.err, ErrReleaseNotFound)
				}
				if !reflect.DeepEqual(outcome.release, Release{}) || !reflect.DeepEqual(outcome.attempt, Attempt{}) {
					t.Errorf("%s %s leaked release=%#v attempt=%#v", test.name, outcomeName, outcome.release, outcome.attempt)
				}
			}
			if existing.err != nil && missing.err != nil && existing.err.Error() != missing.err.Error() {
				t.Errorf("%s errors differ: existing=%q missing=%q", test.name, existing.err, missing.err)
			}
			if stored := repository.releases[record.ID]; !reflect.DeepEqual(stored, record) {
				t.Errorf("%s changed channel-denied release: got=%#v want=%#v", test.name, stored, record)
			}
		})
	}
}

func TestGovernedChannelOnlyScopeCanReadMatchingRelease(t *testing.T) {
	t.Parallel()

	service := newTestReleaseService()
	repository := service.repository.(*memoryReleaseRepository)
	record := Release{ID: uuid.New(), ProductID: "ngep", Channel: "stable", Status: StatusDraft, LockVersion: 1}
	repository.releases[record.ID] = record
	principal := identity.Principal{
		Subject: "governed-stable-viewer", Kind: identity.PrincipalKindHuman, Governed: true,
		RoleScopes: []identity.RoleScope{{
			Role: identity.RoleViewer, Effect: "allow", ScopeType: "channel", ProductID: "ngep", ChannelName: "stable",
		}},
	}

	got, err := service.Get(context.Background(), principal, record.ProductID, record.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !reflect.DeepEqual(got, record) {
		t.Fatalf("Get() = %#v, want %#v", got, record)
	}
}

func TestCreateRejectsArtifactFromAnotherProductWithoutLeakingItsExistence(t *testing.T) {
	t.Parallel()

	service := newTestReleaseService()
	reader := service.artifacts.(*memoryReleaseArtifactReader)
	artifactID := validCreateCommand().ArtifactIDs[0]
	foreign := reader.artifacts[artifactID]
	foreign.ProductID = "other-product"
	reader.artifacts[artifactID] = foreign

	_, err := service.Create(context.Background(), releasePrincipal("alice", identity.RolePublisher), validCreateCommand(), testRequestContext())
	if !errors.Is(err, ErrArtifactProductMismatch) {
		t.Fatalf("Create() error = %v, want %v", err, ErrArtifactProductMismatch)
	}
}

func TestPublishIsAtomicAndIdempotent(t *testing.T) {
	t.Parallel()

	service := newTestReleaseService()
	publisher := releasePrincipal("alice", identity.RolePublisher)
	approver := releasePrincipal("bob", identity.RoleApprover)
	created, err := service.Create(context.Background(), publisher, validCreateCommand(), testRequestContext())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	submitted, err := service.Submit(context.Background(), publisher, created.ProductID, created.ID, created.LockVersion, testRequestContext())
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	approved, err := service.Approve(context.Background(), approver, submitted.ProductID, submitted.ID, submitted.LockVersion, testRequestContext())
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	first, err := service.Publish(context.Background(), publisher, approved.ProductID, approved.ID, approved.LockVersion, "publish-request-12345678", testRequestContext())
	if err != nil {
		t.Fatalf("Publish() error = %v", err)
	}
	second, err := service.Publish(context.Background(), publisher, approved.ProductID, approved.ID, approved.LockVersion, "publish-request-12345678", testRequestContext())
	if err != nil {
		t.Fatalf("idempotent Publish() error = %v", err)
	}
	if first.Release.Status != StatusPublishing || first.Release.LockVersion != approved.LockVersion+1 {
		t.Fatalf("first Publish() release = %#v", first.Release)
	}
	if second.Attempt.ID != first.Attempt.ID || second.Attempt.IdempotencyKey != first.Attempt.IdempotencyKey {
		t.Fatalf("idempotent attempts differ: first=%#v second=%#v", first.Attempt, second.Attempt)
	}
	jobsRecorder := service.jobs.(*recordingReleaseJobs)
	if len(jobsRecorder.items) != 1 || jobsRecorder.items[0].Kind != "catalog.publish.v1" {
		t.Fatalf("publication jobs = %#v", jobsRecorder.items)
	}
	auditor := service.auditor.(*recordingReleaseAuditor)
	var publishAudits int
	for _, command := range auditor.commands {
		if command.Action == "release.publish" {
			publishAudits++
		}
	}
	if publishAudits != 1 {
		t.Fatalf("release.publish audit events = %d, want 1", publishAudits)
	}
}

func TestRevocationRequiresApproverReasonAndPreservesPublishedStatus(t *testing.T) {
	t.Parallel()

	service := newTestReleaseService()
	repository := service.repository.(*memoryReleaseRepository)
	publisher := releasePrincipal("alice", identity.RolePublisher)
	approver := releasePrincipal("bob", identity.RoleApprover)
	created, err := service.Create(context.Background(), publisher, validCreateCommand(), testRequestContext())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	record := repository.releases[created.ID]
	record.Status = StatusPublished
	record.LockVersion = 6
	repository.releases[created.ID] = record

	_, err = service.Revoke(context.Background(), approver, record.ProductID, record.ID, record.LockVersion, "", "revoke-request-12345678", testRequestContext())
	if !errors.Is(err, ErrRevocationReasonRequired) {
		t.Fatalf("Revoke(empty reason) error = %v, want %v", err, ErrRevocationReasonRequired)
	}
	result, err := service.Revoke(context.Background(), approver, record.ProductID, record.ID, record.LockVersion, "critical signing key compromise", "revoke-request-12345678", testRequestContext())
	if err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if result.Release.Status != StatusPublished || result.Release.RevokedAt == nil || result.Release.RevokedBy != "bob" {
		t.Fatalf("revoked release = %#v", result.Release)
	}
	_, err = service.Revoke(context.Background(), approver, record.ProductID, record.ID, result.Release.LockVersion, "duplicate", "revoke-request-87654321", testRequestContext())
	if !errors.Is(err, ErrReleaseAlreadyRevoked) {
		t.Fatalf("duplicate Revoke() error = %v, want %v", err, ErrReleaseAlreadyRevoked)
	}
}

func TestRetryRequiresApproverAndFreshOptimisticLock(t *testing.T) {
	t.Parallel()

	service := newTestReleaseService()
	repository := service.repository.(*memoryReleaseRepository)
	publisher := releasePrincipal("alice", identity.RolePublisher)
	approver := releasePrincipal("bob", identity.RoleApprover)
	created, err := service.Create(context.Background(), publisher, validCreateCommand(), testRequestContext())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	failed := repository.releases[created.ID]
	failed.Status = StatusFailed
	failed.LockVersion = 7
	repository.releases[created.ID] = failed

	_, err = service.Retry(context.Background(), publisher, failed.ProductID, failed.ID, failed.LockVersion, "retry-request-12345678", testRequestContext())
	if !errors.Is(err, identity.ErrActionDenied) {
		t.Fatalf("publisher Retry() error = %v, want %v", err, identity.ErrActionDenied)
	}
	_, err = service.Retry(context.Background(), approver, failed.ProductID, failed.ID, failed.LockVersion-1, "retry-request-12345678", testRequestContext())
	if !errors.Is(err, ErrStaleRelease) {
		t.Fatalf("stale Retry() error = %v, want %v", err, ErrStaleRelease)
	}
	result, err := service.Retry(context.Background(), approver, failed.ProductID, failed.ID, failed.LockVersion, "retry-request-12345678", testRequestContext())
	if err != nil {
		t.Fatalf("Retry() error = %v", err)
	}
	if result.Release.Status != StatusPublishing || result.Attempt.Kind != AttemptKindRetry {
		t.Fatalf("Retry() result = %#v", result)
	}
}

func TestRejectRequiresIndependentApproverAndReason(t *testing.T) {
	t.Parallel()

	service := newTestReleaseService()
	publisher := releasePrincipal("alice", identity.RolePublisher)
	created, err := service.Create(context.Background(), publisher, validCreateCommand(), testRequestContext())
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	submitted, err := service.Submit(context.Background(), publisher, created.ProductID, created.ID, created.LockVersion, testRequestContext())
	if err != nil {
		t.Fatalf("Submit() error = %v", err)
	}
	_, err = service.Reject(context.Background(), releasePrincipal("alice", identity.RoleApprover), submitted.ProductID, submitted.ID, submitted.LockVersion, "duplicate submission", testRequestContext())
	if !errors.Is(err, ErrSelfApprovalForbidden) {
		t.Fatalf("self Reject() error = %v, want %v", err, ErrSelfApprovalForbidden)
	}
	approver := releasePrincipal("bob", identity.RoleApprover)
	_, err = service.Reject(context.Background(), approver, submitted.ProductID, submitted.ID, submitted.LockVersion, "", testRequestContext())
	if !errors.Is(err, ErrRejectionReasonRequired) {
		t.Fatalf("Reject(empty reason) error = %v, want %v", err, ErrRejectionReasonRequired)
	}
	rejected, err := service.Reject(context.Background(), approver, submitted.ProductID, submitted.ID, submitted.LockVersion, "duplicate submission", testRequestContext())
	if err != nil {
		t.Fatalf("Reject() error = %v", err)
	}
	if rejected.Status != StatusRejected || rejected.RejectedBy != "bob" || rejected.RejectionReason != "duplicate submission" {
		t.Fatalf("rejected release = %#v", rejected)
	}
}

func newTestReleaseService() *Service {
	repository := &memoryReleaseRepository{releases: map[uuid.UUID]Release{}, attempts: map[string]Attempt{}}
	productRecord := product.Product{
		ID: "ngep", Status: product.ProductStatusActive, VersionScheme: "semver",
		CompatibilityKeys: []string{"os", "arch"},
		Channels:          []product.Channel{{ProductID: "ngep", Name: "stable"}},
	}
	artifactID := uuid.MustParse("019c1547-e880-7831-949c-7302a3472410")
	artifactRecord := artifact.Artifact{
		ID: artifactID, ProductID: "ngep", ArtifactType: "desktop", Filename: "ngep.tar",
		ContentType: "application/x-tar", Size: 3,
		SHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	}
	return NewService(
		repository,
		passThroughReleaseTransactor{},
		&memoryReleaseProductReader{products: map[string]product.Product{"ngep": productRecord}},
		&memoryReleaseArtifactReader{artifacts: map[uuid.UUID]artifact.Artifact{artifactID: artifactRecord}},
		&recordingReleaseAuditor{},
		&recordingReleaseJobs{},
	)
}

func validCreateCommand() CreateCommand {
	notes := []byte("# Xminds 1.2.3\n\nProduction release.")
	compatibility := []byte(`{"os":["darwin"],"arch":["arm64"]}`)
	return CreateCommand{
		ProductID: "ngep", Channel: "stable", Version: "1.2.3",
		ReleaseNotes: notes, ReleaseNotesSHA256: digestForReleaseTest(notes),
		Compatibility: compatibility, CompatibilitySHA256: digestForReleaseTest(compatibility),
		ArtifactIDs: []uuid.UUID{uuid.MustParse("019c1547-e880-7831-949c-7302a3472410")},
		Source: Source{
			Repository: "https://github.example.com/xminds/ngep.git",
			CommitSHA:  "0123456789abcdef0123456789abcdef01234567",
			Tag:        "v1.2.3", PipelineRef: "github-actions:run/123456",
		},
	}
}

func digestForReleaseTest(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func releasePrincipal(subject string, role identity.Role) identity.Principal {
	return identity.Principal{Subject: subject, Kind: identity.PrincipalKindHuman, Roles: []identity.Role{role}, ProductIDs: []string{"ngep"}}
}

func testRequestContext() RequestContext {
	return RequestContext{RequestID: "019c1547-e880-7831-949c-7302a34724d0", SourceIP: "192.0.2.50"}
}

type passThroughReleaseTransactor struct{}

func (passThroughReleaseTransactor) WithinTransaction(ctx context.Context, function func(pgx.Tx) error) error {
	return function(nil)
}

type memoryReleaseProductReader struct {
	products map[string]product.Product
}

func (reader *memoryReleaseProductReader) Get(_ context.Context, productID string) (product.Product, error) {
	record, found := reader.products[productID]
	if !found {
		return product.Product{}, product.ErrProductNotFound
	}
	return record, nil
}

type memoryReleaseArtifactReader struct {
	artifacts map[uuid.UUID]artifact.Artifact
}

func (reader *memoryReleaseArtifactReader) Get(_ context.Context, _ identity.Principal, productID string, artifactID uuid.UUID) (artifact.Artifact, error) {
	record, found := reader.artifacts[artifactID]
	if !found || record.ProductID != productID {
		return artifact.Artifact{}, artifact.ErrArtifactNotFound
	}
	return record, nil
}

type memoryReleaseRepository struct {
	releases         map[uuid.UUID]Release
	attempts         map[string]Attempt
	getCalls         int
	findAttemptCalls int
}

func (repository *memoryReleaseRepository) FindAttempt(_ context.Context, _ pgx.Tx, releaseID uuid.UUID, kind AttemptKind, idempotencyKey string) (Attempt, error) {
	repository.findAttemptCalls++
	attempt, found := repository.attempts[releaseAttemptKey(releaseID, kind, idempotencyKey)]
	if !found {
		return Attempt{}, ErrAttemptNotFound
	}
	return attempt, nil
}

func (*memoryReleaseRepository) LockOperation(context.Context, pgx.Tx, uuid.UUID, AttemptKind, string) error {
	return nil
}

func (repository *memoryReleaseRepository) CreateAttempt(_ context.Context, _ pgx.Tx, attempt Attempt) (Attempt, error) {
	key := releaseAttemptKey(attempt.ReleaseID, attempt.Kind, attempt.IdempotencyKey)
	if _, exists := repository.attempts[key]; exists {
		return Attempt{}, ErrAttemptAlreadyExists
	}
	attempt.Number = 1
	for _, existing := range repository.attempts {
		if existing.ReleaseID == attempt.ReleaseID && existing.Number >= attempt.Number {
			attempt.Number = existing.Number + 1
		}
	}
	repository.attempts[key] = attempt
	return attempt, nil
}

func (repository *memoryReleaseRepository) Revoke(_ context.Context, _ pgx.Tx, command RevokeCommand) (Release, error) {
	record, found := repository.releases[command.ReleaseID]
	if !found || record.ProductID != command.ProductID {
		return Release{}, ErrReleaseNotFound
	}
	if record.LockVersion != command.ExpectedLockVersion {
		return Release{}, ErrStaleRelease
	}
	if record.Status != StatusPublished {
		return Release{}, ErrInvalidTransition
	}
	if record.RevokedAt != nil {
		return Release{}, ErrReleaseAlreadyRevoked
	}
	record.LockVersion++
	record.RevokedAt = &command.At
	record.RevokedBy = command.Actor
	record.RevocationReason = command.Reason
	record.UpdatedAt = command.At
	repository.releases[record.ID] = record
	return record, nil
}

func releaseAttemptKey(releaseID uuid.UUID, kind AttemptKind, idempotencyKey string) string {
	return releaseID.String() + ":" + string(kind) + ":" + idempotencyKey
}

func (repository *memoryReleaseRepository) Create(_ context.Context, _ pgx.Tx, record Release) error {
	repository.releases[record.ID] = record
	return nil
}

func (repository *memoryReleaseRepository) Get(_ context.Context, productID string, releaseID uuid.UUID) (Release, error) {
	repository.getCalls++
	record, found := repository.releases[releaseID]
	if !found || record.ProductID != productID {
		return Release{}, ErrReleaseNotFound
	}
	return record, nil
}

func (repository *memoryReleaseRepository) Transition(_ context.Context, _ pgx.Tx, command TransitionCommand) (Release, error) {
	record, found := repository.releases[command.ReleaseID]
	if !found || record.ProductID != command.ProductID {
		return Release{}, ErrReleaseNotFound
	}
	if record.LockVersion != command.ExpectedLockVersion {
		return Release{}, ErrStaleRelease
	}
	if !TransitionAllowed(record.Status, command.To) {
		return Release{}, ErrInvalidTransition
	}
	record.Status = command.To
	record.LockVersion++
	record.UpdatedAt = command.At
	switch command.To {
	case StatusSubmitted:
		record.SubmittedBy = command.Actor
		record.SubmittedAt = &command.At
	case StatusApproved:
		record.ApprovedBy = command.Actor
		record.ApprovedAt = &command.At
	case StatusRejected:
		record.RejectedBy = command.Actor
		record.RejectedAt = &command.At
		record.RejectionReason = command.Reason
	}
	repository.releases[record.ID] = record
	return record, nil
}

type recordingReleaseAuditor struct {
	commands []audit.AppendCommand
}

func (recorder *recordingReleaseAuditor) Append(_ context.Context, _ pgx.Tx, command audit.AppendCommand) (audit.Event, error) {
	recorder.commands = append(recorder.commands, command)
	return audit.Event{}, nil
}

type recordingReleaseJobs struct {
	items []jobs.Job
}

func (recorder *recordingReleaseJobs) Enqueue(_ context.Context, _ pgx.Tx, job jobs.Job) error {
	recorder.items = append(recorder.items, job)
	return nil
}

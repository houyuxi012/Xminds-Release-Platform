package iam

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
)

func TestReauthenticationChallengeBindsActorOperationAndCompletingToken(t *testing.T) {
	harness := newReauthenticationHarness(t)
	created, err := harness.service.CreateChallenge(context.Background(), harness.creator, ReauthenticationOperationRoleBindingCreate, harness.request)
	if err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}
	stored := harness.repository.challenges[created.ID]
	if created.Status != ReauthenticationStatusPending || created.Operation != ReauthenticationOperationRoleBindingCreate || !created.ExpiresAt.Equal(harness.now.Add(5*time.Minute)) {
		t.Fatalf("created challenge = %#v", created)
	}
	if stored.CreatedTokenDigest == harness.creator.TokenID || stored.CreatedTokenDigest != sha256Hex(harness.creator.TokenID) {
		t.Fatalf("created token binding = %q", stored.CreatedTokenDigest)
	}

	completed, err := harness.service.CompleteChallenge(context.Background(), harness.completer, created.ID, CompleteReauthenticationCommand{}, harness.request)
	if err != nil {
		t.Fatalf("CompleteChallenge() error = %v", err)
	}
	stored = harness.repository.challenges[created.ID]
	if completed.Evidence == "" || stored.EvidenceDigest == completed.Evidence || stored.EvidenceDigest != sha256Hex(completed.Evidence) {
		t.Fatalf("evidence storage = response %q digest %q", completed.Evidence, stored.EvidenceDigest)
	}
	if stored.VerifiedTokenDigest != sha256Hex(harness.completer.TokenID) || !completed.ExpiresAt.Equal(harness.now.Add(2*time.Minute)) {
		t.Fatalf("verified binding = %#v", stored)
	}
	if _, err := harness.service.CompleteChallenge(context.Background(), harness.completer, created.ID, CompleteReauthenticationCommand{}, harness.request); !errors.Is(err, ErrHighRiskConfirmationRequired) {
		t.Fatalf("second CompleteChallenge() error = %v", err)
	}

	proof := HighRiskProof{ChallengeID: created.ID.String(), Evidence: completed.Evidence, Confirmed: true}
	if err := harness.service.Authorize(context.Background(), harness.creator, string(ReauthenticationOperationRoleBindingCreate), proof, harness.request); !errors.Is(err, ErrHighRiskConfirmationRequired) {
		t.Fatalf("Authorize() with creating token error = %v", err)
	}
	if err := harness.service.Authorize(context.Background(), harness.completer, string(ReauthenticationOperationRoleBindingDelete), proof, harness.request); !errors.Is(err, ErrHighRiskConfirmationRequired) {
		t.Fatalf("Authorize() with wrong operation error = %v", err)
	}
	if harness.repository.challenges[created.ID].Status != ReauthenticationStatusVerified {
		t.Fatal("failed authorization consumed the challenge")
	}
	mutationRequest := RequestContext{RequestID: "018f835d-7e4b-7abc-9f42-67a2f5f48e14", SourceIP: "192.0.2.25"}
	if err := harness.service.Authorize(context.Background(), harness.completer, string(ReauthenticationOperationRoleBindingCreate), proof, mutationRequest); err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	consumptionAudit := harness.auditor.commands[len(harness.auditor.commands)-1]
	if consumptionAudit.RequestID != mutationRequest.RequestID || consumptionAudit.SourceIP != mutationRequest.SourceIP {
		t.Fatalf("consume audit request context = %#v", consumptionAudit)
	}
	if harness.repository.challenges[created.ID].Status != ReauthenticationStatusConsumed {
		t.Fatalf("challenge status = %q", harness.repository.challenges[created.ID].Status)
	}
	if err := harness.service.Authorize(context.Background(), harness.completer, string(ReauthenticationOperationRoleBindingCreate), proof, harness.request); !errors.Is(err, ErrHighRiskConfirmationRequired) {
		t.Fatalf("replayed Authorize() error = %v", err)
	}
}

func TestReauthenticationChallengeRejectsUnsupportedActorsOperationsAndOIDCAssurance(t *testing.T) {
	harness := newReauthenticationHarness(t)
	workload := harness.creator
	workload.Kind, workload.Provider = identity.PrincipalKindWorkload, identity.WorkloadProviderAPIToken
	if _, err := harness.service.CreateChallenge(context.Background(), workload, ReauthenticationOperationRoleBindingCreate, harness.request); !errors.Is(err, ErrHighRiskConfirmationRequired) {
		t.Fatalf("workload CreateChallenge() error = %v", err)
	}
	humanChallenge, err := harness.service.CreateChallenge(context.Background(), harness.creator, ReauthenticationOperationRoleBindingCreate, harness.request)
	if err != nil {
		t.Fatal(err)
	}
	workload.Subject = harness.creator.Subject
	if result, err := harness.service.CompleteChallenge(context.Background(), workload, humanChallenge.ID, CompleteReauthenticationCommand{}, harness.request); !errors.Is(err, ErrHighRiskConfirmationRequired) || result.Evidence != "" {
		t.Fatalf("workload CompleteChallenge() = %#v, %v", result, err)
	}
	if _, err := harness.service.CreateChallenge(context.Background(), harness.creator, ReauthenticationOperation("identity.directory.sync"), harness.request); !errors.Is(err, ErrHighRiskConfirmationRequired) {
		t.Fatalf("unsupported operation error = %v", err)
	}

	for _, testCase := range []struct {
		name  string
		actor identity.Principal
	}{
		{name: "stale", actor: reauthenticationActor(harness.now.Add(-5*time.Minute-time.Microsecond), 1, "fresh-token")},
		{name: "future", actor: reauthenticationActor(harness.now.Add(30*time.Second+time.Microsecond), 1, "fresh-token")},
		{name: "missing authentication time", actor: reauthenticationActor(time.Time{}, 1, "fresh-token")},
		{name: "missing mfa", actor: reauthenticationActor(harness.now.Add(-time.Minute), 0, "fresh-token")},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			created, err := harness.service.CreateChallenge(context.Background(), harness.creator, ReauthenticationOperationUserDisable, harness.request)
			if err != nil {
				t.Fatalf("CreateChallenge() error = %v", err)
			}
			if result, completeErr := harness.service.CompleteChallenge(context.Background(), testCase.actor, created.ID, CompleteReauthenticationCommand{}, harness.request); !errors.Is(completeErr, ErrHighRiskConfirmationRequired) || result.Evidence != "" {
				t.Fatalf("CompleteChallenge() = %#v, %v", result, completeErr)
			}
			if harness.repository.challenges[created.ID].Status != ReauthenticationStatusPending {
				t.Fatalf("challenge status = %q", harness.repository.challenges[created.ID].Status)
			}
		})
	}
}

func TestReauthenticationStateRollsBackWhenImmutableAuditFails(t *testing.T) {
	harness := newReauthenticationHarness(t)
	harness.auditor.err = errors.New("audit unavailable")
	if _, err := harness.service.CreateChallenge(context.Background(), harness.creator, ReauthenticationOperationUserDisable, harness.request); err == nil {
		t.Fatal("CreateChallenge() error = nil")
	}
	if len(harness.repository.challenges) != 0 {
		t.Fatalf("challenge count = %d", len(harness.repository.challenges))
	}

	harness.auditor.err = nil
	created, err := harness.service.CreateChallenge(context.Background(), harness.creator, ReauthenticationOperationUserDisable, harness.request)
	if err != nil {
		t.Fatalf("CreateChallenge() error = %v", err)
	}
	harness.auditor.err = errors.New("audit unavailable")
	if _, err := harness.service.CompleteChallenge(context.Background(), harness.completer, created.ID, CompleteReauthenticationCommand{}, harness.request); err == nil {
		t.Fatal("CompleteChallenge() error = nil")
	}
	if harness.repository.challenges[created.ID].Status != ReauthenticationStatusPending {
		t.Fatalf("challenge status after completion rollback = %q", harness.repository.challenges[created.ID].Status)
	}

	harness.auditor.err = nil
	completed, err := harness.service.CompleteChallenge(context.Background(), harness.completer, created.ID, CompleteReauthenticationCommand{}, harness.request)
	if err != nil {
		t.Fatalf("CompleteChallenge() error = %v", err)
	}
	harness.auditor.err = errors.New("audit unavailable")
	proof := HighRiskProof{ChallengeID: created.ID.String(), Evidence: completed.Evidence, Confirmed: true}
	if err := harness.service.Authorize(context.Background(), harness.completer, string(ReauthenticationOperationUserDisable), proof, harness.request); !errors.Is(err, ErrHighRiskConfirmationRequired) {
		t.Fatalf("Authorize() error = %v", err)
	}
	if harness.repository.challenges[created.ID].Status != ReauthenticationStatusVerified {
		t.Fatalf("challenge status after consume rollback = %q", harness.repository.challenges[created.ID].Status)
	}
}

func TestReauthenticationAuditNeverContainsChallengeEvidenceOrToken(t *testing.T) {
	harness := newReauthenticationHarness(t)
	created, err := harness.service.CreateChallenge(context.Background(), harness.creator, ReauthenticationOperationSSOEnable, harness.request)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := harness.service.CompleteChallenge(context.Background(), harness.completer, created.ID, CompleteReauthenticationCommand{}, harness.request)
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.service.Authorize(context.Background(), harness.completer, string(ReauthenticationOperationSSOEnable), HighRiskProof{ChallengeID: created.ID.String(), Evidence: completed.Evidence, Confirmed: true}, harness.request); err != nil {
		t.Fatal(err)
	}
	for _, command := range harness.auditor.commands {
		serialized := fmt.Sprintf("%v", reflect.ValueOf(command))
		for _, secret := range []string{created.ID.String(), completed.Evidence, harness.creator.TokenID, harness.completer.TokenID} {
			if strings.Contains(serialized, secret) {
				t.Fatalf("audit command contains sensitive challenge material: %#v", command)
			}
		}
	}
}

type reauthenticationHarness struct {
	service    *ReauthenticationService
	repository *memoryReauthenticationRepository
	auditor    *reauthenticationAuditRecorder
	now        time.Time
	creator    identity.Principal
	completer  identity.Principal
	request    RequestContext
}

func newReauthenticationHarness(t *testing.T) *reauthenticationHarness {
	t.Helper()
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	repository := &memoryReauthenticationRepository{challenges: map[uuid.UUID]ReauthenticationChallenge{}}
	auditor := &reauthenticationAuditRecorder{}
	service, err := NewReauthenticationService(ReauthenticationConfig{
		Repository: repository, Auditor: auditor, Local: reauthenticationLocalVerifier{}, Clock: func() time.Time { return now },
		Policy: DefaultReauthenticationPolicy(),
	})
	if err != nil {
		t.Fatal(err)
	}
	creator := reauthenticationActor(now.Add(-30*time.Minute), 0, "oidc-old-token")
	return &reauthenticationHarness{
		service: service, repository: repository, auditor: auditor, now: now, creator: creator,
		completer: reauthenticationActor(now.Add(-time.Minute), 1, "oidc-fresh-token"),
		request:   RequestContext{RequestID: "018f835d-7e4b-7abc-9f42-67a2f5f48e13", SourceIP: "127.0.0.1"},
	}
}

func reauthenticationActor(authenticatedAt time.Time, assurance int, tokenID string) identity.Principal {
	return identity.Principal{
		Subject: "admin", Kind: identity.PrincipalKindHuman, Roles: []identity.Role{identity.RoleAdmin}, TokenID: tokenID,
		AuthenticatedAt: authenticatedAt, AuthenticationAssurance: assurance,
	}
}

type memoryReauthenticationRepository struct {
	challenges map[uuid.UUID]ReauthenticationChallenge
}

func (repository *memoryReauthenticationRepository) WithinTransaction(_ context.Context, function func(pgx.Tx) error) error {
	snapshot := make(map[uuid.UUID]ReauthenticationChallenge, len(repository.challenges))
	for key, value := range repository.challenges {
		snapshot[key] = value
	}
	if err := function(nil); err != nil {
		repository.challenges = snapshot
		return err
	}
	return nil
}

func (repository *memoryReauthenticationRepository) CleanupReauthenticationChallenges(context.Context, pgx.Tx, time.Time, time.Duration, int) error {
	return nil
}

func (repository *memoryReauthenticationRepository) InsertReauthenticationChallenge(_ context.Context, _ pgx.Tx, challenge ReauthenticationChallenge) error {
	repository.challenges[challenge.ID] = challenge
	return nil
}

func (repository *memoryReauthenticationRepository) GetReauthenticationChallenge(_ context.Context, _ pgx.Tx, id uuid.UUID) (ReauthenticationChallenge, error) {
	challenge, ok := repository.challenges[id]
	if !ok {
		return ReauthenticationChallenge{}, ErrHighRiskConfirmationRequired
	}
	return challenge, nil
}

func (repository *memoryReauthenticationRepository) SaveReauthenticationChallenge(_ context.Context, _ pgx.Tx, challenge ReauthenticationChallenge, expectedVersion int64) error {
	current, ok := repository.challenges[challenge.ID]
	if !ok || current.Version != expectedVersion {
		return ErrIAMConflict
	}
	repository.challenges[challenge.ID] = challenge
	return nil
}

type reauthenticationAuditRecorder struct {
	commands []audit.AppendCommand
	err      error
}

func (recorder *reauthenticationAuditRecorder) Append(_ context.Context, _ pgx.Tx, command audit.AppendCommand) (audit.Event, error) {
	if recorder.err != nil {
		return audit.Event{}, recorder.err
	}
	recorder.commands = append(recorder.commands, command)
	return audit.Event{}, nil
}

type reauthenticationLocalVerifier struct{}

func (reauthenticationLocalVerifier) Reauthenticate(context.Context, identity.Principal, CompleteReauthenticationCommand, RequestContext) error {
	return nil
}

func sha256Hex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

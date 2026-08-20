package endpoint

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/catalog"
	"xminds-release-platform/internal/identity"
)

type CatalogReader interface {
	Current(ctx context.Context, productID, channel string) (catalog.VersionRecord, error)
}

type Probe interface {
	Verify(ctx context.Context, endpoint Endpoint, current catalog.VersionRecord) (ProbeResult, error)
}

type AuditAppender interface {
	Append(ctx context.Context, tx pgx.Tx, command audit.AppendCommand) (audit.Event, error)
}

type ServiceConfig struct {
	Repository     Repository
	Transactor     Transactor
	Catalogs       CatalogReader
	Probe          Probe
	Auditor        AuditAppender
	DefaultChannel string
	Clock          func() time.Time
}

type Service struct {
	repository     Repository
	transactor     Transactor
	catalogs       CatalogReader
	probe          Probe
	auditor        AuditAppender
	authorizer     *identity.Authorizer
	defaultChannel string
	clock          func() time.Time
}

func NewService(config ServiceConfig) (*Service, error) {
	config.DefaultChannel = strings.TrimSpace(config.DefaultChannel)
	if config.Repository == nil {
		return nil, ErrEndpointRepository
	}
	if config.Transactor == nil {
		return nil, ErrEndpointTransactor
	}
	if config.Catalogs == nil || config.Probe == nil || config.Clock == nil || config.DefaultChannel == "" {
		return nil, ErrEndpointProbe
	}
	if config.Auditor == nil {
		return nil, ErrEndpointAudit
	}
	return &Service{
		repository: config.Repository, transactor: config.Transactor, catalogs: config.Catalogs,
		probe: config.Probe, auditor: config.Auditor, authorizer: identity.NewAuthorizer(),
		defaultChannel: config.DefaultChannel, clock: config.Clock,
	}, nil
}

func (service *Service) Register(ctx context.Context, principal identity.Principal, command RegisterCommand, request RequestContext) (Endpoint, error) {
	command = normalizeRegisterCommand(command)
	if err := validateRegisterCommand(command); err != nil {
		return Endpoint{}, err
	}
	if err := service.authorizer.Require(principal, identity.ActionIntegrationManage, command.ProductID); err != nil {
		return Endpoint{}, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return Endpoint{}, err
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	record := Endpoint{
		ID: id, ProductID: command.ProductID, Name: command.Name, Type: command.Type, Region: command.Region,
		Priority: command.Priority, BaseURL: command.BaseURL, PathPrefix: command.PathPrefix,
		HealthPath: command.HealthPath, TLSCARef: command.TLSCARef, Status: StatusPending,
		CreatedAt: now, UpdatedAt: now,
	}
	err = service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		if err := service.repository.Create(ctx, tx, record); err != nil {
			return err
		}
		_, err := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: principal, Action: "endpoint.register", ProductID: record.ProductID,
			ResourceType: "distribution_endpoint", ResourceID: record.ID.String(), Outcome: audit.OutcomeSuccess,
			RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"type": record.Type, "region": record.Region, "priority": record.Priority},
		})
		return err
	})
	return record, err
}

func (service *Service) Activate(ctx context.Context, principal identity.Principal, id uuid.UUID, request RequestContext) error {
	if service == nil || id == uuid.Nil {
		return ErrEndpointInvalid
	}
	record, err := service.repository.Get(ctx, id)
	if err != nil {
		return err
	}
	if record.Status == StatusDisabled {
		return ErrEndpointInvalid
	}
	if err := service.authorizer.Require(principal, identity.ActionIntegrationManage, record.ProductID); err != nil {
		return err
	}
	current, err := service.catalogs.Current(ctx, record.ProductID, service.defaultChannel)
	if err != nil {
		return err
	}
	expected, err := catalogDigests(current)
	if err != nil {
		return err
	}
	observed, err := service.probe.Verify(ctx, record, current)
	if err != nil {
		return errors.Join(ErrEndpointProbeFailed, err)
	}
	if observed != expected {
		return ErrCatalogDigestMismatch
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	return service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		updated, err := service.repository.MarkHealthy(ctx, tx, record.ID, observed.RootDigest, observed.TimestampDigest, now)
		if err != nil {
			return err
		}
		_, err = service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: principal, Action: "endpoint.activate", ProductID: record.ProductID,
			ResourceType: "distribution_endpoint", ResourceID: record.ID.String(), Outcome: audit.OutcomeSuccess,
			RequestID: request.RequestID, SourceIP: request.SourceIP,
			Metadata: map[string]any{"root_digest": updated.LastRootDigest, "timestamp_digest": updated.LastTimestampDigest},
		})
		return err
	})
}

func (service *Service) RecordFailure(ctx context.Context, id uuid.UUID, errorCode, requestID string) (Endpoint, error) {
	if service == nil || id == uuid.Nil || strings.TrimSpace(errorCode) == "" {
		return Endpoint{}, ErrEndpointInvalid
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	var updated Endpoint
	err := service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		updatedRecord, markErr := service.repository.MarkFailure(ctx, tx, id, now)
		if markErr != nil {
			return markErr
		}
		updated = updatedRecord
		if updated.Status == StatusUnhealthy && updated.FailureCount == 3 {
			_, auditErr := service.auditor.Append(ctx, tx, audit.AppendCommand{
				Actor: endpointWorkerPrincipal(updated.ProductID), Action: "endpoint.health.unhealthy",
				ProductID: updated.ProductID, ResourceType: "distribution_endpoint", ResourceID: updated.ID.String(),
				Outcome: audit.OutcomeFailed, RequestID: requestID,
				Metadata: map[string]any{"error_code": errorCode, "failure_count": updated.FailureCount},
			})
			return auditErr
		}
		return nil
	})
	return updated, err
}

func (service *Service) Get(ctx context.Context, id uuid.UUID) (Endpoint, error) {
	if service == nil || id == uuid.Nil {
		return Endpoint{}, ErrEndpointInvalid
	}
	return service.repository.Get(ctx, id)
}

func (service *Service) GetAuthorized(ctx context.Context, principal identity.Principal, id uuid.UUID) (Endpoint, error) {
	record, err := service.Get(ctx, id)
	if err != nil {
		return Endpoint{}, err
	}
	if err := service.authorizer.Require(principal, identity.ActionIntegrationManage, record.ProductID); err != nil {
		return Endpoint{}, err
	}
	return record, nil
}

func (service *Service) RecordSuccess(ctx context.Context, id uuid.UUID, result ProbeResult, requestID string) (Endpoint, error) {
	if service == nil || id == uuid.Nil || len(result.RootDigest) != 64 || len(result.TimestampDigest) != 64 {
		return Endpoint{}, ErrEndpointInvalid
	}
	record, err := service.repository.Get(ctx, id)
	if err != nil {
		return Endpoint{}, err
	}
	now := service.clock().UTC().Truncate(time.Microsecond)
	var updated Endpoint
	err = service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		updated, err = service.repository.MarkHealthy(ctx, tx, id, result.RootDigest, result.TimestampDigest, now)
		if err != nil {
			return err
		}
		_, err = service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: endpointWorkerPrincipal(record.ProductID), Action: "endpoint.sync.complete",
			ProductID: record.ProductID, ResourceType: "distribution_endpoint", ResourceID: record.ID.String(),
			Outcome: audit.OutcomeSuccess, RequestID: requestID,
			Metadata: map[string]any{"root_digest": result.RootDigest, "timestamp_digest": result.TimestampDigest},
		})
		return err
	})
	return updated, err
}

func catalogDigests(current catalog.VersionRecord) (ProbeResult, error) {
	root, rootOK := current.Roles[catalog.RoleRoot]
	timestamp, timestampOK := current.Roles[catalog.RoleTimestamp]
	if !rootOK || !timestampOK || len(root.EnvelopeSHA256) != 64 || len(timestamp.EnvelopeSHA256) != 64 {
		return ProbeResult{}, ErrEndpointInvalid
	}
	return ProbeResult{RootDigest: root.EnvelopeSHA256, TimestampDigest: timestamp.EnvelopeSHA256}, nil
}

func normalizeRegisterCommand(command RegisterCommand) RegisterCommand {
	command.ProductID = strings.TrimSpace(command.ProductID)
	command.Name = strings.TrimSpace(command.Name)
	command.Region = strings.TrimSpace(command.Region)
	command.BaseURL = strings.TrimRight(strings.TrimSpace(command.BaseURL), "/")
	command.PathPrefix = strings.TrimRight(strings.TrimSpace(command.PathPrefix), "/")
	command.HealthPath = strings.TrimSpace(command.HealthPath)
	command.TLSCARef = strings.TrimSpace(command.TLSCARef)
	return command
}

func validateRegisterCommand(command RegisterCommand) error {
	parsed, err := url.Parse(command.BaseURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return ErrEndpointInvalid
	}
	if !publicProductID(command.ProductID) || command.Name == "" || len(command.Name) > 128 || !endpointRegionPattern.MatchString(command.Region) || command.Priority < 0 || command.Priority > 1000 {
		return ErrEndpointInvalid
	}
	if command.Type != TypeOrigin && command.Type != TypeCDN && command.Type != TypePrivate {
		return ErrEndpointInvalid
	}
	if !safeAbsolutePath(command.PathPrefix) || !safeAbsolutePath(command.HealthPath) || len(command.TLSCARef) > 256 || strings.ContainsAny(command.TLSCARef, "\x00\r\n") {
		return ErrEndpointInvalid
	}
	return nil
}

func publicProductID(value string) bool {
	if len(value) < 2 || len(value) > 63 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func safeAbsolutePath(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.Contains(value, "..") && !strings.ContainsAny(value, "\\\x00\r\n?#") && len(value) <= 512
}

func endpointWorkerPrincipal(productID string) identity.Principal {
	return identity.Principal{Subject: "release-worker", Kind: identity.PrincipalKindWorkload, Provider: identity.WorkloadProviderAPIToken, Roles: []identity.Role{identity.RolePublisher}, ProductIDs: []string{productID}}
}

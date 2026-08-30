package scm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
)

const maximumWebhookPayloadBytes = 10 * 1024 * 1024

var (
	eventIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)
	digestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type ConnectionReader interface {
	GetConnection(ctx context.Context, id uuid.UUID) (Connection, error)
}

type WebhookRepository interface {
	FindDelivery(ctx context.Context, tx pgx.Tx, connectionID uuid.UUID, eventID string) (Delivery, error)
	CreateDelivery(ctx context.Context, tx pgx.Tx, delivery Delivery) error
}

type SCMTransactor interface {
	WithinTransaction(ctx context.Context, fn func(pgx.Tx) error) error
}

type WebhookDomainSink interface {
	ApplyWebhook(ctx context.Context, tx pgx.Tx, connection Connection, event WebhookEvent, delivery Delivery) error
}

type AuditAppender interface {
	Append(ctx context.Context, tx pgx.Tx, command audit.AppendCommand) (audit.Event, error)
}

type WebhookServiceConfig struct {
	Providers   map[ProviderKind]Provider
	Connections ConnectionReader
	Repository  WebhookRepository
	Transactor  SCMTransactor
	Sink        WebhookDomainSink
	Auditor     AuditAppender
	Clock       func() time.Time
}

type WebhookService struct {
	providers   map[ProviderKind]Provider
	connections ConnectionReader
	repository  WebhookRepository
	transactor  SCMTransactor
	sink        WebhookDomainSink
	auditor     AuditAppender
	clock       func() time.Time
}

func NewWebhookService(config WebhookServiceConfig) (*WebhookService, error) {
	if len(config.Providers) == 0 || config.Connections == nil || config.Repository == nil || config.Transactor == nil || config.Sink == nil || config.Auditor == nil || config.Clock == nil {
		return nil, ErrWebhookServiceConfig
	}
	providers := make(map[ProviderKind]Provider, len(config.Providers))
	for kind, provider := range config.Providers {
		if provider == nil || (kind != ProviderGitHub && kind != ProviderGitLab) {
			return nil, ErrWebhookServiceConfig
		}
		providers[kind] = provider
	}
	return &WebhookService{
		providers: providers, connections: config.Connections, repository: config.Repository,
		transactor: config.Transactor, sink: config.Sink, auditor: config.Auditor, clock: config.Clock,
	}, nil
}

func (service *WebhookService) Handle(ctx context.Context, connectionID uuid.UUID, headers http.Header, body []byte) (Delivery, error) {
	if service == nil || connectionID == uuid.Nil {
		return Delivery{}, ErrWebhookServiceConfig
	}
	if len(body) == 0 || len(body) > maximumWebhookPayloadBytes {
		return Delivery{}, ErrWebhookPayloadTooLarge
	}
	connection, err := service.connections.GetConnection(ctx, connectionID)
	if err != nil {
		return Delivery{}, err
	}
	if connection.ID != connectionID || connection.Status != ConnectionStatusActive {
		return Delivery{}, ErrConnectionInactive
	}
	provider, exists := service.providers[connection.Provider]
	if !exists {
		return Delivery{}, ErrProviderUnsupported
	}
	event, err := provider.VerifyWebhook(ctx, connection, headers.Clone(), append([]byte(nil), body...))
	if err != nil {
		return Delivery{}, err
	}
	actualDigest := sha256.Sum256(body)
	if err := validateWebhookEvent(connection, event, hex.EncodeToString(actualDigest[:])); err != nil {
		return Delivery{}, err
	}

	var result Delivery
	err = service.transactor.WithinTransaction(ctx, func(tx pgx.Tx) error {
		existing, findErr := service.repository.FindDelivery(ctx, tx, connection.ID, event.EventID)
		if findErr == nil {
			if existing.PayloadDigest != event.PayloadDigest {
				return ErrDeliveryReplayConflict
			}
			result = existing
			return nil
		}
		if !errors.Is(findErr, ErrDeliveryNotFound) {
			return findErr
		}
		deliveryID, generateErr := uuid.NewV7()
		if generateErr != nil {
			return generateErr
		}
		result = Delivery{
			ID: deliveryID, ConnectionID: connection.ID, EventID: event.EventID, EventType: event.EventType,
			PayloadDigest: event.PayloadDigest, Repository: event.Repository, CommitSHA: event.CommitSHA,
			OccurredAt: event.OccurredAt.UTC(), ReceivedAt: service.clock().UTC().Truncate(time.Microsecond),
		}
		if err := service.repository.CreateDelivery(ctx, tx, result); err != nil {
			return err
		}
		if err := service.sink.ApplyWebhook(ctx, tx, connection, event, result); err != nil {
			return err
		}
		provider := identity.WorkloadProviderGitHubActions
		if connection.Provider == ProviderGitLab {
			provider = identity.WorkloadProviderGitLabCI
		}
		_, err := service.auditor.Append(ctx, tx, audit.AppendCommand{
			Actor: identity.Principal{
				Subject: event.Actor, Kind: identity.PrincipalKindWorkload, Provider: provider,
				Roles: []identity.Role{identity.RolePublisher}, ProductIDs: []string{connection.ProductID},
			},
			Action: "scm.webhook.accept", ProductID: connection.ProductID,
			ResourceType: "scm_webhook_delivery", ResourceID: result.ID.String(),
			Outcome: audit.OutcomeSuccess, RequestID: result.ID.String(),
			Metadata: map[string]any{
				"connection_id": connection.ID.String(), "event_id": event.EventID,
				"event_type": event.EventType, "repository": event.Repository, "commit_sha": event.CommitSHA,
			},
		})
		return err
	})
	return result, err
}

func validateWebhookEvent(connection Connection, event WebhookEvent, actualDigest string) error {
	if event.Provider != connection.Provider || !eventIDPattern.MatchString(strings.TrimSpace(event.EventID)) ||
		strings.TrimSpace(event.Repository) == "" || strings.TrimSpace(event.CommitSHA) == "" ||
		!digestPattern.MatchString(event.PayloadDigest) || event.PayloadDigest != actualDigest || event.OccurredAt.IsZero() {
		return ErrWebhookEventInvalid
	}
	return nil
}

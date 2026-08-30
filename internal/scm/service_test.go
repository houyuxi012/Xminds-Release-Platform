package scm

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"xminds-release-platform/internal/audit"
	"xminds-release-platform/internal/identity"
)

func TestDuplicateWebhookReturnsOriginalDeliveryWithoutCreatingSecondDomainEvent(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 20, 8, 0, 0, 0, time.UTC)
	connection := Connection{ID: uuid.New(), ProductID: "ngep", Provider: ProviderGitHub, Status: ConnectionStatusActive}
	event := WebhookEvent{
		Provider: ProviderGitHub, EventID: "event-42", Repository: "acme/ngep",
		Ref: "refs/tags/v1.2.3", Tag: "v1.2.3", CommitSHA: "0123456789012345678901234567890123456789",
		Actor: "release-bot", OccurredAt: now, PayloadDigest: "48e8029988b89912cbe6ea8d1ff6bb8f44bcad5edabe6fe06242b62ada6b447d",
	}
	repository := &memoryWebhookRepository{}
	sink := &countingWebhookSink{}
	auditor := &recordingSCMAuditor{}
	service, err := NewWebhookService(WebhookServiceConfig{
		Providers:   map[ProviderKind]Provider{ProviderGitHub: fixedWebhookProvider{event: event}},
		Connections: fixedConnectionReader{connection: connection}, Repository: repository,
		Transactor: passthroughSCMTransactor{}, Sink: sink, Auditor: auditor, Clock: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	first, err := service.Handle(context.Background(), connection.ID, http.Header{}, []byte(`{"ref":"refs/tags/v1.2.3"}`))
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Handle(context.Background(), connection.ID, http.Header{}, []byte(`{"ref":"refs/tags/v1.2.3"}`))
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || sink.calls != 1 {
		t.Fatalf("delivery IDs/sink calls = %s/%s/%d", first.ID, second.ID, sink.calls)
	}
	if len(auditor.commands) != 1 || auditor.commands[0].Action != "scm.webhook.accept" || auditor.commands[0].ResourceID != first.ID.String() {
		t.Fatalf("audit commands = %#v", auditor.commands)
	}
}

type fixedWebhookProvider struct{ event WebhookEvent }

func (provider fixedWebhookProvider) VerifyConnection(context.Context, Connection) (Capabilities, error) {
	return Capabilities{}, nil
}

func (provider fixedWebhookProvider) VerifyWebhook(context.Context, Connection, http.Header, []byte) (WebhookEvent, error) {
	return provider.event, nil
}

func (fixedWebhookProvider) GetCommit(context.Context, Connection, string, string) (Commit, error) {
	return Commit{}, nil
}

func (fixedWebhookProvider) WriteStatus(context.Context, Connection, CommitStatus) error { return nil }

func (fixedWebhookProvider) VerifyWorkload(context.Context, Connection, string) (identity.Principal, error) {
	return identity.Principal{}, nil
}

type fixedConnectionReader struct{ connection Connection }

func (reader fixedConnectionReader) GetConnection(_ context.Context, id uuid.UUID) (Connection, error) {
	if id != reader.connection.ID {
		return Connection{}, ErrConnectionNotFound
	}
	return reader.connection, nil
}

type memoryWebhookRepository struct{ delivery Delivery }

func (repository *memoryWebhookRepository) FindDelivery(_ context.Context, _ pgx.Tx, connectionID uuid.UUID, eventID string) (Delivery, error) {
	if repository.delivery.ConnectionID != connectionID || repository.delivery.EventID != eventID {
		return Delivery{}, ErrDeliveryNotFound
	}
	return repository.delivery, nil
}

func (repository *memoryWebhookRepository) CreateDelivery(_ context.Context, _ pgx.Tx, delivery Delivery) error {
	repository.delivery = delivery
	return nil
}

type passthroughSCMTransactor struct{}

func (passthroughSCMTransactor) WithinTransaction(ctx context.Context, fn func(pgx.Tx) error) error {
	return fn(nil)
}

type countingWebhookSink struct{ calls int }

func (sink *countingWebhookSink) ApplyWebhook(context.Context, pgx.Tx, Connection, WebhookEvent, Delivery) error {
	sink.calls++
	return nil
}

type recordingSCMAuditor struct{ commands []audit.AppendCommand }

func (recorder *recordingSCMAuditor) Append(_ context.Context, _ pgx.Tx, command audit.AppendCommand) (audit.Event, error) {
	recorder.commands = append(recorder.commands, command)
	return audit.Event{}, nil
}

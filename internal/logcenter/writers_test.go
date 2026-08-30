package logcenter

import (
	"errors"
	"testing"
	"time"
)

func TestNewApplicationRequestCopiesMetadataAndNormalizesEvent(t *testing.T) {
	digest := make([]byte, 32)
	digest[0] = 1
	input := ApplicationRequestEvent{
		EventID: "018f835d-7e4b-7abc-9f42-67a2f5f48e71", OccurredAt: time.Date(2026, 8, 29, 12, 0, 0, 123456789, time.UTC),
		Metadata:    EventMetadata{RequestID: "018f835d-7e4b-7abc-9f42-67a2f5f48e72", SchemaVersion: 1},
		ClientAppID: "client", ClientAppVersion: "1.2.3", HTTPMethod: "GET", RouteTemplate: "/v1/releases",
		SnapshotTrusted: true, CustomerID: "customer", CustomerName: "客户", TenantID: "tenant", AuthorizationName: "授权", LicenseID: "license",
		LicenseExpiresAt: timePtr(time.Date(2027, 8, 29, 0, 0, 0, 0, time.UTC)), LicenseStatus: "valid", Decision: "allow", ReasonCode: "LICENSE_VALID",
		ValidatedAt: timePtr(time.Date(2026, 8, 29, 11, 59, 0, 0, time.UTC)), ValidatorIssuer: "issuer", ContextDigest: digest, Result: ResultSuccess,
	}
	status := 200
	input.HTTPStatus = &status
	got, err := NewApplicationRequest(input)
	if err != nil {
		t.Fatalf("NewApplicationRequest() error = %v", err)
	}
	if got.OccurredAt.Location() != time.UTC || got.OccurredAt.Nanosecond() != 123456000 || &got.ContextDigest[0] == &digest[0] {
		t.Fatalf("normalized event = %#v", got)
	}
	input.Metadata.RequestID = "changed"
	digest[0] = 9
	if got.Metadata.RequestID != "018f835d-7e4b-7abc-9f42-67a2f5f48e72" || got.ContextDigest[0] != 1 {
		t.Fatal("constructor did not copy mutable inputs")
	}
}

func timePtr(value time.Time) *time.Time { return &value }

func TestNewApplicationRequestRejectsTrustedFieldsOnUntrustedEvent(t *testing.T) {
	event := ApplicationRequestEvent{EventID: "018f835d-7e4b-7abc-9f42-67a2f5f48e71", Metadata: EventMetadata{RequestID: "018f835d-7e4b-7abc-9f42-67a2f5f48e72", SchemaVersion: 1}, OccurredAt: time.Now(), ClientAppID: "client", ClientAppVersion: "1", HTTPMethod: "GET", RouteTemplate: "/", SnapshotTrusted: false, CustomerID: "must-not-exist", Decision: "deny", ReasonCode: "DENIED", Result: ResultDenied}
	if _, err := NewApplicationRequest(event); err == nil {
		t.Fatal("untrusted event with customer fields was accepted")
	}
}

func TestAllTypedConstructorsExist(t *testing.T) {
	if _, err := NewOperation(OperationCommand{}); err == nil {
		t.Fatal("invalid operation accepted")
	}
	if _, err := NewAuthentication(AuthenticationEvent{}); err == nil {
		t.Fatal("invalid authentication accepted")
	}
	if _, err := NewGitSync(GitSyncEvent{}); err == nil {
		t.Fatal("invalid git sync accepted")
	}
}

func TestNewAuthenticationRejectsInvalidEventMetadata(t *testing.T) {
	event := AuthenticationEvent{EventID: "018f835d-7e4b-7abc-9f42-67a2f5f48e71", Metadata: EventMetadata{RequestID: "018f835d-7e4b-7abc-9f42-67a2f5f48e72", CorrelationID: "not-uuid", SchemaVersion: 1}, OccurredAt: time.Now(), Subject: "subject", IdentitySourceID: "source", AuthenticationMethod: "password", Result: ResultSuccess}
	if _, err := NewAuthentication(event); !errors.Is(err, ErrMetadataInvalid) {
		t.Fatalf("NewAuthentication() error = %v, want ErrMetadataInvalid", err)
	}
}

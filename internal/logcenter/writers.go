package logcenter

import (
	"encoding/hex"
	"errors"
	"net"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

var (
	ErrInvalidEvent      = errors.New("invalid log event")
	ErrMetadataInvalid   = errors.New("invalid event metadata")
	ErrEventIDGeneration = errors.New("failed to generate log event id")
)

var traceIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)
var reasonPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)

func NewApplicationRequest(input ApplicationRequestEvent) (ApplicationRequestEvent, error) {
	if err := assignEventID(&input.EventID); err != nil {
		return ApplicationRequestEvent{}, err
	}
	if err := validateEventMetadata(input.Metadata, input.OccurredAt); err != nil {
		return ApplicationRequestEvent{}, err
	}
	if !validCommon(input.EventID, input.Metadata, input.OccurredAt) || !validText(input.ClientAppID, 128) || !validText(input.ClientAppVersion, 128) || !validText(input.HTTPMethod, 16) || !validText(input.RouteTemplate, 512) || input.DurationMS < 0 || (input.HTTPStatus != nil && (*input.HTTPStatus < 100 || *input.HTTPStatus > 599)) || (input.HTTPStatus == nil && input.ReasonCode != "REQUEST_COMPLETION_UNKNOWN") {
		return ApplicationRequestEvent{}, ErrInvalidEvent
	}
	if input.Metadata.SchemaVersion <= 0 {
		return ApplicationRequestEvent{}, ErrInvalidEvent
	}
	if input.SnapshotTrusted && (!validIdentifier(input.CustomerID, 128) || (input.TenantID != "" && !validIdentifier(input.TenantID, 128)) || !validText(input.CustomerName, 256) || !validText(input.AuthorizationName, 256) || !validIdentifier(input.LicenseID, 128) || !validLicenseStatus(input.LicenseStatus) || !validReason(input.ReasonCode) || len(input.ContextDigest) != 32 || !validateSnapshotTimes(input.OccurredAt, input.ValidatedAt, input.LicenseExpiresAt)) {
		return ApplicationRequestEvent{}, ErrInvalidEvent
	}
	if input.SnapshotTrusted == false && (input.CustomerID != "" || input.CustomerName != "" || input.TenantID != "" || input.AuthorizationName != "" || input.LicenseID != "" || input.LicenseExpiresAt != nil || input.LicenseStatus != "" || input.ValidatorIssuer != "" || input.ValidatedAt != nil || len(input.ContextDigest) != 0 || input.Decision != "deny" || (input.Result != ResultDenied && !(input.Result == ResultFailed && input.ReasonCode == "REQUEST_COMPLETION_UNKNOWN")) || !validReason(input.ReasonCode)) {
		return ApplicationRequestEvent{}, ErrInvalidEvent
	}
	if (input.Decision != "allow" && input.Decision != "deny") || (input.Result != ResultSuccess && input.Result != ResultDenied && input.Result != ResultFailed) {
		return ApplicationRequestEvent{}, ErrInvalidEvent
	}
	input.OccurredAt = input.OccurredAt.UTC().Truncate(time.Microsecond)
	input.Metadata = normalizeMetadata(input.Metadata)
	input.ContextDigest = append([]byte(nil), input.ContextDigest...)
	if input.LicenseExpiresAt != nil {
		value := input.LicenseExpiresAt.UTC()
		input.LicenseExpiresAt = &value
	}
	if input.ValidatedAt != nil {
		value := input.ValidatedAt.UTC()
		input.ValidatedAt = &value
	}
	return input, nil
}

// NewApplicationRequestWithIdentity is restricted to internal retry/test paths.
func NewApplicationRequestWithIdentity(input ApplicationRequestEvent, eventID string) (ApplicationRequestEvent, error) {
	input.EventID = eventID
	return NewApplicationRequest(input)
}

func NewOperation(input OperationCommand) (OperationCommand, error) {
	if err := assignEventID(&input.EventID); err != nil {
		return OperationCommand{}, err
	}
	if err := validateEventMetadata(input.Metadata, input.OccurredAt); err != nil {
		return OperationCommand{}, err
	}
	if !validCommon(input.EventID, input.Metadata, input.OccurredAt) || !validText(input.Action, 128) || !validText(input.ResourceType, 128) || (input.ResourceID != "" && !validText(input.ResourceID, 256)) || (input.ActorSubject != "" && !validText(input.ActorSubject, 256)) || (input.ActorKind != "" && !validActorKind(input.ActorKind)) || !validResult(input.Result) {
		return OperationCommand{}, ErrInvalidEvent
	}
	metadata, err := RedactMetadata(input.MetadataSummary)
	if err != nil {
		return OperationCommand{}, err
	}
	input.OccurredAt = input.OccurredAt.UTC().Truncate(time.Microsecond)
	input.Metadata = normalizeMetadata(input.Metadata)
	input.MetadataSummary = metadata
	return input, nil
}

func NewOperationWithIdentity(input OperationCommand, eventID string) (OperationCommand, error) {
	input.EventID = eventID
	return NewOperation(input)
}

func NewAuthentication(input AuthenticationEvent) (AuthenticationEvent, error) {
	if err := assignEventID(&input.EventID); err != nil {
		return AuthenticationEvent{}, err
	}
	if err := validateEventMetadata(input.Metadata, input.OccurredAt); err != nil {
		return AuthenticationEvent{}, err
	}
	if !validCommon(input.EventID, input.Metadata, input.OccurredAt) || !validText(input.Subject, 256) || !validText(input.IdentitySourceID, 128) || !validText(input.AuthenticationMethod, 64) || (input.ClientName != "" && !validText(input.ClientName, 128)) || (input.MFALevel != "" && !validText(input.MFALevel, 32)) || (input.ReasonCode != "" && !validText(input.ReasonCode, 128)) || !validResult(input.Result) {
		return AuthenticationEvent{}, ErrInvalidEvent
	}
	input.OccurredAt = input.OccurredAt.UTC().Truncate(time.Microsecond)
	input.Metadata = normalizeMetadata(input.Metadata)
	return input, nil
}

func NewAuthenticationWithIdentity(input AuthenticationEvent, eventID string) (AuthenticationEvent, error) {
	input.EventID = eventID
	return NewAuthentication(input)
}

func NewGitSync(input GitSyncEvent) (GitSyncEvent, error) {
	if err := assignEventID(&input.EventID); err != nil {
		return GitSyncEvent{}, err
	}
	if err := validateEventMetadata(input.Metadata, input.OccurredAt); err != nil {
		return GitSyncEvent{}, err
	}
	if !validCommon(input.EventID, input.Metadata, input.OccurredAt) || !validText(input.Provider, 64) || !validText(input.RepositoryID, 256) || !validText(input.RepositoryName, 256) || (input.TagName != "" && !validText(input.TagName, 256)) || (input.ErrorCode != "" && !validText(input.ErrorCode, 128)) || input.Attempt < 1 || !validResult(input.Result) || !validStage(input.Stage) || (input.CommitSHA != "" && !validCommitSHA(input.CommitSHA)) {
		return GitSyncEvent{}, ErrInvalidEvent
	}
	input.OccurredAt = input.OccurredAt.UTC().Truncate(time.Microsecond)
	input.Metadata = normalizeMetadata(input.Metadata)
	return input, nil
}

func NewGitSyncWithIdentity(input GitSyncEvent, eventID string) (GitSyncEvent, error) {
	input.EventID = eventID
	return NewGitSync(input)
}

func assignEventID(target *string) error {
	if *target == "" {
		if generated, err := uuid.NewV7(); err == nil {
			*target = generated.String()
		} else {
			return ErrEventIDGeneration
		}
	}
	return nil
}

func validCommon(eventID string, metadata EventMetadata, occurredAt time.Time) bool {
	return validUUIDv7(eventID) && validateEventMetadata(metadata, occurredAt) == nil
}

func validateEventMetadata(metadata EventMetadata, occurredAt time.Time) error {
	if !validUUID(metadata.RequestID) || metadata.SchemaVersion < 1 || metadata.SchemaVersion > 16 || occurredAt.IsZero() || occurredAt.After(time.Now().UTC().Add(5*time.Minute)) {
		return ErrMetadataInvalid
	}
	if metadata.CorrelationID != "" && !validUUID(metadata.CorrelationID) {
		return ErrMetadataInvalid
	}
	if metadata.TraceID != "" && !traceIDPattern.MatchString(metadata.TraceID) {
		return ErrMetadataInvalid
	}
	if metadata.SourceIP != "" && net.ParseIP(metadata.SourceIP) == nil {
		return ErrMetadataInvalid
	}
	return nil
}

func validCommitSHA(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && (len(decoded) == 20 || len(decoded) == 32)
}
func validResult(result Result) bool {
	return result == ResultSuccess || result == ResultDenied || result == ResultFailed
}
func validText(value string, max int) bool {
	lower := strings.ToLower(value)
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return strings.TrimSpace(value) != "" && len([]rune(value)) <= max && !strings.ContainsAny(value, "?#\\") && !strings.Contains(lower, "%2f") && !strings.Contains(lower, "%3f") && !strings.Contains(lower, "%23") && !strings.Contains(lower, "://")
}
func validIdentifier(value string, max int) bool {
	return len([]rune(value)) <= max && identifierPattern.MatchString(value) && !strings.ContainsAny(value, "/\\?#") && !strings.Contains(value, "://")
}
func validReason(value string) bool { return reasonPattern.MatchString(value) }
func validLicenseStatus(value string) bool {
	switch value {
	case "valid", "expiring", "expired", "revoked", "unknown":
		return true
	}
	return false
}
func validActorKind(value string) bool {
	return value == "human" || value == "service" || value == "system"
}
func validStage(stage string) bool {
	return stage == "webhook_accept" || stage == "fetch" || stage == "validate" || stage == "apply" || stage == "status_writeback"
}

func normalizeMetadata(metadata EventMetadata) EventMetadata {
	metadata.RequestID = strings.TrimSpace(metadata.RequestID)
	metadata.CorrelationID = strings.TrimSpace(metadata.CorrelationID)
	metadata.TraceID = strings.TrimSpace(metadata.TraceID)
	metadata.SourceIP = strings.TrimSpace(metadata.SourceIP)
	return metadata
}

func validUUID(value string) bool { _, err := uuid.Parse(value); return err == nil }

func validUUIDv7(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.Version() == 7
}

func validateSnapshotTimes(occurredAt time.Time, validatedAt, expiresAt *time.Time) bool {
	if validatedAt == nil || expiresAt == nil || validatedAt.IsZero() || expiresAt.IsZero() {
		return false
	}
	return expiresAt.After(occurredAt) && !validatedAt.After(occurredAt) && !validatedAt.After(time.Now().UTC().Add(5*time.Minute))
}

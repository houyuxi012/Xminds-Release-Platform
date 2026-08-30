package iam

import (
	"encoding/base64"
	"strings"
	"time"

	"github.com/google/uuid"
)

const maximumIAMCursorLength = 512

func encodeIAMCursor(createdAt time.Time, id uuid.UUID) string {
	payload := createdAt.UTC().Format(time.RFC3339Nano) + "\n" + id.String()
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

func decodeIAMCursor(cursor string) (time.Time, uuid.UUID, error) {
	payload, err := decodeCanonicalIAMCursor(cursor)
	if err != nil {
		return time.Time{}, uuid.Nil, ErrPageInvalid
	}
	parts := strings.Split(string(payload), "\n")
	if len(parts) != 2 {
		return time.Time{}, uuid.Nil, ErrPageInvalid
	}
	createdAt, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, uuid.Nil, ErrPageInvalid
	}
	id, err := uuid.Parse(parts[1])
	if err != nil || id == uuid.Nil {
		return time.Time{}, uuid.Nil, ErrPageInvalid
	}
	return createdAt.UTC(), id, nil
}

func encodeOrganizationMembershipCursor(createdAt time.Time, userID uuid.UUID, sourceOwned bool) string {
	payload := createdAt.UTC().Format(time.RFC3339Nano) + "\n" + userID.String() + "\n" + map[bool]string{true: "source", false: "platform"}[sourceOwned]
	return base64.RawURLEncoding.EncodeToString([]byte(payload))
}

func decodeOrganizationMembershipCursor(cursor string) (time.Time, uuid.UUID, bool, error) {
	payload, err := decodeCanonicalIAMCursor(cursor)
	if err != nil {
		return time.Time{}, uuid.Nil, false, ErrPageInvalid
	}
	parts := strings.Split(string(payload), "\n")
	if len(parts) != 3 {
		return time.Time{}, uuid.Nil, false, ErrPageInvalid
	}
	createdAt, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, uuid.Nil, false, ErrPageInvalid
	}
	userID, err := uuid.Parse(parts[1])
	if err != nil || userID == uuid.Nil {
		return time.Time{}, uuid.Nil, false, ErrPageInvalid
	}
	var sourceOwned bool
	switch parts[2] {
	case "source":
		sourceOwned = true
	case "platform":
		sourceOwned = false
	default:
		return time.Time{}, uuid.Nil, false, ErrPageInvalid
	}
	return createdAt.UTC(), userID, sourceOwned, nil
}

func decodeCanonicalIAMCursor(cursor string) ([]byte, error) {
	if cursor == "" || len(cursor) > maximumIAMCursorLength || strings.TrimSpace(cursor) != cursor {
		return nil, ErrPageInvalid
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != cursor {
		return nil, ErrPageInvalid
	}
	return payload, nil
}

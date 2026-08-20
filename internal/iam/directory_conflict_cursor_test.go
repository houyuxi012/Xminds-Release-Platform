package iam

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDirectoryConflictCursorIsOpaqueBoundAuthenticatedAndExpiring(t *testing.T) {
	now := time.Date(2026, 8, 21, 13, 30, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	codec, err := NewDirectoryConflictCursorCodec(bytes.Repeat([]byte{0x5a}, 32), clock, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	sourceID, beforeID := uuid.New(), uuid.New()
	beforeTime := now.Add(-time.Minute)
	const route = "iam.directory-sync-conflicts"
	cursor, err := codec.Encode(route, sourceID, 50, beforeTime, beforeID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(cursor, sourceID.String()) || strings.Contains(cursor, beforeID.String()) || strings.Contains(cursor, beforeTime.Format(time.RFC3339)) {
		t.Fatalf("cursor is not opaque: %s", cursor)
	}
	decodedTime, decodedID, err := codec.Decode(cursor, route, sourceID, 50)
	if err != nil || !decodedTime.Equal(beforeTime) || decodedID != beforeID {
		t.Fatalf("Decode() time=%v id=%s error=%v", decodedTime, decodedID, err)
	}
	mutated := []byte(cursor)
	mutated[len(mutated)/2] ^= 1
	for name, decode := range map[string]func() error{
		"tampered":      func() error { _, _, err := codec.Decode(string(mutated), route, sourceID, 50); return err },
		"cross source":  func() error { _, _, err := codec.Decode(cursor, route, uuid.New(), 50); return err },
		"cross route":   func() error { _, _, err := codec.Decode(cursor, "iam.users", sourceID, 50); return err },
		"changed limit": func() error { _, _, err := codec.Decode(cursor, route, sourceID, 100); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := decode(); !errors.Is(err, ErrPageInvalid) {
				t.Fatalf("Decode() error=%v", err)
			}
		})
	}
	replacementCodec, err := NewDirectoryConflictCursorCodec(bytes.Repeat([]byte{0x6b}, 32), clock, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := replacementCodec.Decode(cursor, route, sourceID, 50); !errors.Is(err, ErrPageInvalid) {
		t.Fatalf("rotated-key Decode() error=%v", err)
	}
	sealed, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		t.Fatal(err)
	}
	nonceSize := codec.aead.NonceSize()
	additionalData, err := directoryConflictCursorAdditionalData(route, sourceID, 50)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codec.aead.Open(nil, sealed[:nonceSize], sealed[nonceSize:], []byte("xminds-release-platform:iam:directory-conflict-cursor:v1")); err == nil {
		t.Fatal("cursor unexpectedly authenticates under legacy static additional data")
	}
	payloadJSON, err := codec.aead.Open(nil, sealed[:nonceSize], sealed[nonceSize:], additionalData)
	if err != nil {
		t.Fatalf("cursor does not authenticate under bound additional data: %v", err)
	}
	var payload directoryConflictCursorPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatal(err)
	}
	payload.Version++
	payloadJSON, err = json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	versionNonce := bytes.Repeat([]byte{0x7d}, codec.aead.NonceSize())
	versionCursor := base64.RawURLEncoding.EncodeToString(codec.aead.Seal(versionNonce, versionNonce, payloadJSON, additionalData))
	if _, _, err := codec.Decode(versionCursor, route, sourceID, 50); !errors.Is(err, ErrPageInvalid) {
		t.Fatalf("future-version Decode() error=%v", err)
	}
	now = now.Add(16 * time.Minute)
	if _, _, err := codec.Decode(cursor, route, sourceID, 50); !errors.Is(err, ErrPageInvalid) {
		t.Fatalf("expired Decode() error=%v", err)
	}
}

func TestDirectoryConflictCursorKeySecretRequiresStrictBase64URLText(t *testing.T) {
	raw := bytes.Repeat([]byte{0x5a}, 32)
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	decoded, err := DecodeDirectoryConflictCursorKeySecret([]byte(encoded))
	if err != nil || !bytes.Equal(decoded, raw) {
		t.Fatalf("decoded=%x error=%v", decoded, err)
	}
	for name, secret := range map[string][]byte{
		"raw bytes":  raw,
		"padding":    []byte(encoded + "="),
		"whitespace": []byte(" " + encoded),
		"short":      []byte(base64.RawURLEncoding.EncodeToString(raw[:31])),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeDirectoryConflictCursorKeySecret(secret); !errors.Is(err, ErrDirectorySyncConfiguration) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func newDirectoryTestConflictCursorCodec(t *testing.T, clock func() time.Time) *DirectoryConflictCursorCodec {
	t.Helper()
	codec, err := NewDirectoryConflictCursorCodec(bytes.Repeat([]byte{0x3c}, 32), clock, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

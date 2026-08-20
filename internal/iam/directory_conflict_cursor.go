package iam

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/platform/strictjson"
)

const (
	directoryConflictCursorVersion   = 2
	directoryConflictCursorAADDomain = "xminds-release-platform:iam:directory-conflict-cursor"
)

type DirectoryConflictCursorCodec struct {
	aead  cipher.AEAD
	clock func() time.Time
	ttl   time.Duration
}

type directoryConflictCursorPayload struct {
	Version    int       `json:"version"`
	Route      string    `json:"route"`
	SourceID   uuid.UUID `json:"source_id"`
	Limit      int       `json:"limit"`
	Filter     string    `json:"filter"`
	BeforeTime time.Time `json:"before_time"`
	BeforeID   uuid.UUID `json:"before_id"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type directoryConflictCursorBinding struct {
	Domain   string    `json:"domain"`
	Version  int       `json:"version"`
	Route    string    `json:"route"`
	SourceID uuid.UUID `json:"source_id"`
	Limit    int       `json:"limit"`
	Filter   string    `json:"filter"`
}

func DecodeDirectoryConflictCursorKeySecret(encoded []byte) ([]byte, error) {
	if len(encoded) != base64.RawURLEncoding.EncodedLen(32) || strings.TrimSpace(string(encoded)) != string(encoded) {
		return nil, ErrDirectorySyncConfiguration
	}
	key, err := base64.RawURLEncoding.DecodeString(string(encoded))
	if err != nil || len(key) != 32 {
		return nil, ErrDirectorySyncConfiguration
	}
	return key, nil
}

func NewDirectoryConflictCursorCodec(key []byte, clock func() time.Time, ttl time.Duration) (*DirectoryConflictCursorCodec, error) {
	if len(key) != 32 || clock == nil || ttl < time.Minute || ttl > 24*time.Hour {
		return nil, ErrDirectorySyncConfiguration
	}
	block, err := aes.NewCipher(append([]byte(nil), key...))
	if err != nil {
		return nil, ErrDirectorySyncConfiguration
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDirectorySyncConfiguration
	}
	return &DirectoryConflictCursorCodec{aead: aead, clock: clock, ttl: ttl}, nil
}

func (codec *DirectoryConflictCursorCodec) Encode(route string, sourceID uuid.UUID, status DirectorySyncConflictStatusFilter, limit int, beforeTime time.Time, beforeID uuid.UUID) (string, error) {
	if !validDirectoryConflictCursorBinding(codec, route, sourceID, status, limit) || beforeTime.IsZero() || beforeID == uuid.Nil {
		return "", ErrPageInvalid
	}
	additionalData, err := directoryConflictCursorAdditionalData(route, sourceID, status, limit)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(directoryConflictCursorPayload{
		Version: directoryConflictCursorVersion, Route: route, SourceID: sourceID, Limit: limit, Filter: string(status),
		BeforeTime: beforeTime.UTC(), BeforeID: beforeID, ExpiresAt: codec.clock().UTC().Add(codec.ttl),
	})
	if err != nil {
		return "", ErrPageInvalid
	}
	nonce := make([]byte, codec.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", ErrPageInvalid
	}
	sealed := codec.aead.Seal(nonce, nonce, payload, additionalData)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (codec *DirectoryConflictCursorCodec) Decode(encoded, route string, sourceID uuid.UUID, status DirectorySyncConflictStatusFilter, limit int) (time.Time, uuid.UUID, error) {
	if !validDirectoryConflictCursorBinding(codec, route, sourceID, status, limit) || strings.TrimSpace(encoded) != encoded {
		return time.Time{}, uuid.Nil, ErrPageInvalid
	}
	sealed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(sealed) <= codec.aead.NonceSize() || len(sealed) > 512 {
		return time.Time{}, uuid.Nil, ErrPageInvalid
	}
	nonce, ciphertext := sealed[:codec.aead.NonceSize()], sealed[codec.aead.NonceSize():]
	additionalData, err := directoryConflictCursorAdditionalData(route, sourceID, status, limit)
	if err != nil {
		return time.Time{}, uuid.Nil, err
	}
	payloadJSON, err := codec.aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return time.Time{}, uuid.Nil, ErrPageInvalid
	}
	var payload directoryConflictCursorPayload
	if strictjson.DecodeBytes(payloadJSON, 1024, &payload) != nil || payload.Version != directoryConflictCursorVersion || payload.Route != route ||
		payload.SourceID != sourceID || payload.Limit != limit || payload.Filter != string(status) || payload.BeforeTime.IsZero() || payload.BeforeID == uuid.Nil ||
		!payload.ExpiresAt.After(codec.clock().UTC()) {
		return time.Time{}, uuid.Nil, ErrPageInvalid
	}
	return payload.BeforeTime.UTC(), payload.BeforeID, nil
}

func directoryConflictCursorAdditionalData(route string, sourceID uuid.UUID, status DirectorySyncConflictStatusFilter, limit int) ([]byte, error) {
	if strings.TrimSpace(route) != route || route == "" || len(route) > 128 || sourceID == uuid.Nil || !validDirectoryConflictStatusFilter(status) || limit < 1 || limit > 200 {
		return nil, ErrPageInvalid
	}
	additionalData, err := json.Marshal(directoryConflictCursorBinding{
		Domain: directoryConflictCursorAADDomain, Version: directoryConflictCursorVersion, Route: route,
		SourceID: sourceID, Limit: limit, Filter: string(status),
	})
	if err != nil {
		return nil, ErrPageInvalid
	}
	return additionalData, nil
}

func validDirectoryConflictCursorBinding(codec *DirectoryConflictCursorCodec, route string, sourceID uuid.UUID, status DirectorySyncConflictStatusFilter, limit int) bool {
	route = strings.TrimSpace(route)
	return codec != nil && codec.aead != nil && codec.clock != nil && route != "" && len(route) <= 128 && sourceID != uuid.Nil && validDirectoryConflictStatusFilter(status) && limit >= 1 && limit <= 200
}

func validDirectoryConflictStatusFilter(status DirectorySyncConflictStatusFilter) bool {
	return status == DirectorySyncConflictStatusOpen || status == DirectorySyncConflictStatusResolved || status == DirectorySyncConflictStatusAll
}

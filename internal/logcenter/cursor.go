package logcenter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var ErrInvalidCursor = errors.New("invalid log cursor")

// DecodeCursorKeySecret decodes the fixed-format secret used only for log
// center cursors. The caller is responsible for resolving the secret from the
// configured secret provider and never persisting the decoded key.
func DecodeCursorKeySecret(encoded []byte) ([]byte, error) {
	if len(encoded) != base64.RawURLEncoding.EncodedLen(32) || strings.TrimSpace(string(encoded)) != string(encoded) {
		return nil, ErrInvalidCursor
	}
	key, err := base64.RawURLEncoding.DecodeString(string(encoded))
	if err != nil || len(key) != 32 {
		return nil, ErrInvalidCursor
	}
	return key, nil
}

type LogCursor struct {
	Version        int        `json:"v"`
	Route          string     `json:"r"`
	FilterDigest   [32]byte   `json:"f"`
	ScopeDigest    [32]byte   `json:"s"`
	Limit          int        `json:"l"`
	LastKey        string     `json:"k,omitempty"`
	LastEventID    string     `json:"i"`
	LastLogType    string     `json:"t"`
	LastOccurredAt *time.Time `json:"o"`
	ExpiresAt      time.Time  `json:"e"`
}
type CursorCodec struct {
	aead cipher.AEAD
	now  func() time.Time
	TTL  time.Duration
}

func NewCursorCodec(key []byte, ttl time.Duration) (*CursorCodec, error) {
	if len(key) != 32 || ttl < 5*time.Minute || ttl > 24*time.Hour {
		return nil, ErrInvalidCursor
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	return &CursorCodec{aead: a, now: time.Now, TTL: ttl}, nil
}
func (c *CursorCodec) Encode(in LogCursor) (string, error) {
	if c == nil || c.aead == nil || in.Route == "" || len(in.Route) > 256 || len(in.LastKey) > 512 || in.Limit < 1 || in.Limit > 200 {
		return "", ErrInvalidCursor
	}
	in.Version = 1
	now := c.now().UTC()
	if in.ExpiresAt.IsZero() {
		in.ExpiresAt = now.Add(c.TTL)
	} else {
		in.ExpiresAt = in.ExpiresAt.UTC()
	}
	if !in.ExpiresAt.After(now) || in.ExpiresAt.After(now.Add(c.TTL)) {
		return "", ErrInvalidCursor
	}
	raw, e := json.Marshal(in)
	if e != nil {
		return "", e
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return "", e
	}
	sealed := c.aead.Seal(nil, nonce, raw, []byte("xminds-log-cursor-v1"))
	token := base64.RawURLEncoding.EncodeToString(append(nonce, sealed...))
	if len(token) > 512 {
		return "", ErrInvalidCursor
	}
	return token, nil
}
func (c *CursorCodec) Decode(token, route string, filter, scope [32]byte, limit int) (LogCursor, error) {
	if c == nil || len(token) > 512 || token == "" || strings.ContainsAny(token, "=+/ \t\r\n") {
		return LogCursor{}, ErrInvalidCursor
	}
	raw, e := base64.RawURLEncoding.DecodeString(token)
	if e != nil || len(raw) < c.aead.NonceSize()+c.aead.Overhead() {
		return LogCursor{}, ErrInvalidCursor
	}
	if base64.RawURLEncoding.EncodeToString(raw) != token {
		return LogCursor{}, ErrInvalidCursor
	}
	plain, e := c.aead.Open(nil, raw[:c.aead.NonceSize()], raw[c.aead.NonceSize():], []byte("xminds-log-cursor-v1"))
	if e != nil {
		return LogCursor{}, ErrInvalidCursor
	}
	var out LogCursor
	now := c.now().UTC()
	if json.Unmarshal(plain, &out) != nil || out.Version != 1 || out.LastKey != "" || out.LastEventID == "" || out.LastOccurredAt == nil || (route == "related" && out.LastLogType == "") || out.Route != route || out.FilterDigest != filter || out.ScopeDigest != scope || out.Limit != limit || !out.ExpiresAt.After(now) || out.ExpiresAt.After(now.Add(c.TTL)) {
		return LogCursor{}, ErrInvalidCursor
	}
	return out, nil
}
func FilterDigest(value string) [32]byte { return sha256.Sum256([]byte(value)) }

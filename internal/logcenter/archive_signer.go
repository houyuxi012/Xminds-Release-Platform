package logcenter

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"
)

type ExportManifest struct {
	SchemaVersion int       `json:"schema_version"`
	FiltersDigest string    `json:"filters_digest"`
	ScopeDigest   string    `json:"scope_digest"`
	RecordCount   int       `json:"record_count"`
	ByteSize      int       `json:"byte_size"`
	DataSHA256    string    `json:"data_sha256"`
	CreatedAt     time.Time `json:"created_at"`
	SigningKeyID  string    `json:"signing_key_id"`
}

var ErrArchiveSignature = errors.New("archive signature failed")

func VerifyExportManifest(manifest, signature []byte, key ed25519.PublicKey) error {
	if len(key) != ed25519.PublicKeySize {
		return ErrArchiveSignature
	}
	var m ExportManifest
	dec := json.NewDecoder(bytes.NewReader(manifest))
	dec.DisallowUnknownFields()
	if dec.Decode(&m) != nil || !validExportManifest(m) {
		return ErrArchiveSignature
	}
	var trailing any
	if dec.Decode(&trailing) != io.EOF {
		return ErrArchiveSignature
	}
	sum := sha256.Sum256(manifest)
	if !ed25519.Verify(key, sum[:], signature) {
		return ErrArchiveSignature
	}
	return nil
}

func SignExportManifest(m ExportManifest, key ed25519.PrivateKey) ([]byte, []byte, error) {
	if len(key) != ed25519.PrivateKeySize || !validExportManifest(m) {
		return nil, nil, ErrArchiveSignature
	}
	m.CreatedAt = m.CreatedAt.UTC()
	b, e := json.Marshal(m)
	if e != nil {
		return nil, nil, e
	}
	sum := sha256.Sum256(b)
	return b, ed25519.Sign(key, sum[:]), nil
}

func validExportManifest(m ExportManifest) bool {
	if m.SchemaVersion != 1 || m.RecordCount < 0 || m.ByteSize < 0 || m.CreatedAt.IsZero() || len(m.SigningKeyID) == 0 || len(m.SigningKeyID) > 256 {
		return false
	}
	for _, digest := range []string{m.FiltersDigest, m.ScopeDigest, m.DataSHA256} {
		if len(digest) != 64 {
			return false
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return false
		}
	}
	return true
}
func ManifestDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

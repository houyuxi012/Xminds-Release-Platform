package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xminds-release-platform/internal/catalog"
	"xminds-release-platform/internal/signing"
)

func TestRunGeneratesEncryptedOfflineRootEnvelopeAndPublicBootstrap(t *testing.T) {
	directory := t.TempDir()
	masterPath := filepath.Join(directory, "master.key")
	master := make([]byte, signing.MasterKeySize)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(masterPath, master, 0o600); err != nil {
		t.Fatal(err)
	}
	onlineKeysPath := filepath.Join(directory, "online-keys.json")
	writeOnlineKeys(t, onlineKeysPath)
	privatePath := filepath.Join(directory, "root-private.json")
	envelopePath := filepath.Join(directory, "root.json")
	expires := time.Now().UTC().Add(365 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{
		"--master-key-file", masterPath,
		"--online-keys-file", onlineKeysPath,
		"--private-key-file", privatePath,
		"--root-envelope-file", envelopePath,
		"--key-id", "root-production-2026",
		"--version", "1",
		"--expires", expires,
	}, &stdout, &stderr)
	if exitCode != 0 {
		t.Fatalf("run exit = %d, stderr = %s", exitCode, stderr.String())
	}
	if strings.Contains(strings.ToLower(stdout.String()+stderr.String()), "private") {
		t.Fatalf("command output disclosed a private-key label: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	privateInfo, err := os.Stat(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if privateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %o", privateInfo.Mode().Perm())
	}
	privateRaw, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(privateRaw, []byte(`"ciphertext"`)) || bytes.Contains(privateRaw, master) {
		t.Fatal("root private key file is not an encrypted envelope")
	}

	var bootstrap bootstrapMaterial
	if err := json.Unmarshal(stdout.Bytes(), &bootstrap); err != nil {
		t.Fatalf("decode bootstrap: %v", err)
	}
	if bootstrap.KeyID != "root-production-2026" || bootstrap.RootVersion != 1 || len(bootstrap.PublicKeyDigest) != 64 {
		t.Fatalf("unexpected bootstrap: %+v", bootstrap)
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(bootstrap.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("invalid bootstrap public key: %v", err)
	}
	rootRaw, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatal(err)
	}
	assertRootEnvelopeSignature(t, rootRaw, bootstrap.KeyID, publicKey)
}

func writeOnlineKeys(t *testing.T, path string) {
	t.Helper()
	roles := map[string]any{}
	for _, role := range []string{"targets", "snapshot", "timestamp", "revocation"} {
		public, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		roles[role] = map[string]any{
			"threshold": 1,
			"keys":      []any{map[string]any{"key_id": role + "-production-2026", "public_key": base64.RawURLEncoding.EncodeToString(public)}},
		}
	}
	raw, err := json.Marshal(roles)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertRootEnvelopeSignature(t *testing.T, raw []byte, keyID string, publicKey []byte) {
	t.Helper()
	var envelope struct {
		Signed     json.RawMessage `json:"signed"`
		Signatures []struct {
			KeyID string `json:"keyid"`
			Value string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	payload, err := catalog.CanonicalJSON(envelope.Signed)
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope.Signatures) != 1 || envelope.Signatures[0].KeyID != keyID {
		t.Fatalf("unexpected root signatures: %+v", envelope.Signatures)
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signatures[0].Value)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		t.Fatal("root envelope signature is invalid")
	}
}

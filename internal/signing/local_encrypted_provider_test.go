package signing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLocalEncryptedProviderSignsWithoutPersistingPlaintextPrivateKey(t *testing.T) {
	provider, privateKey, keyFile := newTestProvider(t, "targets-2026", "targets-key-2026")
	payload := []byte("trusted catalog payload")

	signature, err := provider.Sign(context.Background(), "targets-2026", payload)
	if err != nil {
		t.Fatal(err)
	}
	if signature.KeyID != "targets-key-2026" || signature.Algorithm != AlgorithmEd25519 {
		t.Fatalf("unexpected signature metadata: %+v", signature)
	}
	if !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), payload, signature.Value) {
		t.Fatal("provider returned an invalid signature")
	}
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if containsBytes(raw, privateKey.Seed()) {
		t.Fatal("encrypted key file contains plaintext private seed")
	}
}

func TestLocalEncryptedProviderReturnsRequestedPublicKeysInStableOrder(t *testing.T) {
	directory := t.TempDir()
	masterPath, masterKey := writeMasterKey(t, directory, 0o600)
	for _, item := range []struct{ ref, id string }{{"snapshot-2026", "snapshot-key-2026"}, {"targets-2026", "targets-key-2026"}} {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteEncryptedKeyFile(filepath.Join(directory, item.ref+".json"), masterKey, item.ref, item.id, privateKey); err != nil {
			t.Fatal(err)
		}
	}
	provider, err := NewLocalEncryptedProvider(directory, masterPath)
	if err != nil {
		t.Fatal(err)
	}

	keys, err := provider.PublicKeys(context.Background(), []string{"targets-2026", "snapshot-2026"})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || keys[0].KeyID != "targets-key-2026" || keys[1].KeyID != "snapshot-key-2026" {
		t.Fatalf("public keys are not aligned to requested refs: %+v", keys)
	}
}

func TestLocalEncryptedProviderRejectsRootAndUnsafeSecretPermissions(t *testing.T) {
	directory := t.TempDir()
	masterPath, _ := writeMasterKey(t, directory, 0o644)
	if _, err := NewLocalEncryptedProvider(directory, masterPath); !errors.Is(err, ErrSecretPermissions) {
		t.Fatalf("expected unsafe master key permissions error, got %v", err)
	}

	provider, _, _ := newTestProvider(t, "root", "root-key-2026")
	if _, err := provider.Sign(context.Background(), "root", []byte("payload")); !errors.Is(err, ErrRootKeyOffline) {
		t.Fatalf("expected offline root rejection, got %v", err)
	}
}

func TestLocalEncryptedProviderFailsClosedOnTamperedCiphertext(t *testing.T) {
	provider, _, keyFile := newTestProvider(t, "timestamp-2026", "timestamp-key-2026")
	raw, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-3] ^= 1
	if err := os.WriteFile(keyFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := provider.Sign(context.Background(), "timestamp-2026", []byte("payload")); !errors.Is(err, ErrKeyDecryption) {
		t.Fatalf("expected authenticated decryption failure, got %v", err)
	}
}

func TestLocalEncryptedProviderRejectsCanceledContextMissingKeysAndDuplicateRefs(t *testing.T) {
	provider, _, _ := newTestProvider(t, "targets-2026", "targets-key-2026")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.Sign(canceled, "targets-2026", []byte("payload")); !errors.Is(err, ErrSigningContextClosed) {
		t.Fatalf("canceled Sign() error = %v", err)
	}
	if _, err := provider.PublicKeys(canceled, []string{"targets-2026"}); !errors.Is(err, ErrSigningContextClosed) {
		t.Fatalf("canceled PublicKeys() error = %v", err)
	}
	if _, err := provider.Sign(context.Background(), "missing-2026", []byte("payload")); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("missing Sign() error = %v", err)
	}
	if _, err := provider.PublicKeys(context.Background(), []string{"targets-2026", "targets-2026"}); !errors.Is(err, ErrKeyReferenceInvalid) {
		t.Fatalf("duplicate PublicKeys() error = %v", err)
	}
	var nilProvider *LocalEncryptedProvider
	if _, err := nilProvider.Sign(context.Background(), "targets-2026", []byte("payload")); !errors.Is(err, ErrProviderRequired) {
		t.Fatalf("nil provider Sign() error = %v", err)
	}
}

func TestLocalEncryptedProviderRejectsUnsafeKeyFilesAndInvalidKeyMaterial(t *testing.T) {
	directory := t.TempDir()
	masterPath, masterKey := writeMasterKey(t, directory, 0o600)
	provider, err := NewLocalEncryptedProvider(directory, masterPath)
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, "snapshot-2026.json")
	if err := WriteEncryptedKeyFile(keyPath, masterKey, "snapshot-2026", "snapshot-key-2026", privateKey); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Sign(context.Background(), "snapshot-2026", []byte("payload")); !errors.Is(err, ErrSecretPermissions) {
		t.Fatalf("unsafe key mode error = %v", err)
	}
	if err := WriteEncryptedKeyFile(filepath.Join(directory, "invalid-ref.json"), masterKey, "../invalid", "key", privateKey); !errors.Is(err, ErrKeyReferenceInvalid) {
		t.Fatalf("invalid ref error = %v", err)
	}
	if err := WriteEncryptedKeyFile(filepath.Join(directory, "invalid-master.json"), []byte("short"), "targets", "targets-key", privateKey); !errors.Is(err, ErrKeyMaterialInvalid) {
		t.Fatalf("invalid master error = %v", err)
	}
	if err := WriteEncryptedKeyFile(filepath.Join(directory, "invalid-private.json"), masterKey, "targets", "targets-key", ed25519.PrivateKey([]byte("short"))); !errors.Is(err, ErrKeyMaterialInvalid) {
		t.Fatalf("invalid private key error = %v", err)
	}
}

func TestNewLocalEncryptedProviderRejectsMissingShortAndSymlinkedMasterKey(t *testing.T) {
	directory := t.TempDir()
	if _, err := NewLocalEncryptedProvider(directory, filepath.Join(directory, "missing.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing master error = %v", err)
	}
	shortPath := filepath.Join(directory, "short.key")
	if err := os.WriteFile(shortPath, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalEncryptedProvider(directory, shortPath); !errors.Is(err, ErrKeyMaterialInvalid) {
		t.Fatalf("short master error = %v", err)
	}
	targetPath, _ := writeMasterKey(t, directory, 0o600)
	symlinkPath := filepath.Join(directory, "master-link.key")
	if err := os.Symlink(targetPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalEncryptedProvider(directory, symlinkPath); !errors.Is(err, ErrKeyMaterialInvalid) {
		t.Fatalf("symlink master error = %v", err)
	}
	if _, err := NewLocalEncryptedProvider("", targetPath); !errors.Is(err, ErrKeyMaterialInvalid) {
		t.Fatalf("empty directory error = %v", err)
	}
}

func TestLocalEncryptedProviderRejectsMalformedEncryptedKeyMetadata(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"wrong version", func(document map[string]any) { document["version"] = float64(2) }},
		{"wrong key ref", func(document map[string]any) { document["key_ref"] = "other-key" }},
		{"wrong algorithm", func(document map[string]any) { document["algorithm"] = "rsa" }},
		{"invalid public key", func(document map[string]any) { document["public_key"] = "AQ" }},
		{"invalid nonce", func(document map[string]any) { document["nonce"] = "!" }},
		{"invalid ciphertext", func(document map[string]any) { document["ciphertext"] = "!" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			provider, _, keyFile := newTestProvider(t, "revocation-2026", "revocation-key-2026")
			raw, err := os.ReadFile(keyFile)
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := json.Unmarshal(raw, &document); err != nil {
				t.Fatal(err)
			}
			test.mutate(document)
			raw, err = json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyFile, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := provider.Sign(context.Background(), "revocation-2026", []byte("payload")); !errors.Is(err, ErrKeyDecryption) {
				t.Fatalf("expected decryption rejection, got %v", err)
			}
		})
	}
}

func TestWriteEncryptedKeyFileRefusesOverwriteAndInvalidKeyID(t *testing.T) {
	directory := t.TempDir()
	_, master := writeMasterKey(t, directory, 0o600)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "targets.json")
	if err := WriteEncryptedKeyFile(path, master, "targets", "targets-key", privateKey); err != nil {
		t.Fatal(err)
	}
	if err := WriteEncryptedKeyFile(path, master, "targets", "targets-key", privateKey); err == nil {
		t.Fatal("existing encrypted key was overwritten")
	}
	if err := WriteEncryptedKeyFile(filepath.Join(directory, "bad-id.json"), master, "targets", "bad key id", privateKey); !errors.Is(err, ErrKeyMaterialInvalid) {
		t.Fatalf("invalid key ID error = %v", err)
	}
	provider, _, _ := newTestProvider(t, "targets-nil-context", "targets-nil-context-key")
	if _, err := provider.Sign(nil, "targets-nil-context", []byte("payload")); err != nil {
		t.Fatalf("nil context Sign() error = %v", err)
	}
}

func newTestProvider(t *testing.T, keyRef, keyID string) (*LocalEncryptedProvider, ed25519.PrivateKey, string) {
	t.Helper()
	directory := t.TempDir()
	masterPath, masterKey := writeMasterKey(t, directory, 0o600)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(directory, keyRef+".json")
	if err := WriteEncryptedKeyFile(keyFile, masterKey, keyRef, keyID, privateKey); err != nil {
		t.Fatal(err)
	}
	provider, err := NewLocalEncryptedProvider(directory, masterPath)
	if err != nil {
		t.Fatal(err)
	}
	return provider, privateKey, keyFile
}

func writeMasterKey(t *testing.T, directory string, mode os.FileMode) (string, []byte) {
	t.Helper()
	master := make([]byte, MasterKeySize)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "master.key")
	if err := os.WriteFile(path, master, mode); err != nil {
		t.Fatal(err)
	}
	return path, master
}

func containsBytes(haystack, needle []byte) bool {
	for index := 0; index+len(needle) <= len(haystack); index++ {
		matched := true
		for offset := range needle {
			if haystack[index+offset] != needle[offset] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

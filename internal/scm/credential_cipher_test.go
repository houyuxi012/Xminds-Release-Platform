package scm

import (
	"bytes"
	"testing"

	"github.com/google/uuid"
)

func TestAESGCMCredentialCipherBindsCiphertextToCredentialMetadata(t *testing.T) {
	t.Parallel()

	cipher, err := NewAESGCMCredentialCipher("key-2026-08", map[string][]byte{
		"key-2026-08": bytes.Repeat([]byte{0x42}, 32),
		"key-2026-07": bytes.Repeat([]byte{0x24}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	encrypted, err := cipher.Encrypt(id, 3, CredentialKindGitHubToken, []byte("github-secret-value"))
	if err != nil {
		t.Fatal(err)
	}
	if encrypted.KeyID != "key-2026-08" || bytes.Contains(encrypted.Ciphertext, []byte("github-secret-value")) {
		t.Fatalf("unsafe encrypted value = %+v", encrypted)
	}
	plaintext, err := cipher.Decrypt(id, 3, CredentialKindGitHubToken, encrypted)
	if err != nil || string(plaintext) != "github-secret-value" {
		t.Fatalf("decrypt = %q, %v", plaintext, err)
	}
	wipeBytes(plaintext)
	if _, err := cipher.Decrypt(id, 4, CredentialKindGitHubToken, encrypted); err != ErrCredentialUnavailable {
		t.Fatalf("metadata substitution error = %v", err)
	}
	encrypted.Ciphertext[0] ^= 0xff
	if _, err := cipher.Decrypt(id, 3, CredentialKindGitHubToken, encrypted); err != ErrCredentialUnavailable {
		t.Fatalf("tamper error = %v", err)
	}
}

func TestAESGCMCredentialCipherReadsPreviousKeyAfterRotation(t *testing.T) {
	t.Parallel()

	oldCipher, err := NewAESGCMCredentialCipher("old", map[string][]byte{"old": bytes.Repeat([]byte{0x11}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	encrypted, err := oldCipher.Encrypt(id, 1, CredentialKindGitLabAccessToken, []byte("rotatable-secret"))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewAESGCMCredentialCipher("new", map[string][]byte{
		"new": bytes.Repeat([]byte{0x22}, 32),
		"old": bytes.Repeat([]byte{0x11}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := rotated.Decrypt(id, 1, CredentialKindGitLabAccessToken, encrypted)
	if err != nil || string(plaintext) != "rotatable-secret" {
		t.Fatalf("decrypt previous key = %q, %v", plaintext, err)
	}
}

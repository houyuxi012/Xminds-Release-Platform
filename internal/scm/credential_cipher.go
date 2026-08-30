package scm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"strings"

	"github.com/google/uuid"
)

type EncryptedSecret struct {
	KeyID      string
	Nonce      []byte
	Ciphertext []byte
}

type CredentialCipher interface {
	Encrypt(id uuid.UUID, version int, kind CredentialKind, plaintext []byte) (EncryptedSecret, error)
	Decrypt(id uuid.UUID, version int, kind CredentialKind, encrypted EncryptedSecret) ([]byte, error)
}

type AESGCMCredentialCipher struct {
	currentKeyID string
	keys         map[string][]byte
}

func NewAESGCMCredentialCipher(currentKeyID string, keys map[string][]byte) (*AESGCMCredentialCipher, error) {
	currentKeyID = strings.TrimSpace(currentKeyID)
	if currentKeyID == "" || len(keys) == 0 {
		return nil, ErrCredentialUnavailable
	}
	copyKeys := make(map[string][]byte, len(keys))
	for keyID, key := range keys {
		keyID = strings.TrimSpace(keyID)
		if keyID == "" || len(key) != 32 {
			return nil, ErrCredentialUnavailable
		}
		copyKeys[keyID] = append([]byte(nil), key...)
	}
	if _, exists := copyKeys[currentKeyID]; !exists {
		return nil, ErrCredentialUnavailable
	}
	return &AESGCMCredentialCipher{currentKeyID: currentKeyID, keys: copyKeys}, nil
}

func (credentialCipher *AESGCMCredentialCipher) Encrypt(id uuid.UUID, version int, kind CredentialKind, plaintext []byte) (EncryptedSecret, error) {
	if credentialCipher == nil || id == uuid.Nil || version <= 0 || !kind.valid() || len(plaintext) < 8 || len(plaintext) > 64*1024 {
		return EncryptedSecret{}, ErrCredentialUnavailable
	}
	aead, err := credentialCipher.aead(credentialCipher.currentKeyID)
	if err != nil {
		return EncryptedSecret{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return EncryptedSecret{}, errors.Join(ErrCredentialUnavailable, err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, credentialAAD(id, version, kind, credentialCipher.currentKeyID))
	return EncryptedSecret{KeyID: credentialCipher.currentKeyID, Nonce: nonce, Ciphertext: ciphertext}, nil
}

func (credentialCipher *AESGCMCredentialCipher) Decrypt(id uuid.UUID, version int, kind CredentialKind, encrypted EncryptedSecret) ([]byte, error) {
	if credentialCipher == nil || id == uuid.Nil || version <= 0 || !kind.valid() || strings.TrimSpace(encrypted.KeyID) == "" {
		return nil, ErrCredentialUnavailable
	}
	aead, err := credentialCipher.aead(encrypted.KeyID)
	if err != nil || len(encrypted.Nonce) != aeadNonceSize(aead) || len(encrypted.Ciphertext) < aead.Overhead() {
		return nil, ErrCredentialUnavailable
	}
	plaintext, err := aead.Open(nil, encrypted.Nonce, encrypted.Ciphertext, credentialAAD(id, version, kind, encrypted.KeyID))
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	return plaintext, nil
}

func (credentialCipher *AESGCMCredentialCipher) aead(keyID string) (cipher.AEAD, error) {
	key, exists := credentialCipher.keys[keyID]
	if !exists {
		return nil, ErrCredentialUnavailable
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrCredentialUnavailable
	}
	return aead, nil
}

func credentialAAD(id uuid.UUID, version int, kind CredentialKind, keyID string) []byte {
	aad := make([]byte, 0, 16+4+len(kind)+len(keyID)+2)
	aad = append(aad, id[:]...)
	versionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(versionBytes, uint32(version))
	aad = append(aad, versionBytes...)
	aad = append(aad, 0, byte(len(kind)))
	aad = append(aad, kind...)
	aad = append(aad, 0, byte(len(keyID)))
	aad = append(aad, keyID...)
	return aad
}

func aeadNonceSize(aead cipher.AEAD) int {
	if aead == nil {
		return -1
	}
	return aead.NonceSize()
}

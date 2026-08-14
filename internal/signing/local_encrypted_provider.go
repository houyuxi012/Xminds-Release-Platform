package signing

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	MasterKeySize         = 32
	encryptedKeyVersion   = 1
	encryptedKeyExtension = ".json"
)

var keyReferencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type LocalEncryptedProvider struct {
	directory string
	masterKey [MasterKeySize]byte
}

type encryptedKeyDocument struct {
	Version    int    `json:"version"`
	KeyRef     string `json:"key_ref"`
	KeyID      string `json:"key_id"`
	Algorithm  string `json:"algorithm"`
	PublicKey  string `json:"public_key"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func NewLocalEncryptedProvider(directory, masterKeyPath string) (*LocalEncryptedProvider, error) {
	if strings.TrimSpace(directory) == "" || strings.TrimSpace(masterKeyPath) == "" {
		return nil, ErrKeyMaterialInvalid
	}
	masterKey, err := readSecretFile(masterKeyPath)
	if err != nil {
		return nil, err
	}
	defer wipe(masterKey)
	if len(masterKey) != MasterKeySize {
		return nil, ErrKeyMaterialInvalid
	}
	var provider LocalEncryptedProvider
	provider.directory = filepath.Clean(directory)
	copy(provider.masterKey[:], masterKey)
	return &provider, nil
}

func (provider *LocalEncryptedProvider) Sign(ctx context.Context, keyRef string, payload []byte) (Signature, error) {
	if err := checkContext(ctx); err != nil {
		return Signature{}, err
	}
	document, privateKey, err := provider.loadPrivateKey(keyRef)
	if err != nil {
		return Signature{}, err
	}
	defer wipe(privateKey)
	signature := ed25519.Sign(ed25519.PrivateKey(privateKey), payload)
	return Signature{KeyID: document.KeyID, Algorithm: AlgorithmEd25519, Value: signature}, nil
}

func (provider *LocalEncryptedProvider) PublicKeys(ctx context.Context, keyRefs []string) ([]PublicKey, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	result := make([]PublicKey, 0, len(keyRefs))
	seen := make(map[string]struct{}, len(keyRefs))
	for _, keyRef := range keyRefs {
		if _, exists := seen[keyRef]; exists {
			return nil, ErrKeyReferenceInvalid
		}
		seen[keyRef] = struct{}{}
		document, privateKey, err := provider.loadPrivateKey(keyRef)
		if err != nil {
			return nil, err
		}
		publicKey := append([]byte(nil), ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)...)
		wipe(privateKey)
		result = append(result, PublicKey{KeyID: document.KeyID, Algorithm: AlgorithmEd25519, Value: publicKey})
	}
	return result, nil
}

func WriteEncryptedKeyFile(path string, masterKey []byte, keyRef, keyID string, privateKey ed25519.PrivateKey) error {
	if err := validateKeyReference(keyRef, false); err != nil {
		return err
	}
	if !keyReferencePattern.MatchString(keyID) || len(masterKey) != MasterKeySize || len(privateKey) != ed25519.PrivateKeySize {
		return ErrKeyMaterialInvalid
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return ErrKeyMaterialInvalid
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ErrKeyMaterialInvalid
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate signing key nonce: %w", err)
	}
	document := encryptedKeyDocument{
		Version: encryptedKeyVersion, KeyRef: keyRef, KeyID: keyID, Algorithm: AlgorithmEd25519,
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
		Nonce:     base64.RawURLEncoding.EncodeToString(nonce),
	}
	seed := append([]byte(nil), privateKey.Seed()...)
	document.Ciphertext = base64.RawURLEncoding.EncodeToString(gcm.Seal(nil, nonce, seed, documentAAD(document)))
	wipe(seed)
	raw, err := json.Marshal(document)
	if err != nil {
		return ErrKeyMaterialInvalid
	}
	raw = append(raw, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create encrypted signing key: %w", err)
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return fmt.Errorf("write encrypted signing key: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync encrypted signing key: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close encrypted signing key: %w", err)
	}
	return nil
}

func (provider *LocalEncryptedProvider) loadPrivateKey(keyRef string) (encryptedKeyDocument, []byte, error) {
	if provider == nil {
		return encryptedKeyDocument{}, nil, ErrProviderRequired
	}
	if err := validateKeyReference(keyRef, true); err != nil {
		return encryptedKeyDocument{}, nil, err
	}
	path := filepath.Join(provider.directory, keyRef+encryptedKeyExtension)
	raw, err := readSecretFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return encryptedKeyDocument{}, nil, ErrKeyNotFound
	}
	if err != nil {
		return encryptedKeyDocument{}, nil, err
	}
	var document encryptedKeyDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		return encryptedKeyDocument{}, nil, ErrKeyDecryption
	}
	if document.Version != encryptedKeyVersion || document.KeyRef != keyRef || !keyReferencePattern.MatchString(document.KeyID) || document.Algorithm != AlgorithmEd25519 {
		return encryptedKeyDocument{}, nil, ErrKeyDecryption
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(document.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return encryptedKeyDocument{}, nil, ErrKeyDecryption
	}
	nonce, err := base64.RawURLEncoding.DecodeString(document.Nonce)
	if err != nil {
		return encryptedKeyDocument{}, nil, ErrKeyDecryption
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(document.Ciphertext)
	if err != nil {
		return encryptedKeyDocument{}, nil, ErrKeyDecryption
	}
	block, err := aes.NewCipher(provider.masterKey[:])
	if err != nil {
		return encryptedKeyDocument{}, nil, ErrKeyDecryption
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return encryptedKeyDocument{}, nil, ErrKeyDecryption
	}
	seed, err := gcm.Open(nil, nonce, ciphertext, documentAAD(document))
	if err != nil || len(seed) != ed25519.SeedSize {
		wipe(seed)
		return encryptedKeyDocument{}, nil, ErrKeyDecryption
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	wipe(seed)
	actualPublic := privateKey.Public().(ed25519.PublicKey)
	if subtle.ConstantTimeCompare(actualPublic, publicKey) != 1 {
		wipe(privateKey)
		return encryptedKeyDocument{}, nil, ErrKeyDecryption
	}
	return document, privateKey, nil
}

func readSecretFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrKeyMaterialInvalid
	}
	if info.Mode().Perm() != 0o600 {
		return nil, ErrSecretPermissions
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func validateKeyReference(keyRef string, online bool) error {
	if !keyReferencePattern.MatchString(keyRef) {
		return ErrKeyReferenceInvalid
	}
	lower := strings.ToLower(keyRef)
	if online && (lower == "root" || strings.HasPrefix(lower, "root-") || strings.HasPrefix(lower, "root_")) {
		return ErrRootKeyOffline
	}
	return nil
}

func documentAAD(document encryptedKeyDocument) []byte {
	return []byte(fmt.Sprintf("xminds-release-signing-key:v%d:%s:%s:%s:%s", document.Version, document.KeyRef, document.KeyID, document.Algorithm, document.PublicKey))
}

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return fmt.Errorf("%w: %v", ErrSigningContextClosed, ctx.Err())
	default:
		return nil
	}
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

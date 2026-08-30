package signing

import (
	"context"
	"errors"
)

const AlgorithmEd25519 = "ed25519"

var (
	ErrProviderRequired     = errors.New("signing provider is required")
	ErrKeyReferenceInvalid  = errors.New("signing key reference is invalid")
	ErrKeyNotFound          = errors.New("signing key was not found")
	ErrKeyMaterialInvalid   = errors.New("signing key material is invalid")
	ErrKeyDecryption        = errors.New("signing key authenticated decryption failed")
	ErrSecretPermissions    = errors.New("signing secret file permissions must be 0600")
	ErrRootKeyOffline       = errors.New("root signing key is offline and cannot be loaded by the online provider")
	ErrSigningContextClosed = errors.New("signing context is closed")
)

type Provider interface {
	Sign(ctx context.Context, keyRef string, payload []byte) (Signature, error)
	PublicKeys(ctx context.Context, keyRefs []string) ([]PublicKey, error)
}

type Signature struct {
	KeyID     string
	Algorithm string
	Value     []byte
}

type PublicKey struct {
	KeyID     string
	Algorithm string
	Value     []byte
}

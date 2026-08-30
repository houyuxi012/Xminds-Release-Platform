package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"xminds-release-platform/internal/release"
)

type Role string

const (
	RoleRoot       Role = "root"
	RoleTargets    Role = "targets"
	RoleSnapshot   Role = "snapshot"
	RoleTimestamp  Role = "timestamp"
	RoleRevocation Role = "revocation"

	ImageModeOnline  = "online"
	ImageModeOffline = "offline"
)

var (
	ErrCanonicalJSON               = errors.New("catalog canonical JSON is invalid")
	ErrBundleIncomplete            = errors.New("catalog exact five-role bundle is incomplete")
	ErrEnvelopeInvalid             = errors.New("catalog role envelope is invalid")
	ErrRoleTypeInvalid             = errors.New("catalog role type is invalid")
	ErrRoleVersionInvalid          = errors.New("catalog role version is invalid")
	ErrRoleVersionMismatch         = errors.New("catalog cross-role version does not match")
	ErrRoleExpired                 = errors.New("catalog role has expired")
	ErrRoleDigestMismatch          = errors.New("catalog cross-role digest does not match")
	ErrSignatureThreshold          = errors.New("catalog signature threshold was not satisfied")
	ErrRootInvalid                 = errors.New("catalog root keyring is invalid")
	ErrTargetInvalid               = errors.New("catalog target is invalid")
	ErrReleaseNotesDigestMismatch  = errors.New("catalog release notes digest does not match")
	ErrCompatibilityDigestMismatch = errors.New("catalog compatibility digest does not match")
	ErrTargetRevoked               = errors.New("catalog target is revoked")
	ErrKeyRevoked                  = errors.New("catalog signing key is revoked")
	ErrVersionsInvalid             = errors.New("catalog versions are invalid")
	ErrBuilderConfiguration        = errors.New("catalog builder configuration is invalid")
	ErrTargetResolverRequired      = errors.New("catalog target resolver is required")
)

type Bundle struct {
	Root       []byte
	Targets    []byte
	Snapshot   []byte
	Timestamp  []byte
	Revocation []byte
}

func (bundle Bundle) Roles() map[Role][]byte {
	return map[Role][]byte{
		RoleRoot: bundle.Root, RoleTargets: bundle.Targets, RoleSnapshot: bundle.Snapshot,
		RoleTimestamp: bundle.Timestamp, RoleRevocation: bundle.Revocation,
	}
}

type Versions struct {
	Root       uint64
	Targets    uint64
	Snapshot   uint64
	Timestamp  uint64
	Revocation uint64
}

func (versions Versions) valid() bool {
	return versions.Root > 0 && versions.Targets > 0 && versions.Snapshot > 0 && versions.Timestamp > 0 && versions.Revocation > 0
}

type RoleKeyRefs struct {
	Targets    []string
	Snapshot   []string
	Timestamp  []string
	Revocation []string
}

type TargetMetadata struct {
	TargetName               string
	ProductID                string
	ReleaseID                string
	Version                  string
	PlanDigest               string
	ArtifactDigest           string
	ManifestDigest           string
	ReleaseNotesMarkdown     string
	ReleaseNotesDigest       string
	Compatibility            json.RawMessage
	CompatibilityDigest      string
	TargetImages             []string
	ImageMode                string
	OfflineImageBundleDigest string
}

type TargetResolver interface {
	Resolve(ctx context.Context, record release.Release) (TargetMetadata, error)
}

type TargetResolverFunc func(context.Context, release.Release) (TargetMetadata, error)

func (resolver TargetResolverFunc) Resolve(ctx context.Context, record release.Release) (TargetMetadata, error) {
	return resolver(ctx, record)
}

type Clock func() time.Time

type wireSignature struct {
	KeyID string
	Value string
}

type parsedEnvelope struct {
	Signed        map[string]any
	Signatures    []wireSignature
	SignedBytes   []byte
	EnvelopeBytes []byte
}

type rootKey struct {
	Public []byte
}

type rootRole struct {
	KeyIDs    []string
	Threshold int
}

type rootMetadata struct {
	Keys  map[string]rootKey
	Roles map[string]rootRole
}

package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"xminds-release-platform/internal/release"
	"xminds-release-platform/internal/signing"
)

const (
	targetsLifetime    = 30 * 24 * time.Hour
	snapshotLifetime   = 7 * 24 * time.Hour
	timestampLifetime  = 24 * time.Hour
	revocationLifetime = 7 * 24 * time.Hour
)

type BuilderConfig struct {
	Root     []byte
	Provider signing.Provider
	KeyRefs  RoleKeyRefs
	Resolver TargetResolver
	Clock    Clock
}

type Builder struct {
	root     parsedEnvelope
	provider signing.Provider
	keyRefs  RoleKeyRefs
	resolver TargetResolver
	clock    Clock
}

func NewBuilder(config BuilderConfig) (*Builder, error) {
	if config.Provider == nil || config.Resolver == nil || config.Clock == nil || len(config.Root) == 0 {
		return nil, ErrBuilderConfiguration
	}
	root, err := parseEnvelope(config.Root)
	if err != nil {
		return nil, err
	}
	rootMetadata, err := parseRoot(root)
	if err != nil {
		return nil, err
	}
	if root.Signed["_type"] != string(RoleRoot) {
		return nil, ErrRoleTypeInvalid
	}
	if err := verifyRoleSignatures(rootMetadata, root, RoleRoot); err != nil {
		return nil, err
	}
	for _, refs := range [][]string{config.KeyRefs.Targets, config.KeyRefs.Snapshot, config.KeyRefs.Timestamp, config.KeyRefs.Revocation} {
		if len(refs) == 0 {
			return nil, ErrBuilderConfiguration
		}
	}
	return &Builder{root: root, provider: config.Provider, keyRefs: config.KeyRefs, resolver: config.Resolver, clock: config.Clock}, nil
}

func (builder *Builder) Build(ctx context.Context, record release.Release, versions Versions) (Bundle, error) {
	if builder == nil || !versions.valid() {
		return Bundle{}, ErrVersionsInvalid
	}
	rootVersion, err := positiveVersion(builder.root.Signed["version"])
	if err != nil || rootVersion != versions.Root {
		return Bundle{}, ErrRoleVersionMismatch
	}
	target, err := builder.resolver.Resolve(ctx, record)
	if err != nil {
		return Bundle{}, fmt.Errorf("resolve catalog target: %w", err)
	}
	if err := validateTargetMetadata(target); err != nil {
		return Bundle{}, err
	}
	now := builder.clock().UTC().Truncate(time.Second)
	custom := map[string]any{
		"product_id": target.ProductID, "release_id": target.ReleaseID, "version": target.Version,
		"plan_digest": target.PlanDigest, "artifact_digest": target.ArtifactDigest, "manifest_digest": target.ManifestDigest,
		"release_notes_markdown": target.ReleaseNotesMarkdown, "release_notes_digest": target.ReleaseNotesDigest,
		"compatibility": mustStrictValue(target.Compatibility), "compatibility_digest": target.CompatibilityDigest,
		"target_images": append([]string(nil), target.TargetImages...), "image_mode": target.ImageMode,
	}
	if target.OfflineImageBundleDigest != "" {
		custom["offline_image_bundle_digest"] = target.OfflineImageBundleDigest
	}
	targetsSigned := map[string]any{
		"_type": string(RoleTargets), "version": versions.Targets, "expires": roleTime(now.Add(targetsLifetime)),
		"targets": map[string]any{target.TargetName: map[string]any{
			"hashes": map[string]any{"sha256": strings.TrimPrefix(target.ArtifactDigest, "sha256:")}, "custom": custom,
		}},
	}
	targets, err := builder.signEnvelope(ctx, RoleTargets, builder.keyRefs.Targets, targetsSigned)
	if err != nil {
		return Bundle{}, err
	}
	snapshotSigned := map[string]any{
		"_type": string(RoleSnapshot), "version": versions.Snapshot, "expires": roleTime(now.Add(snapshotLifetime)),
		"meta": map[string]any{"targets.json": metadataBinding(versions.Targets, targets)},
	}
	snapshot, err := builder.signEnvelope(ctx, RoleSnapshot, builder.keyRefs.Snapshot, snapshotSigned)
	if err != nil {
		return Bundle{}, err
	}
	timestampSigned := map[string]any{
		"_type": string(RoleTimestamp), "version": versions.Timestamp, "expires": roleTime(now.Add(timestampLifetime)),
		"meta": map[string]any{"snapshot.json": metadataBinding(versions.Snapshot, snapshot)},
	}
	timestamp, err := builder.signEnvelope(ctx, RoleTimestamp, builder.keyRefs.Timestamp, timestampSigned)
	if err != nil {
		return Bundle{}, err
	}
	revocations := []any{}
	if record.RevokedAt != nil {
		revocations = append(revocations, map[string]any{"release_id": target.ReleaseID, "manifest_digest": target.ManifestDigest, "key_id": "", "reason": record.RevocationReason, "revoked_at": roleTime(record.RevokedAt.UTC())})
	}
	revocationSigned := map[string]any{
		"_type": string(RoleRevocation), "version": versions.Revocation, "expires": roleTime(now.Add(revocationLifetime)),
		"revocations": revocations,
	}
	revocation, err := builder.signEnvelope(ctx, RoleRevocation, builder.keyRefs.Revocation, revocationSigned)
	if err != nil {
		return Bundle{}, err
	}
	bundle := Bundle{Root: append([]byte(nil), builder.root.EnvelopeBytes...), Targets: targets, Snapshot: snapshot, Timestamp: timestamp, Revocation: revocation}
	if err := Verify(bundle, builder.clock); err != nil {
		return Bundle{}, fmt.Errorf("verify generated catalog: %w", err)
	}
	return bundle, nil
}

func (builder *Builder) signEnvelope(ctx context.Context, role Role, keyRefs []string, signed map[string]any) ([]byte, error) {
	payload, err := CanonicalJSON(signed)
	if err != nil {
		return nil, err
	}
	signatures := make([]map[string]any, 0, len(keyRefs))
	seen := map[string]struct{}{}
	for _, keyRef := range keyRefs {
		signature, err := builder.provider.Sign(ctx, keyRef, payload)
		if err != nil {
			return nil, fmt.Errorf("sign %s catalog role: %w", role, err)
		}
		if signature.Algorithm != signing.AlgorithmEd25519 || signature.KeyID == "" || len(signature.Value) != 64 {
			return nil, ErrSignatureThreshold
		}
		if _, duplicate := seen[signature.KeyID]; duplicate {
			return nil, ErrSignatureThreshold
		}
		seen[signature.KeyID] = struct{}{}
		signatures = append(signatures, map[string]any{"keyid": signature.KeyID, "sig": base64.RawURLEncoding.EncodeToString(signature.Value)})
	}
	sort.Slice(signatures, func(left, right int) bool {
		return signatures[left]["keyid"].(string) < signatures[right]["keyid"].(string)
	})
	return CanonicalJSON(map[string]any{"signed": signed, "signatures": signatures})
}

func validateTargetMetadata(target TargetMetadata) error {
	if target.TargetName == "" || target.ProductID == "" || target.ReleaseID == "" || target.Version == "" || target.ReleaseNotesMarkdown == "" {
		return ErrTargetInvalid
	}
	for _, digest := range []string{target.PlanDigest, target.ArtifactDigest, target.ManifestDigest, target.ReleaseNotesDigest, target.CompatibilityDigest} {
		if !validDigest(digest) {
			return ErrTargetInvalid
		}
	}
	if !equalDigest(target.ReleaseNotesDigest, sha256Hex([]byte(target.ReleaseNotesMarkdown))) {
		return ErrReleaseNotesDigestMismatch
	}
	compatibility, err := CanonicalJSON(target.Compatibility)
	if err != nil {
		return ErrTargetInvalid
	}
	if !equalDigest(target.CompatibilityDigest, sha256Hex(compatibility)) {
		return ErrCompatibilityDigestMismatch
	}
	if target.ImageMode != ImageModeOnline && target.ImageMode != ImageModeOffline {
		return ErrTargetInvalid
	}
	if target.ImageMode == ImageModeOffline && !validDigest(target.OfflineImageBundleDigest) {
		return ErrTargetInvalid
	}
	if target.ImageMode == ImageModeOnline && target.OfflineImageBundleDigest != "" {
		return ErrTargetInvalid
	}
	seen := map[string]struct{}{}
	for _, image := range target.TargetImages {
		parts := strings.Split(image, "@sha256:")
		if len(parts) != 2 || parts[0] == "" || strings.ContainsAny(image, " \t\r\n") || len(parts[1]) != 64 || !digestPattern.MatchString(parts[1]) {
			return ErrTargetInvalid
		}
		if _, duplicate := seen[image]; duplicate {
			return ErrTargetInvalid
		}
		seen[image] = struct{}{}
	}
	return nil
}

func metadataBinding(version uint64, envelope []byte) map[string]any {
	digest := sha256.Sum256(envelope)
	return map[string]any{"version": version, "hashes": map[string]any{"sha256": hex.EncodeToString(digest[:])}}
}

func mustStrictValue(raw []byte) any {
	value, _ := strictJSONValue(raw)
	return value
}

func roleTime(value time.Time) string { return value.UTC().Truncate(time.Second).Format(time.RFC3339) }

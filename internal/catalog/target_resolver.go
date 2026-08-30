package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"xminds-release-platform/internal/product"
	"xminds-release-platform/internal/release"
)

type TargetProductReader interface {
	Get(ctx context.Context, productID string) (product.Product, error)
}

type RepositoryTargetResolver struct {
	products TargetProductReader
}

func NewRepositoryTargetResolver(products TargetProductReader) (*RepositoryTargetResolver, error) {
	if products == nil {
		return nil, ErrTargetResolverRequired
	}
	return &RepositoryTargetResolver{products: products}, nil
}

func (resolver *RepositoryTargetResolver) Resolve(ctx context.Context, record release.Release) (TargetMetadata, error) {
	if resolver == nil || resolver.products == nil || record.ID.String() == "" || record.ProductID == "" || len(record.Artifacts) == 0 {
		return TargetMetadata{}, ErrTargetInvalid
	}
	productRecord, err := resolver.products.Get(ctx, record.ProductID)
	if err != nil {
		return TargetMetadata{}, err
	}
	compatibility, err := CanonicalJSON(record.Compatibility)
	if err != nil {
		return TargetMetadata{}, ErrTargetInvalid
	}
	plan, err := CanonicalJSON(map[string]any{
		"product_id": record.ProductID,
		"release_id": record.ID.String(),
		"version":    record.Version,
		"channel":    record.Channel,
		"source": map[string]any{
			"repository": record.Source.Repository, "commit_sha": record.Source.CommitSHA,
			"tag": record.Source.Tag, "pipeline_ref": record.Source.PipelineRef,
		},
		"artifacts": record.Artifacts,
	})
	if err != nil {
		return TargetMetadata{}, ErrTargetInvalid
	}
	primary := record.Artifacts[0]
	images := make([]string, 0)
	for _, binding := range record.Artifacts {
		if !validDigest(binding.SHA256) {
			return TargetMetadata{}, ErrTargetInvalid
		}
		if isContainerArtifactType(binding.ArtifactType) {
			image, err := containerImageReference(binding.Filename, binding.SHA256)
			if err != nil {
				return TargetMetadata{}, err
			}
			images = append(images, image)
			continue
		}
		if isContainerArtifactType(primary.ArtifactType) {
			primary = binding
		}
	}
	if strings.TrimSpace(primary.Filename) == "" || !validDigest(primary.SHA256) || !validDigest(productRecord.ManifestDigest) {
		return TargetMetadata{}, ErrTargetInvalid
	}
	return TargetMetadata{
		TargetName: record.ID.String(), ProductID: record.ProductID, ReleaseID: record.ID.String(), Version: record.Version,
		PlanDigest: digestWithPrefix(plan), ArtifactDigest: digestWithPrefixText(primary.SHA256),
		ManifestDigest:       digestWithPrefixText(productRecord.ManifestDigest),
		ReleaseNotesMarkdown: record.ReleaseNotes, ReleaseNotesDigest: digestWithPrefixText(record.ReleaseNotesSHA256),
		Compatibility: record.Compatibility, CompatibilityDigest: digestWithPrefix(compatibility),
		TargetImages: images, ImageMode: ImageModeOnline,
	}, nil
}

func containerImageReference(filename, digest string) (string, error) {
	filename = strings.TrimSpace(filename)
	digest = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(digest)), "sha256:")
	if filename == "" || len(digest) != 64 || !digestPattern.MatchString(digest) {
		return "", ErrTargetInvalid
	}
	parts := strings.Split(filename, "@sha256:")
	switch len(parts) {
	case 1:
		return filename + "@sha256:" + digest, nil
	case 2:
		if parts[0] == "" || !strings.EqualFold(parts[1], digest) {
			return "", ErrTargetInvalid
		}
		return parts[0] + "@sha256:" + digest, nil
	default:
		return "", ErrTargetInvalid
	}
}

func isContainerArtifactType(artifactType string) bool {
	switch strings.ToLower(strings.TrimSpace(artifactType)) {
	case "container", "container-image", "oci", "oci-image":
		return true
	default:
		return false
	}
}

func digestWithPrefix(payload []byte) string {
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func digestWithPrefixText(digest string) string {
	digest = strings.TrimSpace(strings.ToLower(digest))
	if strings.HasPrefix(digest, "sha256:") {
		return digest
	}
	return "sha256:" + digest
}

var _ TargetResolver = (*RepositoryTargetResolver)(nil)

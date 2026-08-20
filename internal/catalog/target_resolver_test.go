package catalog

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"xminds-release-platform/internal/product"
	"xminds-release-platform/internal/release"
)

func TestRepositoryTargetResolverBuildsDeterministicProductMetadata(t *testing.T) {
	t.Parallel()

	resolver, err := NewRepositoryTargetResolver(productReaderFake{record: product.Product{
		ID: "ngep", ManifestDigest: strings.Repeat("b", 64),
	}})
	if err != nil {
		t.Fatal(err)
	}
	releaseID := uuid.New()
	record := release.Release{
		ID: releaseID, ProductID: "ngep", Version: "1.2.3", ReleaseNotes: "# Release",
		ReleaseNotesSHA256: strings.Repeat("c", 64), Compatibility: json.RawMessage(`{"os":["darwin"]}`),
		CompatibilitySHA256: strings.Repeat("d", 64),
		Source:              release.Source{Repository: "https://git.example/ngep", CommitSHA: strings.Repeat("a", 40), Tag: "v1.2.3", PipelineRef: "pipeline/1"},
		Artifacts: []release.ArtifactBinding{
			{ArtifactID: uuid.New(), ArtifactType: "desktop", Filename: "ngep.tar", SHA256: strings.Repeat("e", 64)},
			{ArtifactID: uuid.New(), ArtifactType: "container", Filename: "registry.example/ngep", SHA256: strings.Repeat("f", 64)},
		},
	}
	first, err := resolver.Resolve(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	second, err := resolver.Resolve(context.Background(), record)
	if err != nil {
		t.Fatal(err)
	}
	if first.PlanDigest != second.PlanDigest || !strings.HasPrefix(first.PlanDigest, "sha256:") {
		t.Fatalf("plan digests = %q/%q", first.PlanDigest, second.PlanDigest)
	}
	if first.TargetName != releaseID.String() || first.ArtifactDigest != "sha256:"+strings.Repeat("e", 64) {
		t.Fatalf("target metadata = %+v", first)
	}
	if len(first.TargetImages) != 1 || first.TargetImages[0] != "registry.example/ngep@sha256:"+strings.Repeat("f", 64) {
		t.Fatalf("target images = %#v", first.TargetImages)
	}
}

func TestRepositoryTargetResolverRejectsContainerReferenceWithDifferentDigest(t *testing.T) {
	t.Parallel()

	resolver, err := NewRepositoryTargetResolver(productReaderFake{record: product.Product{
		ID: "ngep", ManifestDigest: strings.Repeat("b", 64),
	}})
	if err != nil {
		t.Fatal(err)
	}
	record := release.Release{
		ID: uuid.New(), ProductID: "ngep", Version: "1.2.3", ReleaseNotes: "# Release",
		ReleaseNotesSHA256: strings.Repeat("c", 64), Compatibility: json.RawMessage(`{}`),
		Artifacts: []release.ArtifactBinding{{
			ArtifactID: uuid.New(), ArtifactType: "container",
			Filename: "registry.example/ngep@sha256:" + strings.Repeat("a", 64), SHA256: strings.Repeat("f", 64),
		}},
	}

	if _, err := resolver.Resolve(context.Background(), record); err != ErrTargetInvalid {
		t.Fatalf("Resolve() error = %v, want %v", err, ErrTargetInvalid)
	}
}

type productReaderFake struct{ record product.Product }

func (reader productReaderFake) Get(context.Context, string) (product.Product, error) {
	return reader.record, nil
}

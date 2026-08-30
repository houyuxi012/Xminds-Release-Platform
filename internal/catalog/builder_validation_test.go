package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"xminds-release-platform/internal/release"
	"xminds-release-platform/internal/signing"
)

func TestValidateTargetMetadataRejectsEverySecurityBoundary(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*TargetMetadata)
		want   error
	}{
		{"missing identity", func(target *TargetMetadata) { target.ReleaseID = "" }, ErrTargetInvalid},
		{"invalid digest", func(target *TargetMetadata) { target.PlanDigest = "invalid" }, ErrTargetInvalid},
		{"release notes mismatch", func(target *TargetMetadata) { target.ReleaseNotesMarkdown += "tampered" }, ErrReleaseNotesDigestMismatch},
		{"invalid compatibility", func(target *TargetMetadata) { target.Compatibility = json.RawMessage(`{"x":1.5}`) }, ErrTargetInvalid},
		{"compatibility mismatch", func(target *TargetMetadata) { target.Compatibility = json.RawMessage(`{"x":1}`) }, ErrCompatibilityDigestMismatch},
		{"invalid image mode", func(target *TargetMetadata) { target.ImageMode = "hybrid" }, ErrTargetInvalid},
		{"offline bundle required", func(target *TargetMetadata) { target.ImageMode = ImageModeOffline }, ErrTargetInvalid},
		{"online bundle forbidden", func(target *TargetMetadata) { target.OfflineImageBundleDigest = "sha256:" + repeat("a", 64) }, ErrTargetInvalid},
		{"malformed image", func(target *TargetMetadata) { target.TargetImages = []string{"registry/image:latest"} }, ErrTargetInvalid},
		{"duplicate image", func(target *TargetMetadata) {
			image := "registry/image@sha256:" + repeat("a", 64)
			target.TargetImages = []string{image, image}
		}, ErrTargetInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := validTargetMetadata(t)
			test.mutate(&target)
			if err := validateTargetMetadata(target); !errors.Is(err, test.want) {
				t.Fatalf("expected %v, got %v", test.want, err)
			}
		})
	}
}

func TestBuilderRejectsInvalidConfigurationVersionsAndResolverFailure(t *testing.T) {
	if _, err := NewBuilder(BuilderConfig{}); !errors.Is(err, ErrBuilderConfiguration) {
		t.Fatalf("empty config error = %v", err)
	}
	provider := newDeterministicProvider()
	now := time.Date(2026, 8, 14, 13, 0, 0, 0, time.UTC)
	root := provider.rootEnvelope(t, now.Add(365*24*time.Hour), 3)
	baseConfig := BuilderConfig{
		Root: root, Provider: provider,
		KeyRefs: RoleKeyRefs{
			Targets: []string{"targets-online"}, Snapshot: []string{"snapshot-online"},
			Timestamp: []string{"timestamp-online"}, Revocation: []string{"revocation-online"},
		},
		Resolver: TargetResolverFunc(func(context.Context, release.Release) (TargetMetadata, error) { return validTargetMetadata(t), nil }),
		Clock:    func() time.Time { return now },
	}
	missingKeyRefs := baseConfig
	missingKeyRefs.KeyRefs.Timestamp = nil
	if _, err := NewBuilder(missingKeyRefs); !errors.Is(err, ErrBuilderConfiguration) {
		t.Fatalf("missing key refs error = %v", err)
	}
	invalidRoot := baseConfig
	invalidRoot.Root = []byte(`{}`)
	if _, err := NewBuilder(invalidRoot); err == nil {
		t.Fatal("invalid root was accepted")
	}
	builder, err := NewBuilder(baseConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := builder.Build(context.Background(), release.Release{}, Versions{}); !errors.Is(err, ErrVersionsInvalid) {
		t.Fatalf("zero versions error = %v", err)
	}
	if _, err := builder.Build(context.Background(), release.Release{}, Versions{Root: 2, Targets: 1, Snapshot: 1, Timestamp: 1, Revocation: 1}); !errors.Is(err, ErrRoleVersionMismatch) {
		t.Fatalf("root version mismatch error = %v", err)
	}
	resolverFailure := baseConfig
	resolverFailure.Resolver = TargetResolverFunc(func(context.Context, release.Release) (TargetMetadata, error) {
		return TargetMetadata{}, errors.New("resolver unavailable")
	})
	builder, err = NewBuilder(resolverFailure)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := builder.Build(context.Background(), release.Release{}, Versions{Root: 3, Targets: 1, Snapshot: 1, Timestamp: 1, Revocation: 1}); err == nil {
		t.Fatal("resolver failure was ignored")
	}
	var nilBuilder *Builder
	if _, err := nilBuilder.Build(context.Background(), release.Release{}, Versions{Root: 1, Targets: 1, Snapshot: 1, Timestamp: 1, Revocation: 1}); !errors.Is(err, ErrVersionsInvalid) {
		t.Fatalf("nil builder error = %v", err)
	}
}

func TestBuilderRejectsInvalidProviderSignatureMetadata(t *testing.T) {
	provider := newDeterministicProvider()
	now := time.Date(2026, 8, 14, 13, 0, 0, 0, time.UTC)
	root := provider.rootEnvelope(t, now.Add(365*24*time.Hour), 1)
	badProvider := invalidSignatureProvider{Provider: provider}
	builder, err := NewBuilder(BuilderConfig{
		Root: root, Provider: badProvider,
		KeyRefs:  RoleKeyRefs{Targets: []string{"targets-online"}, Snapshot: []string{"snapshot-online"}, Timestamp: []string{"timestamp-online"}, Revocation: []string{"revocation-online"}},
		Resolver: TargetResolverFunc(func(context.Context, release.Release) (TargetMetadata, error) { return validTargetMetadata(t), nil }),
		Clock:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := builder.Build(context.Background(), release.Release{}, Versions{Root: 1, Targets: 1, Snapshot: 1, Timestamp: 1, Revocation: 1}); !errors.Is(err, ErrSignatureThreshold) {
		t.Fatalf("invalid provider signature error = %v", err)
	}
}

type invalidSignatureProvider struct{ signing.Provider }

func (provider invalidSignatureProvider) Sign(ctx context.Context, keyRef string, payload []byte) (signing.Signature, error) {
	signature, err := provider.Provider.Sign(ctx, keyRef, payload)
	signature.Algorithm = "rsa"
	return signature, err
}

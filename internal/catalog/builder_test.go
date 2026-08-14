package catalog

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"xminds-release-platform/internal/release"
	"xminds-release-platform/internal/signing"
)

var goldenClock = func() time.Time {
	return time.Date(2026, 8, 14, 12, 30, 0, 0, time.UTC)
}

func TestCanonicalJSONMatchesNGEPGoldenVector(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{"z": 1, "中文": "值", "a": true})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":true,"z":1,"中文":"值"}` {
		t.Fatalf("canonical = %s", got)
	}
}

func TestCanonicalJSONPreservesUnicodeSeparatorsAndUsesJSONControlEscapes(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{"text": "行一\u2028行二\x1b"})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("{\"text\":\"行一\u2028行二\\u001b\"}")
	if string(got) != string(want) {
		t.Fatalf("canonical bytes = %x, want %x", got, want)
	}
}

func TestCanonicalJSONRejectsUnsafeNumericAndTextValues(t *testing.T) {
	for name, value := range map[string]any{
		"float":        map[string]any{"version": 1.5},
		"negativeZero": json.RawMessage(`{"version":-0}`),
		"invalidUTF8":  json.RawMessage([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}),
		"nonStringKey": map[int]string{1: "value"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CanonicalJSON(value); !errors.Is(err, ErrCanonicalJSON) {
				t.Fatalf("expected canonical JSON rejection, got %v", err)
			}
		})
	}
}

func TestCanonicalJSONEncodesCompleteConsumerPrimitiveSubset(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{
		"array": []any{nil, true, false, json.Number("42")},
		"text":  "\"\\\b\f\n\r\t\x00\u2029",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"array\":[null,true,false,42],\"text\":\"\\\"\\\\\\b\\f\\n\\r\\t\\u0000\u2029\"}"
	if string(got) != want {
		t.Fatalf("canonical = %q, want %q", got, want)
	}
}

func TestVerifyAcceptsConsumerGoldenFiveRoleChain(t *testing.T) {
	if err := Verify(loadGoldenBundle(t), goldenClock); err != nil {
		t.Fatalf("valid consumer chain rejected: %v", err)
	}
}

func TestVerifyRejectsSnapshotTargetDigestMismatch(t *testing.T) {
	bundle := loadGoldenBundle(t)
	bundle.Snapshot = readGolden(t, "digest-mismatch-snapshot.json")
	if err := Verify(bundle, goldenClock); !errors.Is(err, ErrRoleDigestMismatch) {
		t.Fatalf("expected digest mismatch, got %v", err)
	}
}

func TestVerifyRejectsConsumerSecurityVectors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Bundle)
		want   error
	}{
		{"expired", func(bundle *Bundle) { bundle.Root = readGolden(t, "expired-root.json") }, ErrRoleExpired},
		{"duplicate key", func(bundle *Bundle) { bundle.Root = readGolden(t, "duplicate-key-root.json") }, ErrCanonicalJSON},
		{"invalid signature", func(bundle *Bundle) { bundle.Targets = readGolden(t, "invalid-signature-targets.json") }, ErrSignatureThreshold},
		{"revoked target", func(bundle *Bundle) { bundle.Revocation = readGolden(t, "revoked-target-revocation.json") }, ErrTargetRevoked},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundle := loadGoldenBundle(t)
			test.mutate(&bundle)
			if err := Verify(bundle, goldenClock); !errors.Is(err, test.want) {
				t.Fatalf("expected %v, got %v", test.want, err)
			}
		})
	}
}

func TestBuilderProducesVerifiableExactFiveRoleBundleWithRequiredTargetFields(t *testing.T) {
	provider := newDeterministicProvider()
	now := time.Date(2026, 8, 14, 13, 0, 0, 0, time.UTC)
	root := provider.rootEnvelope(t, now.Add(365*24*time.Hour), 3)
	descriptor := validTargetMetadata(t)
	builder, err := NewBuilder(BuilderConfig{
		Root:     root,
		Provider: provider,
		KeyRefs: RoleKeyRefs{
			Targets: []string{"targets-online"}, Snapshot: []string{"snapshot-online"},
			Timestamp: []string{"timestamp-online"}, Revocation: []string{"revocation-online"},
		},
		Resolver: TargetResolverFunc(func(context.Context, release.Release) (TargetMetadata, error) { return descriptor, nil }),
		Clock:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	bundle, err := builder.Build(context.Background(), release.Release{ID: uuid.MustParse("0198a012-9650-7b11-9ab0-5016f5a7ab20")}, Versions{Root: 3, Targets: 7, Snapshot: 9, Timestamp: 11, Revocation: 13})
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(bundle, func() time.Time { return now.Add(time.Hour) }); err != nil {
		t.Fatalf("builder produced unverifiable bundle: %v", err)
	}
	if got := len(bundle.Roles()); got != 5 {
		t.Fatalf("role count = %d, want 5", got)
	}

	var envelope struct {
		Signed struct {
			Expires time.Time                  `json:"expires"`
			Targets map[string]json.RawMessage `json:"targets"`
		} `json:"signed"`
	}
	if err := json.Unmarshal(bundle.Targets, &envelope); err != nil {
		t.Fatal(err)
	}
	if !envelope.Signed.Expires.Equal(now.Add(30 * 24 * time.Hour)) {
		t.Fatalf("targets expiry = %s", envelope.Signed.Expires)
	}
	rawTarget := envelope.Signed.Targets[descriptor.TargetName]
	for _, required := range []string{
		`"product_id"`, `"release_id"`, `"version"`, `"plan_digest"`, `"artifact_digest"`,
		`"manifest_digest"`, `"release_notes_markdown"`, `"release_notes_digest"`,
		`"compatibility"`, `"compatibility_digest"`, `"target_images"`, `"image_mode"`,
	} {
		if !jsonContains(rawTarget, required) {
			t.Fatalf("required target field %s is missing from %s", required, rawTarget)
		}
	}
}

func validTargetMetadata(t *testing.T) TargetMetadata {
	t.Helper()
	notes := "# 1.2.3\n\n- 企业级发布。\n"
	compatibility := json.RawMessage(`{"kubernetes":{"minimum":"1.30.0"},"rke2":true}`)
	canonicalCompatibility, err := CanonicalJSON(compatibility)
	if err != nil {
		t.Fatal(err)
	}
	return TargetMetadata{
		TargetName: "rel-20260814-stable", ProductID: "hyx-ngep", ReleaseID: "rel-20260814-stable",
		Version: "1.2.3", PlanDigest: digestOf([]byte("plan")), ArtifactDigest: "sha256:" + repeat("a", 64),
		ManifestDigest: "sha256:" + repeat("b", 64), ReleaseNotesMarkdown: notes,
		ReleaseNotesDigest: digestOf([]byte(notes)), Compatibility: compatibility,
		CompatibilityDigest: digestOf(canonicalCompatibility), TargetImages: []string{}, ImageMode: ImageModeOnline,
	}
}

type deterministicProvider struct {
	private map[string]ed25519.PrivateKey
	ids     map[string]string
}

func newDeterministicProvider() *deterministicProvider {
	provider := &deterministicProvider{private: map[string]ed25519.PrivateKey{}, ids: map[string]string{}}
	for index, role := range []string{"root-offline", "targets-online", "snapshot-online", "timestamp-online", "revocation-online"} {
		seed := make([]byte, ed25519.SeedSize)
		for offset := range seed {
			seed[offset] = byte(index + 1)
		}
		provider.private[role] = ed25519.NewKeyFromSeed(seed)
		provider.ids[role] = role + "-key-2026"
	}
	return provider
}

func (provider *deterministicProvider) Sign(_ context.Context, keyRef string, payload []byte) (signing.Signature, error) {
	privateKey, ok := provider.private[keyRef]
	if !ok {
		return signing.Signature{}, errors.New("unknown key ref")
	}
	return signing.Signature{KeyID: provider.ids[keyRef], Algorithm: signing.AlgorithmEd25519, Value: ed25519.Sign(privateKey, payload)}, nil
}

func (provider *deterministicProvider) PublicKeys(_ context.Context, keyRefs []string) ([]signing.PublicKey, error) {
	result := make([]signing.PublicKey, 0, len(keyRefs))
	for _, keyRef := range keyRefs {
		privateKey, ok := provider.private[keyRef]
		if !ok {
			return nil, errors.New("unknown key ref")
		}
		result = append(result, signing.PublicKey{KeyID: provider.ids[keyRef], Algorithm: signing.AlgorithmEd25519, Value: privateKey.Public().(ed25519.PublicKey)})
	}
	return result, nil
}

func (provider *deterministicProvider) rootEnvelope(t *testing.T, expires time.Time, version uint64) []byte {
	t.Helper()
	keys := map[string]any{}
	roles := map[string]any{}
	for _, item := range []struct{ role, ref string }{{"root", "root-offline"}, {"targets", "targets-online"}, {"snapshot", "snapshot-online"}, {"timestamp", "timestamp-online"}, {"revocation", "revocation-online"}} {
		privateKey := provider.private[item.ref]
		keyID := provider.ids[item.ref]
		keys[keyID] = map[string]any{"keytype": "ed25519", "scheme": "ed25519", "keyval": map[string]any{"public": base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))}}
		roles[item.role] = map[string]any{"keyids": []string{keyID}, "threshold": 1}
	}
	signed := map[string]any{"_type": "root", "version": version, "expires": expires.UTC().Format(time.RFC3339), "keys": keys, "roles": roles}
	payload, err := CanonicalJSON(signed)
	if err != nil {
		t.Fatal(err)
	}
	envelope := map[string]any{"signed": signed, "signatures": []any{map[string]any{"keyid": provider.ids["root-offline"], "sig": base64.RawURLEncoding.EncodeToString(ed25519.Sign(provider.private["root-offline"], payload))}}}
	raw, err := CanonicalJSON(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func loadGoldenBundle(t *testing.T) Bundle {
	t.Helper()
	return Bundle{Root: readGolden(t, "valid-root.json"), Targets: readGolden(t, "valid-targets.json"), Snapshot: readGolden(t, "valid-snapshot.json"), Timestamp: readGolden(t, "valid-timestamp.json"), Revocation: readGolden(t, "valid-revocation.json")}
}

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "ngep-golden", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func digestOf(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + fmtHex(digest[:])
}

func fmtHex(raw []byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, len(raw)*2)
	for index, value := range raw {
		result[index*2] = alphabet[value>>4]
		result[index*2+1] = alphabet[value&15]
	}
	return string(result)
}

func repeat(value string, count int) string {
	result := ""
	for index := 0; index < count; index++ {
		result += value
	}
	return result
}

func jsonContains(raw []byte, value string) bool {
	return len(raw) >= len(value) && string(raw) != "" && contains(string(raw), value)
}

func contains(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}

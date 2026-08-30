package catalog

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestVerifyRejectsSignedReleaseNotesAndCompatibilityDigestMismatch(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   error
	}{
		{
			name: "release notes",
			mutate: func(custom map[string]any) {
				custom["release_notes_markdown"] = "# tampered release notes"
			},
			want: ErrReleaseNotesDigestMismatch,
		},
		{
			name: "compatibility",
			mutate: func(custom map[string]any) {
				custom["compatibility"] = map[string]any{"kubernetes": map[string]any{"minimum": "9.9.9"}}
			},
			want: ErrCompatibilityDigestMismatch,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundle := loadGoldenBundle(t)
			bundle.Targets = resignGolden(t, RoleTargets, bundle.Targets, func(signed map[string]any) {
				targets := signed["targets"].(map[string]any)
				target := targets["rel-20260802-stable"].(map[string]any)
				test.mutate(target["custom"].(map[string]any))
			})
			rebindGoldenSnapshotAndTimestamp(t, &bundle)
			if err := Verify(bundle, goldenClock); !errors.Is(err, test.want) {
				t.Fatalf("expected %v, got %v", test.want, err)
			}
		})
	}
}

func TestVerifyRejectsSignedVersionMismatchRollbackAndRevokedKey(t *testing.T) {
	t.Run("cross-role version mismatch", func(t *testing.T) {
		bundle := loadGoldenBundle(t)
		bundle.Snapshot = resignGolden(t, RoleSnapshot, bundle.Snapshot, func(signed map[string]any) {
			meta := signed["meta"].(map[string]any)["targets.json"].(map[string]any)
			meta["version"] = json.Number("2")
		})
		bundle.Timestamp = rebindGoldenTimestamp(t, bundle.Timestamp, bundle.Snapshot)
		if err := Verify(bundle, goldenClock); !errors.Is(err, ErrRoleVersionMismatch) {
			t.Fatalf("expected version mismatch, got %v", err)
		}
	})

	t.Run("non-positive role version", func(t *testing.T) {
		bundle := loadGoldenBundle(t)
		bundle.Revocation = resignGolden(t, RoleRevocation, bundle.Revocation, func(signed map[string]any) {
			signed["version"] = json.Number("0")
		})
		if err := Verify(bundle, goldenClock); !errors.Is(err, ErrRoleVersionInvalid) {
			t.Fatalf("expected invalid version, got %v", err)
		}
	})

	t.Run("revoked targets key", func(t *testing.T) {
		bundle := loadGoldenBundle(t)
		bundle.Revocation = resignGolden(t, RoleRevocation, bundle.Revocation, func(signed map[string]any) {
			signed["revocations"] = []any{map[string]any{"release_id": "", "manifest_digest": "", "key_id": "targets-key-2026"}}
		})
		if err := Verify(bundle, goldenClock); !errors.Is(err, ErrKeyRevoked) {
			t.Fatalf("expected revoked key, got %v", err)
		}
	})
}

func TestVerifyRejectsIncompleteAndMalformedRoleEnvelopes(t *testing.T) {
	bundle := loadGoldenBundle(t)
	bundle.Timestamp = nil
	if err := Verify(bundle, goldenClock); !errors.Is(err, ErrBundleIncomplete) {
		t.Fatalf("expected incomplete bundle, got %v", err)
	}
	bundle = loadGoldenBundle(t)
	bundle.Timestamp = []byte(`{"signed":{},"signatures":[],"extra":true}`)
	if err := Verify(bundle, goldenClock); !errors.Is(err, ErrEnvelopeInvalid) {
		t.Fatalf("expected invalid envelope, got %v", err)
	}
}

func TestCatalogPrimitiveValidatorsFailClosedOnUnsupportedValues(t *testing.T) {
	if _, err := roleExpiry(json.Number("1")); !errors.Is(err, ErrRoleExpired) {
		t.Fatalf("non-string expiry error = %v", err)
	}
	if _, err := roleExpiry("not-a-time"); !errors.Is(err, ErrRoleExpired) {
		t.Fatalf("malformed expiry error = %v", err)
	}
	if _, err := positiveInt(json.Number("0")); err == nil {
		t.Fatal("zero threshold was accepted")
	}
	maximumInt := int(^uint(0) >> 1)
	converted, err := positiveInt(json.Number(strconv.FormatUint(uint64(maximumInt), 10)))
	if err != nil || converted != maximumInt {
		t.Fatalf("maximum int threshold = %d, %v", converted, err)
	}
	if _, err := positiveInt(json.Number(strconv.FormatUint(uint64(maximumInt)+1, 10))); !errors.Is(err, ErrRootInvalid) {
		t.Fatalf("threshold exceeding maximum int error = %v", err)
	}
	if _, err := positiveInt(json.Number("18446744073709551615")); err == nil {
		t.Fatal("threshold exceeding int was accepted")
	}
	if _, err := canonicalValue(make(chan struct{})); !errors.Is(err, ErrCanonicalJSON) {
		t.Fatalf("unsupported canonical value error = %v", err)
	}
	var pointer *string
	if err := validateCanonicalInput(reflect.ValueOf(pointer)); err != nil {
		t.Fatalf("nil pointer validation error = %v", err)
	}
}

func TestRoleExpiryIsIndependentOfHostLocalTimezone(t *testing.T) {
	expires, err := roleExpiry("2026-08-14T20:00:00+08:00")
	if err != nil {
		t.Fatalf("valid RFC3339 offset rejected: %v", err)
	}
	want := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	if !expires.Equal(want) || expires.Location() != time.UTC {
		t.Fatalf("expiry = %v, want UTC %v", expires, want)
	}
}

func resignGolden(t *testing.T, role Role, raw []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	envelope, err := parseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	mutate(envelope.Signed)
	payload, err := canonicalValue(envelope.Signed)
	if err != nil {
		t.Fatal(err)
	}
	keyID := string(role) + "-key-2026"
	if role == RoleRoot {
		keyID = "root-initial-2026"
	}
	privateKey := goldenPrivateKey(role, keyID)
	result, err := CanonicalJSON(map[string]any{
		"signed": envelope.Signed,
		"signatures": []any{map[string]any{
			"keyid": keyID,
			"sig":   base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func goldenPrivateKey(role Role, keyID string) ed25519.PrivateKey {
	if role == RoleRoot {
		return ed25519.NewKeyFromSeed(bytesOf(1, ed25519.SeedSize))
	}
	seed := sha256.Sum256([]byte(keyID))
	return ed25519.NewKeyFromSeed(seed[:])
}

func rebindGoldenSnapshotAndTimestamp(t *testing.T, bundle *Bundle) {
	t.Helper()
	bundle.Snapshot = resignGolden(t, RoleSnapshot, bundle.Snapshot, func(signed map[string]any) {
		meta := signed["meta"].(map[string]any)["targets.json"].(map[string]any)
		meta["hashes"].(map[string]any)["sha256"] = goldenEnvelopeDigest(t, bundle.Targets)
	})
	bundle.Timestamp = rebindGoldenTimestamp(t, bundle.Timestamp, bundle.Snapshot)
}

func rebindGoldenTimestamp(t *testing.T, timestamp, snapshot []byte) []byte {
	t.Helper()
	return resignGolden(t, RoleTimestamp, timestamp, func(signed map[string]any) {
		meta := signed["meta"].(map[string]any)["snapshot.json"].(map[string]any)
		meta["hashes"].(map[string]any)["sha256"] = goldenEnvelopeDigest(t, snapshot)
	})
}

func goldenEnvelopeDigest(t *testing.T, raw []byte) string {
	t.Helper()
	envelope, err := parseEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	return sha256Hex(envelope.EnvelopeBytes)
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

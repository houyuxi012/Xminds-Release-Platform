package catalog

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	base64URLPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	digestPattern    = regexp.MustCompile(`^(sha256:)?[a-f0-9]{64}$`)
	keyIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

func Verify(bundle Bundle, clock Clock) error {
	if clock == nil {
		return ErrBuilderConfiguration
	}
	roles := bundle.Roles()
	for _, role := range []Role{RoleRoot, RoleTargets, RoleSnapshot, RoleTimestamp, RoleRevocation} {
		if len(roles[role]) == 0 {
			return ErrBundleIncomplete
		}
	}
	rootEnvelope, err := parseEnvelope(bundle.Root)
	if err != nil {
		return err
	}
	root, err := parseRoot(rootEnvelope)
	if err != nil {
		return err
	}
	envelopes := map[Role]parsedEnvelope{RoleRoot: rootEnvelope}
	for _, role := range []Role{RoleTargets, RoleSnapshot, RoleTimestamp, RoleRevocation} {
		envelope, err := parseEnvelope(roles[role])
		if err != nil {
			return err
		}
		envelopes[role] = envelope
	}
	now := clock().UTC()
	versions := map[Role]uint64{}
	for _, role := range []Role{RoleRoot, RoleTargets, RoleSnapshot, RoleTimestamp, RoleRevocation} {
		envelope := envelopes[role]
		if roleType, ok := envelope.Signed["_type"].(string); !ok || roleType != string(role) {
			return fmt.Errorf("%w: %s", ErrRoleTypeInvalid, role)
		}
		version, err := positiveVersion(envelope.Signed["version"])
		if err != nil {
			return err
		}
		versions[role] = version
		expires, err := roleExpiry(envelope.Signed["expires"])
		if err != nil || !expires.After(now) {
			return fmt.Errorf("%w: %s", ErrRoleExpired, role)
		}
		if err := verifyRoleSignatures(root, envelope, role); err != nil {
			return err
		}
	}
	if err := verifyMetaBinding(envelopes[RoleTargets], envelopes[RoleSnapshot], "targets.json", versions[RoleTargets]); err != nil {
		return err
	}
	if err := verifyMetaBinding(envelopes[RoleSnapshot], envelopes[RoleTimestamp], "snapshot.json", versions[RoleSnapshot]); err != nil {
		return err
	}
	targets, err := verifyTargets(envelopes[RoleTargets])
	if err != nil {
		return err
	}
	return verifyRevocations(envelopes[RoleRevocation], envelopes[RoleTargets], targets)
}

func parseEnvelope(raw []byte) (parsedEnvelope, error) {
	value, err := strictJSONValue(raw)
	if err != nil {
		return parsedEnvelope{}, err
	}
	object, ok := value.(map[string]any)
	if !ok || len(object) != 2 || object["signed"] == nil || object["signatures"] == nil {
		return parsedEnvelope{}, ErrEnvelopeInvalid
	}
	signed, ok := object["signed"].(map[string]any)
	if !ok {
		return parsedEnvelope{}, ErrEnvelopeInvalid
	}
	items, ok := object["signatures"].([]any)
	if !ok || len(items) == 0 {
		return parsedEnvelope{}, ErrEnvelopeInvalid
	}
	signatures := make([]wireSignature, 0, len(items))
	for _, item := range items {
		entry, ok := item.(map[string]any)
		if !ok || len(entry) != 2 {
			return parsedEnvelope{}, ErrEnvelopeInvalid
		}
		keyID, keyOK := entry["keyid"].(string)
		value, valueOK := entry["sig"].(string)
		if !keyOK || !valueOK || !keyIDPattern.MatchString(keyID) || !base64URLPattern.MatchString(value) {
			return parsedEnvelope{}, ErrEnvelopeInvalid
		}
		signatures = append(signatures, wireSignature{KeyID: keyID, Value: value})
	}
	signedBytes, err := canonicalValue(signed)
	if err != nil {
		return parsedEnvelope{}, err
	}
	envelopeBytes, err := canonicalValue(object)
	if err != nil {
		return parsedEnvelope{}, err
	}
	return parsedEnvelope{Signed: signed, Signatures: signatures, SignedBytes: signedBytes, EnvelopeBytes: envelopeBytes}, nil
}

func parseRoot(envelope parsedEnvelope) (rootMetadata, error) {
	keysObject, ok := envelope.Signed["keys"].(map[string]any)
	if !ok || len(keysObject) == 0 {
		return rootMetadata{}, ErrRootInvalid
	}
	rolesObject, ok := envelope.Signed["roles"].(map[string]any)
	if !ok {
		return rootMetadata{}, ErrRootInvalid
	}
	root := rootMetadata{Keys: make(map[string]rootKey, len(keysObject)), Roles: make(map[string]rootRole, len(rolesObject))}
	for keyID, raw := range keysObject {
		if !keyIDPattern.MatchString(keyID) {
			return rootMetadata{}, ErrRootInvalid
		}
		object, ok := raw.(map[string]any)
		if !ok || object["keytype"] != "ed25519" || object["scheme"] != "ed25519" {
			return rootMetadata{}, ErrRootInvalid
		}
		keyValue, ok := object["keyval"].(map[string]any)
		publicText, textOK := keyValue["public"].(string)
		if !ok || !textOK || !base64URLPattern.MatchString(publicText) {
			return rootMetadata{}, ErrRootInvalid
		}
		public, err := base64.RawURLEncoding.DecodeString(publicText)
		if err != nil || len(public) != ed25519.PublicKeySize {
			return rootMetadata{}, ErrRootInvalid
		}
		root.Keys[keyID] = rootKey{Public: public}
	}
	for roleName, raw := range rolesObject {
		object, ok := raw.(map[string]any)
		if !ok {
			return rootMetadata{}, ErrRootInvalid
		}
		idsRaw, ok := object["keyids"].([]any)
		threshold, err := positiveInt(object["threshold"])
		if !ok || err != nil || len(idsRaw) == 0 {
			return rootMetadata{}, ErrRootInvalid
		}
		ids := make([]string, 0, len(idsRaw))
		seen := map[string]struct{}{}
		for _, item := range idsRaw {
			id, ok := item.(string)
			if !ok || !keyIDPattern.MatchString(id) {
				return rootMetadata{}, ErrRootInvalid
			}
			if _, exists := root.Keys[id]; !exists {
				return rootMetadata{}, ErrRootInvalid
			}
			if _, duplicate := seen[id]; duplicate {
				return rootMetadata{}, ErrRootInvalid
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
		if threshold > len(ids) {
			return rootMetadata{}, ErrRootInvalid
		}
		root.Roles[roleName] = rootRole{KeyIDs: ids, Threshold: threshold}
	}
	for _, required := range []Role{RoleRoot, RoleTargets, RoleSnapshot, RoleTimestamp, RoleRevocation} {
		if _, exists := root.Roles[string(required)]; !exists {
			return rootMetadata{}, ErrRootInvalid
		}
	}
	return root, nil
}

func verifyRoleSignatures(root rootMetadata, envelope parsedEnvelope, role Role) error {
	policy, exists := root.Roles[string(role)]
	if !exists || policy.Threshold < 1 {
		return ErrRootInvalid
	}
	allowed := map[string]struct{}{}
	for _, keyID := range policy.KeyIDs {
		allowed[keyID] = struct{}{}
	}
	valid := map[string]struct{}{}
	for _, signature := range envelope.Signatures {
		if _, ok := allowed[signature.KeyID]; !ok {
			continue
		}
		if _, duplicate := valid[signature.KeyID]; duplicate {
			continue
		}
		decoded, err := base64.RawURLEncoding.DecodeString(signature.Value)
		if err != nil || len(decoded) != ed25519.SignatureSize {
			continue
		}
		key := root.Keys[signature.KeyID]
		if ed25519.Verify(ed25519.PublicKey(key.Public), envelope.SignedBytes, decoded) {
			valid[signature.KeyID] = struct{}{}
		}
	}
	if len(valid) < policy.Threshold {
		return fmt.Errorf("%w: %s", ErrSignatureThreshold, role)
	}
	return nil
}

func verifyMetaBinding(document, binding parsedEnvelope, name string, version uint64) error {
	metaObject, ok := binding.Signed["meta"].(map[string]any)
	item, okItem := metaObject[name].(map[string]any)
	if !ok || !okItem {
		return ErrRoleDigestMismatch
	}
	actualVersion, err := positiveVersion(item["version"])
	if err != nil || actualVersion != version {
		return ErrRoleVersionMismatch
	}
	hashes, ok := item["hashes"].(map[string]any)
	expected, textOK := hashes["sha256"].(string)
	if !ok || !textOK {
		return ErrRoleDigestMismatch
	}
	digest := sha256.Sum256(document.EnvelopeBytes)
	if !equalDigest(expected, hex.EncodeToString(digest[:])) {
		return ErrRoleDigestMismatch
	}
	return nil
}

type verifiedTarget struct {
	Name           string
	ReleaseID      string
	ManifestDigest string
	ReleaseKeyID   string
}

func verifyTargets(envelope parsedEnvelope) ([]verifiedTarget, error) {
	items, ok := envelope.Signed["targets"].(map[string]any)
	if !ok || len(items) == 0 {
		return nil, ErrTargetInvalid
	}
	names := make([]string, 0, len(items))
	for name := range items {
		names = append(names, name)
	}
	sort.Strings(names)
	result := make([]verifiedTarget, 0, len(names))
	for _, name := range names {
		item, ok := items[name].(map[string]any)
		custom, customOK := item["custom"].(map[string]any)
		if !ok || !customOK {
			return nil, ErrTargetInvalid
		}
		for _, required := range []string{"product_id", "release_id", "version", "plan_digest", "artifact_digest", "manifest_digest", "release_notes_markdown", "release_notes_digest", "compatibility", "compatibility_digest"} {
			if _, exists := custom[required]; !exists {
				return nil, ErrTargetInvalid
			}
		}
		releaseID, releaseOK := custom["release_id"].(string)
		manifestDigest, manifestOK := custom["manifest_digest"].(string)
		notes, notesOK := custom["release_notes_markdown"].(string)
		notesDigest, notesDigestOK := custom["release_notes_digest"].(string)
		compatibilityDigest, compatibilityDigestOK := custom["compatibility_digest"].(string)
		if !releaseOK || releaseID == "" || !manifestOK || !validDigest(manifestDigest) || !notesOK || !notesDigestOK || !compatibilityDigestOK {
			return nil, ErrTargetInvalid
		}
		for _, field := range []string{"plan_digest", "artifact_digest", "manifest_digest", "release_notes_digest", "compatibility_digest"} {
			value, ok := custom[field].(string)
			if !ok || !validDigest(value) {
				return nil, ErrTargetInvalid
			}
		}
		if !equalDigest(notesDigest, sha256Hex([]byte(notes))) {
			return nil, ErrReleaseNotesDigestMismatch
		}
		compatibilityBytes, err := canonicalValue(custom["compatibility"])
		if err != nil {
			return nil, ErrTargetInvalid
		}
		if !equalDigest(compatibilityDigest, sha256Hex(compatibilityBytes)) {
			return nil, ErrCompatibilityDigestMismatch
		}
		releaseKeyID, _ := custom["release_key_id"].(string)
		result = append(result, verifiedTarget{Name: name, ReleaseID: releaseID, ManifestDigest: manifestDigest, ReleaseKeyID: releaseKeyID})
	}
	return result, nil
}

func verifyRevocations(revocation, targetsEnvelope parsedEnvelope, targets []verifiedTarget) error {
	if _, forbidden := revocation.Signed["revoked"]; forbidden {
		return ErrEnvelopeInvalid
	}
	items, ok := revocation.Signed["revocations"].([]any)
	if !ok {
		return ErrEnvelopeInvalid
	}
	revokedReleases := map[string]struct{}{}
	revokedManifests := map[string]struct{}{}
	revokedKeys := map[string]struct{}{}
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			return ErrEnvelopeInvalid
		}
		if value, _ := item["release_id"].(string); value != "" {
			revokedReleases[value] = struct{}{}
		}
		if value, _ := item["manifest_digest"].(string); value != "" {
			if !validDigest(value) {
				return ErrEnvelopeInvalid
			}
			revokedManifests[value] = struct{}{}
		}
		if value, _ := item["key_id"].(string); value != "" {
			revokedKeys[value] = struct{}{}
		}
	}
	for _, signature := range targetsEnvelope.Signatures {
		if _, revoked := revokedKeys[signature.KeyID]; revoked {
			return ErrKeyRevoked
		}
	}
	for _, target := range targets {
		if _, revoked := revokedReleases[target.Name]; revoked {
			return ErrTargetRevoked
		}
		if _, revoked := revokedReleases[target.ReleaseID]; revoked {
			return ErrTargetRevoked
		}
		if _, revoked := revokedManifests[target.ManifestDigest]; revoked {
			return ErrTargetRevoked
		}
		if _, revoked := revokedKeys[target.ReleaseKeyID]; revoked && target.ReleaseKeyID != "" {
			return ErrKeyRevoked
		}
	}
	return nil
}

func canonicalValue(value any) ([]byte, error) {
	var builder strings.Builder
	if err := encodeCanonicalValue(&builder, value); err != nil {
		return nil, err
	}
	return []byte(builder.String()), nil
}

func positiveVersion(value any) (uint64, error) {
	number, ok := value.(json.Number)
	if !ok || !integerJSONPattern.MatchString(number.String()) || strings.HasPrefix(number.String(), "-") {
		return 0, ErrRoleVersionInvalid
	}
	parsed, err := strconv.ParseUint(number.String(), 10, 64)
	if err != nil || parsed == 0 {
		return 0, ErrRoleVersionInvalid
	}
	return parsed, nil
}

func positiveInt(value any) (int, error) {
	parsed, err := positiveVersion(value)
	if err != nil || parsed > uint64(^uint(0)>>1) {
		return 0, ErrRootInvalid
	}
	return int(parsed), nil
}

func roleExpiry(value any) (time.Time, error) {
	text, ok := value.(string)
	if !ok {
		return time.Time{}, ErrRoleExpired
	}
	parsed, err := time.Parse(time.RFC3339, text)
	if err != nil {
		return time.Time{}, ErrRoleExpired
	}
	return parsed.UTC(), nil
}

func validDigest(value string) bool { return digestPattern.MatchString(value) }

func equalDigest(expected, actual string) bool {
	expected = strings.TrimPrefix(strings.ToLower(expected), "sha256:")
	actual = strings.TrimPrefix(strings.ToLower(actual), "sha256:")
	if len(expected) != 64 || len(actual) != 64 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func sha256Hex(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

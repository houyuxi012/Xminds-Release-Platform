// Command root-key performs the offline root-key ceremony for a new trust root.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"time"

	"xminds-release-platform/internal/catalog"
	"xminds-release-platform/internal/signing"
)

const maximumOnlineKeyFileSize = 1024 * 1024

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type bootstrapMaterial struct {
	KeyID              string `json:"key_id"`
	PublicKey          string `json:"public_key"`
	PublicKeyDigest    string `json:"public_key_digest"`
	RootVersion        uint64 `json:"root_version"`
	RootEnvelopeDigest string `json:"root_envelope_digest"`
}

type onlineKeyDefinition struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

type onlineRoleDefinition struct {
	Keys      []onlineKeyDefinition `json:"keys"`
	Threshold int                   `json:"threshold"`
}

type onlineKeyDefinitions struct {
	Targets    onlineRoleDefinition `json:"targets"`
	Snapshot   onlineRoleDefinition `json:"snapshot"`
	Timestamp  onlineRoleDefinition `json:"timestamp"`
	Revocation onlineRoleDefinition `json:"revocation"`
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("root-key", flag.ContinueOnError)
	flags.SetOutput(stderr)
	masterKeyFile := flags.String("master-key-file", "", "0600 文件，内容必须是 32 字节随机主密钥")
	onlineKeysFile := flags.String("online-keys-file", "", "包含四个在线角色公钥与阈值的 JSON 文件")
	privateKeyFile := flags.String("private-key-file", "", "离线 root 私钥加密文件输出路径")
	rootEnvelopeFile := flags.String("root-envelope-file", "", "公开 root.json 输出路径")
	keyID := flags.String("key-id", "", "root 公钥稳定标识")
	versionText := flags.String("version", "1", "root 元数据正整数版本")
	expiresText := flags.String("expires", "", "root 元数据 RFC3339 UTC 到期时间")
	if err := flags.Parse(arguments); err != nil {
		return 2
	}
	version, err := strconv.ParseUint(*versionText, 10, 64)
	if err != nil || version == 0 || !keyIDPattern.MatchString(*keyID) || *masterKeyFile == "" || *onlineKeysFile == "" || *privateKeyFile == "" || *rootEnvelopeFile == "" {
		fmt.Fprintln(stderr, "参数无效：必须提供全部文件路径、合法 key-id 和正整数 version")
		return 2
	}
	expires, err := time.Parse(time.RFC3339, *expiresText)
	if err != nil || expires.Location() != time.UTC || !expires.After(time.Now().UTC().Add(24*time.Hour)) {
		fmt.Fprintln(stderr, "参数无效：expires 必须是至少 24 小时后的 UTC RFC3339 时间")
		return 2
	}
	if sameFilePath(*masterKeyFile, *privateKeyFile) || sameFilePath(*onlineKeysFile, *privateKeyFile) || sameFilePath(*rootEnvelopeFile, *privateKeyFile) {
		fmt.Fprintln(stderr, "参数无效：输入和输出文件路径必须互不相同")
		return 2
	}
	masterKey, err := read0600File(*masterKeyFile, signing.MasterKeySize)
	if err != nil {
		fmt.Fprintln(stderr, "读取主密钥失败：文件必须为常规 0600 文件且长度为 32 字节")
		return 1
	}
	defer wipe(masterKey)
	onlineKeys, err := loadOnlineKeys(*onlineKeysFile)
	if err != nil {
		fmt.Fprintln(stderr, "读取在线角色公钥失败：", err)
		return 1
	}
	if fileExists(*privateKeyFile) || fileExists(*rootEnvelopeFile) {
		fmt.Fprintln(stderr, "拒绝覆盖已有密钥或 root envelope 文件")
		return 1
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(stderr, "生成 Ed25519 root 密钥失败")
		return 1
	}
	defer wipe(privateKey)
	envelope, err := buildRootEnvelope(*keyID, version, expires.UTC(), publicKey, privateKey, onlineKeys)
	if err != nil {
		fmt.Fprintln(stderr, "构建 root envelope 失败：", err)
		return 1
	}
	if err := signing.WriteEncryptedKeyFile(*privateKeyFile, masterKey, "root", *keyID, privateKey); err != nil {
		fmt.Fprintln(stderr, "写入加密 root 密钥失败")
		return 1
	}
	if err := writeExclusive(*rootEnvelopeFile, append(envelope, '\n'), 0o644); err != nil {
		_ = os.Remove(*privateKeyFile)
		fmt.Fprintln(stderr, "写入 root envelope 失败")
		return 1
	}
	publicDigest := sha256.Sum256(publicKey)
	envelopeDigest := sha256.Sum256(envelope)
	bootstrap := bootstrapMaterial{
		KeyID: *keyID, PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
		PublicKeyDigest: hex.EncodeToString(publicDigest[:]), RootVersion: version,
		RootEnvelopeDigest: hex.EncodeToString(envelopeDigest[:]),
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(bootstrap); err != nil {
		fmt.Fprintln(stderr, "输出 bootstrap 公钥材料失败")
		return 1
	}
	return 0
}

func buildRootEnvelope(keyID string, version uint64, expires time.Time, publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey, online onlineKeyDefinitions) ([]byte, error) {
	keys := map[string]any{
		keyID: map[string]any{"keytype": "ed25519", "scheme": "ed25519", "keyval": map[string]any{"public": base64.RawURLEncoding.EncodeToString(publicKey)}},
	}
	roles := map[string]any{"root": map[string]any{"keyids": []string{keyID}, "threshold": 1}}
	for roleName, definition := range map[string]onlineRoleDefinition{
		"targets": online.Targets, "snapshot": online.Snapshot, "timestamp": online.Timestamp, "revocation": online.Revocation,
	} {
		keyIDs := make([]string, 0, len(definition.Keys))
		for _, key := range definition.Keys {
			keys[key.KeyID] = map[string]any{"keytype": "ed25519", "scheme": "ed25519", "keyval": map[string]any{"public": key.PublicKey}}
			keyIDs = append(keyIDs, key.KeyID)
		}
		roles[roleName] = map[string]any{"keyids": keyIDs, "threshold": definition.Threshold}
	}
	signed := map[string]any{
		"_type": "root", "version": version, "expires": expires.Format(time.RFC3339), "keys": keys, "roles": roles,
	}
	payload, err := catalog.CanonicalJSON(signed)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(privateKey, payload)
	return catalog.CanonicalJSON(map[string]any{
		"signed":     signed,
		"signatures": []any{map[string]any{"keyid": keyID, "sig": base64.RawURLEncoding.EncodeToString(signature)}},
	})
}

func loadOnlineKeys(path string) (onlineKeyDefinitions, error) {
	file, err := os.Open(path)
	if err != nil {
		return onlineKeyDefinitions{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximumOnlineKeyFileSize {
		return onlineKeyDefinitions{}, errors.New("在线公钥文件不是受支持的常规文件")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumOnlineKeyFileSize+1))
	if err != nil || len(raw) > maximumOnlineKeyFileSize {
		return onlineKeyDefinitions{}, errors.New("在线公钥文件过大")
	}
	canonical, err := catalog.CanonicalJSON(raw)
	if err != nil {
		return onlineKeyDefinitions{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	var definitions onlineKeyDefinitions
	if err := decoder.Decode(&definitions); err != nil {
		return onlineKeyDefinitions{}, errors.New("在线公钥 JSON 结构无效")
	}
	seen := map[string]struct{}{}
	for _, definition := range []onlineRoleDefinition{definitions.Targets, definitions.Snapshot, definitions.Timestamp, definitions.Revocation} {
		if len(definition.Keys) == 0 || definition.Threshold < 1 || definition.Threshold > len(definition.Keys) {
			return onlineKeyDefinitions{}, errors.New("在线角色阈值无效")
		}
		for _, key := range definition.Keys {
			public, decodeErr := base64.RawURLEncoding.DecodeString(key.PublicKey)
			if !keyIDPattern.MatchString(key.KeyID) || decodeErr != nil || len(public) != ed25519.PublicKeySize {
				return onlineKeyDefinitions{}, errors.New("在线 Ed25519 公钥无效")
			}
			if _, duplicate := seen[key.KeyID]; duplicate {
				return onlineKeyDefinitions{}, errors.New("在线 key-id 重复")
			}
			seen[key.KeyID] = struct{}{}
		}
	}
	return definitions, nil
}

func read0600File(path string, expectedSize int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != int64(expectedSize) {
		return nil, errors.New("secret file is unsafe")
	}
	return os.ReadFile(path)
}

func writeExclusive(path string, raw []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil || !errors.Is(err, os.ErrNotExist)
}

func sameFilePath(left, right string) bool { return left == right }

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

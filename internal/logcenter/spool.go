package logcenter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var ErrSpoolFull = errors.New("log spool quota exceeded")
var ErrSpoolQuarantine = errors.New("log spool quarantine failed")

const spoolEnvelopeVersion byte = 1

type EncryptedSpool struct {
	dir      string
	aead     cipher.AEAD
	keys     map[string]cipher.AEAD
	maxBytes int64
	keyID    string
}

func (spool *EncryptedSpool) ReplaceEventIntent(eventID string, record middlewareIntent) error {
	if spool == nil || spool.aead == nil {
		return errors.New("spool unavailable")
	}
	lock, err := os.OpenFile(filepath.Join(spool.dir, ".quota.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	nonce := make([]byte, spool.aead.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	header := append([]byte{'X', 'L', 'G', spoolEnvelopeVersion, byte(len(spool.keyID))}, []byte(spool.keyID)...)
	envelope := append(append(header, nonce...), spool.aead.Seal(nil, nonce, payload, header)...)
	tmp, err := os.CreateTemp(spool.dir, ".replace-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(envelope)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	target := filepath.Join(spool.dir, "intent-"+eventID)
	if err = os.Rename(tmpName, target); err != nil {
		return err
	}
	entries, err := os.ReadDir(spool.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == filepath.Base(target) || entry.IsDir() || len(entry.Name()) < 7 || entry.Name()[:7] != "intent-" {
			continue
		}
		path := filepath.Join(spool.dir, entry.Name())
		plain, readErr := spool.readEnvelope(path)
		if readErr != nil {
			return fmt.Errorf("read existing intent %s: %w", entry.Name(), readErr)
		}
		var old middlewareIntent
		if err := json.Unmarshal(plain, &old); err != nil {
			return fmt.Errorf("decode existing intent %s: %w", entry.Name(), err)
		}
		if old.EventID == eventID {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove superseded intent %s: %w", entry.Name(), err)
			}
		}
	}
	dirFile, err := os.Open(spool.dir)
	if err == nil {
		err = dirFile.Sync()
		if closeErr := dirFile.Close(); err == nil {
			err = closeErr
		}
	}
	return err
}

// IntentLifecycle allows the request path to settle a durable intent after
// the immutable event has been persisted.
func (spool *EncryptedSpool) DeleteEventIntents(eventID string) error {
	lock, err := os.OpenFile(filepath.Join(spool.dir, ".quota.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	entries, err := os.ReadDir(spool.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || len(entry.Name()) < 7 || entry.Name()[:7] != "intent-" {
			continue
		}
		path := filepath.Join(spool.dir, entry.Name())
		plain, readErr := spool.readEnvelope(path)
		if readErr != nil {
			if quarantineErr := quarantine(path); quarantineErr != nil {
				return fmt.Errorf("quarantine unreadable intent %s: %w (original: %v)", entry.Name(), quarantineErr, readErr)
			}
			continue
		}
		var record middlewareIntent
		if err := json.Unmarshal(plain, &record); err != nil {
			if quarantineErr := quarantine(path); quarantineErr != nil {
				return fmt.Errorf("quarantine malformed intent %s: %w (original: %v)", entry.Name(), quarantineErr, err)
			}
			continue
		}
		if record.EventID == eventID {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

func NewEncryptedSpool(dir string, key []byte, maxBytes int64) (*EncryptedSpool, error) {
	return NewEncryptedSpoolWithKeyring(dir, map[string][]byte{"default-v1": key}, "default-v1", maxBytes)
}

func NewEncryptedSpoolWithKeyring(dir string, keys map[string][]byte, activeKeyID string, maxBytes int64) (*EncryptedSpool, error) {
	if !validSpoolKeyID(activeKeyID) {
		return nil, errors.New("invalid active spool key id")
	}
	key, ok := keys[activeKeyID]
	if !ok {
		return nil, errors.New("active spool key is missing")
	}
	if len(key) != 32 || maxBytes <= 0 {
		return nil, errors.New("invalid spool configuration")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	keyring := make(map[string]cipher.AEAD, len(keys))
	for id, raw := range keys {
		if !validSpoolKeyID(id) || len(raw) != 32 {
			return nil, errors.New("invalid spool key")
		}
		block, err := aes.NewCipher(raw)
		if err != nil {
			return nil, err
		}
		keyring[id], err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	}
	return &EncryptedSpool{dir: dir, aead: aead, keys: keyring, maxBytes: maxBytes, keyID: activeKeyID}, nil
}

func validSpoolKeyID(id string) bool {
	if len(id) == 0 || len(id) > 255 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x21 || id[i] > 0x7e {
			return false
		}
	}
	return true
}

func (spool *EncryptedSpool) ReserveAndWrite(plain []byte) error {
	if spool == nil || spool.aead == nil {
		return errors.New("spool unavailable")
	}
	lock, err := os.OpenFile(filepath.Join(spool.dir, ".quota.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	var used int64
	entries, err := os.ReadDir(spool.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			info, statErr := entry.Info()
			if statErr == nil {
				used += info.Size()
			}
		}
	}
	nonce := make([]byte, spool.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	header := append([]byte{'X', 'L', 'G', spoolEnvelopeVersion, byte(len(spool.keyID))}, []byte(spool.keyID)...)
	ciphertext := spool.aead.Seal(nil, nonce, plain, header)
	envelope := append(append(header, nonce...), ciphertext...)
	if used+int64(len(envelope)) > spool.maxBytes {
		return ErrSpoolFull
	}
	tmp, err := os.CreateTemp(spool.dir, ".intent-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(envelope)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	name := filepath.Join(spool.dir, "intent-"+filepath.Base(tmpName)[len(".intent-"):])
	if err = os.Rename(tmpName, name); err != nil {
		return err
	}
	dirFile, err := os.Open(spool.dir)
	if err == nil {
		err = dirFile.Sync()
		_ = dirFile.Close()
	}
	return err
}

func (spool *EncryptedSpool) ReadAll() ([][]byte, error) {
	lock, err := os.OpenFile(filepath.Join(spool.dir, ".quota.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return nil, err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return spool.readAllUnlocked()
}

func (spool *EncryptedSpool) readAllUnlocked() ([][]byte, error) {
	entries, err := os.ReadDir(spool.dir)
	if err != nil {
		return nil, err
	}
	result := make([][]byte, 0)
	for _, entry := range entries {
		if entry.IsDir() || len(entry.Name()) < len("intent-") || entry.Name()[:len("intent-")] != "intent-" {
			continue
		}
		path := filepath.Join(spool.dir, entry.Name())
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		if len(data) < 5 {
			if err := quarantine(path); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrSpoolQuarantine, err)
			}
			continue
		}
		headerLen := 5 + int(data[4])
		if len(data) < headerLen+spool.aead.NonceSize() || string(data[:3]) != "XLG" || data[3] != spoolEnvelopeVersion || data[4] == 0 {
			if err := quarantine(path); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrSpoolQuarantine, err)
			}
			continue
		}
		nonceStart := headerLen
		decoder, exists := spool.keys[string(data[5:headerLen])]
		if !exists {
			if err := quarantine(path); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrSpoolQuarantine, err)
			}
			continue
		}
		plain, openErr := decoder.Open(nil, data[nonceStart:nonceStart+decoder.NonceSize()], data[nonceStart+decoder.NonceSize():], data[:headerLen])
		if openErr != nil {
			if err := quarantine(path); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrSpoolQuarantine, err)
			}
			continue
		}
		result = append(result, plain)
	}
	return result, nil
}

func (spool *EncryptedSpool) readEnvelope(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 5 {
		return nil, fmt.Errorf("truncated spool envelope")
	}
	headerLen := 5 + int(data[4])
	if len(data) < headerLen || string(data[:3]) != "XLG" || data[3] != spoolEnvelopeVersion {
		return nil, fmt.Errorf("invalid spool envelope")
	}
	keyID := string(data[5:headerLen])
	decoder, exists := spool.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("unknown spool key")
	}
	if len(data) < headerLen+decoder.NonceSize() {
		return nil, fmt.Errorf("truncated spool envelope")
	}
	plain, err := decoder.Open(nil, data[headerLen:headerLen+decoder.NonceSize()], data[headerLen+decoder.NonceSize():], data[:headerLen])
	if err != nil {
		return nil, fmt.Errorf("authentication failed")
	}
	return plain, nil
}

func quarantine(path string) error {
	for i := 0; i < 3; i++ {
		suffix := fmt.Sprintf(".quarantine-%d-%d", time.Now().UnixNano(), i)
		if err := os.Rename(path, path+suffix); err == nil {
			return nil
		} else if !os.IsExist(err) {
			return err
		}
	}
	return os.ErrExist
}

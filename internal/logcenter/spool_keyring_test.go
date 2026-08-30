package logcenter

import (
	"crypto/cipher"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedSpoolKeyRotationReadsOldAndWritesActive(t *testing.T) {
	dir := t.TempDir()
	oldKey := []byte("01234567890123456789012345678901")
	newKey := []byte("abcdefghijklmnopqrstuvwxyz123456")
	old, err := NewEncryptedSpoolWithKeyring(dir, map[string][]byte{"old-v1": oldKey}, "old-v1", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.ReserveAndWrite([]byte("old")); err != nil {
		t.Fatal(err)
	}
	rotated, err := NewEncryptedSpoolWithKeyring(dir, map[string][]byte{"old-v1": oldKey, "new-v2": newKey}, "new-v2", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := rotated.ReadAll(); err != nil || len(got) != 1 || string(got[0]) != "old" {
		t.Fatalf("read old key: got=%q err=%v", got, err)
	}
	if err := rotated.ReserveAndWrite([]byte("new")); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	foundNew := false
	for _, entry := range entries {
		if len(entry.Name()) < len("intent-") || entry.Name()[:len("intent-")] != "intent-" {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(dir, entry.Name()))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if len(data) >= 5 && int(data[4])+5 <= len(data) && string(data[5:5+int(data[4])]) == "new-v2" {
			foundNew = true
		}
	}
	if !foundNew {
		t.Fatal("active key was not used")
	}
}

func TestEncryptedSpoolUnknownKeyIsQuarantined(t *testing.T) {
	dir := t.TempDir()
	key := []byte("01234567890123456789012345678901")
	spool, err := NewEncryptedSpool(dir, key, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.ReserveAndWrite([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	spool.keys = map[string]cipher.AEAD{}
	_, err = spool.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	found := false
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".quarantine" || contains(entry.Name(), ".quarantine-") {
			found = true
		}
	}
	if !found {
		t.Fatal("unknown key was not quarantined")
	}
	if errors.Is(err, ErrSpoolQuarantine) {
		t.Fatal("unknown key should not report quarantine rename failure")
	}
}

func TestEncryptedSpoolRejectsInvalidKeyIDs(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	for _, id := range []string{"", string(make([]byte, 256)), "bad\nkey"} {
		if _, err := NewEncryptedSpoolWithKeyring(t.TempDir(), map[string][]byte{id: key}, id, 1<<20); err == nil {
			t.Fatalf("key id %q accepted", id)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > len(sub) && indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

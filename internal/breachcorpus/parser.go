package breachcorpus

import (
	"bufio"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
)

type Set struct {
	sha1   map[string]struct{}
	sha256 map[string]struct{}
}

func Parse(reader io.Reader) (*Set, Counts, error) {
	var counts Counts
	if reader == nil {
		return nil, counts, ErrInvalidCorpus
	}

	set := &Set{
		sha1:   make(map[string]struct{}),
		sha256: make(map[string]struct{}),
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024), MaximumLineBytes+1)
	for scanner.Scan() {
		digest, algorithm, ignored, err := NormalizeLine(scanner.Text())
		if err != nil {
			counts.RejectedEntries++
			return nil, counts, ErrInvalidCorpus
		}
		if ignored {
			continue
		}
		target := set.sha1
		if algorithm == SHA256 {
			target = set.sha256
		}
		if _, duplicate := target[digest]; duplicate {
			counts.DuplicateEntries++
			continue
		}
		target[digest] = struct{}{}
		switch algorithm {
		case SHA1:
			counts.SHA1Entries++
		case SHA256:
			counts.SHA256Entries++
		default:
			counts.RejectedEntries++
			return nil, counts, ErrInvalidCorpus
		}
		counts.UniqueEntries++
	}
	if scanner.Err() != nil {
		counts.RejectedEntries++
		return nil, counts, ErrInvalidCorpus
	}
	if counts.UniqueEntries == 0 {
		return nil, counts, ErrInvalidCorpus
	}
	return set, counts, nil
}

func NormalizeLine(line string) (string, Algorithm, bool, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", true, nil
	}
	line = strings.ToUpper(line)
	decoded, err := hex.DecodeString(line)
	if err != nil {
		return "", "", false, ErrInvalidCorpus
	}
	switch len(decoded) {
	case sha1.Size:
		return line, SHA1, false, nil
	case sha256.Size:
		return line, SHA256, false, nil
	default:
		return "", "", false, ErrInvalidCorpus
	}
}

func (set *Set) ContainsPassword(password string) bool {
	if set == nil {
		return false
	}
	sha1Digest := sha1.Sum([]byte(password))
	if _, found := set.sha1[strings.ToUpper(hex.EncodeToString(sha1Digest[:]))]; found {
		return true
	}
	sha256Digest := sha256.Sum256([]byte(password))
	_, found := set.sha256[strings.ToUpper(hex.EncodeToString(sha256Digest[:]))]
	return found
}

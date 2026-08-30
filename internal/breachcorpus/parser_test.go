package breachcorpus

import (
	"errors"
	"strings"
	"testing"
)

const (
	testSHA1Password   = "Known-SHA1-Breached-Password!"
	testSHA1Digest     = "844EBA1A7A7BEBADAAD266BF2DB5B9429D441818"
	testSHA256Password = "Known-SHA256-Breached-Password!"
	testSHA256Digest   = "6CE0335CCB0E6AD50693A435D4BF0659DB2D69D53D84631661774AC86E8F5722"
)

func TestParseNormalizesSupportedDigestsDeduplicatesAndMatchesPasswords(t *testing.T) {
	t.Parallel()

	raw := "# approved digest formats\n" +
		strings.ToLower(testSHA1Digest) + "\n" +
		testSHA256Digest + "\n" +
		testSHA1Digest + "\n"
	set, counts, err := Parse(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if counts.SHA1Entries != 1 || counts.SHA256Entries != 1 || counts.UniqueEntries != 2 ||
		counts.DuplicateEntries != 1 || counts.RejectedEntries != 0 {
		t.Fatalf("Parse() counts = %+v", counts)
	}
	if !set.ContainsPassword(testSHA1Password) {
		t.Fatal("SHA-1 password was not matched")
	}
	if !set.ContainsPassword(testSHA256Password) {
		t.Fatal("SHA-256 password was not matched")
	}
	if set.ContainsPassword("A-Different-Safe-Password!") {
		t.Fatal("safe password was matched")
	}
}

func TestNormalizeLineClassifiesDigestsAndIgnoresOnlyBlankOrCommentLines(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		line      string
		digest    string
		algorithm Algorithm
		ignored   bool
	}{
		{name: "blank", line: " \t ", ignored: true},
		{name: "comment", line: "  # approved source", ignored: true},
		{name: "SHA-1", line: " " + strings.ToLower(testSHA1Digest) + " ", digest: testSHA1Digest, algorithm: SHA1},
		{name: "SHA-256", line: testSHA256Digest, digest: testSHA256Digest, algorithm: SHA256},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			digest, algorithm, ignored, err := NormalizeLine(test.line)
			if err != nil {
				t.Fatalf("NormalizeLine() error = %v", err)
			}
			if digest != test.digest || algorithm != test.algorithm || ignored != test.ignored {
				t.Fatalf("NormalizeLine() = %q, %q, %v", digest, algorithm, ignored)
			}
		})
	}
}

func TestParseRejectsEmptyMalformedAndOversizedCorpus(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"empty":           "\n# comment only\n",
		"non hexadecimal": strings.Repeat("G", 40) + "\n",
		"wrong length":    strings.Repeat("A", 42) + "\n",
		"oversized line":  strings.Repeat("A", MaximumLineBytes+1) + "\n",
	}
	for name, raw := range tests {
		raw := raw
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, counts, err := Parse(strings.NewReader(raw)); !errors.Is(err, ErrInvalidCorpus) {
				t.Fatalf("Parse() counts = %+v, error = %v", counts, err)
			}
		})
	}
}

func TestParseCountsARejectedLineBeforeFailingClosed(t *testing.T) {
	t.Parallel()

	raw := testSHA1Digest + "\nnot-a-digest\n"
	if _, counts, err := Parse(strings.NewReader(raw)); !errors.Is(err, ErrInvalidCorpus) || counts.RejectedEntries != 1 {
		t.Fatalf("Parse() counts = %+v, error = %v", counts, err)
	}
}

package breachcorpus

import (
	"errors"
	"strings"
	"testing"
)

func TestReadBuildRequestAcceptsCompleteBoundedMetadata(t *testing.T) {
	t.Parallel()

	request, err := ReadBuildRequest(strings.NewReader(`{
		"schema_version": 1,
		"corpus_version": "2026.08.30.1",
		"sources": [
			{
				"id": "source-a",
				"version": "2026-08",
				"expected_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"license_review_ref": "LEGAL-2026-001"
			}
		]
	}`))
	if err != nil {
		t.Fatalf("ReadBuildRequest() error = %v", err)
	}
	if request.SchemaVersion != 1 || request.CorpusVersion != "2026.08.30.1" || len(request.Sources) != 1 {
		t.Fatalf("ReadBuildRequest() = %+v", request)
	}
	if request.Sources[0].ID != "source-a" || request.Sources[0].Version != "2026-08" ||
		request.Sources[0].ExpectedSHA256 != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ||
		request.Sources[0].LicenseReviewRef != "LEGAL-2026-001" {
		t.Fatalf("source = %+v", request.Sources[0])
	}
}

func TestReadBuildRequestRejectsUnknownFieldsDuplicateSourcesAndTrailingJSON(t *testing.T) {
	t.Parallel()

	const validSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tests := map[string]string{
		"unknown field": `{
			"schema_version": 1,
			"corpus_version": "2026.08.30.1",
			"sources": [{"id":"source-a","version":"1","expected_sha256":"` + validSHA256 + `","license_review_ref":"LEGAL-1"}],
			"unknown": true
		}`,
		"duplicate source": `{
			"schema_version": 1,
			"corpus_version": "2026.08.30.1",
			"sources": [
				{"id":"source-a","version":"1","expected_sha256":"` + validSHA256 + `","license_review_ref":"LEGAL-1"},
				{"id":"source-a","version":"2","expected_sha256":"` + validSHA256 + `","license_review_ref":"LEGAL-2"}
			]
		}`,
		"trailing JSON": `{
			"schema_version": 1,
			"corpus_version": "2026.08.30.1",
			"sources": [{"id":"source-a","version":"1","expected_sha256":"` + validSHA256 + `","license_review_ref":"LEGAL-1"}]
		} {}`,
	}
	for name, raw := range tests {
		raw := raw
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ReadBuildRequest(strings.NewReader(raw)); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("ReadBuildRequest() error = %v", err)
			}
		})
	}
}

func TestReadBuildRequestRejectsMissingOrUnboundedFields(t *testing.T) {
	t.Parallel()

	const validSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	tests := map[string]string{
		"unsupported schema": `{"schema_version":2,"corpus_version":"2026.08.30.1","sources":[{"id":"a","version":"1","expected_sha256":"` + validSHA256 + `","license_review_ref":"LEGAL-1"}]}`,
		"empty version":      `{"schema_version":1,"corpus_version":"","sources":[{"id":"a","version":"1","expected_sha256":"` + validSHA256 + `","license_review_ref":"LEGAL-1"}]}`,
		"no sources":         `{"schema_version":1,"corpus_version":"2026.08.30.1","sources":[]}`,
		"invalid source id":  `{"schema_version":1,"corpus_version":"2026.08.30.1","sources":[{"id":"source/a","version":"1","expected_sha256":"` + validSHA256 + `","license_review_ref":"LEGAL-1"}]}`,
		"invalid digest":     `{"schema_version":1,"corpus_version":"2026.08.30.1","sources":[{"id":"a","version":"1","expected_sha256":"abc","license_review_ref":"LEGAL-1"}]}`,
		"empty license":      `{"schema_version":1,"corpus_version":"2026.08.30.1","sources":[{"id":"a","version":"1","expected_sha256":"` + validSHA256 + `","license_review_ref":""}]}`,
	}
	for name, raw := range tests {
		raw := raw
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := ReadBuildRequest(strings.NewReader(raw)); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("ReadBuildRequest() error = %v", err)
			}
		})
	}
}

func TestValidateInputsRequiresExactAbsoluteSourceBindings(t *testing.T) {
	t.Parallel()

	request := BuildRequest{
		SchemaVersion: ManifestSchemaVersion,
		CorpusVersion: "2026.08.30.1",
		Sources: []SourceRequest{
			{ID: "source-a", Version: "1", ExpectedSHA256: strings.Repeat("a", 64), LicenseReviewRef: "LEGAL-1"},
			{ID: "source-b", Version: "2", ExpectedSHA256: strings.Repeat("b", 64), LicenseReviewRef: "LEGAL-2"},
		},
	}
	if err := ValidateInputs(request, []Input{
		{SourceID: "source-b", Path: "/secure/source-b.txt"},
		{SourceID: "source-a", Path: "/secure/source-a.txt"},
	}); err != nil {
		t.Fatalf("ValidateInputs(valid) error = %v", err)
	}

	tests := map[string][]Input{
		"missing": {
			{SourceID: "source-a", Path: "/secure/source-a.txt"},
		},
		"extra": {
			{SourceID: "source-a", Path: "/secure/source-a.txt"},
			{SourceID: "source-b", Path: "/secure/source-b.txt"},
			{SourceID: "source-c", Path: "/secure/source-c.txt"},
		},
		"duplicate": {
			{SourceID: "source-a", Path: "/secure/source-a.txt"},
			{SourceID: "source-a", Path: "/secure/source-a-copy.txt"},
			{SourceID: "source-b", Path: "/secure/source-b.txt"},
		},
		"relative path": {
			{SourceID: "source-a", Path: "source-a.txt"},
			{SourceID: "source-b", Path: "/secure/source-b.txt"},
		},
	}
	for name, inputs := range tests {
		inputs := inputs
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateInputs(request, inputs); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("ValidateInputs() error = %v", err)
			}
		})
	}
}

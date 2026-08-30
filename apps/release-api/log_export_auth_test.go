package main

import (
	"testing"

	"xminds-release-platform/internal/iam"
)

func TestDecodeLogExportProofRequiresExactConfirmedShape(t *testing.T) {
	valid := map[string]any{
		"challenge_id": "018f835d-7e4b-7abc-9f42-67a2f5f48e13",
		"evidence":     "xmr_1234567890123456789012345678901234567890123",
		"confirmed":    true,
	}
	proof, ok := decodeLogExportProof(valid)
	if !ok || proof.ChallengeID != valid["challenge_id"] || !proof.Confirmed {
		t.Fatalf("proof=%+v ok=%v", proof, ok)
	}

	for _, invalid := range []map[string]any{
		{"challenge_id": valid["challenge_id"], "evidence": valid["evidence"], "confirmed": false},
		{"challenge_id": valid["challenge_id"], "evidence": valid["evidence"], "confirmed": true, "extra": "rejected"},
		{"challenge_id": valid["challenge_id"], "evidence": "", "confirmed": true},
	} {
		if _, ok := decodeLogExportProof(invalid); ok {
			t.Fatalf("accepted invalid proof: %#v", invalid)
		}
	}
}

func TestLogExportReauthenticationOperationIsSupported(t *testing.T) {
	if iam.ReauthenticationOperationLogExport != "log.export.create" {
		t.Fatalf("operation=%q", iam.ReauthenticationOperationLogExport)
	}
}

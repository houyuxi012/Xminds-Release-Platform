package iam

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

const (
	canonicalIAMCursor                    = "MjAyNi0wOC0yMVQxNzozMDowMFoKMDE4ZjgzNWQtN2U0Yi03YWJjLTlmNDItNjdhMmY1ZjQ4ZTYx"
	canonicalOrganizationMembershipCursor = "MjAyNi0wOC0yMVQxNzozMDowMFoKMDE4ZjgzNWQtN2U0Yi03YWJjLTlmNDItNjdhMmY1ZjQ4ZTYxCnNvdXJjZQ"
)

// Mutation caught: trimming before enforcing the public 512-byte cursor limit
// allows an arbitrarily large input to reach Base64 decoding and allocation.
func TestCursorDecodersRejectRawInputOverLimitBeforeNormalization(t *testing.T) {
	for _, length := range []int{513, 4096} {
		t.Run("generic/"+strconv.Itoa(length), func(t *testing.T) {
			cursor := canonicalIAMCursor + strings.Repeat(" ", length-len(canonicalIAMCursor))
			if _, _, err := decodeIAMCursor(cursor); !errors.Is(err, ErrPageInvalid) {
				t.Fatalf("decodeIAMCursor(raw_length=%d) error=%v", len(cursor), err)
			}
		})
		t.Run("membership/"+strconv.Itoa(length), func(t *testing.T) {
			cursor := canonicalOrganizationMembershipCursor + strings.Repeat(" ", length-len(canonicalOrganizationMembershipCursor))
			if _, _, _, err := decodeOrganizationMembershipCursor(cursor); !errors.Is(err, ErrPageInvalid) {
				t.Fatalf("decodeOrganizationMembershipCursor(raw_length=%d) error=%v", len(cursor), err)
			}
		})
	}
}

// Mutation caught: non-strict RawURLEncoding accepts alternate trailing bits
// that decode to the same payload, violating the opaque cursor's one spelling.
func TestCursorDecodersRejectNonCanonicalBase64URL(t *testing.T) {
	t.Run("generic surrounding whitespace", func(t *testing.T) {
		if _, _, err := decodeIAMCursor(" " + canonicalIAMCursor); !errors.Is(err, ErrPageInvalid) {
			t.Fatalf("decodeIAMCursor(non-canonical) error=%v", err)
		}
	})
	t.Run("membership alternate trailing bits", func(t *testing.T) {
		if _, _, _, err := decodeOrganizationMembershipCursor(canonicalOrganizationMembershipCursor[:len(canonicalOrganizationMembershipCursor)-1] + "R"); !errors.Is(err, ErrPageInvalid) {
			t.Fatalf("decodeOrganizationMembershipCursor(non-canonical) error=%v", err)
		}
	})
}

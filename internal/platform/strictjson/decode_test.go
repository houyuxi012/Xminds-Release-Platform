package strictjson

import (
	"errors"
	"strings"
	"testing"
)

type strictJSONFixture struct {
	Version int `json:"version"`
	Nested  struct {
		Name string `json:"name"`
	} `json:"nested"`
}

func TestDecodeRejectsDuplicateUnknownTrailingAndActualOversizeInput(t *testing.T) {
	testCases := []struct {
		name string
		raw  string
		max  int
	}{
		{name: "top-level duplicate", raw: `{"version":1,"version":2,"nested":{"name":"ok"}}`, max: 128},
		{name: "nested duplicate", raw: `{"version":1,"nested":{"name":"first","name":"second"}}`, max: 128},
		{name: "case-fold alias", raw: `{"version":1,"Version":2,"nested":{"name":"ok"}}`, max: 128},
		{name: "nested case-fold alias", raw: `{"version":1,"nested":{"name":"ok","Name":"override"}}`, max: 128},
		{name: "unknown", raw: `{"version":1,"unexpected":true,"nested":{"name":"ok"}}`, max: 128},
		{name: "trailing", raw: `{"version":1,"nested":{"name":"ok"}} {}`, max: 128},
		{name: "whitespace beyond limit", raw: `{"version":1,"nested":{"name":"ok"}}` + strings.Repeat(" ", 128), max: 64},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var decoded strictJSONFixture
			if err := DecodeBytes([]byte(testCase.raw), testCase.max, &decoded); err == nil {
				t.Fatal("DecodeBytes() error=nil")
			}
			if err := Decode(strings.NewReader(testCase.raw), testCase.max, &decoded); err == nil {
				t.Fatal("Decode() error=nil")
			}
		})
	}
}

func TestDecodeKnownBytesAllowsExtensionsButRejectsKnownFieldAliases(t *testing.T) {
	var decoded strictJSONFixture
	if err := DecodeKnownBytes([]byte(`{"version":1,"extension":{"vendor":true},"nested":{"name":"ok","vendor_name":"allowed"}}`), 128, &decoded); err != nil {
		t.Fatalf("DecodeKnownBytes(extension) error=%v", err)
	}
	if err := DecodeKnownBytes([]byte(`{"Version":1,"nested":{"name":"ok"}}`), 128, &decoded); err == nil {
		t.Fatal("DecodeKnownBytes() accepted known-field case alias")
	}
}

func TestDecodeAcceptsOneStrictObject(t *testing.T) {
	var decoded strictJSONFixture
	if err := DecodeBytes([]byte(`{"version":1,"nested":{"name":"ok"}}`), 64, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Version != 1 || decoded.Nested.Name != "ok" {
		t.Fatalf("decoded=%#v", decoded)
	}
}

func TestDecodeRejectsInvalidConfiguration(t *testing.T) {
	var decoded strictJSONFixture
	if !errors.Is(DecodeBytes([]byte(`{}`), 0, &decoded), ErrInvalidInput) ||
		!errors.Is(DecodeBytes([]byte(`{}`), 2, nil), ErrInvalidInput) {
		t.Fatal("invalid decode configuration was accepted")
	}
}

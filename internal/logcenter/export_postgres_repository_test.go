package logcenter

import (
	"testing"
	"time"
)

func TestSameExportRequestUsesScopeTypesAndFilters(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	leftScope, err := NewLogReadScope(true, false, []string{"product-a"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rightScope := leftScope
	left := ExportRecord{LogTypes: []ScopeTable{ScopeTableOperations}, Scope: leftScope, Filters: LogQueryFilters{ProductID: "product-a", From: now}}
	right := ExportRecord{LogTypes: []ScopeTable{ScopeTableOperations}, Scope: rightScope, Filters: LogQueryFilters{ProductID: "product-a", From: now}}
	if !sameExportRequest(left, right) {
		t.Fatal("equivalent export records were not treated as the same request")
	}
	right.Filters.ProductID = "product-b"
	if sameExportRequest(left, right) {
		t.Fatal("different filters were treated as the same request")
	}
}

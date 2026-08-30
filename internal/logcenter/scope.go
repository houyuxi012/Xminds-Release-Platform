package logcenter

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
)

type ScopeTable string

const (
	ScopeTableOperations          ScopeTable = "operations"
	ScopeTableAuthentications     ScopeTable = "authentications"
	ScopeTableApplicationRequests ScopeTable = "application_requests"
	ScopeTableGitSyncs            ScopeTable = "git_syncs"
)

type LogReadScope struct {
	AllowGlobal        bool
	AllProducts        bool
	IncludedProductIDs []string
	ExcludedProductIDs []string
	Digest             [32]byte
}

var ErrInvalidScope = errors.New("invalid log read scope")

func NewLogReadScope(global, all bool, included, excluded []string) (LogReadScope, error) {
	clean := func(values []string) ([]string, error) {
		seen := map[string]bool{}
		out := make([]string, 0, len(values))
		for _, v := range values {
			v = strings.TrimSpace(v)
			if v == "" || len(v) > 256 {
				return nil, ErrInvalidScope
			}
			if !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
		sort.Strings(out)
		return out, nil
	}
	in, err := clean(included)
	if err != nil {
		return LogReadScope{}, err
	}
	ex, err := clean(excluded)
	if err != nil {
		return LogReadScope{}, err
	}
	if !all && len(in) == 0 {
		return LogReadScope{}, ErrInvalidScope
	}
	for _, v := range in {
		for _, x := range ex {
			if v == x {
				return LogReadScope{}, ErrInvalidScope
			}
		}
	}
	s := LogReadScope{AllowGlobal: global, AllProducts: all, IncludedProductIDs: in, ExcludedProductIDs: ex}
	sum := sha256.New()
	sum.Write([]byte{boolByte(global), boolByte(all)})
	for _, v := range in {
		sum.Write([]byte("+" + v))
	}
	for _, v := range ex {
		sum.Write([]byte("-" + v))
	}
	copy(s.Digest[:], sum.Sum(nil))
	return s, nil
}
func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}
func ScopePredicate(scope LogReadScope, table ScopeTable) (string, []any, error) {
	switch table {
	case ScopeTableOperations, ScopeTableAuthentications, ScopeTableApplicationRequests, ScopeTableGitSyncs:
	default:
		return "", nil, ErrInvalidScope
	}
	global := ""
	if scope.AllowGlobal {
		global = "product_id IS NULL"
	}
	if scope.AllProducts {
		if len(scope.ExcludedProductIDs) == 0 {
			if global != "" {
				return "(" + global + " OR product_id IS NOT NULL)", nil, nil
			}
			return "product_id IS NOT NULL", nil, nil
		}
		if global != "" {
			return "(" + global + " OR (product_id IS NOT NULL AND product_id <> ALL($1)))", []any{scope.ExcludedProductIDs}, nil
		}
		return "product_id <> ALL($1)", []any{scope.ExcludedProductIDs}, nil
	}
	product := "product_id = ANY($1) AND product_id <> ALL($2)"
	if global != "" {
		return "(" + global + " OR (" + product + "))", []any{scope.IncludedProductIDs, scope.ExcludedProductIDs}, nil
	}
	return product, []any{scope.IncludedProductIDs, scope.ExcludedProductIDs}, nil
}
func ScopeDigestHex(scope LogReadScope) string { return hex.EncodeToString(scope.Digest[:]) }

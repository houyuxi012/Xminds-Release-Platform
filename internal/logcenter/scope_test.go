package logcenter

import "testing"

func TestScopePredicateGlobalAndExcluded(t *testing.T) {
	s, e := NewLogReadScope(true, true, nil, []string{"blocked"})
	if e != nil {
		t.Fatal(e)
	}
	q, _, e := ScopePredicate(s, ScopeTableApplicationRequests)
	if e != nil || q == "" {
		t.Fatal(e)
	}
	if _, _, e = ScopePredicate(s, ScopeTable("bad")); e == nil {
		t.Fatal("unknown table accepted")
	}
}

package graph

import (
	"testing"
)

// Tests for the per-file Perl call index (crossfile_walk_perl_index.go).
// buildPerlCallIndex parses Perl source via tree-sitter and groups every
// call site by its method basename. We drive it end-to-end with small Perl
// snippets so the parse + walk + basename derivation are all exercised.

func TestBuildPerlCallIndex_BareAndQualified(t *testing.T) {
	src := `package Main;
sub run {
    my $cgi = CGI->new;
    my $name = get_name($cgi);
    system($name);
}
1;
`
	idx := buildPerlCallIndex(src)
	if idx == nil || idx.byBaseName == nil {
		t.Fatal("buildPerlCallIndex returned an empty/nil index for non-empty source")
	}
	// The two bare/named calls should be indexed under their basenames.
	if len(idx.byBaseName["get_name"]) == 0 {
		t.Errorf("expected get_name call site, got index keys: %v", keysOf(idx.byBaseName))
	}
	if len(idx.byBaseName["system"]) == 0 {
		t.Errorf("expected system call site, got index keys: %v", keysOf(idx.byBaseName))
	}
}

func TestBuildPerlCallIndex_Empty(t *testing.T) {
	idx := buildPerlCallIndex("")
	if idx == nil {
		t.Fatal("buildPerlCallIndex(\"\") should return a non-nil index")
	}
	if len(idx.byBaseName) != 0 {
		t.Errorf("empty source should produce no call sites, got %v", idx.byBaseName)
	}
}

func TestBuildPerlCallIndex_AssignedTo(t *testing.T) {
	// `my $x = foo(...)` should record the LHS binding on the call site.
	src := `sub f {
    my $val = lookup($key);
    return $val;
}
`
	idx := buildPerlCallIndex(src)
	sites := idx.byBaseName["lookup"]
	if len(sites) == 0 {
		t.Fatalf("expected a lookup call site; keys=%v", keysOf(idx.byBaseName))
	}
	// At least one site should carry the assigned-to binding name.
	sawAssign := false
	for _, s := range sites {
		if s.assignedTo == "val" {
			sawAssign = true
		}
	}
	if !sawAssign {
		t.Errorf("expected lookup() call to record assignedTo=val, sites=%+v", sites)
	}
}

func TestPerlCallIndexCache_Get(t *testing.T) {
	c := newPerlCallIndexCache()
	src := `sub g { do_thing(); }`
	first := c.get(src)
	if first == nil {
		t.Fatal("cache.get returned nil")
	}
	// A second get for identical content returns the SAME cached instance.
	second := c.get(src)
	if first != second {
		t.Error("cache.get should return the memoised index for identical content")
	}
	// A nil cache still builds an index (defensive path).
	var nilCache *perlCallIndexCache
	if idx := nilCache.get(src); idx == nil {
		t.Error("nil cache.get should still build an index")
	}
}

func TestPerlCallIndexLookup_LineWindow(t *testing.T) {
	src := `package M;
sub run {
    helper();
}
1;
`
	idx := buildPerlCallIndex(src)
	if len(idx.byBaseName["helper"]) == 0 {
		t.Fatalf("expected helper call site; keys=%v", keysOf(idx.byBaseName))
	}
	// A caller node whose line window contains the call returns it.
	caller := &FuncNode{StartLine: 1, EndLine: 10}
	if got := idx.lookup(caller, "helper"); len(got) == 0 {
		t.Error("lookup with an enclosing window should return the helper call site")
	}
	// A window that excludes the call returns nothing.
	outside := &FuncNode{StartLine: 100, EndLine: 200}
	if got := idx.lookup(outside, "helper"); len(got) != 0 {
		t.Errorf("lookup outside the line window should return nothing, got %d", len(got))
	}
	// Unknown basename / nil index are safe.
	if got := idx.lookup(caller, "nope"); got != nil {
		t.Errorf("lookup(unknown) = %v, want nil", got)
	}
	var nilIdx *perlCallIndex
	if got := nilIdx.lookup(caller, "helper"); got != nil {
		t.Errorf("nil index lookup = %v, want nil", got)
	}
}

func keysOf(m map[string][]perlCallSite) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

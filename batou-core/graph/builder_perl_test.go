package graph

import (
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// The Perl cross-file call-graph builder (builder_perl.go, PR-Gperl) is the live
// path UpdateFileWithAST dispatches to for rules.LangPerl (builder.go case
// `rules.LangPerl`). It is exercised by full scans but had ZERO graph-package
// unit coverage. These tests drive it through the real UpdateFile API (mirrors
// builder_rust_test.go #1276 / builder_shell_test.go #1277), asserting
// package-qualified FuncNodes, the synthetic "__main__" top-level node, RawCalls
// (with :: -> . normalization), and same-file edges. They exercise buildPerlNodes
// and every helper (walkPerlBuilderNodes, perlPackageName, perlSubName,
// perlQualify, emitPerlSub, registerPerlSub, walkPerlBodyForCalls, perlCallName,
// perlNormalizeColons, emitPerlTopLevel, collectPerlTopLevelCalls).

// TestPerlBuilder_PackageQualifiedSubs: `package Foo; sub s {}` qualifies to
// "Foo.s"; a sub in the implicit/`main` package stays bare. Drives
// walkPerlBuilderNodes (package_statement threading), perlPackageName,
// perlSubName, perlQualify, emitPerlSub.
func TestPerlBuilder_PackageQualifiedSubs(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "mod.pl")
	src := `package Foo;
sub get_name {
    return "x";
}

package main;
sub helper {
    return 1;
}
`
	UpdateFile(cg, filePath, src, rules.LangPerl)

	if n := cg.GetNode(FuncID(filePath, "Foo.get_name")); n == nil {
		names := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			names = append(names, x.Name)
		}
		t.Errorf("Foo.get_name node not emitted; have %v", names)
	}
	// `package main;` subs drop the package qualifier (perlQualify).
	if n := cg.GetNode(FuncID(filePath, "helper")); n == nil {
		t.Errorf("main-package sub should be bare-named 'helper'")
	}
	if n := cg.GetNode(FuncID(filePath, "Foo.get_name")); n != nil && n.Language != rules.LangPerl {
		t.Errorf("Foo.get_name node Language = %v, want LangPerl", n.Language)
	}
}

// TestPerlBuilder_NestedPackageName: a multi-segment `package Foo::Bar;` keeps
// the full package path in the qualified node name ("Foo::Bar.s"). Drives
// perlPackageName + perlQualify with a `::` package. (The block-form
// `package Bar { ... }` idiom is rare and the current tree-sitter grammar does
// not surface its body the way the builder's block arm expects, so it emits no
// node — it does not crash; the canonical statement form is covered above.)
func TestPerlBuilder_NestedPackageName(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "nested.pl")
	src := `package Foo::Bar;
sub render {
    return "x";
}
`
	UpdateFile(cg, filePath, src, rules.LangPerl)
	if n := cg.GetNode(FuncID(filePath, "Foo::Bar.render")); n == nil {
		names := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			names = append(names, x.Name)
		}
		t.Errorf("Foo::Bar.render node not emitted; have %v", names)
	}
}

// TestPerlBuilder_TopLevelNode: a flat entry script with top-level calls gets
// the synthetic "__main__" node whose RawCalls capture those calls (including a
// package-qualified one). Drives emitPerlTopLevel + collectPerlTopLevelCalls.
func TestPerlBuilder_TopLevelNode(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "main.pl")
	src := `use Foo;
my $n = Foo::get_name();
system($n);
`
	UpdateFile(cg, filePath, src, rules.LangPerl)

	mod := cg.GetNode(FuncID(filePath, "__main__"))
	if mod == nil {
		t.Fatal("__main__ top-level node not emitted for a script with top-level calls")
	}
	for _, want := range []string{"Foo.get_name", "system"} {
		if !containsStr(mod.RawCalls, want) {
			t.Errorf("__main__.RawCalls missing %q (got %v)", want, mod.RawCalls)
		}
	}
}

// TestPerlBuilder_NoTopLevelCalls_NoNode: a pure-module file (only sub defs, no
// top-level call) gets NO "__main__" node. Drives emitPerlTopLevel's early
// return.
func TestPerlBuilder_NoTopLevelCalls_NoNode(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "pure.pl")
	src := `sub only_sub {
    return 1;
}
`
	UpdateFile(cg, filePath, src, rules.LangPerl)
	if n := cg.GetNode(FuncID(filePath, "__main__")); n != nil {
		t.Errorf("pure-module file should have NO __main__ node, got %q", n.ID)
	}
	if cg.GetNode(FuncID(filePath, "only_sub")) == nil {
		t.Errorf("only_sub node not emitted")
	}
}

// TestPerlBuilder_CallNameForms: every perlCallName branch records the canonical
// raw-name form (bare, Pkg::sub -> Pkg.sub, deep A::B::sub -> A::B.sub, $obj->m
// -> m). Drives perlCallName + perlNormalizeColons + walkPerlBodyForCalls.
func TestPerlBuilder_CallNameForms(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "calls.pl")
	src := `sub caller_sub {
    bare_call();
    Pkg::scoped_call();
    Deep::Mod::deep_call();
    $obj->method_call();
}
`
	UpdateFile(cg, filePath, src, rules.LangPerl)

	caller := cg.GetNode(FuncID(filePath, "caller_sub"))
	if caller == nil {
		t.Fatal("caller_sub node not emitted")
	}
	// bare        -> "bare_call"
	// Pkg::sub    -> "Pkg.scoped_call" (last :: normalised to .)
	// A::B::sub   -> "Deep::Mod.deep_call" (only the LAST :: becomes ., path kept)
	// $obj->m     -> "method_call" (method name only)
	for _, want := range []string{"bare_call", "Pkg.scoped_call", "Deep::Mod.deep_call", "method_call"} {
		if !containsStr(caller.RawCalls, want) {
			t.Errorf("caller_sub.RawCalls missing %q (got %v)", want, caller.RawCalls)
		}
	}
}

// TestPerlBuilder_SameFileEdge: a bare call to a sibling sub in the same package
// becomes a Calls edge via the suffix match (bare "do_work" -> "App.do_work").
// Drives the same-file resolution loop in buildPerlNodes.
func TestPerlBuilder_SameFileEdge(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "edges.pl")
	src := `package App;
sub main_sub {
    do_work();
}
sub do_work {
    return 1;
}
`
	UpdateFile(cg, filePath, src, rules.LangPerl)

	mainSub := cg.GetNode(FuncID(filePath, "App.main_sub"))
	if mainSub == nil {
		names := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			names = append(names, x.Name)
		}
		t.Fatalf("App.main_sub node not emitted; have %v", names)
	}
	if !containsStr(mainSub.RawCalls, "do_work") {
		t.Errorf("App.main_sub.RawCalls missing %q (got %v)", "do_work", mainSub.RawCalls)
	}
	if !containsStr(mainSub.Calls, FuncID(filePath, "App.do_work")) {
		t.Errorf("App.main_sub.Calls missing suffix-matched edge to App.do_work (got %v)", mainSub.Calls)
	}
}

// TestPerlBuilder_WarmRescan_ReusesNodes: rebuilding the same unchanged file
// reuses both the sub node and the __main__ node by content hash and does NOT
// duplicate RawCalls. Guards registerPerlSub / emitPerlTopLevel reuse branches.
func TestPerlBuilder_WarmRescan_ReusesNodes(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "warm.pl")
	src := `sub run {
    step_a();
    step_b();
}

sub step_a { return 1; }
sub step_b { return 2; }

run();
`
	UpdateFile(cg, filePath, src, rules.LangPerl)
	run1 := cg.GetNode(FuncID(filePath, "run"))
	mod1 := cg.GetNode(FuncID(filePath, "__main__"))
	if run1 == nil || mod1 == nil {
		t.Fatal("run and __main__ nodes must both exist on first build")
	}
	runCalls, modCalls := len(run1.RawCalls), len(mod1.RawCalls)

	UpdateFile(cg, filePath, src, rules.LangPerl)
	run2 := cg.GetNode(FuncID(filePath, "run"))
	mod2 := cg.GetNode(FuncID(filePath, "__main__"))
	if run2 == nil || mod2 == nil {
		t.Fatal("run and __main__ nodes missing after warm rescan")
	}
	if len(run2.RawCalls) != runCalls {
		t.Errorf("warm rescan changed run RawCalls: %d -> %d (%v)", runCalls, len(run2.RawCalls), run2.RawCalls)
	}
	if len(mod2.RawCalls) != modCalls {
		t.Errorf("warm rescan changed __main__ RawCalls: %d -> %d (%v)", modCalls, len(mod2.RawCalls), mod2.RawCalls)
	}
	for _, want := range []string{"step_a", "step_b"} {
		if !containsStr(run2.Calls, FuncID(filePath, want)) {
			t.Errorf("warm rescan dropped same-file edge run -> %q (got %v)", want, run2.Calls)
		}
	}
}

// TestPerlBuilder_EmptyContent_NoPanic: an empty/whitespace Perl file builds no
// nodes and does not panic.
func TestPerlBuilder_EmptyContent_NoPanic(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "empty.pl")
	UpdateFile(cg, filePath, "   \n\n", rules.LangPerl)
	if got := len(cg.NodesInFile(filePath)); got != 0 {
		t.Errorf("empty Perl file produced %d nodes, want 0", got)
	}
}

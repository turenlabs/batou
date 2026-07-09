package graph

import (
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// The Rust cross-file call-graph builder (builder_rust.go, PR #1050) is the live
// path UpdateFileWithAST dispatches to for rules.LangRust (builder.go case
// `rules.LangRust`). It is exercised by full scans but had ZERO graph-package
// unit coverage. These tests drive it through the same real API the cpp/php/java
// builder tests use — parse a Rust source string via UpdateFile, then assert on
// the produced CallGraph (emitted FuncNodes, RawCalls, same-file edges). They
// exercise buildRustNodes and every helper (walkRustBuilderNodes,
// rustFunctionDeclName, emitRustFunc, registerRustFunc, walkRustBodyForCalls,
// rustCallName, rustLeadingPathIdent) so a regression in the Rust builder
// surfaces here instead of only in an integration scan.

// TestRustBuilder_FreeAndImplMethods_Emitted: free functions (`fn`/`pub fn`) and
// impl methods (`impl T { fn m() }`) each become a FuncNode. Impl methods are
// keyed by their BARE name (the resolver suffix-matches), never "T.m". Drives
// walkRustBuilderNodes (function_item + impl_item arms), rustFunctionDeclName,
// emitRustFunc, registerRustFunc.
func TestRustBuilder_FreeAndImplMethods_Emitted(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "svc.rs")
	src := `pub fn handler(req: Request) {
    let url = req.param("url");
    fetch(url);
}

fn fetch(u: String) {
    let c = make_client();
}

struct Svc;

impl Svc {
    fn process(&self, x: String) {
        run_cmd(x);
    }
}
`
	UpdateFile(cg, filePath, src, rules.LangRust)

	for _, want := range []string{"handler", "fetch", "process"} {
		if n := cg.GetNode(FuncID(filePath, want)); n == nil {
			ids := make([]string, 0)
			for _, x := range cg.NodesInFile(filePath) {
				ids = append(ids, x.Name)
			}
			t.Errorf("%q node not emitted; have %v", want, ids)
		}
	}
	// Impl methods are emitted bare, never qualified "Svc.process".
	if n := cg.GetNode(FuncID(filePath, "Svc.process")); n != nil {
		t.Errorf("impl method should be a bare-name node, not qualified: %q", n.ID)
	}
	// Language is tagged so the cross-file resolver routes it correctly.
	if n := cg.GetNode(FuncID(filePath, "handler")); n != nil && n.Language != rules.LangRust {
		t.Errorf("handler node Language = %v, want LangRust", n.Language)
	}
}

// TestRustBuilder_SameFileEdge_Exact: a bare call to a sibling function in the
// same file becomes a resolved Calls/CalledBy edge. Drives the same-file
// resolution loop in buildRustNodes (exact-name branch).
func TestRustBuilder_SameFileEdge_Exact(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "edges.rs")
	src := `fn handler(req: Request) {
    fetch(req.body());
}

fn fetch(u: String) {
    println!("{}", u);
}
`
	UpdateFile(cg, filePath, src, rules.LangRust)

	handler := cg.GetNode(FuncID(filePath, "handler"))
	if handler == nil {
		t.Fatal("handler node not emitted")
	}
	if !containsStr(handler.RawCalls, "fetch") {
		t.Errorf("handler.RawCalls missing %q (got %v)", "fetch", handler.RawCalls)
	}
	wantTarget := FuncID(filePath, "fetch")
	if !containsStr(handler.Calls, wantTarget) {
		t.Errorf("handler.Calls missing %q (got %v) — exact-name same-file edge not wired",
			wantTarget, handler.Calls)
	}
}

// TestRustBuilder_CallShapes_RawCalls: every rustCallName branch records the
// canonical raw-name form. Drives rustCallName (identifier, scoped_identifier,
// scoped ctor, field_expression, generic_function) + rustLeadingPathIdent.
func TestRustBuilder_CallShapes_RawCalls(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "shapes.rs")
	src := `fn shapes() {
    bare_call();
    mymod::scoped_fn();
    Command::new("ls");
    obj.method_call();
    generic_fn::<String>();
}
`
	UpdateFile(cg, filePath, src, rules.LangRust)

	shapes := cg.GetNode(FuncID(filePath, "shapes"))
	if shapes == nil {
		t.Fatal("shapes node not emitted")
	}
	// bare identifier -> "bare_call"
	// scoped a::b      -> "mymod.scoped_fn" (leading path segment + method)
	// Command::new     -> "Command.new" (scoped_identifier is keyed uniformly as
	//                     lead "." method — the leading single segment is the path;
	//                     a std ctor like this just never matches a user node)
	// recv.method()    -> "method_call" (field_expression, method only)
	// foo::<T>()       -> "generic_fn" (turbofish unwraps to the inner identifier)
	for _, want := range []string{"bare_call", "mymod.scoped_fn", "Command.new", "method_call", "generic_fn"} {
		if !containsStr(shapes.RawCalls, want) {
			t.Errorf("shapes.RawCalls missing %q (got %v)", want, shapes.RawCalls)
		}
	}
}

// TestRustBuilder_ModDescent: function_items nested in a `mod { ... }` block are
// still discovered. Drives walkRustBuilderNodes' default (descend) arm.
func TestRustBuilder_ModDescent(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "mods.rs")
	src := `mod inner {
    pub fn nested_fn() {
        helper();
    }
}

fn top_level() {
    other();
}
`
	UpdateFile(cg, filePath, src, rules.LangRust)

	for _, want := range []string{"nested_fn", "top_level"} {
		if n := cg.GetNode(FuncID(filePath, want)); n == nil {
			ids := make([]string, 0)
			for _, x := range cg.NodesInFile(filePath) {
				ids = append(ids, x.Name)
			}
			t.Errorf("%q (mod-nested) node not emitted; have %v", want, ids)
		}
	}
}

// TestRustBuilder_NestedCallInArgs: a call nested inside another call's argument
// list (`db_query(get_id())`) is captured too — walkRustBodyForCalls falls
// through after a call_expression so argument-nested calls are still visited.
func TestRustBuilder_NestedCallInArgs(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "nested.rs")
	src := `fn outer() {
    db_query(get_id());
}
`
	UpdateFile(cg, filePath, src, rules.LangRust)

	outer := cg.GetNode(FuncID(filePath, "outer"))
	if outer == nil {
		t.Fatal("outer node not emitted")
	}
	for _, want := range []string{"db_query", "get_id"} {
		if !containsStr(outer.RawCalls, want) {
			t.Errorf("outer.RawCalls missing %q (nested-in-args call not captured); got %v",
				want, outer.RawCalls)
		}
	}
}

// TestRustBuilder_WarmRescan_ReusesNode: rebuilding the same unchanged file
// reuses the existing FuncNode by content hash (registerRustFunc reuse branch)
// and does NOT duplicate RawCalls. Guards against a warm-rescan regression that
// would double-count calls or drop the tree-sitter nodes.
func TestRustBuilder_WarmRescan_ReusesNode(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "warm.rs")
	src := `fn caller() {
    helper_a();
    helper_b();
}

fn helper_a() {}
fn helper_b() {}
`
	UpdateFile(cg, filePath, src, rules.LangRust)
	first := cg.GetNode(FuncID(filePath, "caller"))
	if first == nil {
		t.Fatal("caller node not emitted on first build")
	}
	firstCalls := len(first.RawCalls)
	if firstCalls < 2 {
		t.Fatalf("expected >=2 RawCalls on first build, got %d (%v)", firstCalls, first.RawCalls)
	}

	// Warm rescan with byte-identical content.
	UpdateFile(cg, filePath, src, rules.LangRust)
	second := cg.GetNode(FuncID(filePath, "caller"))
	if second == nil {
		t.Fatal("caller node missing after warm rescan")
	}
	if len(second.RawCalls) != firstCalls {
		t.Errorf("warm rescan changed RawCalls count: first=%d second=%d (%v) — "+
			"reuse branch should reset+recollect, not duplicate", firstCalls, len(second.RawCalls), second.RawCalls)
	}
	// The same-file edges must survive the rescan.
	for _, want := range []string{"helper_a", "helper_b"} {
		if !containsStr(second.Calls, FuncID(filePath, want)) {
			t.Errorf("warm rescan dropped same-file edge to %q (got %v)", want, second.Calls)
		}
	}
}

// TestRustBuilder_EmptyContent_NoPanic: an empty/whitespace Rust file builds no
// nodes and does not panic (buildRustNodes guard + walk over an empty tree).
func TestRustBuilder_EmptyContent_NoPanic(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "empty.rs")
	UpdateFile(cg, filePath, "   \n\n", rules.LangRust)
	if got := len(cg.NodesInFile(filePath)); got != 0 {
		t.Errorf("empty Rust file produced %d nodes, want 0", got)
	}
}

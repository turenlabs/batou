package graph

import (
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// The Shell cross-file call-graph builder (builder_shell.go, PR-Gshell) is the
// live path UpdateFileWithAST dispatches to for rules.LangShell (builder.go case
// `rules.LangShell`). It is exercised by full scans but had ZERO graph-package
// unit coverage. These tests drive it through the real UpdateFile API (mirrors
// builder_cpp_test.go / builder_rust_test.go), asserting emitted FuncNodes, the
// synthetic "<module>" top-level node, RawCalls (every command-word), and
// same-file edges. They exercise buildShellNodes and every helper
// (walkShellBuilderNodes, shellFuncDeclName, emitShellFunc, registerShellFunc,
// walkShellBodyForCalls, shellCommandWord, emitShellModuleNode,
// collectShellTopLevelCalls) so a regression in the Shell builder surfaces here
// instead of only in an integration scan.

// TestShellBuilder_FunctionDefs_BothSyntaxes: `name() { ... }` and
// `function name { ... }` both become a bare-name FuncNode. Drives
// walkShellBuilderNodes, shellFuncDeclName, emitShellFunc, registerShellFunc.
func TestShellBuilder_FunctionDefs_BothSyntaxes(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "lib.sh")
	src := `get_name() {
    echo "name"
}

function fetch_url {
    curl "$1"
}
`
	UpdateFile(cg, filePath, src, rules.LangShell)

	for _, want := range []string{"get_name", "fetch_url"} {
		if n := cg.GetNode(FuncID(filePath, want)); n == nil {
			names := make([]string, 0)
			for _, x := range cg.NodesInFile(filePath) {
				names = append(names, x.Name)
			}
			t.Errorf("%q node not emitted; have %v", want, names)
		}
	}
	if n := cg.GetNode(FuncID(filePath, "get_name")); n != nil && n.Language != rules.LangShell {
		t.Errorf("get_name node Language = %v, want LangShell", n.Language)
	}
}

// TestShellBuilder_PureLibrary_NoModuleNode: a file with only function
// definitions (no top-level command) gets NO synthetic "<module>" node. Drives
// emitShellModuleNode's early return when collectShellTopLevelCalls finds none.
func TestShellBuilder_PureLibrary_NoModuleNode(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "pure.sh")
	src := `helper_a() {
    echo a
}

helper_b() {
    echo b
}
`
	UpdateFile(cg, filePath, src, rules.LangShell)

	if n := cg.GetNode(FuncID(filePath, "<module>")); n != nil {
		t.Errorf("pure-library file should have NO <module> node, got %q", n.ID)
	}
	// The function nodes must still exist.
	for _, want := range []string{"helper_a", "helper_b"} {
		if cg.GetNode(FuncID(filePath, want)) == nil {
			t.Errorf("%q function node not emitted", want)
		}
	}
}

// TestShellBuilder_ModuleNode_TopLevelCalls: a script with top-level statements
// (the canonical `source lib; n=$(get_name); eval "$n"` entry-point shape) gets
// a synthetic "<module>" node whose RawCalls capture those command-words —
// including the call nested in a command substitution. Drives emitShellModuleNode
// + collectShellTopLevelCalls (descends into $(...)).
func TestShellBuilder_ModuleNode_TopLevelCalls(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "entry.sh")
	src := `source ./lib.sh
n=$(get_name)
eval "$n"
`
	UpdateFile(cg, filePath, src, rules.LangShell)

	mod := cg.GetNode(FuncID(filePath, "<module>"))
	if mod == nil {
		t.Fatal("<module> node not emitted for a script with top-level commands")
	}
	// `n=$(get_name)` records get_name (command nested in a substitution);
	// `eval "$n"` records the eval built-in command-word.
	for _, want := range []string{"get_name", "eval"} {
		if !containsStr(mod.RawCalls, want) {
			t.Errorf("<module>.RawCalls missing %q (got %v)", want, mod.RawCalls)
		}
	}
}

// TestShellBuilder_SameFileEdge_BuiltinsNoEdge: a call to a sibling function
// defined in the same file becomes a Calls edge; a built-in command (echo) does
// NOT (no node by that name). Drives the same-file resolution loop in
// buildShellNodes + walkShellBodyForCalls + shellCommandWord.
func TestShellBuilder_SameFileEdge_BuiltinsNoEdge(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "edges.sh")
	src := `main() {
    do_work
    echo "done"
}

do_work() {
    echo "working"
}
`
	UpdateFile(cg, filePath, src, rules.LangShell)

	main := cg.GetNode(FuncID(filePath, "main"))
	if main == nil {
		t.Fatal("main node not emitted")
	}
	// Both command-words are recorded as RawCalls...
	for _, want := range []string{"do_work", "echo"} {
		if !containsStr(main.RawCalls, want) {
			t.Errorf("main.RawCalls missing %q (got %v)", want, main.RawCalls)
		}
	}
	// ...but only the defined function forms a same-file edge.
	if !containsStr(main.Calls, FuncID(filePath, "do_work")) {
		t.Errorf("main.Calls missing edge to do_work (got %v)", main.Calls)
	}
	if containsStr(main.Calls, FuncID(filePath, "echo")) {
		t.Errorf("main.Calls should NOT have an edge to the echo built-in (got %v)", main.Calls)
	}
}

// TestShellBuilder_NestedCommandSub_InBody: a command nested in a command
// substitution inside a function body (`out=$(get_data)`) is captured as a
// RawCall too — walkShellBodyForCalls falls through after a command node.
func TestShellBuilder_NestedCommandSub_InBody(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "nested.sh")
	src := `process() {
    local out=$(get_data)
    eval "$out"
}
`
	UpdateFile(cg, filePath, src, rules.LangShell)

	process := cg.GetNode(FuncID(filePath, "process"))
	if process == nil {
		t.Fatal("process node not emitted")
	}
	for _, want := range []string{"get_data", "eval"} {
		if !containsStr(process.RawCalls, want) {
			t.Errorf("process.RawCalls missing %q (nested-command-sub not captured); got %v",
				want, process.RawCalls)
		}
	}
}

// TestShellBuilder_ModuleSkipsFunctionBodies: collectShellTopLevelCalls stops at
// a function_definition boundary — a command that exists ONLY inside a function
// body must NOT leak into the <module> node's RawCalls.
func TestShellBuilder_ModuleSkipsFunctionBodies(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "scope.sh")
	src := `helper() {
    only_in_helper
}

top_level_cmd arg
`
	UpdateFile(cg, filePath, src, rules.LangShell)

	mod := cg.GetNode(FuncID(filePath, "<module>"))
	if mod == nil {
		t.Fatal("<module> node not emitted (there is a top-level command)")
	}
	if !containsStr(mod.RawCalls, "top_level_cmd") {
		t.Errorf("<module>.RawCalls missing top-level %q (got %v)", "top_level_cmd", mod.RawCalls)
	}
	if containsStr(mod.RawCalls, "only_in_helper") {
		t.Errorf("<module>.RawCalls leaked a command from inside a function body: %q (got %v)",
			"only_in_helper", mod.RawCalls)
	}
}

// TestShellBuilder_WarmRescan_ReusesNodes: rebuilding the same unchanged script
// reuses both the function node and the <module> node by content hash and does
// NOT duplicate RawCalls. Guards the registerShellFunc / emitShellModuleNode
// content-hash reuse branches against a warm-rescan regression.
func TestShellBuilder_WarmRescan_ReusesNodes(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "warm.sh")
	src := `run() {
    step_a
    step_b
}

step_a() { echo a; }
step_b() { echo b; }

run
`
	UpdateFile(cg, filePath, src, rules.LangShell)
	run1 := cg.GetNode(FuncID(filePath, "run"))
	mod1 := cg.GetNode(FuncID(filePath, "<module>"))
	if run1 == nil || mod1 == nil {
		t.Fatal("run and <module> nodes must both exist on first build")
	}
	runCalls, modCalls := len(run1.RawCalls), len(mod1.RawCalls)

	// Warm rescan, byte-identical content.
	UpdateFile(cg, filePath, src, rules.LangShell)
	run2 := cg.GetNode(FuncID(filePath, "run"))
	mod2 := cg.GetNode(FuncID(filePath, "<module>"))
	if run2 == nil || mod2 == nil {
		t.Fatal("run and <module> nodes missing after warm rescan")
	}
	if len(run2.RawCalls) != runCalls {
		t.Errorf("warm rescan changed run RawCalls: %d -> %d (%v)", runCalls, len(run2.RawCalls), run2.RawCalls)
	}
	if len(mod2.RawCalls) != modCalls {
		t.Errorf("warm rescan changed <module> RawCalls: %d -> %d (%v)", modCalls, len(mod2.RawCalls), mod2.RawCalls)
	}
	// Same-file edges to the defined helpers must survive.
	for _, want := range []string{"step_a", "step_b"} {
		if !containsStr(run2.Calls, FuncID(filePath, want)) {
			t.Errorf("warm rescan dropped same-file edge run -> %q (got %v)", want, run2.Calls)
		}
	}
}

// TestShellBuilder_EmptyContent_NoPanic: an empty/whitespace shell file builds
// no nodes and does not panic.
func TestShellBuilder_EmptyContent_NoPanic(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "empty.sh")
	UpdateFile(cg, filePath, "   \n\n", rules.LangShell)
	if got := len(cg.NodesInFile(filePath)); got != 0 {
		t.Errorf("empty shell file produced %d nodes, want 0", got)
	}
}

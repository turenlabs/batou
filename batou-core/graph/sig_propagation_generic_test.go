package graph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// TestGenericParamName_LanguageShapes locks the decl-line parameter-name
// parser against the syntactic shapes of every generalized language. A
// regression here silently breaks the sink-lift for that language (the
// forwarded arg would never match a param name), so the table is exhaustive
// across the families: `Type name`, `name: Type`, `$name`, `const T& name`,
// and a leading-`_` Swift external label.
func TestGenericParamName_LanguageShapes(t *testing.T) {
	cases := []struct {
		name string
		decl string
		want []string
	}{
		{"csharp_type_name", "static void Relay(string n) {", []string{"n"}},
		{"java_two_params", "void relay(String a, int b) {", []string{"a", "b"}},
		{"swift_underscore_label", "static func relay(_ c: String) {", []string{"c"}},
		{"swift_external_internal", "func relay(for name: String) {", []string{"name"}},
		{"kotlin_name_type", "fun relay(c: String) {", []string{"c"}},
		{"php_dollar", "public static function relay($n) {", []string{"$n"}},
		{"php_typed_dollar", "function relay(string $name) {", []string{"$name"}},
		{"ruby_bare", "def self.relay(c)", []string{"c"}},
		{"lua_bare", "function S.relay(c)", []string{"c"}},
		{"cpp_const_ref_scope", "void service_relay(const std::string& c) {", []string{"c"}},
		{"cpp_generic_type", "void f(std::vector<int> xs, int n) {", []string{"xs", "n"}},
		{"rust_ref", "pub fn relay(c: &str) {", []string{"c"}},
		{"default_value", "def handle(name, code = nil)", []string{"name", "code"}},
		{"empty_params", "func handle() {", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := genericCallerParamNames(&FuncNode{}, []string{tc.decl})
			if len(got) != len(tc.want) {
				t.Fatalf("decl %q -> %#v, want %#v", tc.decl, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("decl %q param[%d] = %q, want %q", tc.decl, i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestGenericParamName_StartLineOffset verifies the decl scanner tolerates a
// node whose StartLine lands a line ABOVE the signature (the Lua
// table-method builder records `local S = {}` as the start). Without the
// small scan window the param list would be empty and the sink-lift inert.
func TestGenericParamName_StartLineOffset(t *testing.T) {
	body := []string{
		"local S = {}",        // StartLine lands here for Lua table methods
		"function S.relay(c)", // real signature one line down
		"  repo.run(c)",
		"end",
	}
	got := genericCallerParamNames(&FuncNode{}, body)
	if len(got) != 1 || got[0] != "c" {
		t.Fatalf("StartLine-offset decl -> %#v, want [c]", got)
	}
}

// genericLiftHarness hand-builds a controller→relay→leaf chain for one
// generalized language and returns the relay node after propagation, so the
// tests can assert the leaf sink lifted up to the relay (the multi-hop
// composition step). The leaf sink is a wildcard (ArgFromParam == -1) — the
// shape every generalized-language producer emits — so the lift must resolve
// the forwarded arg to the relay's own parameter by NAME.
//
// Both the leaf and relay file contents are passed to the propagation pass
// so the Kotlin reconciliation pre-pass (which re-derives the leaf's sinks
// from its real body) has a body to validate against — the harness uses a
// real `exec(c)` call in the leaf so the hand-set sink survives.
func genericLiftHarness(t *testing.T, lang rules.Language, relayName, relayBody string, calleeBase, leafBody string) *FuncNode {
	t.Helper()
	// Write real files: the Kotlin reconciliation pre-pass
	// (ensureKotlinCalleeSinks) re-derives the leaf's sinks by reading the
	// leaf body FROM DISK (it ignores the in-memory fileContents map), so a
	// purely in-memory harness would see the leaf's hand-set sink dropped.
	root := t.TempDir()
	leafPath := filepath.Join(root, "leaf")
	relayPath := filepath.Join(root, "relay")
	if err := os.WriteFile(leafPath, []byte(leafBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(relayPath, []byte(relayBody), 0o644); err != nil {
		t.Fatal(err)
	}
	cg := NewCallGraph(root, "t")
	leafID := leafPath + ":" + calleeBase
	leaf := &FuncNode{
		ID: leafID, Name: calleeBase, FilePath: leafPath, Language: lang,
		StartLine: 1, EndLine: 3,
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkCommand, MethodName: "exec", Line: 2, ArgFromParam: -1}},
		},
	}
	relay := &FuncNode{
		ID: relayPath + ":relay", Name: "relay", FilePath: relayPath, Language: lang,
		StartLine: 1, EndLine: 3, Calls: []string{leafID},
	}
	cg.Nodes[leaf.ID] = leaf
	cg.Nodes[relay.ID] = relay
	PropagateSignaturesAcrossCallgraph(cg, nil)
	return relay
}

// TestGenericMultiHop_SinkLiftsIntoRelay is the core multi-hop assertion for
// the generalized languages: a leaf sink composes UP into a relay that
// forwards its own parameter to the leaf. One sub-case per language family
// so a per-language adapter regression (wrong cache type assertion, missing
// table entry, broken param parse) is caught here rather than only in the
// real-scan benches.
func TestGenericMultiHop_SinkLiftsIntoRelay(t *testing.T) {
	cases := []struct {
		name     string
		lang     rules.Language
		body     string
		base     string
		leafBody string
	}{
		{"csharp", rules.LangCSharp, "static void Relay(string c) {\n    Save(c);\n}\n", "Save", "void Save(string x) {\n    Process.Start(x);\n}\n"},
		{"swift", rules.LangSwift, "static func relay(_ c: String) {\n    run(c)\n}\n", "run", "func run(_ x: String) {\n    system(x)\n}\n"},
		{"php", rules.LangPHP, "<?php\nfunction relay($c) {\n    find($c);\n}\n", "find", "<?php\nfunction find($x) {\n    system($x);\n}\n"},
		{"ruby", rules.LangRuby, "def self.relay(c)\n  run_code(c)\nend\n", "run_code", "def self.run_code(x)\n  system(x)\nend\n"},
		{"kotlin", rules.LangKotlin, "fun relay(c: String) {\n    run(c)\n}\n", "run", "fun run(x: String) {\n    Runtime.getRuntime().exec(x)\n}\n"},
		{"groovy", rules.LangGroovy, "static void relay(String c) {\n    run(c)\n}\n", "run", "void run(String x) {\n    \"cmd\".execute()\n}\n"},
		{"rust", rules.LangRust, "pub fn relay(c: &str) {\n    run(c);\n}\n", "run", "fn run(x: &str) {\n    Command::new(x);\n}\n"},
		{"lua", rules.LangLua, "function S.relay(c)\n  run(c)\nend\n", "run", "function run(x)\n  os.execute(x)\nend\n"},
		{"cpp", rules.LangCPP, "void relay(const std::string& c) {\n    run(c);\n}\n", "run", "void run(const std::string& x) {\n    system(x.c_str());\n}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relay := genericLiftHarness(t, tc.lang, "relay", tc.body, tc.base, tc.leafBody)
			if len(relay.TaintSig.SinkCalls) != 1 {
				t.Fatalf("%s: relay.SinkCalls = %d, want 1 (lift failed)", tc.name, len(relay.TaintSig.SinkCalls))
			}
			lifted := relay.TaintSig.SinkCalls[0]
			if lifted.ArgFromParam != 0 {
				t.Errorf("%s: lifted ArgFromParam = %d, want 0 (relay's own param)", tc.name, lifted.ArgFromParam)
			}
			if lifted.OriginFile == "" {
				t.Errorf("%s: lifted sink lost OriginFile provenance", tc.name)
			}
			if lifted.SinkCategory != taint.SnkCommand {
				t.Errorf("%s: lifted category = %v, want command_exec", tc.name, lifted.SinkCategory)
			}
		})
	}
}

// TestGenericMultiHop_SameLanguageGate verifies a leaf sink in one language
// never lifts into a relay of a DIFFERENT generalized language, even when
// the call-site text matches. A C# convention must not contaminate a Swift
// caller's signature.
func TestGenericMultiHop_SameLanguageGate(t *testing.T) {
	cg := NewCallGraph("/p", "t")
	// Leaf is C#; relay is Swift. The Swift adapter must skip the C# callee.
	leaf := &FuncNode{
		ID: "/p/leaf:run", Name: "run", FilePath: "/p/leaf", Language: rules.LangCSharp,
		StartLine: 1, EndLine: 3,
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkCommand, MethodName: "exec", Line: 2, ArgFromParam: -1}},
		},
	}
	relay := &FuncNode{
		ID: "/p/relay:relay", Name: "relay", FilePath: "/p/relay", Language: rules.LangSwift,
		StartLine: 1, EndLine: 3, Calls: []string{"/p/leaf:run"},
	}
	cg.Nodes[leaf.ID] = leaf
	cg.Nodes[relay.ID] = relay
	PropagateSignaturesAcrossCallgraph(cg, map[string]string{
		"/p/relay": "static func relay(_ c: String) {\n    run(c)\n}\n",
	})
	if len(relay.TaintSig.SinkCalls) != 0 {
		t.Errorf("cross-language lift leaked: Swift relay gained %d C# sinks, want 0",
			len(relay.TaintSig.SinkCalls))
	}
}

// TestGenericMultiHop_ReturnLiftComposesChain verifies the return-lift path:
// a relay that does `return leaf(req)` inherits the leaf's tainted return,
// so a hop-2 caller can compose the chain. Uses a Returns-capable language
// (C#); Ruby/Python intentionally have no return producer.
func TestGenericMultiHop_ReturnLiftComposesChain(t *testing.T) {
	cg := NewCallGraph("/p", "t")
	leaf := &FuncNode{
		ID: "/p/leaf:source", Name: "source", FilePath: "/p/leaf", Language: rules.LangCSharp,
		StartLine: 1, EndLine: 3,
		TaintSig: TaintSignature{
			TaintedReturns: map[int][]taint.SourceCategory{0: {taint.SrcUserInput}},
		},
	}
	relay := &FuncNode{
		ID: "/p/relay:relay", Name: "relay", FilePath: "/p/relay", Language: rules.LangCSharp,
		StartLine: 1, EndLine: 3, Calls: []string{"/p/leaf:source"},
	}
	cg.Nodes[leaf.ID] = leaf
	cg.Nodes[relay.ID] = relay
	PropagateSignaturesAcrossCallgraph(cg, map[string]string{
		"/p/relay": "static string relay() {\n    return source();\n}\n",
	})
	if len(relay.TaintSig.TaintedReturns) == 0 {
		t.Fatalf("return-lift failed: relay did not inherit leaf's tainted return")
	}
}

// genericLookbackHarness mirrors genericLiftHarness but computes the relay's
// EndLine from the body's line count, so multi-line relay bodies (one local
// rebind between the param and the sink-forwarding call) keep the call site
// inside the caller range. Returns the relay node after propagation.
func genericLookbackHarness(t *testing.T, lang rules.Language, relayBody, calleeBase, leafBody string) *FuncNode {
	t.Helper()
	root := t.TempDir()
	leafPath := filepath.Join(root, "leaf")
	relayPath := filepath.Join(root, "relay")
	if err := os.WriteFile(leafPath, []byte(leafBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(relayPath, []byte(relayBody), 0o644); err != nil {
		t.Fatal(err)
	}
	cg := NewCallGraph(root, "t")
	leafID := leafPath + ":" + calleeBase
	leaf := &FuncNode{
		ID: leafID, Name: calleeBase, FilePath: leafPath, Language: lang,
		StartLine: 1, EndLine: 3,
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkCommand, MethodName: "exec", Line: 2, ArgFromParam: -1}},
		},
	}
	relay := &FuncNode{
		ID: relayPath + ":relay", Name: "relay", FilePath: relayPath, Language: lang,
		StartLine: 1, EndLine: strings.Count(relayBody, "\n"), Calls: []string{leafID},
	}
	cg.Nodes[leaf.ID] = leaf
	cg.Nodes[relay.ID] = relay
	PropagateSignaturesAcrossCallgraph(cg, nil)
	return relay
}

// TestGenericLookback_LiftsLocalAssignment: the generic-adapter wiring of the
// local-assignment lookback. One local rebind between the relay's param and
// the sink-forwarding call (`q = Build(c); Save(q)`) must now lift the leaf
// sink into the relay — previously the generic call sites passed nil
// bodyLines / 0 callLineIdx so this never lifted. One C-family case and one
// sigil case (PHP `$q`) cover the two argument-token shapes the generic
// adapters produce.
func TestGenericLookback_LiftsLocalAssignment(t *testing.T) {
	cases := []struct {
		name      string
		lang      rules.Language
		relayBody string
		base      string
		leafBody  string
	}{
		{
			"csharp", rules.LangCSharp,
			"static void Relay(string c) {\n    string q = Build(c);\n    Save(q);\n}\n",
			"Save", "void Save(string x) {\n    Process.Start(x);\n}\n",
		},
		{
			"php_sigil", rules.LangPHP,
			"<?php\nfunction relay($c) {\n    $q = build($c);\n    find($q);\n}\n",
			"find", "<?php\nfunction find($x) {\n    system($x);\n}\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relay := genericLookbackHarness(t, tc.lang, tc.relayBody, tc.base, tc.leafBody)
			if len(relay.TaintSig.SinkCalls) != 1 {
				t.Fatalf("%s: relay.SinkCalls = %d, want 1 (lookback lift failed)", tc.name, len(relay.TaintSig.SinkCalls))
			}
			if relay.TaintSig.SinkCalls[0].ArgFromParam != 0 {
				t.Errorf("%s: lifted ArgFromParam = %d, want 0 (relay's own param)", tc.name, relay.TaintSig.SinkCalls[0].ArgFromParam)
			}
		})
	}
}

// TestGenericLookback_SanitizerNoLift: a rebind through a sanitizer-named
// call (`string q = Escape(c)`) must NOT lift — isSanitizerByName is
// consulted on the looked-back RHS exactly as in the Go path.
func TestGenericLookback_SanitizerNoLift(t *testing.T) {
	relay := genericLookbackHarness(t, rules.LangCSharp,
		"static void Relay(string c) {\n    string q = Escape(c);\n    Save(q);\n}\n",
		"Save", "void Save(string x) {\n    Process.Start(x);\n}\n")
	if len(relay.TaintSig.SinkCalls) != 0 {
		t.Errorf("relay.SinkCalls = %d, want 0 (rebind through Escape must not lift)", len(relay.TaintSig.SinkCalls))
	}
}

// TestGenericLookback_UnrelatedNoLift: a binding not derived from any relay
// param must not lift.
func TestGenericLookback_UnrelatedNoLift(t *testing.T) {
	relay := genericLookbackHarness(t, rules.LangCSharp,
		"static void Relay(string c) {\n    string q = Unrelated();\n    Save(q);\n}\n",
		"Save", "void Save(string x) {\n    Process.Start(x);\n}\n")
	if len(relay.TaintSig.SinkCalls) != 0 {
		t.Errorf("relay.SinkCalls = %d, want 0 (q not derived from c must not lift)", len(relay.TaintSig.SinkCalls))
	}
}

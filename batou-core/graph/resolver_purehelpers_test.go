package graph

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
)

// These tests cover the pure, deterministic string/path helpers used by
// the per-language resolvers and builders. They take plain string inputs
// (no AST, no disk) so they are fast and flake-free. The targets were the
// 0%-coverage helpers reported by `go tool cover -func`.

// ---- C# resolver helpers (resolver_csharp.go) ----

func TestCSharpSplitClassMethod(t *testing.T) {
	cases := []struct {
		in, class, method string
	}{
		{"Helper.GetName", "Helper", "GetName"},
		{"MyApp.Helpers.Helper.GetName", "Helper", "GetName"},
		{"GetName", "", ""}, // no dot -> empty
		{"a.b", "a", "b"},
	}
	for _, tc := range cases {
		c, m := csharpSplitClassMethod(tc.in)
		if c != tc.class || m != tc.method {
			t.Errorf("csharpSplitClassMethod(%q) = (%q,%q), want (%q,%q)", tc.in, c, m, tc.class, tc.method)
		}
	}
}

func TestCSharpSplitNamespaceType(t *testing.T) {
	cases := []struct {
		in, ns, typ string
	}{
		{"NS.Sub.Type", "NS.Sub", "Type"},
		{"Type", "", "Type"},
		{"  A.B  ", "A", "B"},
	}
	for _, tc := range cases {
		ns, typ := csharpSplitNamespaceType(tc.in)
		if ns != tc.ns || typ != tc.typ {
			t.Errorf("csharpSplitNamespaceType(%q) = (%q,%q), want (%q,%q)", tc.in, ns, typ, tc.ns, tc.typ)
		}
	}
}

func TestCSharpNodeFuncName(t *testing.T) {
	if got := csharpNodeFuncName("/abs/path/File.cs:NS.Cls.Method"); got != "NS.Cls.Method" {
		t.Errorf("csharpNodeFuncName qualified = %q", got)
	}
	if got := csharpNodeFuncName("bareName"); got != "bareName" {
		t.Errorf("csharpNodeFuncName no-colon = %q, want bareName", got)
	}
}

func TestIsCSharpExternFQN(t *testing.T) {
	// csharpExternPrefixes includes BCL roots like "System".
	if !isCSharpExternFQN("System.IO.File") {
		t.Error("System.IO.File should be extern")
	}
	if isCSharpExternFQN("MyApp.Service.Handler") {
		t.Error("in-project FQN should not be extern")
	}
}

func TestIsCSharpExternReceiver(t *testing.T) {
	if !isCSharpExternReceiver("System") {
		t.Error("System receiver should be extern")
	}
	if isCSharpExternReceiver("MyService") {
		t.Error("in-project receiver should not be extern")
	}
}

// ---- Kotlin resolver helpers (resolver_kotlin.go) ----

func TestKotlinStripOverloadSuffix(t *testing.T) {
	if got := kotlinStripOverloadSuffix("foo#2"); got != "foo" {
		t.Errorf("kotlinStripOverloadSuffix(foo#2) = %q, want foo", got)
	}
	if got := kotlinStripOverloadSuffix("foo"); got != "foo" {
		t.Errorf("kotlinStripOverloadSuffix(foo) = %q, want foo", got)
	}
}

func TestKotlinSplitClassMethod(t *testing.T) {
	cases := []struct {
		in, class, method string
	}{
		{"Helper.getName", "Helper", "getName"},
		{"com.foo.Helper.getName", "Helper", "getName"},
		{"bare", "", ""},
	}
	for _, tc := range cases {
		c, m := kotlinSplitClassMethod(tc.in)
		if c != tc.class || m != tc.method {
			t.Errorf("kotlinSplitClassMethod(%q) = (%q,%q), want (%q,%q)", tc.in, c, m, tc.class, tc.method)
		}
	}
}

func TestKotlinSplitPackageType(t *testing.T) {
	cases := []struct {
		in, pkg, typ string
	}{
		{"a.b.Type", "a.b", "Type"},
		{"Type", "", "Type"},
	}
	for _, tc := range cases {
		pkg, typ := kotlinSplitPackageType(tc.in)
		if pkg != tc.pkg || typ != tc.typ {
			t.Errorf("kotlinSplitPackageType(%q) = (%q,%q), want (%q,%q)", tc.in, pkg, typ, tc.pkg, tc.typ)
		}
	}
}

func TestIsKotlinExternFQN(t *testing.T) {
	if !isKotlinExternFQN("kotlin.collections.List") {
		t.Error("kotlin.* should be extern")
	}
	if !isKotlinExternFQN("java.util.Map") {
		t.Error("java.* should be extern")
	}
	if isKotlinExternFQN("com.myapp.Service") {
		t.Error("in-project FQN should not be extern")
	}
}

func TestIsKotlinExternReceiver(t *testing.T) {
	if !isKotlinExternReceiver("Runtime") {
		t.Error("Runtime should be an extern receiver")
	}
	if isKotlinExternReceiver("MyHelper") {
		t.Error("in-project receiver should not be extern")
	}
}

// ---- Groovy resolver helpers (resolver_groovy.go) ----

func TestGroovySplitClassMethod(t *testing.T) {
	cases := []struct {
		in, class, method string
	}{
		{"a.getName", "a", "getName"},
		{"app.Helper.getName", "Helper", "getName"},
		{"bare", "", ""},
	}
	for _, tc := range cases {
		c, m := groovySplitClassMethod(tc.in)
		if c != tc.class || m != tc.method {
			t.Errorf("groovySplitClassMethod(%q) = (%q,%q), want (%q,%q)", tc.in, c, m, tc.class, tc.method)
		}
	}
}

func TestGroovyJoinPkg(t *testing.T) {
	if got := groovyJoinPkg("com.foo", "Bar.baz"); got != "com.foo.Bar.baz" {
		t.Errorf("groovyJoinPkg with pkg = %q", got)
	}
	if got := groovyJoinPkg("", "Bar.baz"); got != "Bar.baz" {
		t.Errorf("groovyJoinPkg empty pkg = %q, want Bar.baz", got)
	}
}

func TestGroovyNodeFuncName(t *testing.T) {
	if got := groovyNodeFuncName("/a/b/File.groovy:pkg.Class.method"); got != "pkg.Class.method" {
		t.Errorf("groovyNodeFuncName = %q", got)
	}
	if got := groovyNodeFuncName("noColon"); got != "noColon" {
		t.Errorf("groovyNodeFuncName no-colon = %q", got)
	}
}

func TestGroovyNodeIsBarePackage(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"Helper.method", true},  // leading uppercase = class-ish
		{"helper.method", false}, // leading lowercase = variable-ish
		{"", false},
		{"<init>", false},
		{"App", true},
	}
	for _, tc := range cases {
		if got := groovyNodeIsBarePackage(tc.in); got != tc.want {
			t.Errorf("groovyNodeIsBarePackage(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestIsGroovyExternFQN(t *testing.T) {
	if !isGroovyExternFQN("java.lang.String") {
		t.Error("java.lang.String should be extern")
	}
	if isGroovyExternFQN("com.myapp.Svc") {
		t.Error("in-project FQN should not be extern")
	}
}

func TestIsGroovyExternReceiver(t *testing.T) {
	for _, r := range []string{"System", "String", "Runtime", "Math"} {
		if !isGroovyExternReceiver(r) {
			t.Errorf("%q should be a Groovy extern receiver", r)
		}
	}
	if isGroovyExternReceiver("MyHelper") {
		t.Error("in-project receiver should not be extern")
	}
}

func TestAppendUnique(t *testing.T) {
	xs := appendUnique(nil, "a")
	xs = appendUnique(xs, "b")
	xs = appendUnique(xs, "a") // dup, no-op
	if len(xs) != 2 || xs[0] != "a" || xs[1] != "b" {
		t.Errorf("appendUnique = %v, want [a b]", xs)
	}
}

// ---- Perl resolver / walk helpers (resolver_perl.go, crossfile_walk_perl.go) ----

func TestPerlPathToPackage(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Foo/Bar.pm", "Foo::Bar"},
		{"./Foo/Bar.pm", "Foo::Bar"},
		{"Foo/Bar.pl", "Foo::Bar"},
		{"Foo", "Foo"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := perlPathToPackage(tc.in); got != tc.want {
			t.Errorf("perlPathToPackage(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsPerlExternSpecifier(t *testing.T) {
	if !isPerlExternSpecifier("strict") {
		t.Error("strict pragma should be extern")
	}
	if !isPerlExternSpecifier("DBI::st") {
		t.Error("DBI::st should be extern")
	}
	if isPerlExternSpecifier("MyApp::Model") {
		t.Error("in-project package should not be extern")
	}
	if isPerlExternSpecifier("") {
		t.Error("empty should not be extern")
	}
}

func TestPerlRootIdent(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"$foo", "foo"},
		{"@bar->method", "bar"},
		{"$h{key}", "h"},
		{"  $x  ", "x"},
		{`\$ref`, "ref"},
	}
	for _, tc := range cases {
		if got := perlRootIdent(tc.in); got != tc.want {
			t.Errorf("perlRootIdent(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPerlAssignEq(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"my $x = foo()", 6},
		{"$a == $b", -1},
		{"$a != $b", -1},
		{"$h => 1", -1},
		{"$x =~ /re/", -1},
		{"no equals here", -1},
	}
	for _, tc := range cases {
		if got := perlAssignEq(tc.in); got != tc.want {
			t.Errorf("perlAssignEq(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestPerlLastIdent(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"my $result", "result"},
		{"our $thing", "thing"},
		{"local $tmp", "tmp"},
		{"$a + $b", "b"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := perlLastIdent(tc.in); got != tc.want {
			t.Errorf("perlLastIdent(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPerlSplitStatements(t *testing.T) {
	// With a sub wrapper: header is stripped, body split on ; and \n.
	body := "sub foo {\n  my $x = 1;\n  bar($x);\n}"
	stmts := perlSplitStatements(body)
	if len(stmts) != 2 {
		t.Fatalf("perlSplitStatements wrapped = %d stmts, want 2: %#v", len(stmts), stmts)
	}
	// Quoted semicolons must not split.
	raw := `print "a;b"; next`
	stmts = perlSplitStatements(raw)
	if len(stmts) != 2 {
		t.Fatalf("perlSplitStatements quoted-semicolon = %d stmts, want 2: %#v", len(stmts), stmts)
	}
}

// ---- Lua resolver helpers (resolver_lua.go) ----

func TestLuaModuleBasename(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"a.b.c", "c"},
		{"foo", "foo"},
		{"path/to/mod", "mod"},
		{"a.b/c", "c"},
	}
	for _, tc := range cases {
		if got := luaModuleBasename(tc.in); got != tc.want {
			t.Errorf("luaModuleBasename(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---- Rust resolver helpers (resolver_rust.go) ----

func TestIsRustExternSpecifier(t *testing.T) {
	if !isRustExternSpecifier("std") {
		t.Error("std should be extern")
	}
	if !isRustExternSpecifier("tokio::sync::Mutex") {
		t.Error("tokio::* should be extern")
	}
	if isRustExternSpecifier("crate::handlers") {
		t.Error("crate::* (in-project) should not be extern")
	}
	if isRustExternSpecifier("") {
		t.Error("empty should not be extern")
	}
}

// ---- C++ scope helpers (builder_cpp.go, resolver_cpp.go) ----

func TestSplitCPPScope(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"ns::Foo::bar", []string{"ns", "Foo", "bar"}},
		{"Foo<int>::bar", []string{"Foo", "bar"}},
		{"bare", []string{"bare"}},
		{"", nil},
	}
	for _, tc := range cases {
		got := splitCPPScope(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("splitCPPScope(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitCPPScope(%q)[%d] = %q, want %q", tc.in, i, got[i], tc.want[i])
			}
		}
	}
}

func TestCPPLastScopeSegment(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"ns::Foo", "Foo"},
		{"Foo<int>", "Foo"},
		{"plain", "plain"},
	}
	for _, tc := range cases {
		if got := cppLastScopeSegment(tc.in); got != tc.want {
			t.Errorf("cppLastScopeSegment(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCPPIsHeaderPath(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"foo.h", true},
		{"foo.hpp", true},
		{"foo.cpp", false},
		{"foo.cc", false},
		{"foo", false},
	}
	for _, tc := range cases {
		if got := cppIsHeaderPath(tc.in); got != tc.want {
			t.Errorf("cppIsHeaderPath(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestCPPParallelDirs(t *testing.T) {
	// include/ <-> src/ mirror under root.
	got := cppParallelDirs("/proj/include/foo", "/proj")
	if len(got) != 1 || got[0] != "/proj/src/foo" {
		t.Errorf("cppParallelDirs include->src = %v, want [/proj/src/foo]", got)
	}
	got = cppParallelDirs("/proj/src/foo", "/proj")
	if len(got) != 1 || got[0] != "/proj/include/foo" {
		t.Errorf("cppParallelDirs src->include = %v, want [/proj/include/foo]", got)
	}
	// No include/src segment -> nothing.
	if got := cppParallelDirs("/proj/lib/foo", "/proj"); got != nil {
		t.Errorf("cppParallelDirs unrelated = %v, want nil", got)
	}
	// dir == root -> nothing.
	if got := cppParallelDirs("/proj", "/proj"); got != nil {
		t.Errorf("cppParallelDirs dir==root = %v, want nil", got)
	}
}

func TestCPPRootIdent(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"obj.method", "obj"},
		{"*ptr", "ptr"},
		{"&ref", "ref"},
		{"arr[0]", "arr"},
		{"ptr->field", "ptr"},
		{"plain", "plain"},
	}
	for _, tc := range cases {
		if got := cppRootIdent(tc.in); got != tc.want {
			t.Errorf("cppRootIdent(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---- Java MyBatis short-name helpers (java_mybatis.go) ----

func TestJavaShortName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"com.foo.Bar", "Bar"},
		{"com.foo.Bar<X>", "Bar"},
		{"Bar[]", "Bar"},
		{"Bar", "Bar"},
		{"  java.util.List<String>  ", "List"},
	}
	for _, tc := range cases {
		if got := javaShortName(tc.in); got != tc.want {
			t.Errorf("javaShortName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---- interprocedural pure helpers (interprocedural.go) ----

func TestIsPlainIdentifier(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"foo", true},
		{"_bar", true},
		{"x1", true},
		{"1x", false}, // leading digit
		{"", false},
		{"_", false},
		{"a.b", false}, // dot is not identifier char
		{"a-b", false},
	}
	for _, tc := range cases {
		if got := isPlainIdentifier(tc.in); got != tc.want {
			t.Errorf("isPlainIdentifier(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestTokenAfter(t *testing.T) {
	// "x" appears at index 0 and again later as a word boundary token.
	s := "a = compute(x)"
	if !tokenAfter(s, "x", 0) {
		t.Error("tokenAfter should find x at/after 0")
	}
	// Require the token to appear at or after a position past its only use.
	if tokenAfter(s, "x", len(s)) {
		t.Error("tokenAfter should not find x past end")
	}
	// Substring-but-not-a-token must not match (word boundary).
	if tokenAfter("maximum", "max", 0) {
		t.Error("tokenAfter should not match substring inside identifier")
	}
	// Missing name -> false.
	if tokenAfter(s, "zzz", 0) {
		t.Error("tokenAfter should not find absent token")
	}
	// Defensive empty inputs.
	if tokenAfter("", "x", 0) || tokenAfter(s, "", 0) || tokenAfter(s, "x", -1) {
		t.Error("tokenAfter should reject empty/negative inputs")
	}
}

// ---- sig_propagation pure helpers (sig_propagation.go) ----

func TestGoAssignTarget(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"v := f(x)", "v"},
		{"v = f(x)", "v"},
		{"a, b := f()", ""}, // multi-target
		{"f(x)", ""},        // bare call
		{"v == f(x)", ""},   // comparison, not assignment
		{"x.y := f()", ""},  // non-identifier LHS
		{"  out := g()  ", "out"},
	}
	for _, tc := range cases {
		if got := goAssignTarget(tc.in); got != tc.want {
			t.Errorf("goAssignTarget(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestStripBalancedOuterParens(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"(p)", "p"},
		{"((p))", "p"},
		{"parse(p)", "parse(p)"}, // call expr, not enclosing
		{"(a) + (b)", "(a) + (b)"},
		{"p", "p"},
		{"(a + b)", "a + b"},
	}
	for _, tc := range cases {
		if got := stripBalancedOuterParens(tc.in); got != tc.want {
			t.Errorf("stripBalancedOuterParens(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---- stored-state sanitizer category gate (crossfile_stored_state_langs.go) ----

func TestJavaSinkLineSanitizerNeutralises(t *testing.T) {
	neutralising := []taint.SinkCategory{
		taint.SnkHTMLOutput, taint.SnkRedirect, taint.SnkTemplate, taint.SnkTrustBoundary,
	}
	for _, c := range neutralising {
		if !javaSinkLineSanitizerNeutralises(c) {
			t.Errorf("javaSinkLineSanitizerNeutralises(%v) = false, want true", c)
		}
	}
	// A category that does NOT get wrap-style same-line neutralisation.
	if javaSinkLineSanitizerNeutralises(taint.SnkSQLQuery) {
		t.Error("SnkSQLQuery must not be neutralised by a same-line wrap")
	}
}

// ---- golang sameFile (resolver_golang_types.go) ----

func TestSameFile(t *testing.T) {
	if !sameFile("/a/b/foo.go", "/a/b/foo.go") {
		t.Error("identical paths should be sameFile")
	}
	if sameFile("/a/b/foo.go", "/a/b/bar.go") {
		t.Error("different basenames should not be sameFile")
	}
	// Same basename, suffix-match fallback.
	if !sameFile("/abs/pkg/foo.go", "pkg/foo.go") {
		t.Error("absolute path ending in the relative one should be sameFile")
	}
}

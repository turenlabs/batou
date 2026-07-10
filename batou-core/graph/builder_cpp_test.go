package graph

import (
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// The C/C++ cross-file call-graph builder (builder_cpp.go, PR #1051) is the
// live path UpdateFileWithAST dispatches to for rules.LangC / rules.LangCPP
// (builder.go case `rules.LangC, rules.LangCPP`). These tests drive it through
// the same real API the php/java builder tests use — parse a source string,
// build the nodes, and assert on the produced CallGraph (qualified names,
// RawCalls, same-file edges). They exercise buildCPPNodes and every helper
// (walkCPPBuilderNodes, cppNamespaceName, cppTypeDeclName, cppFuncDeclName,
// firstCPPNamedDeclarator, emitCPPFunc, registerCPPFunc, walkCPPBodyForCalls,
// cppCallName, cppLastScopeSegment) so a regression in the C++ builder surfaces.

// TestCPPBuilder_NamespaceClassMethods_QualifiedNames: a free function plus a
// class inside a namespace produce a bare-name node and namespace::Class
// qualified method nodes (net.Server.getName). Drives cppNamespaceName,
// cppTypeDeclName, cppFuncDeclName, emitCPPFunc, registerCPPFunc.
func TestCPPBuilder_NamespaceClassMethods_QualifiedNames(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "server.cpp")
	src := `namespace net {
class Server {
public:
    std::string getName(const Request& req) {
        return req.param("id");
    }
    void handle() {
        std::string n = getName(req);
        system(n.c_str());
    }
};
}
void freeFn(int x) {
    helper(x);
}
`
	UpdateFile(cg, filePath, src, rules.LangCPP)

	for _, want := range []string{"net.Server.getName", "net.Server.handle", "freeFn"} {
		if n := cg.GetNode(filePath + ":" + want); n == nil {
			ids := make([]string, 0)
			for _, x := range cg.NodesInFile(filePath) {
				ids = append(ids, x.ID)
			}
			t.Errorf("%q node not emitted; have %v", want, ids)
		}
	}
	// The free function carries the namespace? No — it is outside `net`, so
	// it must NOT be qualified.
	if n := cg.GetNode(filePath + ":net.freeFn"); n != nil {
		t.Errorf("freeFn should be a bare-name node, not qualified: %q", n.ID)
	}
}

// TestCPPBuilder_CallSiteExtraction_RawCalls: a method body that calls a
// same-class method, a free function, and member calls records each call's
// name in RawCalls. Drives walkCPPBodyForCalls + cppCallName for identifier,
// field_expression (n.c_str()) shapes.
func TestCPPBuilder_CallSiteExtraction_RawCalls(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "calls.cpp")
	src := `namespace net {
class Server {
public:
    std::string getName(const Request& req) {
        return req.param("id");
    }
    void handle() {
        std::string n = getName(req);
        system(n.c_str());
    }
};
}
`
	UpdateFile(cg, filePath, src, rules.LangCPP)

	handle := cg.GetNode(filePath + ":net.Server.handle")
	if handle == nil {
		t.Fatal("net.Server.handle node not emitted")
	}
	// `getName(req)` is a bare identifier call; `system(...)` a free call;
	// `n.c_str()` a field_expression call (records the trailing field name).
	for _, want := range []string{"getName", "system", "c_str"} {
		if !containsStr(handle.RawCalls, want) {
			t.Errorf("net.Server.handle RawCalls missing %q (got %v)", want, handle.RawCalls)
		}
	}

	getName := cg.GetNode(filePath + ":net.Server.getName")
	if getName == nil {
		t.Fatal("net.Server.getName node not emitted")
	}
	// `req.param("id")` is a field_expression on a runtime receiver — the
	// builder keeps the trailing field name.
	if !containsStr(getName.RawCalls, "param") {
		t.Errorf("net.Server.getName RawCalls missing 'param' (got %v)", getName.RawCalls)
	}
}

// TestCPPBuilder_SameFileEdge_MemberCall: a same-namespace/class method call
// (`getName(req)` inside `handle`) is wired as a Calls edge during the
// builder's same-file resolution pass (suffix match on `.getName`).
func TestCPPBuilder_SameFileEdge_MemberCall(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "edge.cpp")
	src := `namespace net {
class Server {
public:
    std::string getName(const Request& req) {
        return req.param("id");
    }
    void handle() {
        std::string n = getName(req);
    }
};
}
`
	UpdateFile(cg, filePath, src, rules.LangCPP)

	handle := cg.GetNode(filePath + ":net.Server.handle")
	if handle == nil {
		t.Fatal("net.Server.handle node not emitted")
	}
	wantTarget := filePath + ":net.Server.getName"
	if !containsStr(handle.Calls, wantTarget) {
		t.Errorf("handle.Calls missing %q (got %v) — same-file suffix edge not wired",
			wantTarget, handle.Calls)
	}
}

// TestCPPBuilder_OutOfLineMethod_ScopePromoted: an out-of-line definition
// `void net::Server::reset() {}` maps to the SAME dotted node name as an
// inline method would (net.Server.reset). Drives cppFuncDeclName's
// qualified_identifier branch (scope promotion) + splitCPPScope.
func TestCPPBuilder_OutOfLineMethod_ScopePromoted(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "outofline.cpp")
	src := `void net::Server::reset() {
    cleanup();
}
`
	UpdateFile(cg, filePath, src, rules.LangCPP)

	n := cg.GetNode(filePath + ":net.Server.reset")
	if n == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Fatalf("out-of-line method net.Server.reset not emitted; have %v", ids)
	}
	if !containsStr(n.RawCalls, "cleanup") {
		t.Errorf("reset RawCalls missing 'cleanup' (got %v)", n.RawCalls)
	}
}

// TestCPPBuilder_NestedNamespaces_DottedPrefix: nested namespaces + a struct
// thread through with a dotted prefix (a.b.C.m). Drives the recursive
// namespace/struct descent in walkCPPBuilderNodes and the prefix concatenation.
func TestCPPBuilder_NestedNamespaces_DottedPrefix(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "nested.cpp")
	src := `namespace a {
namespace b {
struct C {
    void m() {
        work();
    }
};
}
}
`
	UpdateFile(cg, filePath, src, rules.LangCPP)

	if n := cg.GetNode(filePath + ":a.b.C.m"); n == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Errorf("a.b.C.m node not emitted; have %v", ids)
	}
}

// TestCPPBuilder_PlainC_FreeFunctions: a plain C file (rules.LangC routes to
// buildCPPNodes too) emits bare-name function nodes and wires a same-file
// edge for an exact-name call. Covers the rules.LangC dispatch branch.
func TestCPPBuilder_PlainC_FreeFunctions(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "math.c")
	src := `int add(int a, int b) {
    return a + b;
}
int caller() {
    return add(1, 2);
}
`
	UpdateFile(cg, filePath, src, rules.LangC)

	for _, want := range []string{"add", "caller"} {
		if n := cg.GetNode(filePath + ":" + want); n == nil {
			ids := make([]string, 0)
			for _, x := range cg.NodesInFile(filePath) {
				ids = append(ids, x.ID)
			}
			t.Errorf("%q node not emitted; have %v", want, ids)
		}
	}
	caller := cg.GetNode(filePath + ":caller")
	if caller == nil {
		t.Fatal("caller node not emitted")
	}
	if !containsStr(caller.RawCalls, "add") {
		t.Errorf("caller RawCalls missing 'add' (got %v)", caller.RawCalls)
	}
	wantTarget := filePath + ":add"
	if !containsStr(caller.Calls, wantTarget) {
		t.Errorf("caller.Calls missing %q (got %v) — exact-name same-file edge not wired",
			wantTarget, caller.Calls)
	}
}

// TestCPPBuilder_PointerReturnDeclarator: a function returning a pointer
// (`char* getbuf()`) still yields a node named after the function — drives
// the pointer_declarator unwrap loop in cppFuncDeclName + firstCPPNamedDeclarator.
func TestCPPBuilder_PointerReturnDeclarator(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "ptr.cpp")
	src := `char* getbuf(int n) {
    return allocate(n);
}
const char& getref() {
    return store();
}
`
	UpdateFile(cg, filePath, src, rules.LangCPP)

	for _, want := range []string{"getbuf", "getref"} {
		if n := cg.GetNode(filePath + ":" + want); n == nil {
			ids := make([]string, 0)
			for _, x := range cg.NodesInFile(filePath) {
				ids = append(ids, x.ID)
			}
			t.Errorf("%q node (pointer/reference return) not emitted; have %v", want, ids)
		}
	}
	gb := cg.GetNode(filePath + ":getbuf")
	if gb != nil && !containsStr(gb.RawCalls, "allocate") {
		t.Errorf("getbuf RawCalls missing 'allocate' (got %v)", gb.RawCalls)
	}
}

// TestCPPBuilder_StructInlineMethod_TypePrefix: a method defined inline in a
// struct (no namespace) gets a Type.method node (Foo.bar). Drives
// cppTypeDeclName for struct_specifier and the type-prefix branch of
// walkCPPBuilderNodes.
func TestCPPBuilder_StructInlineMethod_TypePrefix(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "struct.cpp")
	src := `struct Foo {
    void bar() {
        baz();
    }
};
`
	UpdateFile(cg, filePath, src, rules.LangCPP)

	if n := cg.GetNode(filePath + ":Foo.bar"); n == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Errorf("Foo.bar node not emitted; have %v", ids)
	}
}

// TestCPPBuilder_TemplateFunctionCall: a templated call `foo<int>(x)` records
// the bare name "foo" (template argument tail stripped). Drives cppCallName's
// template_function branch.
func TestCPPBuilder_TemplateFunctionCall(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "tmpl.cpp")
	src := `void run() {
    convert<int>(value);
}
`
	UpdateFile(cg, filePath, src, rules.LangCPP)

	n := cg.GetNode(filePath + ":run")
	if n == nil {
		t.Fatal("run node not emitted")
	}
	if !containsStr(n.RawCalls, "convert") {
		t.Errorf("run RawCalls missing 'convert' for convert<int>() (got %v)", n.RawCalls)
	}
}

// TestCPPBuilder_QualifiedScopeCall_Preserved: a `ns::foo(...)` call keeps the
// `::`-qualified form in RawCalls (the resolver strips the scope later).
// Drives cppCallName's qualified_identifier branch.
func TestCPPBuilder_QualifiedScopeCall_Preserved(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "scoped.cpp")
	src := `void run() {
    util::sanitize(input);
}
`
	UpdateFile(cg, filePath, src, rules.LangCPP)

	n := cg.GetNode(filePath + ":run")
	if n == nil {
		t.Fatal("run node not emitted")
	}
	if !containsStr(n.RawCalls, "util::sanitize") {
		t.Errorf("run RawCalls missing 'util::sanitize' (got %v)", n.RawCalls)
	}
}

// TestCPPBuilder_ExactQualifiedSameFileEdge: a free function in namespace `ns`
// called as `ns::helper()` from another function in the SAME file resolves to
// the qualified node via the exact-qualified branch of buildCPPNodes' same-file
// resolution (callName contains "::", ReplaceAll "::"→".").
func TestCPPBuilder_ExactQualifiedSameFileEdge(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "qedge.cpp")
	src := `namespace ns {
void helper() {}
}
void caller() {
    ns::helper();
}
`
	UpdateFile(cg, filePath, src, rules.LangCPP)

	caller := cg.GetNode(filePath + ":caller")
	if caller == nil {
		t.Fatal("caller node not emitted")
	}
	if !containsStr(caller.RawCalls, "ns::helper") {
		t.Fatalf("caller RawCalls missing 'ns::helper' (got %v)", caller.RawCalls)
	}
	wantTarget := filePath + ":ns.helper"
	if !containsStr(caller.Calls, wantTarget) {
		t.Errorf("caller.Calls missing %q (got %v) — exact-qualified same-file edge not wired",
			wantTarget, caller.Calls)
	}
}

// TestCPPBuilder_AnonymousNamespace_PrefixSkipped: an anonymous namespace
// (`namespace { ... }`) contributes no prefix segment, so functions inside it
// keep their bare name. Drives the cppNamespaceName "" return + the
// nsName == "" branch of walkCPPBuilderNodes.
func TestCPPBuilder_AnonymousNamespace_PrefixSkipped(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "anon.cpp")
	src := `namespace {
void localOnly() {
    work();
}
}
`
	UpdateFile(cg, filePath, src, rules.LangCPP)

	if n := cg.GetNode(filePath + ":localOnly"); n == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Errorf("localOnly node not emitted as bare name (anon namespace); have %v", ids)
	}
}

// TestCPPBuilder_TemplateDeclarationWrapper: a templated free function
// (`template <typename T> T id(T x) {}`) is wrapped in a template_declaration
// node — the walker descends into it without adding a prefix and still emits
// the function node. Drives the template_declaration wrapper case.
func TestCPPBuilder_TemplateDeclarationWrapper(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "templated.cpp")
	src := `template <typename T>
T identity(T x) {
    return transform(x);
}
`
	UpdateFile(cg, filePath, src, rules.LangCPP)

	n := cg.GetNode(filePath + ":identity")
	if n == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Fatalf("identity node (templated free fn) not emitted; have %v", ids)
	}
	if !containsStr(n.RawCalls, "transform") {
		t.Errorf("identity RawCalls missing 'transform' (got %v)", n.RawCalls)
	}
}

// TestCPPBuilder_UnionMethod_TypePrefix: a method inside a union gets a
// Type.method node (U.doThing). Drives the union_specifier case of
// walkCPPBuilderNodes + cppTypeDeclName for a union.
func TestCPPBuilder_UnionMethod_TypePrefix(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "union.cpp")
	src := `union U {
    int doThing() {
        return helper();
    }
};
`
	UpdateFile(cg, filePath, src, rules.LangCPP)

	n := cg.GetNode(filePath + ":U.doThing")
	if n == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Fatalf("U.doThing node (union method) not emitted; have %v", ids)
	}
	if !containsStr(n.RawCalls, "helper") {
		t.Errorf("U.doThing RawCalls missing 'helper' (got %v)", n.RawCalls)
	}
}

// TestCPPBuilder_ArrowMemberCall: `ptr->method(...)` is a field_expression
// callee — the builder records the trailing field name "method". Drives the
// field_expression branch of cppCallName via the `->` arrow form.
func TestCPPBuilder_ArrowMemberCall(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "arrow.cpp")
	src := `void run(Conn* c) {
    c->execute(query);
}
`
	UpdateFile(cg, filePath, src, rules.LangCPP)

	n := cg.GetNode(filePath + ":run")
	if n == nil {
		t.Fatal("run node not emitted")
	}
	if !containsStr(n.RawCalls, "execute") {
		t.Errorf("run RawCalls missing 'execute' for c->execute() (got %v)", n.RawCalls)
	}
}

// TestCPPBuilder_TemplatedClassName_LastSegment: a templated class name
// (`template <class T> class Vec { void push() {} };`) still yields a
// Vec.push node — the class name's last `::`/template segment is extracted.
// Drives cppTypeDeclName's name-cleanup path and cppLastScopeSegment.
func TestCPPBuilder_TemplatedClassName_LastSegment(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "vec.cpp")
	src := `template <class T>
class Vec {
public:
    void push(T v) {
        store(v);
    }
};
`
	UpdateFile(cg, filePath, src, rules.LangCPP)

	if n := cg.GetNode(filePath + ":Vec.push"); n == nil {
		ids := make([]string, 0)
		for _, x := range cg.NodesInFile(filePath) {
			ids = append(ids, x.ID)
		}
		t.Errorf("Vec.push node (templated class) not emitted; have %v", ids)
	}
}

// TestCPPBuilder_ParseFailureFallsThrough: empty content parses to a tree with
// no function definitions; buildCPPNodes returns a non-nil empty slice (so
// UpdateFile keeps the C++ path) and registers zero nodes. Confirms the
// no-panic / empty-file contract, mirroring the PHP builder test.
func TestCPPBuilder_ParseFailureFallsThrough(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "empty.cpp")
	UpdateFile(cg, filePath, "", rules.LangCPP)
	if cnt := len(cg.NodesInFile(filePath)); cnt != 0 {
		t.Errorf("empty file should have 0 nodes, got %d", cnt)
	}
}

// TestCPPBuilder_Idempotent: calling buildCPPNodes directly twice on identical
// content reuses the existing node (content-hash short-circuit in
// registerCPPFunc) and does not double RawCalls. Invokes buildCPPNodes
// directly because UpdateFile's dispatcher falls back to the generic builder
// when the second call returns an empty updatedIDs slice — same quirk the
// PHP/Java builder tests work around.
func TestCPPBuilder_Idempotent(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "idem.cpp")
	src := `void m() {
    helper();
}
`
	buildCPPNodes(cg, filePath, src, rules.LangCPP, nil)
	first := cg.GetNode(filePath + ":m")
	if first == nil {
		t.Fatal("m node not emitted")
	}
	rawCallsLen := len(first.RawCalls)

	buildCPPNodes(cg, filePath, src, rules.LangCPP, nil)
	second := cg.GetNode(filePath + ":m")
	if second == nil {
		t.Fatal("m node missing after second buildCPPNodes")
	}
	if len(second.RawCalls) != rawCallsLen {
		t.Errorf("RawCalls doubled across buildCPPNodes calls: got %d, want %d (%v)",
			len(second.RawCalls), rawCallsLen, second.RawCalls)
	}
}

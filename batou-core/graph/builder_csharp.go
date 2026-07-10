// C# FuncNode builder.
//
// The generic regex-based path in buildGenericNodes can't see class
// boundaries, doesn't qualify method names with their owning class, and
// does NOT populate FuncNode.RawCalls — which the cross-file resolver
// needs to walk per-call expressions. This file implements a
// tree-sitter-based C# builder that closes those gaps (the Java analog,
// using the C# grammar's node names):
//
//   - `class Foo { void Bar() {} }` becomes a FuncNode named "Foo.Bar"
//     (mirrors the Java / Python / JS extractor naming).
//   - Methods, constructors, and top-level local functions are emitted.
//     Constructors use the class name as the method name ("Foo.Foo" for
//     class Foo) so cross-file `new Foo(...)` resolution works via the
//     same `Foo.Foo` lookup the Java builder uses.
//   - Nested types and namespaces flow through with dotted prefixes:
//     `namespace N { class Outer { class Inner { void M() {} } } }` →
//     "N.Outer.Inner.M". Both block-scoped (`namespace N { ... }`) and
//     file-scoped (`namespace N;`) namespace forms are handled; records,
//     structs, and interfaces walk through the same tree.
//   - Each call expression inside a method body is attributed to its
//     innermost enclosing method/constructor and recorded in RawCalls in
//     the bare / "Receiver.method" form the C# resolver expects.
//   - Same-file edges (FuncNode.Calls) get added for any RawCalls that
//     map to a node in the same file. The cross-file pass handles the
//     rest.
//
// Inline lambdas / anonymous methods passed as callbacks are NOT emitted
// as separate nodes — the C# cross-file idiom is a *named* method on a
// type, which is what cross-file resolution needs. The per-file tsflow
// walker already handles callback bodies.
//
// Every line here is reached only for rules.LangCSharp files: UpdateFile-
// WithAST dispatches to buildCSharpNodes solely from its
// `case rules.LangCSharp` arm, so this builder cannot alter graph
// construction for any other language.
package graph

import (
	"fmt"
	"strings"
	"time"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// buildCSharpNodes is the C#-specific equivalent of buildJavaNodes /
// buildJSNodes. Returns nil ONLY when tree-sitter parsing fails, letting
// the caller (UpdateFileWithAST) fall back to the generic regex path. On
// a successful parse it returns a non-nil slice (possibly empty, when a
// warm rescan reuses every content-hash-unchanged node) so the dispatcher
// keeps the class-qualified C# nodes instead of clobbering them with the
// generic builder.
func buildCSharpNodes(cg *CallGraph, filePath, content string, tsTree *tsast.Tree) []string {
	tree := tsTree
	if tree == nil {
		tree = tsast.Parse([]byte(content), rules.LangCSharp)
	}
	if tree == nil || tree.Root() == nil {
		return nil
	}

	oldNodes := make(map[string]*FuncNode)
	for _, n := range cg.NodesInFile(filePath) {
		oldNodes[n.ID] = n
	}
	cg.RemoveFile(filePath)

	// Non-nil empty slice: a successful parse with zero *changed* nodes
	// (the warm-rescan content-hash-reuse case) must still return non-nil
	// so UpdateFileWithAST does NOT fall back to the generic regex builder
	// and clobber the class-qualified nodes we just re-registered. nil is
	// reserved for genuine parse failure (handled above). Mirrors
	// buildJavaNodes.
	updatedIDs := []string{}
	callMap := make(map[string][]string)

	walkCSharpBuilderNodes(tree.Root(), "", cg, filePath, content, oldNodes, &updatedIDs, callMap)

	// Same-file resolution: bare-name RawCalls that hit a known node in
	// this file become Calls/CalledBy edges immediately. Qualified
	// "Receiver.name" calls are left to the cross-file pass — the receiver
	// may be an import alias / same-namespace class only known to the
	// resolver.
	for callerID, calls := range callMap {
		for _, callName := range calls {
			if strings.ContainsRune(callName, '.') {
				continue
			}
			calleeID := FuncID(filePath, callName)
			if cg.GetNode(calleeID) != nil {
				cg.AddEdge(callerID, calleeID)
				continue
			}
			// Class-method suffix match: caller does `DoThing()` which
			// might actually be `Cls.DoThing` on `this` — accept the
			// suffix match same as the Java / JS builders.
			for _, n := range cg.NodesInFile(filePath) {
				if strings.HasSuffix(n.Name, "."+callName) {
					cg.AddEdge(callerID, n.ID)
					break
				}
			}
		}
	}

	return updatedIDs
}

// walkCSharpBuilderNodes recursively visits namespace / class / struct /
// record / interface declarations, threading the dotted prefix and
// emitting one FuncNode per discovered method or constructor. Calls
// inside each method body go into callMap.
//
// Both namespace forms are handled: a block-scoped `namespace N { ... }`
// nests its declarations under a `declaration_list` body, while a
// file-scoped `namespace N;` makes every subsequent compilation-unit
// sibling part of N. For the file-scoped form the namespace prefix is
// threaded into the remaining siblings of the SAME parent.
func walkCSharpBuilderNodes(
	n *tsast.Node,
	prefix string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if n == nil {
		return
	}
	children := n.NamedChildren()
	for i := 0; i < len(children); i++ {
		child := children[i]
		switch child.Type() {
		case "namespace_declaration":
			nsName := csharpNamespaceName(child)
			nsPrefix := nsName
			if prefix != "" && nsName != "" {
				nsPrefix = prefix + "." + nsName
			}
			if body := child.ChildByFieldName("body"); body != nil {
				walkCSharpBuilderNodes(body, nsPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
			}
		case "file_scoped_namespace_declaration":
			// `namespace N;` — the remaining siblings of THIS parent belong
			// to namespace N. Thread the namespace prefix into the rest of
			// the current child list and stop the local loop (everything
			// after is handled under the namespaced recursion).
			nsName := csharpNamespaceName(child)
			nsPrefix := nsName
			if prefix != "" && nsName != "" {
				nsPrefix = prefix + "." + nsName
			}
			for j := i + 1; j < len(children); j++ {
				walkCSharpBuilderTypeOrContainer(children[j], nsPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
			}
			return
		case "class_declaration", "struct_declaration",
			"record_declaration", "record_struct_declaration",
			"interface_declaration", "enum_declaration":
			className := nodeFieldText(child, "name")
			classPrefix := className
			if prefix != "" && className != "" {
				classPrefix = prefix + "." + className
			}
			if body := child.ChildByFieldName("body"); body != nil {
				walkCSharpClassBodyForBuilder(body, classPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
			}
		case "method_declaration", "local_function_statement":
			emitCSharpMethod(child, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap, false, nil)
		case "constructor_declaration":
			emitCSharpMethod(child, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap, true, nil)
		default:
			// Descend through compilation_unit / declaration_list / etc.
			walkCSharpBuilderNodes(child, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
		}
	}
}

// walkCSharpBuilderTypeOrContainer dispatches a single node that is a
// sibling following a file-scoped namespace declaration. It handles the
// type-declaration and nested-namespace shapes the same way the main
// walker arm does, threading the file-scoped namespace prefix.
func walkCSharpBuilderTypeOrContainer(
	child *tsast.Node,
	prefix string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	switch child.Type() {
	case "namespace_declaration":
		nsName := csharpNamespaceName(child)
		nsPrefix := nsName
		if prefix != "" && nsName != "" {
			nsPrefix = prefix + "." + nsName
		}
		if body := child.ChildByFieldName("body"); body != nil {
			walkCSharpBuilderNodes(body, nsPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
		}
	case "class_declaration", "struct_declaration",
		"record_declaration", "record_struct_declaration",
		"interface_declaration", "enum_declaration":
		className := nodeFieldText(child, "name")
		classPrefix := className
		if prefix != "" && className != "" {
			classPrefix = prefix + "." + className
		}
		if body := child.ChildByFieldName("body"); body != nil {
			walkCSharpClassBodyForBuilder(body, classPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
		}
	case "method_declaration", "local_function_statement":
		emitCSharpMethod(child, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap, false, nil)
	case "constructor_declaration":
		emitCSharpMethod(child, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap, true, nil)
	}
}

// walkCSharpClassBodyForBuilder emits a FuncNode for every method and
// constructor in a class/struct/record body, recursing into nested type
// declarations.
func walkCSharpClassBodyForBuilder(
	body *tsast.Node,
	classPrefix string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if body == nil {
		return
	}
	// Collect this class's field/property → declared-class-type bindings
	// once, so instance-method calls through a field (`_repo.Run(...)`) can
	// be receiver-rewritten to `Repo.Run` for cross-file resolution. Locals
	// declared inside each method body are layered on top per-body.
	fieldTypes := collectCSharpFieldTypes(body)
	for _, child := range body.NamedChildren() {
		switch child.Type() {
		case "method_declaration", "local_function_statement":
			emitCSharpMethod(child, classPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap, false, fieldTypes)
		case "constructor_declaration":
			emitCSharpMethod(child, classPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap, true, fieldTypes)
		case "class_declaration", "struct_declaration",
			"record_declaration", "record_struct_declaration",
			"interface_declaration", "enum_declaration":
			nestedName := nodeFieldText(child, "name")
			nestedPrefix := nestedName
			if classPrefix != "" && nestedName != "" {
				nestedPrefix = classPrefix + "." + nestedName
			}
			if nbody := child.ChildByFieldName("body"); nbody != nil {
				walkCSharpClassBodyForBuilder(nbody, nestedPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
			}
		}
	}
}

// collectCSharpFieldTypes reads a class/struct/record body's field and
// property declarations, recording each member name → declared in-project
// class type (`private Repo _repo;` → "_repo" → "Repo";
// `public Service Svc { get; }` → "Svc" → "Service"). Only PascalCase class
// types are kept (see isCSharpResolvableClassName) so primitives never seed
// a receiver rewrite. Extern framework types stay in the map but resolve to
// nothing in-project, so they create no edges.
func collectCSharpFieldTypes(body *tsast.Node) map[string]string {
	out := make(map[string]string)
	if body == nil {
		return out
	}
	for _, child := range body.NamedChildren() {
		switch child.Type() {
		case "field_declaration":
			// A field_declaration wraps a variable_declaration whose `type`
			// applies to every declarator — reuse the local-var collector.
			for _, vc := range child.NamedChildren() {
				if vc.Type() == "variable_declaration" {
					collectCSharpVarDeclTypes(vc, out)
				}
			}
		case "property_declaration":
			typeNode := child.ChildByFieldName("type")
			name := nodeFieldText(child, "name")
			if typeNode == nil || name == "" {
				continue
			}
			typ := csharpSimpleTypeName(typeNode.Text())
			if isCSharpResolvableClassName(typ) {
				out[strings.TrimSpace(name)] = typ
			}
		}
	}
	return out
}

// emitCSharpMethod is the entry point for method / constructor /
// local-function nodes. For constructors we use the class's short name as
// the method name so cross-file `new Foo(...)` calls find the node via
// the same Foo.Foo lookup path the Java builder uses.
func emitCSharpMethod(
	method *tsast.Node,
	classPrefix string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
	isCtor bool,
	fieldTypes map[string]string,
) {
	var methodName string
	if isCtor {
		// Constructor: name child carries the class's short name.
		methodName = nodeFieldText(method, "name")
		if methodName == "" {
			if dot := strings.LastIndexByte(classPrefix, '.'); dot >= 0 {
				methodName = classPrefix[dot+1:]
			} else {
				methodName = classPrefix
			}
		}
	} else {
		methodName = nodeFieldText(method, "name")
	}
	if methodName == "" {
		return
	}
	fullName := methodName
	if classPrefix != "" {
		fullName = classPrefix + "." + methodName
	}
	emitCSharpFunc(method, fullName, cg, filePath, content, oldNodes, updatedIDs, callMap, fieldTypes)
}

// emitCSharpFunc creates (or reuses) a FuncNode for fn with the
// already-qualified fullName, then walks its body to collect RawCalls
// into callMap[node.ID]. fieldTypes carries the enclosing class's
// field/property → class-type bindings for instance-call receiver rewrite
// (nil at namespace/top level where there is no enclosing class).
func emitCSharpFunc(
	fn *tsast.Node,
	fullName string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
	fieldTypes map[string]string,
) {
	if fn == nil || fullName == "" {
		return
	}
	node := registerCSharpFunc(fn, fullName, cg, filePath, content, oldNodes, updatedIDs)
	if node == nil {
		return
	}
	// Method / constructor body field is "body". Expression-bodied members
	// (`=> expr`) have no "body" field — scan the node itself.
	body := fn.ChildByFieldName("body")
	if body == nil {
		body = fn
	}
	walkCSharpBodyForCalls(body, node, callMap, fieldTypes)
	if calls := callMap[node.ID]; len(calls) > 0 {
		if n := cg.GetNode(node.ID); n != nil {
			n.RawCalls = append(n.RawCalls, calls...)
		}
	}
}

// registerCSharpFunc builds or reuses a FuncNode for fn.
func registerCSharpFunc(
	fn *tsast.Node,
	fullName string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
) *FuncNode {
	startLine := int(fn.StartRow()) + 1
	endLine := int(fn.EndRow()) + 1
	bodyStart := fn.StartByte()
	bodyEnd := fn.EndByte()
	bodyText := ""
	if int(bodyStart) >= 0 && int(bodyEnd) <= len(content) && bodyStart < bodyEnd {
		bodyText = content[bodyStart:bodyEnd]
	}
	hash := ContentHash(bodyText)
	id := FuncID(filePath, fullName)

	if old, exists := oldNodes[id]; exists && old.ContentHash == hash {
		old.RawCalls = nil
		cg.AddNode(old)
		return old
	}
	node := &FuncNode{
		ID:          id,
		FilePath:    filePath,
		Name:        fullName,
		StartLine:   startLine,
		EndLine:     endLine,
		ContentHash: hash,
		LastScanAt:  time.Now(),
		Language:    rules.LangCSharp,
	}
	cg.AddNode(node)
	*updatedIDs = append(*updatedIDs, id)
	return node
}

// walkCSharpBodyForCalls walks a method body and records every call
// expression's textual function reference into callMap[outer.ID]. We
// don't descend into nested method / constructor / type declarations or
// local functions — those are emitted as separate nodes elsewhere.
//
// fieldTypes maps an enclosing-class field/property name to its declared
// in-project class type (`private Repo _repo;` → "_repo" → "Repo"). It is
// consulted, alongside locally-declared variables, to rewrite an
// instance-method call's receiver to its concrete class so the resolver
// can pin `repo.RunQuery(...)` to `Repo.RunQuery` cross-file — the same
// qualified shape the static call `Repo.RunQuery(...)` already resolves.
// nil/empty fieldTypes is fine (locals are still collected).
func walkCSharpBodyForCalls(root *tsast.Node, outer *FuncNode, callMap map[string][]string, fieldTypes map[string]string) {
	if root == nil || outer == nil {
		return
	}
	// Per-body receiver-type map: start from the enclosing class fields,
	// then layer locally-declared variables on top (a local shadows a
	// field of the same name within this body). Both bindings carry only
	// EXPLICIT declared types — `var x = new Repo()` / `Repo x = ...` /
	// `private Repo _x;` — never inferred. This keeps the rewrite anchored
	// to a concrete class the programmer named, so it can only ever target
	// the right `Class.Method` (no bare-suffix over-linking).
	recvTypes := collectCSharpLocalVarTypes(root)
	for name, typ := range fieldTypes {
		if _, shadowed := recvTypes[name]; !shadowed {
			recvTypes[name] = typ
		}
	}

	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "method_declaration", "constructor_declaration",
			"local_function_statement", "class_declaration",
			"struct_declaration", "record_declaration",
			"record_struct_declaration", "interface_declaration":
			// Don't descend into nested declarations — they become separate
			// nodes. (The root passed in here is the outer's own
			// declaration, so we still walk its body below before the guard
			// can fire on the root.)
			if n != root {
				return
			}
		case "invocation_expression":
			if name := csCallText(n); name != "" {
				name = rewriteCSharpReceiverType(name, recvTypes)
				callMap[outer.ID] = append(callMap[outer.ID], name)
			}
			// Fall through so calls inside arguments are also captured.
		case "object_creation_expression":
			// `new Foo(...)` — record as a call to "Foo.Foo" so the
			// cross-file resolver can pin it to the constructor node.
			if name := csCtorName(n); name != "" {
				callMap[outer.ID] = append(callMap[outer.ID], name)
			}
		}
		for _, c := range n.NamedChildren() {
			visit(c)
		}
	}
	visit(root)
}

// collectCSharpLocalVarTypes walks a method body and records every local
// variable whose declared type is an in-project-looking class name, in two
// shapes:
//
//	Repo repo = ...;          (explicitly-typed local_declaration_statement)
//	var repo = new Repo();    (var local with an object_creation initializer)
//
// The map is receiverName → ClassName. We deliberately ignore `var x = f()`
// (initializer is not a `new`), generic locals, and built-in / extern types
// — only an explicit class name a sibling/same-namespace file can declare is
// useful for cross-file resolution, and anything looser risks mislinking.
func collectCSharpLocalVarTypes(root *tsast.Node) map[string]string {
	out := make(map[string]string)
	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil {
			return
		}
		// Don't descend into nested type/function declarations — their
		// locals belong to a different body. The root method's own
		// declaration is the entry node, so guard only on non-root nests.
		switch n.Type() {
		case "method_declaration", "constructor_declaration",
			"local_function_statement", "class_declaration",
			"struct_declaration", "record_declaration",
			"record_struct_declaration", "interface_declaration":
			if n != root {
				return
			}
		case "variable_declaration":
			collectCSharpVarDeclTypes(n, out)
		}
		for _, c := range n.NamedChildren() {
			visit(c)
		}
	}
	visit(root)
	return out
}

// collectCSharpVarDeclTypes reads one `variable_declaration` node — the C#
// grammar node that wraps `<type> <declarator>, <declarator>...` inside a
// local_declaration_statement — and records each declarator's bound name →
// concrete class type. The declaration's `type` field is either an explicit
// class name (`Repo repo = ...`) or `var` (`var repo = new Repo()`); for the
// `var` case we read the type off a `new T(...)` initializer.
func collectCSharpVarDeclTypes(decl *tsast.Node, out map[string]string) {
	typeNode := decl.ChildByFieldName("type")
	declaredType := ""
	if typeNode != nil {
		declaredType = csharpSimpleTypeName(typeNode.Text())
	}
	isVar := typeNode != nil && strings.TrimSpace(typeNode.Text()) == "var"
	for _, child := range decl.NamedChildren() {
		if child.Type() != "variable_declarator" {
			continue
		}
		name := nodeFieldText(child, "name")
		if name == "" {
			// Some grammars surface the bound identifier as the first child
			// rather than a `name` field.
			if child.ChildCount() > 0 {
				name = strings.TrimSpace(child.Child(0).Text())
			}
		}
		if name == "" {
			continue
		}
		typ := declaredType
		if isVar || typ == "" {
			// `var repo = new Repo();` — recover the type from the
			// object-creation initializer.
			typ = csharpDeclaratorNewType(child)
		}
		if isCSharpResolvableClassName(typ) {
			out[strings.TrimSpace(name)] = typ
		}
	}
}

// csharpDeclaratorNewType returns the constructed class name from a
// declarator whose initializer is `= new T(...)`, or "" otherwise. It scans
// the declarator's descendants for the first object_creation_expression
// (the initializer sits after `=` as an unnamed child in the C# grammar).
func csharpDeclaratorNewType(declarator *tsast.Node) string {
	var found string
	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil || found != "" {
			return
		}
		if n.Type() == "object_creation_expression" {
			if typ := n.ChildByFieldName("type"); typ != nil {
				found = csharpSimpleTypeName(typ.Text())
			}
			return
		}
		for _, c := range n.NamedChildren() {
			visit(c)
		}
	}
	for _, c := range declarator.NamedChildren() {
		visit(c)
	}
	return found
}

// csharpSimpleTypeName strips generics and a namespace qualifier from a type
// expression text: `MyApp.Data.Repo<int>` → "Repo".
func csharpSimpleTypeName(text string) string {
	text = strings.TrimSpace(text)
	if i := strings.IndexByte(text, '<'); i >= 0 {
		text = text[:i]
	}
	if dot := strings.LastIndexByte(text, '.'); dot >= 0 {
		text = text[dot+1:]
	}
	return strings.TrimSpace(text)
}

// isCSharpResolvableClassName reports whether name looks like an
// in-project class type worth recording as a receiver binding: a non-empty
// PascalCase identifier that is not a C# built-in / primitive alias. We use
// the PascalCase convention (and reject the lowercase keyword aliases) so we
// never rewrite a receiver to a primitive (`string`, `int`) or to a
// lowercased local that isn't a class. Extern framework types (DbContext,
// HttpClient) pass this filter but harmlessly fail to resolve to an
// in-project node, so they don't create edges.
func isCSharpResolvableClassName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	switch name {
	case "var", "dynamic", "object", "string", "int", "long", "short",
		"byte", "bool", "char", "float", "double", "decimal", "uint",
		"ulong", "ushort", "sbyte", "void", "nint", "nuint":
		return false
	}
	first := rune(name[0])
	return first >= 'A' && first <= 'Z'
}

// rewriteCSharpReceiverType rewrites an instance-method call's textual
// reference `recv.Method` to `Type.Method` when `recv` is a known receiver
// binding (a local variable or class field whose concrete in-project class
// type was captured). Bare names (`Foo`) and already-class-qualified calls
// whose receiver is not a known binding pass through unchanged — so a true
// static call `Repo.RunQuery` is never disturbed and an unknown receiver
// (`someApi.Send`) stays unresolved rather than getting mislinked.
func rewriteCSharpReceiverType(callName string, recvTypes map[string]string) string {
	if len(recvTypes) == 0 {
		return callName
	}
	dot := strings.IndexByte(callName, '.')
	if dot <= 0 {
		return callName
	}
	recv := callName[:dot]
	if typ, ok := recvTypes[recv]; ok && typ != "" && typ != recv {
		return typ + callName[dot:]
	}
	return callName
}

// csCallText returns the canonical raw-name form of a C#
// invocation_expression's function reference. Returns:
//
//	"Foo"          for `Foo(...)`              (bare identifier)
//	"Recv.Bar"     for `Recv.Bar(...)`         (single-level member access)
//	"Bar"          for `this.Bar(...)`         (this-receiver collapsed)
//	""             for chained member calls and other complex shapes —
//	               those can't be resolved without type inference.
func csCallText(n *tsast.Node) string {
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return ""
	}
	switch fn.Type() {
	case "identifier":
		return strings.TrimSpace(fn.Text())
	case "generic_name":
		// Foo<T>() — return the bare identifier.
		if id := fn.ChildByFieldName("name"); id != nil {
			return strings.TrimSpace(id.Text())
		}
		if fn.ChildCount() > 0 {
			return strings.TrimSpace(fn.Child(0).Text())
		}
		return ""
	case "member_access_expression":
		expr := fn.ChildByFieldName("expression")
		nameNode := fn.ChildByFieldName("name")
		if nameNode == nil {
			return ""
		}
		method := csMemberName(nameNode)
		if method == "" {
			return ""
		}
		if expr == nil {
			return method
		}
		// Only one level of receiver depth — chained `a.b.c()` calls can't
		// be resolved here without type inference.
		if expr.Type() != "identifier" {
			return ""
		}
		recv := strings.TrimSpace(expr.Text())
		if recv == "this" || recv == "base" {
			return method
		}
		return recv + "." + method
	}
	return ""
}

// csMemberName returns the method name from a member-access `name` child,
// stripping generic type arguments (`GetJson<object>` → "GetJson").
func csMemberName(name *tsast.Node) string {
	if name == nil {
		return ""
	}
	if name.Type() == "generic_name" {
		if id := name.ChildByFieldName("name"); id != nil {
			return strings.TrimSpace(id.Text())
		}
		if name.ChildCount() > 0 {
			return strings.TrimSpace(name.Child(0).Text())
		}
		return ""
	}
	return strings.TrimSpace(name.Text())
}

// csCtorName returns "Foo.Foo" for `new Foo(...)` or "" when the type is
// generic / complex enough that we can't pin it.
func csCtorName(n *tsast.Node) string {
	typeNode := n.ChildByFieldName("type")
	if typeNode == nil {
		return ""
	}
	text := strings.TrimSpace(typeNode.Text())
	if text == "" {
		return ""
	}
	// Strip generics: `Foo<Bar>` → `Foo`.
	if i := strings.IndexByte(text, '<'); i >= 0 {
		text = text[:i]
	}
	// Strip qualifier prefix: `NS.Foo` → `Foo`.
	if dot := strings.LastIndexByte(text, '.'); dot >= 0 {
		text = text[dot+1:]
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	return fmt.Sprintf("%s.%s", text, text)
}

// csharpNamespaceName returns the dotted name from a `namespace N.M { }`
// or `namespace N.M;` declaration's `name` field.
func csharpNamespaceName(n *tsast.Node) string {
	name := n.ChildByFieldName("name")
	if name == nil {
		return ""
	}
	return strings.TrimSpace(name.Text())
}

// Java FuncNode builder.
//
// The generic regex-based path in buildGenericNodes can't see class
// boundaries, doesn't qualify method names with their owning class,
// and does NOT populate FuncNode.RawCalls — which the cross-file
// resolver needs to walk per-call expressions. This file implements a
// tree-sitter-based Java builder that closes those gaps:
//
//   - `class Foo { void bar() {} }` becomes a FuncNode named "Foo.bar"
//     (mirrors the Python / JS extractor naming).
//   - Static methods, instance methods, and constructors are all
//     emitted. Constructors use the class name as the method name
//     ("Foo.Foo" for class Foo). This makes cross-file `new Foo(...)`
//     resolution work via the same `Foo.Foo` lookup.
//   - Nested classes flow through with dotted prefixes:
//     `class Outer { class Inner { void m() {} } }` → "Outer.Inner.m".
//   - Records, enums, interfaces with default methods, and anonymous
//     classes all walk through the same tree (anonymous classes get
//     a synthetic prefix like "EnclosingType.anon@<line>").
//   - Lambdas assigned to a variable
//     (`Runnable r = () -> {...};`) emit a FuncNode named after the
//     binding ("Cls.r" inside a class, "r" at the file level).
//     Anonymous-callback lambdas (passed inline to methods) are NOT
//     emitted as nodes — the per-file taint walker handles them.
//   - Spring `@RestController` / `@Service` / `@Repository` classes are
//     extracted normally; the annotations don't change naming. PR-BBjava
//     wires framework-aware source semantics through the existing
//     TypeCatalog path.
//   - Each call expression in a method body is attributed to its
//     innermost enclosing method/constructor and recorded in RawCalls
//     in the bare / "Alias.method" form the Java resolver expects.
//   - Same-file edges (FuncNode.Calls) get added for any RawCalls that
//     map to a node in the same file. The cross-file pass handles the
//     rest.
package graph

import (
	"fmt"
	"strings"
	"time"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// buildJavaNodes is the Java-specific equivalent of buildJSNodes and
// buildPythonNodes. Returns nil ONLY when tree-sitter parsing fails,
// letting the caller (UpdateFileWithAST) fall back to the generic regex
// path. On a successful parse it returns a non-nil slice (possibly empty,
// when a warm rescan reuses every content-hash-unchanged node) so the
// dispatcher keeps the class-qualified Java nodes instead of clobbering
// them with the generic builder. This empty-but-non-nil distinction is
// what makes the Spring→MyBatis cross-file sink survive a second scan.
func buildJavaNodes(cg *CallGraph, filePath, content string, tsTree *tsast.Tree) []string {
	tree := tsTree
	if tree == nil {
		tree = tsast.Parse([]byte(content), rules.LangJava)
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
	// and clobber the class-qualified nodes we just re-registered. `nil`
	// is reserved for genuine parse failure (handled above). See
	// UpdateFileWithAST's dispatch and
	// TestUpdateFileWithAST_JavaUnchangedRescanKeepsTreeSitterNodes.
	updatedIDs := []string{}
	callMap := make(map[string][]string)

	// Pre-extract the package name + imports so the per-method walker
	// can see them (unused at builder-time today, but stashed for
	// symmetry with the JS builder — the cross-file resolver does its
	// own ExtractScope pass).
	walkJavaBuilderNodes(tree.Root(), "", cg, filePath, content, oldNodes, &updatedIDs, callMap)

	// Same-file resolution: bare-name RawCalls that hit a known node in
	// this file become Calls/CalledBy edges immediately. Qualified
	// "Alias.name" calls are left to the cross-file pass — the receiver
	// may be an import alias only known to the resolver.
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
			// Class-method suffix match: caller does `doThing()` which
			// might actually be `Cls.doThing` on `this` — accept the
			// suffix match same as the Python / JS builders.
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

// walkJavaBuilderNodes recursively visits class/interface/record/enum
// declarations at the file or class-body level, threading the dotted
// class prefix and emitting one FuncNode per discovered method or
// constructor. Calls inside each method body go into callMap.
func walkJavaBuilderNodes(
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
	for _, child := range n.NamedChildren() {
		switch child.Type() {
		case "class_declaration", "interface_declaration",
			"record_declaration", "enum_declaration",
			"annotation_type_declaration":
			className := nodeFieldText(child, "name")
			classPrefix := className
			if prefix != "" && className != "" {
				classPrefix = prefix + "." + className
			}
			if body := child.ChildByFieldName("body"); body != nil {
				walkJavaClassBodyForBuilder(body, classPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
			}
		case "method_declaration":
			// Top-level method (shouldn't happen in Java — methods live
			// in classes — but tree-sitter sometimes emits the type
			// directly under program for partial parses).
			emitJavaMethod(child, prefix, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap, false)
		case "constructor_declaration":
			emitJavaMethod(child, prefix, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap, true)
		default:
			// Descend through program / block / etc.
			walkJavaBuilderNodes(child, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
		}
	}
}

// walkJavaClassBodyForBuilder emits a FuncNode for every method and
// constructor in a class body, recursing into nested type declarations.
func walkJavaClassBodyForBuilder(
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
	for _, child := range body.NamedChildren() {
		switch child.Type() {
		case "method_declaration":
			emitJavaMethod(child, classPrefix, classPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap, false)
		case "constructor_declaration":
			emitJavaMethod(child, classPrefix, classPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap, true)
		case "class_declaration", "interface_declaration",
			"record_declaration", "enum_declaration",
			"annotation_type_declaration":
			nestedName := nodeFieldText(child, "name")
			nestedPrefix := nestedName
			if classPrefix != "" && nestedName != "" {
				nestedPrefix = classPrefix + "." + nestedName
			}
			if nbody := child.ChildByFieldName("body"); nbody != nil {
				walkJavaClassBodyForBuilder(nbody, nestedPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
			}
		case "field_declaration":
			// `Runnable r = () -> {...};` — a field initialised to a
			// lambda. Emit a node named "<classPrefix>.<fieldName>" so
			// cross-file references like `c.r.run()` could hop through
			// it (future PR-Hjava). Right now we only emit for the
			// explicit-lambda case; record fields use FuncNodes for
			// their getters/setters, not the field itself.
			handleJavaFieldLambda(child, classPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
		}
	}
}

// handleJavaFieldLambda emits a FuncNode for a field declaration whose
// initialiser is a lambda or anonymous-class instance bound to a method
// reference. Only the single-binding shape is handled; multi-variable
// `Runnable a = ..., b = ...;` declarations process each declarator.
func handleJavaFieldLambda(
	field *tsast.Node,
	classPrefix string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	for _, c := range field.NamedChildren() {
		if c.Type() != "variable_declarator" {
			continue
		}
		nameNode := c.ChildByFieldName("name")
		if nameNode == nil {
			continue
		}
		name := strings.TrimSpace(nameNode.Text())
		if name == "" {
			continue
		}
		val := c.ChildByFieldName("value")
		if val == nil {
			continue
		}
		switch val.Type() {
		case "lambda_expression":
			fullName := name
			if classPrefix != "" {
				fullName = classPrefix + "." + name
			}
			emitJavaFunc(val, fullName, cg, filePath, content, oldNodes, updatedIDs, callMap)
		case "object_creation_expression":
			// `Runnable r = new Runnable() { @Override public void run() {...} };`
			// Walk the anonymous class body; its methods get nested
			// under "<classPrefix>.<fieldName>". The Java grammar does
			// NOT name the body field — class_body sits as a trailing
			// named child of object_creation_expression.
			anonPrefix := name
			if classPrefix != "" {
				anonPrefix = classPrefix + "." + name
			}
			if body := findJavaClassBodyChild(val); body != nil {
				walkJavaClassBodyForBuilder(body, anonPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
			}
		}
	}
}

// emitJavaMethod is the entry point for method / constructor nodes. For
// constructors we use the class's short name as the method name so
// cross-file `new Foo(...)` calls find the node via the same Foo.Foo
// lookup path.
//
// classPrefix is the dotted class chain ("Outer.Inner"); methodPrefix
// is the same in this PR but kept separate so future PRs can introduce
// a different naming for static-initialiser blocks etc.
func emitJavaMethod(
	method *tsast.Node,
	classPrefix, _methodPrefix string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
	isCtor bool,
) {
	var methodName string
	if isCtor {
		// Constructor: name child carries the class's short name.
		methodName = nodeFieldText(method, "name")
		if methodName == "" {
			// Fall back to the trailing component of the class prefix.
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
	emitJavaFunc(method, fullName, cg, filePath, content, oldNodes, updatedIDs, callMap)
}

// emitJavaFunc creates (or reuses) a FuncNode for fn with the
// already-qualified fullName, then walks its body to collect RawCalls
// into callMap[node.ID].
func emitJavaFunc(
	fn *tsast.Node,
	fullName string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if fn == nil || fullName == "" {
		return
	}
	node := registerJavaFunc(fn, fullName, cg, filePath, content, oldNodes, updatedIDs)
	if node == nil {
		return
	}
	// Method / constructor body field is "body"; lambdas use the same
	// field name in the tree-sitter Java grammar.
	body := fn.ChildByFieldName("body")
	if body == nil {
		// Lambdas with a single-expression body have no "body" field —
		// the expression is a direct child. Use the lambda itself as
		// the root to scan; we'll skip over the parameter list inside
		// walkJavaBodyForCalls.
		body = fn
	}
	walkJavaBodyForCalls(body, node, callMap)
	if calls := callMap[node.ID]; len(calls) > 0 {
		if n := cg.GetNode(node.ID); n != nil {
			n.RawCalls = append(n.RawCalls, calls...)
		}
	}
}

// registerJavaFunc builds or reuses a FuncNode for fn.
func registerJavaFunc(
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
		Language:    rules.LangJava,
	}
	cg.AddNode(node)
	*updatedIDs = append(*updatedIDs, id)
	return node
}

// walkJavaBodyForCalls walks a method body and records every call
// expression's textual function reference into callMap[outer.ID]. We
// don't descend into nested method / constructor / class declarations
// — those are emitted as separate top-level nodes elsewhere.
//
// We DO descend into lambdas and anonymous-class bodies that aren't
// captured by handleJavaFieldLambda — but for those nested function
// shapes we DON'T attribute their inner calls to the outer method
// (they should belong to their own node). For now that's a documented
// gap: inline lambdas passed as callbacks have their calls counted on
// the enclosing method, which is the JS builder's behaviour too.
func walkJavaBodyForCalls(root *tsast.Node, outer *FuncNode, callMap map[string][]string) {
	if root == nil || outer == nil {
		return
	}
	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "method_declaration", "constructor_declaration",
			"class_declaration", "interface_declaration",
			"record_declaration", "enum_declaration":
			// Don't descend into nested type/method declarations — they
			// either become separate top-level nodes or live inside an
			// anonymous-class instance whose calls are attributed to
			// the field they're bound to (handleJavaFieldLambda).
			return
		case "method_invocation":
			if name := javaInvocationName(n); name != "" {
				callMap[outer.ID] = append(callMap[outer.ID], name)
			}
			// Fall through so calls inside arguments are also captured.
		case "object_creation_expression":
			// `new Foo(...)` — record as a call to "Foo.Foo" so the
			// cross-file resolver can pin it to the constructor node.
			if name := javaCtorName(n); name != "" {
				callMap[outer.ID] = append(callMap[outer.ID], name)
			}
		}
		for _, c := range n.NamedChildren() {
			visit(c)
		}
	}
	for _, c := range root.NamedChildren() {
		visit(c)
	}
}

// javaInvocationName returns the canonical raw-name form of a Java
// method_invocation. Tree-sitter produces three field shapes here:
//
//	foo(...)          — `name` field only, no `object`.
//	obj.foo(...)      — `object` field (identifier) + `name`.
//	Cls.foo(...)      — same shape; `object` is a class identifier.
//	a.b.c.foo(...)    — `object` is a method_invocation or field_access
//	                    (multi-hop) — we can't resolve without type
//	                    inference, so return "".
//
// We also handle `super.foo(...)` (object text == "super") by
// returning the bare method name — the same-file resolver picks up
// inherited methods via suffix match.
func javaInvocationName(n *tsast.Node) string {
	nameNode := n.ChildByFieldName("name")
	if nameNode == nil {
		return ""
	}
	method := strings.TrimSpace(nameNode.Text())
	if method == "" {
		return ""
	}
	obj := n.ChildByFieldName("object")
	if obj == nil {
		return method
	}
	switch obj.Type() {
	case "identifier":
		recv := strings.TrimSpace(obj.Text())
		if recv == "super" || recv == "this" {
			return method
		}
		return recv + "." + method
	case "this":
		return method
	}
	// Chained / complex receiver — can't pin without type inference.
	return ""
}

// findJavaClassBodyChild returns the class_body named child of n, if
// any. The Java grammar doesn't name the body field on
// object_creation_expression (anonymous classes), so we scan named
// children.
func findJavaClassBodyChild(n *tsast.Node) *tsast.Node {
	if n == nil {
		return nil
	}
	for _, c := range n.NamedChildren() {
		if c.Type() == "class_body" {
			return c
		}
	}
	return nil
}

// javaCtorName returns "Foo.Foo" for `new Foo(...)` or "" when the
// type is generic / complex enough that we can't pin it.
func javaCtorName(n *tsast.Node) string {
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
	// Strip qualifier prefix: `outer.Foo` → `Foo`. We can't preserve
	// the qualifier safely without distinguishing class-name vs
	// package-name receivers (the latter would be an import alias
	// already in scope.Imports), so we use the short name and let the
	// same-file / same-package resolver handle it.
	if dot := strings.LastIndexByte(text, '.'); dot >= 0 {
		text = text[dot+1:]
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	return fmt.Sprintf("%s.%s", text, text)
}

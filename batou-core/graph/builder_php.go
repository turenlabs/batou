// PHP FuncNode builder.
//
// The generic regex-based path in buildGenericNodes can't see namespace
// boundaries, doesn't qualify method names with their owning class, and
// does NOT populate FuncNode.RawCalls — which the cross-file resolver
// needs to walk per-call expressions. This file implements a tree-sitter
// PHP builder that closes those gaps:
//
//   - `function foo($x) {}` in `namespace App;` becomes "App\foo".
//   - `class Foo { public function bar() {} }` becomes "App\Foo::bar".
//   - Static methods, instance methods, and constructors all emit the
//     same shape. Constructors use the method name `__construct`, so a
//     `new App\Foo(...)` call site records "Foo.__construct" in RawCalls;
//     the resolver routes that to the constructor node.
//   - Abstract methods and interface methods are skipped (they have no
//     body; the cross-file resolver doesn't need to land calls on them).
//   - Closures bound to a variable
//     (`$cb = function() use ($s) { ... };` or `$cb = fn() => ...;`)
//     emit a FuncNode named after the binding ("App\$cb" at file scope,
//     "App\Cls::$cb" inside a class property).
//   - Each call expression in a function body is attributed to its
//     innermost enclosing method/function and recorded in RawCalls in
//     the bare / "Alias::method" / "$obj.method" form the PHP resolver
//     expects.
//   - Same-file edges (FuncNode.Calls) get added for any RawCalls that
//     resolve to a node in the same file. The cross-file pass handles
//     the rest.
package graph

import (
	"fmt"
	"strings"
	"time"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// buildPHPNodes is the PHP-specific equivalent of buildJavaNodes and
// buildPythonNodes. Returns nil when tree-sitter parsing fails so the
// caller (UpdateFileWithAST) falls back to the generic regex path.
func buildPHPNodes(cg *CallGraph, filePath, content string, tsTree *tsast.Tree) []string {
	tree := tsTree
	if tree == nil {
		tree = tsast.Parse([]byte(content), rules.LangPHP)
	}
	if tree == nil || tree.Root() == nil {
		return nil
	}

	oldNodes := make(map[string]*FuncNode)
	for _, n := range cg.NodesInFile(filePath) {
		oldNodes[n.ID] = n
	}
	cg.RemoveFile(filePath)

	var updatedIDs []string
	callMap := make(map[string][]string)

	root := tree.Root()
	ns := extractPHPNamespace(root)
	walkPHPBuilderNodes(root, ns, "", cg, filePath, content, oldNodes, &updatedIDs, callMap)

	// Same-file resolution: bare-name RawCalls that hit a node in this
	// file become Calls/CalledBy edges. Qualified "Alias::method" or
	// "$obj.method" calls are left to the cross-file pass.
	for callerID, calls := range callMap {
		for _, callName := range calls {
			if strings.Contains(callName, "::") || strings.Contains(callName, ".") {
				continue
			}
			calleeID := FuncID(filePath, callName)
			if cg.GetNode(calleeID) != nil {
				cg.AddEdge(callerID, calleeID)
				continue
			}
			// Class-method suffix match: caller does `doThing()` which
			// might actually be a same-class method.
			for _, n := range cg.NodesInFile(filePath) {
				if strings.HasSuffix(n.Name, "::"+callName) ||
					strings.HasSuffix(n.Name, `\`+callName) {
					cg.AddEdge(callerID, n.ID)
					break
				}
			}
		}
	}

	return updatedIDs
}

// walkPHPBuilderNodes recursively walks program-level (and namespace-body)
// children and emits FuncNodes for top-level functions, class methods,
// and closures bound to top-level assignments.
func walkPHPBuilderNodes(
	n *tsast.Node,
	ns, classPrefix string,
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

		case "function_definition":
			fnName := nodeFieldText(child, "name")
			if fnName == "" {
				continue
			}
			fullName := fnName
			if ns != "" {
				fullName = ns + `\` + fnName
			}
			emitPHPFunc(child, fullName, cg, filePath, content, oldNodes, updatedIDs, callMap, nil)

		case "class_declaration", "interface_declaration", "trait_declaration",
			"enum_declaration":
			className := nodeFieldText(child, "name")
			if className == "" {
				continue
			}
			classPath := className
			if ns != "" {
				classPath = ns + `\` + className
			}
			if classPrefix != "" {
				classPath = classPrefix + `\` + className
			}
			if body := child.ChildByFieldName("body"); body != nil {
				walkPHPClassBodyForBuilder(body, classPath, child.Type() == "interface_declaration",
					cg, filePath, content, oldNodes, updatedIDs, callMap)
			}

		case "namespace_definition":
			innerNS := ns
			if name := child.ChildByFieldName("name"); name != nil {
				innerNS = strings.TrimSpace(name.Text())
			}
			if body := child.ChildByFieldName("body"); body != nil {
				walkPHPBuilderNodes(body, innerNS, classPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
			}

		case "expression_statement":
			for _, gc := range child.NamedChildren() {
				switch gc.Type() {
				case "assignment_expression":
					phpHandleBuilderAssignment(gc, ns, cg, filePath, content, oldNodes, updatedIDs, callMap)
				case "scoped_call_expression", "function_call_expression",
					"member_call_expression":
					phpHandleBuilderCallCallbacks(gc, ns, cg, filePath, content, oldNodes, updatedIDs, callMap)
				}
			}

		default:
			walkPHPBuilderNodes(child, ns, classPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
		}
	}
}

// walkPHPClassBodyForBuilder emits a FuncNode for each method in a class
// / interface / trait body, recursing into nested type declarations.
// Skips abstract / interface methods (no body to walk).
func walkPHPClassBodyForBuilder(
	body *tsast.Node,
	classPath string,
	inInterface bool,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if body == nil {
		return
	}
	// Collect this class's typed-property → declared-class-type bindings once,
	// so an instance-method call through a property (`$this->repo->run(...)`)
	// can be receiver-rewritten to `Repo::run` for cross-file resolution.
	// Keyed by the receiver text form the builder records (`$this->repo`).
	// Locals/typed-params declared inside each method body are layered on top
	// per-body. Mirrors collectCSharpFieldTypes.
	fieldTypes := collectPHPFieldTypes(body)
	for _, child := range body.NamedChildren() {
		switch child.Type() {
		case "method_declaration":
			if inInterface || phpMethodIsAbstract(child) {
				continue
			}
			methodName := nodeFieldText(child, "name")
			if methodName == "" {
				continue
			}
			fullName := classPath + "::" + methodName
			emitPHPFunc(child, fullName, cg, filePath, content, oldNodes, updatedIDs, callMap, fieldTypes)
		case "property_declaration":
			// `public Closure $fn = fn() => 1;` — emit nodes for closure-
			// valued properties so cross-file references to them have a
			// landing pad. Property name retains its `$` sigil.
			phpHandleBuilderPropertyClosure(child, classPath, cg, filePath, content, oldNodes, updatedIDs, callMap)
		}
	}
}

// phpHandleBuilderAssignment emits a FuncNode for `$x = fn() => ...;` or
// `$x = function() { ... };` at the file (or namespace) level.
func phpHandleBuilderAssignment(
	n *tsast.Node,
	ns string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	lhs := n.ChildByFieldName("left")
	rhs := n.ChildByFieldName("right")
	if lhs == nil || rhs == nil {
		return
	}
	if lhs.Type() != "variable_name" {
		return
	}
	name := strings.TrimSpace(lhs.Text())
	if name == "" {
		return
	}
	switch rhs.Type() {
	case "anonymous_function_creation_expression", "arrow_function":
		fullName := name
		if ns != "" {
			fullName = ns + `\` + name
		}
		emitPHPFunc(rhs, fullName, cg, filePath, content, oldNodes, updatedIDs, callMap, nil)
	}
}

// phpHandleBuilderPropertyClosure walks a class property_declaration and
// emits a FuncNode when the initialiser is a closure/arrow function.
func phpHandleBuilderPropertyClosure(
	decl *tsast.Node,
	classPath string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	for _, c := range decl.NamedChildren() {
		if c.Type() != "property_element" {
			continue
		}
		var propName string
		var init *tsast.Node
		for _, e := range c.NamedChildren() {
			switch e.Type() {
			case "variable_name":
				propName = strings.TrimSpace(e.Text())
			case "property_initializer":
				for _, ic := range e.NamedChildren() {
					init = ic
					break
				}
			}
		}
		if propName == "" || init == nil {
			continue
		}
		if init.Type() != "anonymous_function_creation_expression" && init.Type() != "arrow_function" {
			continue
		}
		fullName := classPath + "::" + propName
		emitPHPFunc(init, fullName, cg, filePath, content, oldNodes, updatedIDs, callMap, nil)
	}
}

// phpHandleBuilderCallCallbacks detects framework route registrations and
// emits a FuncNode for each inline closure argument. Synthetic names use
// `<callee>@<line>` so each handler gets a unique ID.
func phpHandleBuilderCallCallbacks(
	call *tsast.Node,
	ns string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if call == nil {
		return
	}
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return
	}
	calleeMethod := ""
	switch call.Type() {
	case "scoped_call_expression", "member_call_expression":
		if name := call.ChildByFieldName("name"); name != nil {
			calleeMethod = strings.TrimSpace(name.Text())
		}
	case "function_call_expression":
		if fn := call.ChildByFieldName("function"); fn != nil {
			calleeMethod = strings.TrimSpace(fn.Text())
		}
	}
	for _, arg := range args.NamedChildren() {
		inner := arg
		if arg.Type() == "argument" {
			for _, ic := range arg.NamedChildren() {
				inner = ic
				break
			}
		}
		if inner == nil {
			continue
		}
		switch inner.Type() {
		case "anonymous_function_creation_expression", "arrow_function":
			name := calleeMethod
			if name == "" {
				name = "handler"
			}
			synth := fmt.Sprintf("%s@%d", name, int(inner.StartRow())+1)
			fullName := synth
			if ns != "" {
				fullName = ns + `\` + synth
			}
			emitPHPFunc(inner, fullName, cg, filePath, content, oldNodes, updatedIDs, callMap, nil)
		}
	}
}

// emitPHPFunc creates (or reuses) a FuncNode for fn with the
// already-qualified fullName, then walks its body to populate
// callMap[node.ID] with raw call expressions. fieldTypes carries the
// enclosing class's typed-property → class-type bindings for instance-call
// receiver rewrite (nil at namespace/top/closure level with no enclosing
// class).
func emitPHPFunc(
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
	node := registerPHPFunc(fn, fullName, cg, filePath, content, oldNodes, updatedIDs)
	if node == nil {
		return
	}
	body := fn.ChildByFieldName("body")
	if body == nil {
		// arrow_function uses an expression body; the whole expression
		// hangs directly off `body` for the named-body shape. When the
		// body field is absent (rare), scan the function node itself.
		body = fn
	}
	// The receiver-type map needs the full function node (formal_parameters
	// live as a sibling of body), so pass fn for type collection.
	walkPHPBodyForCalls(body, fn, node, callMap, fieldTypes)
	if calls := callMap[node.ID]; len(calls) > 0 {
		if n := cg.GetNode(node.ID); n != nil {
			n.RawCalls = append(n.RawCalls, calls...)
		}
	}
}

// registerPHPFunc creates (or reuses) a FuncNode for fn.
func registerPHPFunc(
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
		Language:    rules.LangPHP,
	}
	cg.AddNode(node)
	*updatedIDs = append(*updatedIDs, id)
	return node
}

// walkPHPBodyForCalls walks a function body and records every call
// expression's textual function reference into callMap[outer.ID]. We
// don't descend into nested method / function / class declarations
// — those become separate top-level nodes via the outer walk.
//
// fnNode is the enclosing function/method node (so formal_parameters,
// which sit as a sibling of body, can be read for typed-param bindings).
// fieldTypes carries the enclosing class's typed-property → class-type
// bindings (`private Repo $repo;` → "$this->repo" → "Repo"). Together with
// the per-body local + typed-param bindings they let an instance call's
// receiver be rewritten to its concrete class so the resolver can pin
// `$repo->runQuery(...)` to `Repo::runQuery` cross-file — the same
// qualified shape the static call `Repo::runQuery(...)` already resolves.
// nil/empty fieldTypes is fine (locals + typed params are still collected).
func walkPHPBodyForCalls(root, fnNode *tsast.Node, outer *FuncNode, callMap map[string][]string, fieldTypes map[string]string) {
	if root == nil || outer == nil {
		return
	}
	// Per-body receiver-type map: start from the enclosing class typed
	// properties, then layer typed parameters and locally-declared
	// `$x = new Repo()` bindings on top (a local shadows a field of the same
	// receiver text within this body). Every binding carries only an EXPLICIT
	// programmer-named class — `new Repo()` / `Repo $x` / `private Repo $x;`
	// — never inferred, so the rewrite can only ever target the right
	// `Class::method` (no bare-suffix over-linking). Mirrors
	// walkCSharpBodyForCalls.
	recvTypes := map[string]string{}
	for name, typ := range fieldTypes {
		recvTypes[name] = typ
	}
	if fnNode != nil {
		collectPHPParamTypes(fnNode, recvTypes)
	}
	collectPHPLocalVarTypes(root, recvTypes)

	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "function_definition", "method_declaration",
			"class_declaration", "interface_declaration",
			"trait_declaration", "enum_declaration":
			// Don't descend into nested declarations — they get their own
			// nodes elsewhere.
			return
		case "function_call_expression":
			if name := phpFuncCallName(n); name != "" {
				callMap[outer.ID] = append(callMap[outer.ID], name)
			}
		case "scoped_call_expression":
			if name := phpScopedCallName(n); name != "" {
				callMap[outer.ID] = append(callMap[outer.ID], name)
			}
		case "member_call_expression":
			if name := phpMemberCallName(n, recvTypes); name != "" {
				callMap[outer.ID] = append(callMap[outer.ID], name)
			}
		case "object_creation_expression":
			if name := phpCtorCallName(n); name != "" {
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

// collectPHPFieldTypes reads a class body's typed property declarations,
// recording each property's receiver text form → declared class type
// (`private Repo $repo;` → "$this->repo" → "Repo"). Only resolvable class
// names are kept (see isPHPResolvableClassName) so primitives / built-ins
// never seed a receiver rewrite. The receiver text key uses the
// `$this->prop` form because that is exactly what the builder records for a
// `$this->prop->method()` member call. Mirrors collectCSharpFieldTypes.
func collectPHPFieldTypes(body *tsast.Node) map[string]string {
	out := make(map[string]string)
	if body == nil {
		return out
	}
	for _, child := range body.NamedChildren() {
		if child.Type() != "property_declaration" {
			continue
		}
		typ := phpDeclaredTypeName(child)
		if !isPHPResolvableClassName(typ) {
			continue
		}
		for _, e := range child.NamedChildren() {
			if e.Type() != "property_element" {
				continue
			}
			for _, pe := range e.NamedChildren() {
				if pe.Type() == "variable_name" {
					prop := phpStripSigil(strings.TrimSpace(pe.Text()))
					if prop != "" {
						out["$this->"+prop] = typ
					}
				}
			}
		}
	}
	return out
}

// collectPHPParamTypes reads a function/method node's formal_parameters and
// records each typed parameter's receiver text → declared class type
// (`function handle(Repo $r)` → "$r" → "Repo"). Untyped params and
// primitive/built-in types are skipped. Mirrors the typed-decl arm of the
// C# local collector.
func collectPHPParamTypes(fnNode *tsast.Node, out map[string]string) {
	params := fnNode.ChildByFieldName("parameters")
	if params == nil {
		return
	}
	for _, p := range params.NamedChildren() {
		if p.Type() != "simple_parameter" && p.Type() != "property_promotion_parameter" {
			continue
		}
		typ := phpDeclaredTypeName(p)
		if !isPHPResolvableClassName(typ) {
			continue
		}
		for _, c := range p.NamedChildren() {
			if c.Type() == "variable_name" {
				name := strings.TrimSpace(c.Text())
				if name != "" {
					out[name] = typ
				}
			}
		}
	}
}

// collectPHPLocalVarTypes walks a function body and records every local
// whose initializer is `new Repo()`:
//
//	$repo = new Repo();    →   "$repo" → "Repo"
//
// The map is receiverText → ClassName. We deliberately recover ONLY the
// `new T()` shape (not `$x = f()` or DI container fetches) — only an
// explicit constructed class a sibling/same-namespace file can declare is
// useful for cross-file resolution, and anything looser risks mislinking.
// Mirrors collectCSharpLocalVarTypes.
func collectPHPLocalVarTypes(root *tsast.Node, out map[string]string) {
	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "function_definition", "method_declaration",
			"class_declaration", "interface_declaration",
			"trait_declaration", "enum_declaration":
			// Don't descend into nested declarations — their locals belong to
			// a different body. The root is the method body, never one of
			// these node types, so this is a pure nested-scope guard.
			return
		case "assignment_expression":
			lhs := n.ChildByFieldName("left")
			rhs := n.ChildByFieldName("right")
			if lhs != nil && lhs.Type() == "variable_name" && rhs != nil &&
				rhs.Type() == "object_creation_expression" {
				name := strings.TrimSpace(lhs.Text())
				cls := phpObjectCreationClassName(rhs)
				if name != "" && isPHPResolvableClassName(cls) {
					out[name] = cls
				}
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

// phpDeclaredTypeName reads the declared type name off a node that has a
// `named_type` / `optional_type` / `union_type` type child (property,
// parameter). Returns the simple short class name (`App\Repo` → "Repo",
// `?Repo` → "Repo"), or "" when the type is absent, a primitive, or a
// shape we don't pin (unions, intersections).
func phpDeclaredTypeName(n *tsast.Node) string {
	for _, c := range n.NamedChildren() {
		switch c.Type() {
		case "named_type":
			return phpShortName(strings.TrimPrefix(strings.TrimSpace(c.Text()), `\`))
		case "optional_type":
			// `?Repo` — the inner named_type carries the class.
			for _, inner := range c.NamedChildren() {
				if inner.Type() == "named_type" {
					return phpShortName(strings.TrimPrefix(strings.TrimSpace(inner.Text()), `\`))
				}
			}
			// Some grammars surface `?Repo` as a flat optional_type whose text
			// is the type; strip the `?`.
			t := strings.TrimSpace(c.Text())
			t = strings.TrimPrefix(t, "?")
			return phpShortName(strings.TrimPrefix(t, `\`))
		}
	}
	return ""
}

// phpObjectCreationClassName returns the constructed class short name from a
// `new Repo()` / `new App\Repo()` object_creation_expression, or "" when the
// type is dynamic (`new $cls()`) or too complex to pin.
func phpObjectCreationClassName(n *tsast.Node) string {
	for _, c := range n.NamedChildren() {
		switch c.Type() {
		case "name":
			return strings.TrimSpace(c.Text())
		case "qualified_name":
			return phpShortName(strings.TrimPrefix(strings.TrimSpace(c.Text()), `\`))
		}
	}
	return ""
}

// isPHPResolvableClassName reports whether name looks like an in-project
// class type worth recording as a receiver binding: a non-empty identifier
// whose first letter is uppercase (PHP class convention) and that is not a
// PHP primitive / pseudo-type keyword. The uppercase-first gate (and the
// keyword reject-list) ensures we never rewrite a receiver to a primitive
// or a lowercased non-class. Built-in framework classes (PDO, ...) pass
// this filter but harmlessly fail to resolve to an in-project node, so they
// create no edges. Mirrors isCSharpResolvableClassName.
func isPHPResolvableClassName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	switch name {
	// PHP scalar / pseudo types and reserved keywords that can appear in a
	// type position. (Most are lowercase so the case gate already rejects
	// them, but be explicit for the rare uppercased spelling.)
	case "int", "integer", "float", "double", "string", "bool", "boolean",
		"array", "object", "mixed", "void", "null", "callable", "iterable",
		"self", "static", "parent", "never", "false", "true", "Closure":
		return false
	}
	first := rune(name[0])
	return first >= 'A' && first <= 'Z'
}

// phpFuncCallName returns the canonical raw-name form of a
// function_call_expression node. For `foo()` → "foo"; for `\App\foo()`
// → "App\foo"; for `$f()` (variable call) → "".
func phpFuncCallName(n *tsast.Node) string {
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return ""
	}
	switch fn.Type() {
	case "name":
		return strings.TrimSpace(fn.Text())
	case "qualified_name":
		// `App\foo` — strip the leading `\` if any.
		return strings.TrimPrefix(strings.TrimSpace(fn.Text()), `\`)
	}
	return ""
}

// phpScopedCallName returns the canonical raw-name form of a
// scoped_call_expression node ("Cls::method"). The `scope` field holds
// the class name; `name` holds the method name.
func phpScopedCallName(n *tsast.Node) string {
	name := n.ChildByFieldName("name")
	scope := n.ChildByFieldName("scope")
	if name == nil {
		return ""
	}
	method := strings.TrimSpace(name.Text())
	if method == "" {
		return ""
	}
	if scope == nil {
		return method
	}
	cls := strings.TrimSpace(scope.Text())
	cls = strings.TrimPrefix(cls, `\`)
	if cls == "self" || cls == "static" || cls == "parent" {
		return method
	}
	return cls + "::" + method
}

// phpMemberCallName returns the canonical raw-name form of a
// member_call_expression node ("$obj->method"). When the receiver's
// concrete in-project class type was captured (a `$x = new Repo()` local, a
// typed `Repo $x` param, or a `private Repo $repo;` property), the call is
// rewritten to the qualified `Repo::method` form — the SAME shape the
// static call `Repo::method(...)` already resolves cross-file — so the
// resolver pins it exactly instead of returning "no opinion" on the
// lowercase local receiver. Unknown / untyped receivers pass through as
// `$recv.method` unchanged (no mislinking), matching the prior behaviour.
func phpMemberCallName(n *tsast.Node, recvTypes map[string]string) string {
	name := n.ChildByFieldName("name")
	obj := n.ChildByFieldName("object")
	if name == nil {
		return ""
	}
	method := strings.TrimSpace(name.Text())
	if method == "" {
		return ""
	}
	if obj == nil {
		return method
	}
	recv := strings.TrimSpace(obj.Text())
	// `$this->method()` → record as bare method name so same-class lookup
	// via suffix match finds it.
	if recv == "$this" {
		return method
	}
	// Receiver-type recovery: rewrite `$repo->runQuery` → `Repo::runQuery`
	// (and `$this->svc->runQuery` → `Repo::runQuery`) when the receiver's
	// class is a known explicit binding. Type-anchored: only an exact class
	// name a programmer wrote (`new Repo()` / `Repo $x` / `private Repo $x;`)
	// ever rewrites, so the result can only be the right `Class::method`.
	if typ, ok := recvTypes[recv]; ok && typ != "" {
		return typ + "::" + method
	}
	return recv + "." + method
}

// phpCtorCallName returns "Cls.__construct" for `new Cls(...)` or "" when
// the type expression is too complex to pin.
func phpCtorCallName(n *tsast.Node) string {
	for _, c := range n.NamedChildren() {
		switch c.Type() {
		case "name":
			cls := strings.TrimSpace(c.Text())
			if cls == "" {
				return ""
			}
			return cls + ".__construct"
		case "qualified_name":
			cls := strings.TrimPrefix(strings.TrimSpace(c.Text()), `\`)
			if cls == "" {
				return ""
			}
			// Keep the short name for cross-file resolution; the builder
			// has no idea which namespace owns it.
			short := phpShortName(cls)
			return short + ".__construct"
		}
	}
	return ""
}

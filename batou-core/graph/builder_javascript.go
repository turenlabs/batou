// JavaScript / TypeScript FuncNode builder.
//
// The generic regex-based path in buildGenericNodes can't see class
// boundaries, doesn't qualify method names with their owning class,
// and most importantly does NOT populate FuncNode.RawCalls — which the
// cross-file resolver needs to walk per-call expressions. This file
// implements a tree-sitter-based JS/TS builder that fixes all three:
//
//   - Top-level `function foo(...)` becomes a FuncNode named "foo".
//   - `const foo = (...) => {...}` becomes "foo" (arrow / function-expr
//     assigned to const/let/var).
//   - `class Cls { method() {} }` becomes "Cls.method" (mirrors the
//     Python / Java extractor naming).
//   - Object-literal methods (`const ctrl = { foo() {} }`) become
//     "ctrl.foo".
//   - CommonJS exports (`module.exports.handler = function () {}`,
//     `exports.X = ...`) become "handler" / "X" respectively, with
//     `module.exports = function () {}` keyed as "default".
//   - ESM exports inherit the underlying declaration's name; `export
//     default function () {}` is keyed as "default".
//   - Each call expression inside a function body is attributed to its
//     innermost enclosing function and recorded in RawCalls in the
//     "bare" / "alias.name" form the JS resolver expects.
//   - Same-file edges (FuncNode.Calls) get added for any RawCalls that
//     map to a node in the same file. The cross-file pass handles the
//     rest.
//
// Closures (arrow callbacks passed to .map(), .then(), etc.) are NOT
// emitted as separate nodes. JS callsites overwhelmingly use anonymous
// callbacks; emitting a closure node per .map() lambda would explode the
// node count without buying cross-file resolution wins. The per-file
// taint walker (tsflow) already handles callback bodies; the cross-file
// layer only needs *named* function definitions.

package graph

import (
	"fmt"
	"strings"
	"time"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// buildJSNodes is the JS/TS-specific equivalent of buildGoNodes and
// buildPythonNodes. Returns nil when tree-sitter parsing fails, letting
// the caller (UpdateFileWithAST) fall back to the generic regex path.
func buildJSNodes(cg *CallGraph, filePath, content string, lang rules.Language, tsTree *tsast.Tree) []string {
	tree := tsTree
	if tree == nil {
		tree = tsast.ParseFile([]byte(content), lang, filePath)
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

	walkJSNodes(tree.Root(), "", cg, filePath, content, lang, oldNodes, &updatedIDs, callMap)

	// See buildPythonNodes: return a non-nil slice when tree-sitter parsed
	// this file so UpdateFileWithAST does not fall back to the generic
	// regex builder on a fully-unchanged warm rescan (which would clobber
	// the tree-sitter nodes and drop RawCalls / cross-language OutboundRequests
	// + RoutePath).
	if updatedIDs == nil {
		updatedIDs = []string{}
	}

	// Same-file resolution: bare-name RawCalls that hit a known node in
	// this file become Calls/CalledBy edges immediately. Qualified
	// "alias.name" calls are left to the cross-file pass — the receiver
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
			// Class-method suffix match: caller does `do_thing()` which
			// might actually be `Cls.do_thing` on `this` — accept the
			// suffix match same as the Python builder.
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

// walkJSNodes recursively visits class / function / variable-declaration
// nodes at the file or class-body level, threading the dotted class
// prefix and emitting one FuncNode per discovered callable. Calls
// inside each function body are collected into callMap.
func walkJSNodes(
	n *tsast.Node,
	prefix string,
	cg *CallGraph,
	filePath, content string,
	lang rules.Language,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if n == nil {
		return
	}
	for _, child := range n.NamedChildren() {
		switch child.Type() {

		case "function_declaration", "generator_function_declaration":
			name := nodeFieldText(child, "name")
			fullName := name
			if prefix != "" && name != "" {
				fullName = prefix + "." + name
			}
			emitJSFunc(child, fullName, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)

		case "class_declaration":
			className := nodeFieldText(child, "name")
			classPrefix := className
			if prefix != "" && className != "" {
				classPrefix = prefix + "." + className
			}
			if body := child.ChildByFieldName("body"); body != nil {
				walkJSClassBodyForBuilder(body, classPrefix, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
			}

		case "export_statement":
			// ESM exports wrap one of the above shapes.
			if decl := child.ChildByFieldName("declaration"); decl != nil {
				dispatchJSDeclarationForBuilder(decl, prefix, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
				continue
			}
			if val := child.ChildByFieldName("value"); val != nil {
				switch val.Type() {
				case "function_declaration", "function_expression", "function",
					"arrow_function", "generator_function_declaration", "generator_function":
					name := "default"
					if prefix != "" {
						name = prefix + "." + name
					}
					emitJSFunc(val, name, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
				case "class":
					if body := val.ChildByFieldName("body"); body != nil {
						walkJSClassBodyForBuilder(body, "default", cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
					}
				}
			}

		case "lexical_declaration", "variable_declaration":
			for _, gc := range child.NamedChildren() {
				if gc.Type() != "variable_declarator" {
					continue
				}
				bindName := nodeFieldText(gc, "name")
				val := gc.ChildByFieldName("value")
				if bindName == "" || val == nil {
					continue
				}
				fullName := bindName
				if prefix != "" {
					fullName = prefix + "." + bindName
				}
				switch val.Type() {
				case "arrow_function", "function_expression", "function",
					"generator_function":
					emitJSFunc(val, fullName, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
				case "object":
					walkJSObjectLiteralForBuilder(val, fullName, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
				}
			}

		case "expression_statement":
			for _, gc := range child.NamedChildren() {
				switch gc.Type() {
				case "assignment_expression":
					handleJSAssignmentForBuilder(gc, prefix, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
				case "call_expression":
					// PR-BBjs: handler callback inside Express /
					// Fastify / Koa / Hapi registration call. Mirror
					// jsHandleCallExpressionCallback in the extractor.
					handleJSCallExpressionCallbackForBuilder(gc, prefix, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
				}
			}

		default:
			// Descend through containers — program/block/etc.
			walkJSNodes(child, prefix, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
		}
	}
}

// handleJSCallExpressionCallbackForBuilder is the builder-side analog of
// jsHandleCallExpressionCallback in extractor_javascript.go. It emits a
// FuncNode for any function/arrow argument of a top-level
// call_expression so that the cross-file graph has a node whose Name
// matches the FuncSignature the extractor produced for the same source
// range.
func handleJSCallExpressionCallbackForBuilder(
	call *tsast.Node,
	prefix string,
	cg *CallGraph,
	filePath, content string,
	lang rules.Language,
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
	if callee := call.ChildByFieldName("function"); callee != nil {
		if callee.Type() == "member_expression" {
			if prop := callee.ChildByFieldName("property"); prop != nil {
				calleeMethod = strings.TrimSpace(prop.Text())
			}
		}
	}
	// Cross-language routes: capture the route path literal. Express / Fastify / Koa-
	// router register a handler as `app.<verb>("/path", handler)`; the
	// first argument is a string literal naming the served path. We record
	// it on the handler node so the cross-language matcher can link an
	// outbound request to it. Only fires for HTTP-verb method names so we
	// don't treat arbitrary callback-taking calls as routes.
	routePath := ""
	if jsIsRouteVerb(calleeMethod) {
		if first := firstNamedArg(args); first != nil && jsIsStringLiteral(first) {
			routePath = NormalizeRoutePath(jsStringLiteralValue(first))
		}
	}
	for _, arg := range args.NamedChildren() {
		switch arg.Type() {
		case "arrow_function", "function_expression", "function":
			name := nodeFieldText(arg, "name")
			if name == "" {
				if calleeMethod != "" {
					name = fmt.Sprintf("%s@%d", calleeMethod, int(arg.StartRow())+1)
				} else {
					name = fmt.Sprintf("handler@%d", int(arg.StartRow())+1)
				}
			}
			fullName := name
			if prefix != "" {
				fullName = prefix + "." + name
			}
			emitJSFunc(arg, fullName, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
			// Tag the just-emitted handler node with its route path.
			if routePath != "" {
				if n := cg.GetNode(FuncID(filePath, fullName)); n != nil {
					n.RoutePath = routePath
					n.RouteMethod = jsRouteMethod(calleeMethod)
				}
			}
		case "object":
			walkJSObjectLiteralForBuilder(arg, prefix, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
		}
	}
}

// dispatchJSDeclarationForBuilder handles a single declaration node (the
// body of `export <decl>`) at builder time. Mirrors the extractor's
// dispatchJSDeclaration.
func dispatchJSDeclarationForBuilder(
	decl *tsast.Node,
	prefix string,
	cg *CallGraph,
	filePath, content string,
	lang rules.Language,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if decl == nil {
		return
	}
	switch decl.Type() {
	case "function_declaration", "generator_function_declaration":
		name := nodeFieldText(decl, "name")
		fullName := name
		if prefix != "" && name != "" {
			fullName = prefix + "." + name
		}
		emitJSFunc(decl, fullName, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
	case "class_declaration":
		className := nodeFieldText(decl, "name")
		classPrefix := className
		if prefix != "" && className != "" {
			classPrefix = prefix + "." + className
		}
		if body := decl.ChildByFieldName("body"); body != nil {
			walkJSClassBodyForBuilder(body, classPrefix, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
		}
	case "lexical_declaration", "variable_declaration":
		for _, gc := range decl.NamedChildren() {
			if gc.Type() != "variable_declarator" {
				continue
			}
			bindName := nodeFieldText(gc, "name")
			val := gc.ChildByFieldName("value")
			if bindName == "" || val == nil {
				continue
			}
			fullName := bindName
			if prefix != "" {
				fullName = prefix + "." + bindName
			}
			switch val.Type() {
			case "arrow_function", "function_expression", "function",
				"generator_function":
				emitJSFunc(val, fullName, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
			case "object":
				walkJSObjectLiteralForBuilder(val, fullName, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
			}
		}
	}
}

// walkJSClassBodyForBuilder is the builder-time counterpart to the
// extractor's walkJSClassBody: it emits one FuncNode per method, walking
// the method's body to attribute calls.
func walkJSClassBodyForBuilder(
	body *tsast.Node,
	classPrefix string,
	cg *CallGraph,
	filePath, content string,
	lang rules.Language,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if body == nil {
		return
	}
	for _, child := range body.NamedChildren() {
		switch child.Type() {
		case "method_definition":
			name := nodeFieldText(child, "name")
			if name == "" {
				continue
			}
			fullName := name
			if classPrefix != "" {
				fullName = classPrefix + "." + name
			}
			emitJSFunc(child, fullName, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
		case "field_definition":
			fieldName := nodeFieldText(child, "property")
			if fieldName == "" {
				fieldName = nodeFieldText(child, "name")
			}
			val := child.ChildByFieldName("value")
			if fieldName == "" || val == nil {
				continue
			}
			switch val.Type() {
			case "arrow_function", "function_expression", "function":
				fullName := fieldName
				if classPrefix != "" {
					fullName = classPrefix + "." + fieldName
				}
				emitJSFunc(val, fullName, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
			}
		}
	}
}

// walkJSObjectLiteralForBuilder emits FuncNodes for the function-valued
// properties of an object literal bound to `objPrefix`.
func walkJSObjectLiteralForBuilder(
	obj *tsast.Node,
	objPrefix string,
	cg *CallGraph,
	filePath, content string,
	lang rules.Language,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if obj == nil {
		return
	}
	for _, child := range obj.NamedChildren() {
		switch child.Type() {
		case "pair":
			key := child.ChildByFieldName("key")
			val := child.ChildByFieldName("value")
			if key == nil || val == nil {
				continue
			}
			keyName := strings.Trim(strings.TrimSpace(key.Text()), `"'`)
			if keyName == "" {
				continue
			}
			switch val.Type() {
			case "arrow_function", "function_expression", "function",
				"generator_function":
				fullName := keyName
				if objPrefix != "" {
					fullName = objPrefix + "." + keyName
				}
				emitJSFunc(val, fullName, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
			}
		case "method_definition":
			name := nodeFieldText(child, "name")
			if name == "" {
				continue
			}
			fullName := name
			if objPrefix != "" {
				fullName = objPrefix + "." + name
			}
			emitJSFunc(child, fullName, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
		}
	}
}

// handleJSAssignmentForBuilder is the builder-time counterpart to
// jsHandleAssignment in the extractor.
func handleJSAssignmentForBuilder(
	n *tsast.Node,
	prefix string,
	cg *CallGraph,
	filePath, content string,
	lang rules.Language,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	lhs := n.ChildByFieldName("left")
	rhs := n.ChildByFieldName("right")
	if lhs == nil || rhs == nil {
		return
	}
	switch rhs.Type() {
	case "arrow_function", "function_expression", "function",
		"generator_function":
		// ok
	default:
		return
	}
	name := jsCommonJSExportName(lhs)
	if name == "" {
		return
	}
	if prefix != "" {
		name = prefix + "." + name
	}
	emitJSFunc(rhs, name, cg, filePath, content, lang, oldNodes, updatedIDs, callMap)
}

// emitJSFunc creates (or reuses) a FuncNode for fn with the
// already-qualified fullName, then walks its body to collect RawCalls
// into callMap[node.ID].
func emitJSFunc(
	fn *tsast.Node,
	fullName string,
	cg *CallGraph,
	filePath, content string,
	lang rules.Language,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if fn == nil || fullName == "" {
		return
	}
	node := registerJSFunc(fn, fullName, cg, filePath, content, lang, oldNodes, updatedIDs)
	if node == nil {
		return
	}
	body := fn.ChildByFieldName("body")
	if body == nil {
		return
	}
	walkJSBodyForCalls(body, node, callMap)
	if calls := callMap[node.ID]; len(calls) > 0 {
		if n := cg.GetNode(node.ID); n != nil {
			n.RawCalls = append(n.RawCalls, calls...)
		}
	}
}

// registerJSFunc builds or reuses a FuncNode for fn.
func registerJSFunc(
	fn *tsast.Node,
	fullName string,
	cg *CallGraph,
	filePath, content string,
	lang rules.Language,
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
		// Cross-language routes: clear OutboundRequests so the body re-walk repopulates
		// them without duplicating across warm rescans (mirrors the
		// RawCalls reset). RoutePath/RouteMethod are scalars re-set by the
		// registration-site walk, but we leave them intact here so a route
		// is never transiently dropped if the re-walk order differs.
		old.OutboundRequests = nil
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
		Language:    lang,
	}
	cg.AddNode(node)
	*updatedIDs = append(*updatedIDs, id)
	return node
}

// walkJSBodyForCalls walks a function body and records every call
// expression's textual function reference into callMap[outer.ID]. We
// intentionally do NOT descend into nested function definitions — those
// would either be already-emitted top-level/class methods (already
// visited at the module level) or anonymous callbacks (out of scope).
func walkJSBodyForCalls(root *tsast.Node, outer *FuncNode, callMap map[string][]string) {
	if root == nil || outer == nil {
		return
	}
	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "function_declaration", "generator_function_declaration",
			"function_expression", "function", "arrow_function",
			"generator_function", "method_definition", "class_declaration",
			"class":
			// Don't descend into nested function-like nodes — their bodies
			// are either separate top-level nodes or anonymous callbacks
			// whose calls aren't attributed to the outer for the
			// cross-file pass.
			return
		case "call_expression", "new_expression":
			if name := jsCallText(n); name != "" {
				callMap[outer.ID] = append(callMap[outer.ID], name)
			}
			// Cross-language routes: record outbound HTTP request sites (fetch/axios)
			// that target an in-repo path with a tainted argument so the
			// cross-language matcher can link them to the route handler.
			if n.Type() == "call_expression" {
				if ob, ok := jsOutboundRequest(n); ok {
					outer.OutboundRequests = append(outer.OutboundRequests, ob)
				}
			}
			// Fall through to recurse so calls inside arguments
			// (e.g. `foo(bar())`) are also captured. Note we still
			// won't descend into arrow_function arguments because of
			// the guard above; that's intentional.
		}
		for _, c := range n.NamedChildren() {
			visit(c)
		}
	}
	for _, c := range root.NamedChildren() {
		visit(c)
	}
}

// jsCallText returns the canonical raw-name form of a JS call
// expression's function reference. Returns:
//
//	"foo"         for `foo(...)` or `new foo(...)`
//	"alias.bar"   for `alias.bar(...)` (single-level member call)
//	""            for chained member calls and other complex shapes —
//	              those can't be resolved without type inference.
func jsCallText(n *tsast.Node) string {
	fn := n.ChildByFieldName("function")
	if fn == nil {
		// new_expression uses `constructor` instead.
		fn = n.ChildByFieldName("constructor")
	}
	if fn == nil {
		return ""
	}
	switch fn.Type() {
	case "identifier":
		return strings.TrimSpace(fn.Text())
	case "member_expression":
		obj := fn.ChildByFieldName("object")
		prop := fn.ChildByFieldName("property")
		if obj == nil || prop == nil {
			return ""
		}
		// Only one level of receiver depth — chained `a.b.c()` calls
		// can't be resolved here without type inference.
		if obj.Type() != "identifier" {
			return ""
		}
		return strings.TrimSpace(obj.Text()) + "." + strings.TrimSpace(prop.Text())
	}
	return ""
}

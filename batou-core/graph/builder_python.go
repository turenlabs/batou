// Python-specific FuncNode builder.
//
// The generic regex-based path in buildGenericNodes can't see class
// boundaries, doesn't qualify method names with their owning class,
// and most importantly does NOT populate FuncNode.RawCalls — which the
// cross-file resolver needs to walk per-call expressions. This file
// implements a tree-sitter-based Python builder that fixes all three:
//
//   - Top-level `def foo(...)` becomes a FuncNode named "foo".
//   - `class Cls: def bar(self, ...)` becomes "Cls.bar" (mirrors Go's
//     "Receiver.Method" form and the Java extractor's "Outer.method").
//   - Nested classes get dotted prefixes: "Outer.Inner.method".
//   - Lambdas (`lambda x: ...`) become first-class FuncNodes named
//     "<EnclosingName>.lambda@<line>:<col>".
//   - Nested `def name(...)` inside another def becomes
//     "<EnclosingName>.<name>@<line>:<col>".
//   - Each call expression inside a function body is attributed to its
//     innermost enclosing function/closure and recorded in RawCalls as
//     either "bare" or "alias.name" — the form the Python resolver
//     expects.
//   - A synthetic call edge from the enclosing function to each closure
//     it constructs is added so the closure is reachable in the graph.
//   - Same-file edges (FuncNode.Calls) get added for any RawCalls that
//     map to a node in the same file. The cross-file pass handles the
//     rest.
//
// Comprehensions (`[x for x in ...]`) are intentionally NOT emitted as
// closure nodes — they have their own scope in Python but are rarely
// security-relevant. Captured (closed-over) variables from outer scope
// are also out of scope here; precise taint tracking through closure
// captures is the taint engine's job, not the builder's.

package graph

import (
	"fmt"
	"strings"
	"time"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// PythonLambdaSuffixFormat is the suffix appended to an enclosing
// function's name for a `lambda ...` literal. The line:col coordinates
// come from the tree-sitter node so the same source produces the same
// IDs across runs. Mirrors Go's ClosureSuffixFormat shape.
const PythonLambdaSuffixFormat = ".lambda@%d:%d"

// PythonNestedDefSuffixFormat is the suffix appended for a nested `def`
// inside another def. Includes the inner def's name so collisions are
// avoided when multiple nested defs share a parent.
const PythonNestedDefSuffixFormat = ".%s@%d:%d"

// FormatPythonLambdaName returns the canonical
// "<EnclosingName>.lambda@<line>:<col>" name for a Python lambda at the
// given tree-sitter position (1-based line, 0-based column).
func FormatPythonLambdaName(enclosingName string, line, col int) string {
	return enclosingName + fmt.Sprintf(PythonLambdaSuffixFormat, line, col)
}

// FormatPythonNestedDefName returns the canonical
// "<EnclosingName>.<DefName>@<line>:<col>" name for a nested Python
// def at the given tree-sitter position (1-based line, 0-based column).
func FormatPythonNestedDefName(enclosingName, defName string, line, col int) string {
	return enclosingName + fmt.Sprintf(PythonNestedDefSuffixFormat, defName, line, col)
}

// buildPythonNodes is the Python-specific equivalent of buildGoNodes.
// It uses tree-sitter to walk class/function declarations and emits
// FuncNodes with proper class-qualified names and populated RawCalls.
//
// Falls back to nothing-built (returns nil) if tree-sitter parsing
// fails — the caller (UpdateFileWithAST) keeps the previous nodes for
// this file untouched in that case, matching buildGoNodes's behavior.
func buildPythonNodes(cg *CallGraph, filePath, content string, tsTree *tsast.Tree) []string {
	tree := tsTree
	if tree == nil {
		tree = tsast.Parse([]byte(content), rules.LangPython)
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

	walkPythonNodes(tree.Root(), "", cg, filePath, content, oldNodes, &updatedIDs, callMap)

	// Tree-sitter parsed successfully and we (re)built this file's nodes.
	// Ensure a non-nil return even when every node was content-hash-reused
	// (updatedIDs stays nil in that case): UpdateFileWithAST treats a nil
	// result as "builder failed, fall back to the generic regex builder",
	// and that fallback would clobber the tree-sitter nodes — dropping
	// RawCalls and the cross-language RoutePath on every warm rescan. A non-nil
	// empty slice signals "handled, nothing changed".
	if updatedIDs == nil {
		updatedIDs = []string{}
	}

	// Same-file resolution: when a RawCall matches a known node in
	// this file, add the edge. The cross-file pass handles imports.
	for callerID, calls := range callMap {
		for _, callName := range calls {
			// Bare name only — qualified "obj.method" can't be resolved
			// without type inference; leave it for the cross-file pass
			// to interpret as either an import alias or to drop.
			if strings.ContainsRune(callName, '.') {
				continue
			}
			calleeID := FuncID(filePath, callName)
			if cg.GetNode(calleeID) != nil {
				cg.AddEdge(callerID, calleeID)
				continue
			}
			// Class-method match: look for nodes whose Name ends with
			// ".callName" in the same file (e.g. caller does
			// `do_thing()` which is actually `Cls.do_thing` on self).
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

// walkPythonNodes recursively visits class/function nodes, threading
// the dotted class prefix and emitting one FuncNode per def. Calls
// inside each def's body are collected into callMap[<funcID>]. Lambdas
// and nested defs inside def bodies become closure FuncNodes — handled
// by emitPythonFunc, not by this walker.
func walkPythonNodes(
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
		case "class_definition":
			name := pythonNodeName(child)
			childPrefix := name
			if prefix != "" && name != "" {
				childPrefix = prefix + "." + name
			}
			if body := child.ChildByFieldName("body"); body != nil {
				walkPythonNodes(body, childPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
			}
		case "function_definition":
			emitPythonFunc(child, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
		case "decorated_definition":
			// Cross-language routes: capture a Flask/Blueprint route decorator path so
			// the cross-language matcher can link an outbound request to
			// this handler. `@app.route("/x")`, `@app.get("/x")`,
			// `@bp.route("/x", methods=["POST"])` etc.
			routePath, routeMethod := pythonRouteFromDecorators(child)
			// Unwrap decorators around classes and defs.
			for i := 0; i < child.ChildCount(); i++ {
				c := child.Child(i)
				if c == nil {
					continue
				}
				switch c.Type() {
				case "function_definition":
					emitPythonFunc(c, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
					if routePath != "" {
						name := pythonNodeName(c)
						fullName := name
						if prefix != "" && name != "" {
							fullName = prefix + "." + name
						}
						if n := cg.GetNode(FuncID(filePath, fullName)); n != nil {
							n.RoutePath = routePath
							n.RouteMethod = routeMethod
						}
					}
				case "class_definition":
					name := pythonNodeName(c)
					childPrefix := name
					if prefix != "" && name != "" {
						childPrefix = prefix + "." + name
					}
					if body := c.ChildByFieldName("body"); body != nil {
						walkPythonNodes(body, childPrefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
					}
				}
			}
		default:
			// Descend through module / block / expression containers so
			// nested classes and defs at any depth are discovered.
			walkPythonNodes(child, prefix, cg, filePath, content, oldNodes, updatedIDs, callMap)
		}
	}
}

func pythonNodeName(n *tsast.Node) string {
	name := n.ChildByFieldName("name")
	if name == nil {
		return ""
	}
	return strings.TrimSpace(name.Text())
}

func emitPythonFunc(
	fn *tsast.Node,
	prefix string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	name := pythonNodeName(fn)
	if name == "" {
		return
	}
	fullName := name
	if prefix != "" {
		fullName = prefix + "." + name
	}
	node := registerPythonFunc(fn, fullName, cg, filePath, content, oldNodes, updatedIDs)
	if node == nil {
		return
	}

	// Walk the function's body, attributing calls to this node and
	// emitting closure FuncNodes for any lambdas / nested defs found.
	body := fn.ChildByFieldName("body")
	if body == nil {
		return
	}
	walkPythonBody(body, node, cg, filePath, content, oldNodes, updatedIDs, callMap)

	// Persist RawCalls on the node so the cross-file resolver can walk
	// them. (Calls added by AddEdge dedupe; RawCalls is the input the
	// resolver re-reads on every resolution pass.)
	if calls := callMap[node.ID]; len(calls) > 0 {
		if n := cg.GetNode(node.ID); n != nil {
			n.RawCalls = append(n.RawCalls, calls...)
		}
	}
}

// registerPythonFunc creates (or reuses) a FuncNode for fn with the
// already-qualified fullName. Returns the registered node.
func registerPythonFunc(
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
		// Unchanged — re-add the cached node and keep its taint sig.
		// Reset RawCalls before re-collecting so we don't double them.
		old.RawCalls = nil
		// Cross-language routes: keep the persisted RoutePath/RouteMethod on warm reuse.
		// Identical content means identical route metadata, so leaving it
		// is both correct and idempotent. The decorated_definition walk in
		// walkPythonNodes does NOT run on this early-return reuse path
		// (registerPythonFunc returns before emitPythonFunc walks the
		// body), so clearing here would drop the route permanently on a
		// warm rescan.
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
		Language:    rules.LangPython,
	}
	cg.AddNode(node)
	*updatedIDs = append(*updatedIDs, id)
	return node
}

// walkPythonBody walks a function-body subtree with a stack-based
// "innermost enclosing function" tracker. For every encountered:
//
//   - call          → recorded in callMap[<currentTopOfStack>.ID]
//   - lambda        → emit a closure FuncNode named
//     "<currentName>.lambda@<line>:<col>", push it
//     on the stack, recurse into its body, pop.
//   - nested def    → emit a closure FuncNode named
//     "<currentName>.<defName>@<line>:<col>", push,
//     recurse into its body, pop.
//   - class_definition → do not descend (class methods are handled by
//     walkPythonNodes at the module level).
//
// Mirrors the stack pattern in builder.go::walkFuncBody. The synthetic
// edge from the enclosing function to each closure is added so the
// closure node is reachable in the graph; closures are otherwise
// anonymous (their names are line:col anchored).
func walkPythonBody(
	root *tsast.Node,
	outer *FuncNode,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if root == nil || outer == nil {
		return
	}
	var visit func(n *tsast.Node, current *FuncNode)
	visit = func(n *tsast.Node, current *FuncNode) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "class_definition":
			// Class methods inside a function body are emitted by the
			// outer walkPythonNodes pass; we don't descend here.
			return
		case "lambda":
			// Emit a closure FuncNode for this lambda.
			line := int(n.StartRow()) + 1
			col := int(n.StartCol())
			closureName := FormatPythonLambdaName(current.Name, line, col)
			closure := registerPythonClosure(n, closureName, cg, filePath, content, oldNodes, updatedIDs)
			if closure == nil {
				// Registration somehow failed; still recurse so we
				// don't lose deeper-nested calls. Attribute to the
				// outer.
				for _, c := range n.NamedChildren() {
					visit(c, current)
				}
				return
			}
			// Synthetic edge: the enclosing function constructs this
			// closure. Do NOT add to RawCalls — closure names with
			// line:col coords aren't valid call expressions and would
			// just churn UnresolvedCalls in the resolver.
			cg.AddEdge(current.ID, closure.ID)
			// Descend into the lambda body, attributing calls to the
			// closure. Lambda has `parameters` and `body` fields; we
			// only care about body (params don't contain calls in
			// any practical Python).
			if body := n.ChildByFieldName("body"); body != nil {
				visit(body, closure)
			}
			// Flush the closure's collected calls onto its RawCalls.
			flushPythonClosureCalls(cg, closure.ID, callMap)
			return
		case "function_definition":
			// Nested def inside a function body — emit as a closure
			// FuncNode (the top-level walk only handles defs at the
			// module/class level).
			name := pythonNodeName(n)
			line := int(n.StartRow()) + 1
			col := int(n.StartCol())
			if name == "" {
				// Anonymous (shouldn't happen for `def`) — skip.
				return
			}
			closureName := FormatPythonNestedDefName(current.Name, name, line, col)
			closure := registerPythonClosure(n, closureName, cg, filePath, content, oldNodes, updatedIDs)
			if closure == nil {
				if body := n.ChildByFieldName("body"); body != nil {
					visit(body, current)
				}
				return
			}
			cg.AddEdge(current.ID, closure.ID)
			if body := n.ChildByFieldName("body"); body != nil {
				visit(body, closure)
			}
			flushPythonClosureCalls(cg, closure.ID, callMap)
			return
		case "decorated_definition":
			// A nested `@deco def inner(...): ...`. Unwrap and recurse
			// into the function_definition / class_definition child.
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c == nil {
					continue
				}
				switch c.Type() {
				case "function_definition", "class_definition", "lambda":
					visit(c, current)
				}
			}
			return
		case "call":
			if name := pythonCallText(n); name != "" {
				callMap[current.ID] = append(callMap[current.ID], name)
			}
			// Fall through to recurse so calls nested in the arguments
			// (e.g. foo(bar())) are also captured.
		}
		for _, c := range n.NamedChildren() {
			visit(c, current)
		}
	}
	for _, c := range root.NamedChildren() {
		visit(c, outer)
	}
}

// registerPythonClosure creates (or reuses) a FuncNode for a lambda or
// nested-def at fn with the already-qualified closureName. Reuses the
// existing oldNodes cache when the body hash matches.
func registerPythonClosure(
	fn *tsast.Node,
	closureName string,
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
	id := FuncID(filePath, closureName)

	if old, exists := oldNodes[id]; exists && old.ContentHash == hash {
		old.RawCalls = nil
		cg.AddNode(old)
		return old
	}
	node := &FuncNode{
		ID:          id,
		FilePath:    filePath,
		Name:        closureName,
		StartLine:   startLine,
		EndLine:     endLine,
		ContentHash: hash,
		LastScanAt:  time.Now(),
		Language:    rules.LangPython,
	}
	cg.AddNode(node)
	*updatedIDs = append(*updatedIDs, id)
	return node
}

// flushPythonClosureCalls copies the collected raw-call strings for a
// closure onto its FuncNode.RawCalls. Mirrors the same operation done
// for outer functions at the tail of emitPythonFunc.
func flushPythonClosureCalls(cg *CallGraph, closureID string, callMap map[string][]string) {
	calls := callMap[closureID]
	if len(calls) == 0 {
		return
	}
	if node := cg.GetNode(closureID); node != nil {
		node.RawCalls = append(node.RawCalls, calls...)
	}
}

// pythonCallText returns the canonical raw-name form of a Python call
// expression's function reference. Returns:
//
//	"foo"        for `foo(...)`
//	"mod.bar"    for `mod.bar(...)` (single-level attribute)
//	""           for everything else (chained attributes, subscripts,
//	             call-of-a-call) — those can't be resolved without
//	             type inference and we'd just churn UnresolvedCalls.
func pythonCallText(call *tsast.Node) string {
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return ""
	}
	switch fn.Type() {
	case "identifier":
		return strings.TrimSpace(fn.Text())
	case "attribute":
		obj := fn.ChildByFieldName("object")
		attr := fn.ChildByFieldName("attribute")
		if obj == nil || attr == nil {
			return ""
		}
		// Only emit when the object is a simple identifier — chained
		// attributes ("a.b.c") and subscripts can't be resolved here.
		if obj.Type() != "identifier" {
			return ""
		}
		return strings.TrimSpace(obj.Text()) + "." + strings.TrimSpace(attr.Text())
	}
	return ""
}

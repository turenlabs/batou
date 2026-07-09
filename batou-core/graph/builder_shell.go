// Shell FuncNode builder (PR-Gshell).
//
// The generic regex-based path in buildGenericNodes can't see a shell
// script's `name() { ... }` / `function name { ... }` structure and does
// NOT populate FuncNode.RawCalls — which the cross-file resolver needs to
// walk per-call expressions. This file implements a tree-sitter-based
// Shell builder mirroring the Lua / Swift builders:
//
//   - `get_name() { ... }`          → FuncNode "get_name" (bare function).
//   - `function get_name { ... }`   → FuncNode "get_name".
//
// Shell has no method receivers — every function is a top-level bare name
// (like Swift free functions). Within one project a function defined in a
// sourced file (`source lib.sh` / `. lib.sh`) is callable by bare name in
// the sourcing file, so cross-file resolution (resolver_shell.go) keys all
// Shell nodes under one shared module bucket and resolves a call by its
// bare name.
//
// THE SHELL WRINKLE: a function CALL and a sink COMMAND are the SAME
// tree-sitter node type (`command`). `get_name` and `eval` both parse as
// `command` nodes. The builder records EVERY command-word in a function
// body as a RawCall — same-file edges only form when the command-word
// matches a function defined in the file; built-in commands like `eval` /
// `echo` / `curl` simply resolve to nothing and create no edge. The
// cross-file pass forms the rest.
//
// Every line here is reached only for rules.LangShell files:
// UpdateFileWithAST dispatches to buildShellNodes solely from its
// `case rules.LangShell` arm, so this builder cannot alter graph
// construction for any other language.
package graph

import (
	"strings"
	"time"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// buildShellNodes is the Shell-specific equivalent of buildLuaNodes /
// buildSwiftNodes. Returns nil ONLY when tree-sitter parsing fails,
// letting the caller (UpdateFileWithAST) fall back to the generic regex
// path. On a successful parse it returns a non-nil slice (possibly empty,
// on a warm rescan where every content-hash-unchanged node is reused) so
// the dispatcher keeps the shell nodes instead of clobbering them with the
// generic builder.
func buildShellNodes(cg *CallGraph, filePath, content string, tsTree *tsast.Tree) []string {
	tree := tsTree
	if tree == nil {
		tree = tsast.Parse([]byte(content), rules.LangShell)
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
	// and clobber the nodes we just re-registered. `nil` is reserved for
	// genuine parse failure (handled above). Mirrors the Swift / Lua
	// builders.
	updatedIDs := []string{}
	callMap := make(map[string][]string)

	walkShellBuilderNodes(tree.Root(), cg, filePath, content, oldNodes, &updatedIDs, callMap)

	// Synthesise a module-level node for the script's TOP-LEVEL statements
	// (everything outside any `function_definition`). Unlike a Swift/Lua
	// library, a shell script EXECUTES its top-level code directly: the
	// canonical entry-point shape `source ./lib.sh; n=$(get_name); eval
	// "$n"` lives at the top level, not inside a function. Without this node
	// there is no caller FuncNode for that code and the cross-file flow is
	// invisible. We emit it only when there is at least one top-level command
	// call so pure-library files (only `foo(){...}` defs) get no empty node.
	emitShellModuleNode(tree.Root(), cg, filePath, content, oldNodes, &updatedIDs, callMap)

	// Same-file resolution: RawCalls whose command-word hits a known
	// function in this file become Calls/CalledBy edges immediately.
	// Built-in commands (eval, echo, curl, ...) resolve to nothing and
	// create no edge. The cross-file pass handles bare-name resolution
	// across sourced files.
	for callerID, calls := range callMap {
		for _, callName := range calls {
			calleeID := FuncID(filePath, callName)
			if cg.GetNode(calleeID) != nil {
				cg.AddEdge(callerID, calleeID)
			}
		}
	}

	return updatedIDs
}

// shellModuleNodeName is the sentinel name of the synthetic node that holds
// a script's top-level (outside-any-function) statements. The angle brackets
// guarantee it can never collide with a real shell command-word, so a call
// to a function literally named "module" still resolves to that function and
// never to this node.
const shellModuleNodeName = "<module>"

// emitShellModuleNode creates a synthetic FuncNode for the program's
// top-level statements (those NOT inside any `function_definition`) and
// records their command-words as its RawCalls. This is the caller node for
// a script's entry-point code (`source ./lib.sh; n=$(get_name); eval "$n"`),
// which a Swift/Lua-style builder would drop because it only emits nodes for
// `function_definition`s. The node spans the whole file so the cross-file
// walker's body-line scan (extractFuncBody over [StartLine,EndLine]) sees
// the top-level sink lines. Emitted only when at least one top-level command
// call exists, so a pure-library file (only `foo(){...}`) gets no node.
func emitShellModuleNode(
	root *tsast.Node,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if root == nil {
		return
	}
	var topCalls []string
	collectShellTopLevelCalls(root, &topCalls)
	if len(topCalls) == 0 {
		return
	}
	id := FuncID(filePath, shellModuleNodeName)
	// The module node's body is the whole file; its content hash is the full
	// content so a warm rescan reuses it when nothing changed.
	hash := ContentHash(content)
	startLine := int(root.StartRow()) + 1
	endLine := int(root.EndRow()) + 1
	if old, exists := oldNodes[id]; exists && old.ContentHash == hash {
		old.RawCalls = nil
		cg.AddNode(old)
		old.RawCalls = append(old.RawCalls, topCalls...)
		callMap[old.ID] = append(callMap[old.ID], topCalls...)
		return
	}
	node := &FuncNode{
		ID:          id,
		FilePath:    filePath,
		Name:        shellModuleNodeName,
		StartLine:   startLine,
		EndLine:     endLine,
		ContentHash: hash,
		LastScanAt:  time.Now(),
		Language:    rules.LangShell,
	}
	cg.AddNode(node)
	*updatedIDs = append(*updatedIDs, id)
	node.RawCalls = append(node.RawCalls, topCalls...)
	callMap[node.ID] = append(callMap[node.ID], topCalls...)
}

// collectShellTopLevelCalls walks the program tree recording every command-
// word that appears OUTSIDE any `function_definition`. Descends into
// compound shapes (if/for/while/case, subshells, command substitutions,
// pipelines) so a top-level `n=$(get_name)` or `if get_name; then` is
// captured, but stops at a `function_definition` boundary (those bodies
// belong to their own FuncNode).
func collectShellTopLevelCalls(n *tsast.Node, out *[]string) {
	if n == nil {
		return
	}
	for _, child := range n.NamedChildren() {
		if child.Type() == "function_definition" {
			continue // belongs to its own node, not the module node
		}
		if child.Type() == "command" {
			if name := shellCommandWord(child); name != "" {
				*out = append(*out, name)
			}
		}
		collectShellTopLevelCalls(child, out)
	}
}

// walkShellBuilderNodes recursively visits the tree and emits one FuncNode
// per `function_definition`. Shell has no nested-type structure, so there
// is no dotted prefix to thread; every function is a bare top-level name.
// Calls inside each function body go into callMap.
func walkShellBuilderNodes(
	n *tsast.Node,
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
			name := shellFuncDeclName(child)
			if name == "" {
				// Still descend so nested definitions aren't dropped.
				walkShellBuilderNodes(child, cg, filePath, content, oldNodes, updatedIDs, callMap)
				continue
			}
			emitShellFunc(child, name, cg, filePath, content, oldNodes, updatedIDs, callMap)
		default:
			walkShellBuilderNodes(child, cg, filePath, content, oldNodes, updatedIDs, callMap)
		}
	}
}

// shellFuncDeclName returns the declared name of a `function_definition`:
// the `name` field (a `word`).
func shellFuncDeclName(fn *tsast.Node) string {
	if nm := fn.ChildByFieldName("name"); nm != nil {
		return strings.TrimSpace(nm.Text())
	}
	// Fallback: first word child (covers grammar revisions that don't
	// expose the name field).
	for _, c := range fn.NamedChildren() {
		if c.Type() == "word" {
			return strings.TrimSpace(c.Text())
		}
	}
	return ""
}

// emitShellFunc creates (or reuses) a FuncNode for fn, then walks the body
// to collect RawCalls into callMap[node.ID].
func emitShellFunc(
	fn *tsast.Node,
	name string,
	cg *CallGraph,
	filePath, content string,
	oldNodes map[string]*FuncNode,
	updatedIDs *[]string,
	callMap map[string][]string,
) {
	if fn == nil || name == "" {
		return
	}
	node := registerShellFunc(fn, name, cg, filePath, content, oldNodes, updatedIDs)
	if node == nil {
		return
	}
	walkShellBodyForCalls(fn, node, callMap)
	if calls := callMap[node.ID]; len(calls) > 0 {
		if n := cg.GetNode(node.ID); n != nil {
			n.RawCalls = append(n.RawCalls, calls...)
		}
	}
}

// registerShellFunc builds or reuses a FuncNode for fn.
func registerShellFunc(
	fn *tsast.Node,
	name string,
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
	id := FuncID(filePath, name)

	if old, exists := oldNodes[id]; exists && old.ContentHash == hash {
		old.RawCalls = nil
		cg.AddNode(old)
		return old
	}
	node := &FuncNode{
		ID:          id,
		FilePath:    filePath,
		Name:        name,
		StartLine:   startLine,
		EndLine:     endLine,
		ContentHash: hash,
		LastScanAt:  time.Now(),
		Language:    rules.LangShell,
	}
	cg.AddNode(node)
	*updatedIDs = append(*updatedIDs, id)
	return node
}

// walkShellBodyForCalls walks a function body and records every `command`
// node's command-word into callMap[outer.ID]. We don't descend into nested
// `function_definition` nodes — those become separate top-level nodes.
//
// Every command word is recorded (function call or built-in); only words
// matching a defined function form an edge during resolution.
func walkShellBodyForCalls(root *tsast.Node, outer *FuncNode, callMap map[string][]string) {
	if root == nil || outer == nil {
		return
	}
	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "function_definition":
			// Don't descend into nested definitions — they become separate
			// top-level nodes. (The root passed in here is the outer's own
			// definition, so we still walk its body below via NamedChildren
			// before this guard can fire on the root.)
			if n != root {
				return
			}
		case "command":
			if name := shellCommandWord(n); name != "" {
				callMap[outer.ID] = append(callMap[outer.ID], name)
			}
			// Fall through so calls nested in command substitutions
			// (`x=$(get_name)`) are also captured.
		}
		for _, c := range n.NamedChildren() {
			visit(c)
		}
	}
	visit(root)
}

// shellCommandWord returns the bare command word of a `command` node:
// `get_name` for `get_name arg`, `eval` for `eval "$x"`. Returns "" for
// shapes without a recognisable command name (assignments, expansions).
func shellCommandWord(n *tsast.Node) string {
	cn := n.ChildByFieldName("name")
	if cn == nil {
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.Type() == "command_name" {
				cn = c
				break
			}
		}
	}
	if cn == nil {
		return ""
	}
	if cn.Type() == "command_name" {
		for i := 0; i < cn.ChildCount(); i++ {
			c := cn.Child(i)
			if c.Type() == "word" {
				return strings.TrimSpace(c.Text())
			}
		}
		return strings.TrimSpace(cn.Text())
	}
	return strings.TrimSpace(cn.Text())
}

// Per-language extractor: Ruby.
//
// Walks a tree-sitter Ruby tree and yields FuncSignatures for every
// top-level `def`, instance method, singleton (class) method, module
// method, Sinatra/Roda DSL route block, and `define_method` call.
//
// Naming convention (mirrors extractor_java.go's "Outer.method"):
//
//   - Top-level `def foo(...)`               → "foo"
//   - `class Cls; def bar(...); end`         → "Cls.bar"
//   - `class Cls; def self.baz(...); end`    → "Cls.baz"
//   - `module Foo; def self.bar(...); end`   → "Foo.bar"
//   - Nested types                           → "Outer.Inner.method"
//   - Sinatra/Roda DSL `get '/x' do ... end` → "<prefix>get@<line>" where
//     <prefix> is the enclosing class/module path (often empty at the
//     file level). The block body is what carries the request taint.
//   - `define_method(:dyn) do ... end`       → "<prefix>.dyn" (treated
//     like an explicit `def dyn(...)`) so cross-file resolution finds
//     it by its declared name.
//
// Scope of this initial implementation:
//   - Top-level + class + singleton + module methods.
//   - Sinatra DSL HTTP-verb blocks (get/post/put/patch/delete/options/head/link/unlink).
//   - `define_method(:name) do ... end` becomes a regular FuncNode.
//   - `namespace :x do ... end` recurses into its block body so routes
//     declared inside still emit nodes.
//
// Param shape:
//   - `method_parameters` named children: identifier, optional_parameter,
//     keyword_parameter, splat_parameter, hash_splat_parameter, block_parameter.
//   - Sinatra block params come from the `do_block`'s `block_parameters`
//     (e.g. `get '/x' do |arg| ...`).
//
// Type catalog:
//   - Ruby is dynamically typed; type annotations exist only in RBS
//     sidecar files which are out of scope here. We don't populate
//     CanonicalType, IsSourceType, IsSinkType — that work is the
//     tsflow taint engine's job. The extractor's role for Ruby is to
//     produce stable FuncSignatures with Name + line range so the
//     cross-file resolver can pin call sites to their declarations.
//
// Known limitations (documented for follow-up):
//   - `respond_to`, `respond_to_missing?`, method_missing dispatch are
//     not modeled — those are inherently dynamic.
//   - Rails ActiveSupport `delegate :foo, to: :bar` is not expanded.
//   - Refinements (`refine X do ...`) are not tracked.
package graph

import (
	"fmt"
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// rubyExtractor implements TypeExtractor for Ruby.
type rubyExtractor struct{}

func (rubyExtractor) Language() rules.Language { return rules.LangRuby }

func (rubyExtractor) ExtractFunctions(ctx *ExtractContext) []FuncSignature {
	tree := rubyTree(ctx)
	if tree == nil {
		return nil
	}
	var sigs []FuncSignature
	walkRubyTypes(tree.Root(), "", &sigs)
	return sigs
}

// ResolveVarType is a no-op for Ruby — dynamic typing means we can't
// give per-call-site argument types without runtime info.
func (rubyExtractor) ResolveVarType(ctx *ExtractContext, varName string, line int) string {
	return ""
}

func rubyTree(ctx *ExtractContext) *ast.Tree {
	if ctx == nil {
		return nil
	}
	if t, ok := ctx.TSTree.(*ast.Tree); ok && t != nil {
		return t
	}
	if ctx.Content == nil {
		return nil
	}
	return ast.Parse(ctx.Content, rules.LangRuby)
}

// rubyDSLRouteVerbs is the set of bare identifiers we treat as Sinatra/Roda
// HTTP-verb DSL handlers. When a top-level (or class/module-level) `call`
// node has one of these as its method name AND has a `do_block`, we emit
// a synthetic FuncSignature for the block body. This is the dominant
// handler shape in Sinatra/Roda apps and represents the actual code path
// that handles user input.
var rubyDSLRouteVerbs = map[string]bool{
	"get":     true,
	"post":    true,
	"put":     true,
	"patch":   true,
	"delete":  true,
	"options": true,
	"head":    true,
	"link":    true,
	"unlink":  true,
}

// rubyDSLNamespaceVerbs is the set of identifiers we recurse INTO without
// emitting a synthetic node — Rails-style routing DSL containers
// (`namespace :api do ... end`, `scope ... do ... end`).
var rubyDSLNamespaceVerbs = map[string]bool{
	"namespace": true,
	"scope":     true,
	"resources": true,
	"resource":  true,
}

// walkRubyTypes recurses into class/module declarations and the top
// level, threading the enclosing class/module path as a dot-separated
// prefix ("" at top-level → "Foo" → "Foo.Inner"). For every `method`,
// `singleton_method`, DSL route, or `define_method` call encountered,
// it appends a FuncSignature.
func walkRubyTypes(n *ast.Node, prefix string, sigs *[]FuncSignature) {
	if n == nil {
		return
	}
	for _, child := range n.NamedChildren() {
		switch child.Type() {
		case "class", "module":
			name := rubyTypeName(child)
			childPrefix := name
			if prefix != "" && name != "" {
				childPrefix = prefix + "." + name
			}
			if body := child.ChildByFieldName("body"); body != nil {
				walkRubyTypes(body, childPrefix, sigs)
			}
		case "method":
			if sig := extractRubyMethod(child, prefix, false); sig != nil {
				*sigs = append(*sigs, *sig)
			}
		case "singleton_method":
			// `def self.bar(...)` inside a class/module — qualifies as
			// "<prefix>.bar" the same way an instance method does.
			if sig := extractRubyMethod(child, prefix, true); sig != nil {
				*sigs = append(*sigs, *sig)
			}
		case "call":
			handleRubyDSLCall(child, prefix, sigs)
		case "body_statement", "program":
			// Container nodes — descend.
			walkRubyTypes(child, prefix, sigs)
		default:
			// Other containers (begin, if, etc.) — descend so we don't
			// miss methods declared inside conditional blocks.
			walkRubyTypes(child, prefix, sigs)
		}
	}
}

// rubyTypeName returns the class/module name. The `name` field is either
// a `constant` (e.g. `Foo`) or a `scope_resolution` (`Foo::Bar`). For
// scope_resolution we keep the dotted form so nested-class naming stays
// disambiguated.
func rubyTypeName(n *ast.Node) string {
	name := n.ChildByFieldName("name")
	if name == nil {
		return ""
	}
	text := strings.TrimSpace(name.Text())
	// Normalise `Foo::Bar` → `Foo.Bar` so it matches our dotted-prefix
	// convention. Real code rarely declares nested types this way, but
	// it's cheap to handle.
	text = strings.ReplaceAll(text, "::", ".")
	return text
}

// extractRubyMethod builds a FuncSignature for a `method` or
// `singleton_method` node. prefix is the enclosing class/module path
// ("" at top-level); methodPrefix is the same in this PR. isSingleton
// is true for `def self.x` and `def Foo.x` shapes — they qualify under
// the enclosing type the same way instance methods do, so the naming
// doesn't differ here.
func extractRubyMethod(n *ast.Node, prefix string, isSingleton bool) *FuncSignature {
	nameNode := n.ChildByFieldName("name")
	if nameNode == nil {
		return nil
	}
	name := strings.TrimSpace(nameNode.Text())
	if name == "" {
		return nil
	}
	fullName := name
	if prefix != "" {
		fullName = prefix + "." + name
	}
	sig := &FuncSignature{
		Name:      fullName,
		StartLine: int(n.StartRow()) + 1,
		EndLine:   int(n.EndRow()) + 1,
	}
	if params := n.ChildByFieldName("parameters"); params != nil {
		sig.Params = extractRubyParams(params)
	}
	return sig
}

// extractRubyParams walks a `method_parameters` (or `block_parameters`)
// node and emits one ParamTaint per positional / keyword / splat /
// block parameter, in source order.
func extractRubyParams(params *ast.Node) []ParamTaint {
	if params == nil {
		return nil
	}
	var out []ParamTaint
	idx := 0
	for _, c := range params.NamedChildren() {
		var name string
		switch c.Type() {
		case "identifier":
			name = strings.TrimSpace(c.Text())
		case "optional_parameter", "keyword_parameter",
			"splat_parameter", "hash_splat_parameter",
			"block_parameter":
			if nn := c.ChildByFieldName("name"); nn != nil {
				name = strings.TrimSpace(nn.Text())
			}
		default:
			// Unknown parameter shape — skip but increment idx so
			// downstream positional indexing stays accurate.
		}
		out = append(out, ParamTaint{
			Index: idx,
			Name:  name,
		})
		idx++
	}
	return out
}

// handleRubyDSLCall inspects a top-level / class-body `call` node and
// emits a FuncSignature when it's one of:
//
//	get '/x' do ... end       — Sinatra/Roda HTTP-verb handler
//	post '/x' do ... end
//	...
//	define_method(:name) do ... end
//
// `namespace :x do ... end` and similar grouping DSLs recurse into
// their block body so handlers declared inside them are also extracted.
// Everything else is a no-op (random method calls at module scope are
// not handler declarations).
func handleRubyDSLCall(n *ast.Node, prefix string, sigs *[]FuncSignature) {
	methodNode := n.ChildByFieldName("method")
	if methodNode == nil {
		return
	}
	// Only bare-name calls; receiver-style DSL calls (`SomeRouter.get`)
	// are uncommon and out of scope.
	if recv := n.ChildByFieldName("receiver"); recv != nil {
		return
	}
	methodName := strings.TrimSpace(methodNode.Text())
	if methodName == "" {
		return
	}

	block := n.ChildByFieldName("block")
	if block == nil {
		return
	}

	switch {
	case methodName == "define_method":
		emitRubyDefineMethod(n, block, prefix, sigs)
	case rubyDSLRouteVerbs[methodName]:
		emitRubyRouteBlock(n, block, methodName, prefix, sigs)
	case rubyDSLNamespaceVerbs[methodName]:
		// Recurse into the namespace block body without emitting a node
		// for the namespace itself.
		if body := block.ChildByFieldName("body"); body != nil {
			walkRubyTypes(body, prefix, sigs)
		}
	}
}

// emitRubyDefineMethod handles `define_method(:name) do |args| ... end`.
// The first argument is the method name (a `simple_symbol` like `:foo`
// or a string literal). We strip the leading `:` to get the bare name
// and emit a FuncSignature qualified by the enclosing prefix — making
// it indistinguishable from a regular `def name`.
func emitRubyDefineMethod(n, block *ast.Node, prefix string, sigs *[]FuncSignature) {
	args := n.ChildByFieldName("arguments")
	if args == nil {
		return
	}
	name := ""
	for _, a := range args.NamedChildren() {
		switch a.Type() {
		case "simple_symbol":
			name = strings.TrimPrefix(strings.TrimSpace(a.Text()), ":")
		case "string":
			// `define_method('foo') do ... end`
			name = rubyStripStringLiteral(a)
		}
		if name != "" {
			break
		}
	}
	if name == "" {
		return
	}
	fullName := name
	if prefix != "" {
		fullName = prefix + "." + name
	}
	sig := FuncSignature{
		Name:      fullName,
		StartLine: int(n.StartRow()) + 1,
		EndLine:   int(n.EndRow()) + 1,
	}
	if params := block.ChildByFieldName("parameters"); params != nil {
		sig.Params = extractRubyParams(params)
	}
	*sigs = append(*sigs, sig)
}

// emitRubyRouteBlock handles Sinatra/Roda HTTP-verb DSL routes:
//
//	get '/users/:id' do
//	  params[:id]
//	end
//
// The block body is what carries the request taint, so we emit a
// FuncSignature anchored to the block's coordinates with a synthetic
// name "<prefix>.<verb>@<line>". Without this, Sinatra apps would have
// no FuncNode for their request handlers and cross-file resolution
// couldn't reason about them.
func emitRubyRouteBlock(n, block *ast.Node, verb, prefix string, sigs *[]FuncSignature) {
	// Synthetic name: <prefix>.<verb>@<line> at top level → "get@10",
	// nested in a class/module → "Outer.get@10". The line:col anchor
	// keeps multiple routes with the same verb distinct.
	line := int(n.StartRow()) + 1
	col := int(n.StartCol())
	name := fmt.Sprintf("%s@%d:%d", verb, line, col)
	fullName := name
	if prefix != "" {
		fullName = prefix + "." + name
	}
	sig := FuncSignature{
		Name:      fullName,
		StartLine: int(n.StartRow()) + 1,
		EndLine:   int(n.EndRow()) + 1,
		IsClosure: true,
	}
	if params := block.ChildByFieldName("parameters"); params != nil {
		sig.Params = extractRubyParams(params)
	}
	*sigs = append(*sigs, sig)
}

// rubyStripStringLiteral returns the inner text of a `string` node. The
// tree-sitter Ruby grammar wraps the body in a `string_content` child;
// returns "" if the node isn't a single-piece string (interpolation,
// concatenation, etc.).
func rubyStripStringLiteral(s *ast.Node) string {
	if s == nil {
		return ""
	}
	for _, c := range s.NamedChildren() {
		if c.Type() == "string_content" {
			return strings.TrimSpace(c.Text())
		}
	}
	return ""
}

func init() {
	RegisterExtractor(rubyExtractor{})
}

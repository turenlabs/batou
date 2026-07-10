// Per-language extractor: JavaScript / TypeScript.
//
// Walks a tree-sitter JavaScript or TypeScript tree and yields a
// FuncSignature for every callable declaration the cross-file graph layer
// needs to track. Coverage targets the dominant shapes you'll find in
// real-world Node and TS codebases:
//
//   - Top-level function declarations: `function foo(req, res) { ... }`
//   - Async / generator variants:      `async function foo(...) { ... }`
//   - Arrow assigned to const/let/var: `const foo = (req, res) => { ... }`
//     (and the async variant)
//   - Function expressions assigned to a binding:
//     `const foo = function (req) { ... }`
//   - Class methods (including async / static / accessors).
//   - Object-literal methods (`{ foo: function () { ... } }` and the
//     shorthand `{ foo() {} }`).
//   - ESM exports: `export function foo() {}`, `export const foo = ...`,
//     `export default function () {}`, `export default () => {}`.
//   - CommonJS exports:
//     module.exports          = function () {}
//     module.exports.handler  = function () {}
//     exports.handler         = function () {}
//   - TypeScript-specific shapes: typed parameters, optional/default
//     parameters, generic type parameters on functions. The same
//     tree-sitter tree handles TSX/JSX scaffolding — we only emit the
//     function defs themselves; JSX bodies are walked transparently.
//
// What this extractor does NOT do (documented as future work):
//
//   - Resolve TypeScript `paths` from tsconfig.json. The relative-import
//     resolver covers the common case; alias paths are a follow-up.
//   - Walk into node_modules — bare specifiers return empty.
//   - Type-narrow `this.method()` calls. The receiver-type story for
//     classes is a follow-up; for now class methods just emit names like
//     "Cls.method" so cross-file lookups by suffix can still hit them.
//   - Closure naming with line:col anchors. The Python/Go extractors
//     emit signatures for nested closures; JS closures are extremely
//     common and frequently anonymous (callback args). We skip them
//     here — the per-file taint walker handles their bodies, and the
//     cross-file layer only needs *named* callable definitions.
package graph

import (
	"fmt"
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// jsExtractor implements TypeExtractor for both JavaScript and TypeScript.
// Two registry entries (one per Language) share the same logic — the
// underlying tree-sitter grammars are different, but the node types we
// inspect (function_declaration, arrow_function, method_definition, etc.)
// are named identically. Type annotations only appear in the TS tree;
// the JS tree silently produces no `type_annotation` children for plain
// JS files, so the same walker handles both.
type jsExtractor struct {
	lang rules.Language
}

func (j jsExtractor) Language() rules.Language { return j.lang }

func (j jsExtractor) ExtractFunctions(ctx *ExtractContext) []FuncSignature {
	tree := jsTree(ctx, j.lang)
	if tree == nil {
		return nil
	}
	var sigs []FuncSignature
	walkJSTopLevel(tree.Root(), "", &sigs)
	return sigs
}

// ResolveVarType is intentionally a no-op for JS/TS in this PR. Tracking
// variable types across assignments and member accesses needs a flow-
// sensitive type environment (TS's tsserver does this); the Python/Java
// extractors degrade the same way. Returning "" cleanly skips the
// confidence-bump path in interprocedural analysis.
func (j jsExtractor) ResolveVarType(ctx *ExtractContext, varName string, line int) string {
	return ""
}

// jsTree returns the parsed tree-sitter tree for ctx, parsing fresh
// from ctx.Content when TSTree is unset. We use the language passed in
// by the extractor (LangJavaScript vs LangTypeScript) so the right
// grammar is picked.
func jsTree(ctx *ExtractContext, lang rules.Language) *ast.Tree {
	if ctx == nil {
		return nil
	}
	if t, ok := ctx.TSTree.(*ast.Tree); ok && t != nil {
		return t
	}
	if ctx.Content == nil {
		return nil
	}
	return ast.ParseFile(ctx.Content, lang, ctx.FilePath)
}

// walkJSTopLevel walks a module-level subtree, emitting FuncSignatures
// for every top-level declaration. The prefix arg threads the enclosing
// class name through recursion so methods come out as "Cls.method".
//
// Recursion descends through statement containers (export_statement,
// lexical_declaration, expression_statement, variable_declarator,
// assignment_expression, class_body) so nested shapes like
// `export const handler = () => {}` are reached.
func walkJSTopLevel(n *ast.Node, prefix string, sigs *[]FuncSignature) {
	if n == nil {
		return
	}
	for _, child := range n.NamedChildren() {
		switch child.Type() {

		case "function_declaration", "generator_function_declaration":
			// `function foo(...) { ... }` — has a `name` field.
			name := nodeFieldText(child, "name")
			if prefix != "" && name != "" {
				name = prefix + "." + name
			}
			if sig := jsSignatureFromFunction(child, name); sig != nil {
				*sigs = append(*sigs, *sig)
			}

		case "class_declaration":
			// `class Foo { ... }` — recurse into the class body with the
			// class name as the prefix so methods come out "Foo.method".
			className := nodeFieldText(child, "name")
			body := child.ChildByFieldName("body")
			if body == nil {
				continue
			}
			classPrefix := className
			if prefix != "" && className != "" {
				classPrefix = prefix + "." + className
			}
			walkJSClassBody(body, classPrefix, sigs)

		case "export_statement":
			// ESM exports wrap one of the above shapes. Two cases:
			//   1. `export function foo() {}` — has a `declaration` field
			//      pointing at a function_declaration / class_declaration /
			//      lexical_declaration.
			//   2. `export default ...` — has a `value` field pointing at
			//      a function/arrow_function (possibly anonymous) or an
			//      identifier.
			if decl := child.ChildByFieldName("declaration"); decl != nil {
				// `decl` IS the function/class/lexical_declaration node;
				// dispatch on its type directly rather than recursing.
				dispatchJSDeclaration(decl, prefix, sigs)
				continue
			}
			// `export default function () {}` / `export default () => {}` —
			// we treat default as the binding name "default" so downstream
			// resolvers can hit it via the file's import-alias for default.
			if val := child.ChildByFieldName("value"); val != nil {
				switch val.Type() {
				case "function_declaration", "function_expression", "function",
					"arrow_function", "generator_function_declaration", "generator_function":
					name := "default"
					if prefix != "" {
						name = prefix + "." + name
					}
					if sig := jsSignatureFromFunction(val, name); sig != nil {
						*sigs = append(*sigs, *sig)
					}
				case "class":
					// `export default class { ... }` — anonymous default
					// class. Walk its body with "default" as the prefix.
					if body := val.ChildByFieldName("body"); body != nil {
						walkJSClassBody(body, "default", sigs)
					}
				}
			}

		case "lexical_declaration", "variable_declaration":
			// `const foo = ...` / `let foo = ...` / `var foo = ...`.
			// Each declarator inside may bind an arrow or function expr.
			for _, gc := range child.NamedChildren() {
				if gc.Type() != "variable_declarator" {
					continue
				}
				bindName := nodeFieldText(gc, "name")
				val := gc.ChildByFieldName("value")
				if bindName == "" || val == nil {
					continue
				}
				jsHandleBoundValue(bindName, prefix, val, sigs)
			}

		case "expression_statement":
			// CommonJS exports look like `module.exports.X = function () {}`
			// (an assignment_expression wrapped in expression_statement).
			// Walk through to find them.
			for _, gc := range child.NamedChildren() {
				switch gc.Type() {
				case "assignment_expression":
					jsHandleAssignment(gc, prefix, sigs)
				case "call_expression":
					// PR-BBjs: Express / Fastify / Koa / Hapi register
					// handlers via `app.get(path, handler)` /
					// `router.use(handler)` / `server.route({handler})`.
					// The handler is a callback argument of a top-level
					// call_expression. Walk arguments to find function
					// / arrow_function / function_expression nodes and
					// emit a signature for each so the framework-handler
					// heuristic (see jsFrameworkHandlerCategory) can
					// tag req as a SrcUserInput source.
					jsHandleCallExpressionCallback(gc, prefix, sigs)
				}
			}

		default:
			// Containers like `program`, `block`, `statement_block` —
			// descend so nested top-level shapes are reached.
			walkJSTopLevel(child, prefix, sigs)
		}
	}
}

// dispatchJSDeclaration handles a single declaration node (the body of
// `export <decl>`). Unlike walkJSTopLevel — which iterates a container's
// children — this dispatches on the node's own type.
func dispatchJSDeclaration(decl *ast.Node, prefix string, sigs *[]FuncSignature) {
	if decl == nil {
		return
	}
	switch decl.Type() {
	case "function_declaration", "generator_function_declaration":
		name := nodeFieldText(decl, "name")
		if prefix != "" && name != "" {
			name = prefix + "." + name
		}
		if sig := jsSignatureFromFunction(decl, name); sig != nil {
			*sigs = append(*sigs, *sig)
		}
	case "class_declaration":
		className := nodeFieldText(decl, "name")
		classPrefix := className
		if prefix != "" && className != "" {
			classPrefix = prefix + "." + className
		}
		if body := decl.ChildByFieldName("body"); body != nil {
			walkJSClassBody(body, classPrefix, sigs)
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
			jsHandleBoundValue(bindName, prefix, val, sigs)
		}
	}
}

// jsHandleBoundValue handles the RHS of `const NAME = <value>`. When
// value is a function-shaped node, emit a signature named NAME (with the
// enclosing class prefix, if any). Object literals get walked too so
// `const ctrl = { getUser: () => ... }` is reachable.
func jsHandleBoundValue(bindName, prefix string, val *ast.Node, sigs *[]FuncSignature) {
	fullName := bindName
	if prefix != "" {
		fullName = prefix + "." + bindName
	}
	switch val.Type() {
	case "arrow_function", "function_expression", "function",
		"generator_function":
		if sig := jsSignatureFromFunction(val, fullName); sig != nil {
			*sigs = append(*sigs, *sig)
		}
	case "object":
		// `const ctrl = { foo: () => {}, bar() {} }` — each method-
		// shaped property becomes a signature "<bindName>.<key>".
		walkJSObjectLiteral(val, fullName, sigs)
	}
}

// jsHandleCallExpressionCallback recognises the dominant Express /
// Fastify / Koa / Hapi handler registration shape and emits a
// FuncSignature for the callback. Recognised shapes:
//
//	app.get(path, handler)        — Express
//	app.post(path, handler)
//	router.use(handler)
//	router.get(path, mw1, ..., handler)  — chained middleware
//	server.route({ handler })     — Hapi (handler inside object literal)
//	fastify.get(path, opts?, handler) — Fastify with optional schema
//
// We do not try to model the routing path string itself. The handler's
// name is taken from a named function expression when possible; an
// anonymous arrow/function falls back to a synthetic name composed of
// the call's receiver method and the handler's start line. The
// FuncSignature's framework-handler heuristic (req,res / ctx / etc.)
// then tags req as a source.
//
// Hapi's `server.route({ handler: ... })` is handled by recursing into
// argument object literals — the existing walkJSObjectLiteral helper
// emits a "<obj-context>.handler" signature.
func jsHandleCallExpressionCallback(call *ast.Node, prefix string, sigs *[]FuncSignature) {
	if call == nil {
		return
	}
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return
	}
	// Best-effort method name for synthetic naming. The call's `function`
	// field is the callee — usually a member_expression like `app.get`.
	calleeMethod := ""
	if callee := call.ChildByFieldName("function"); callee != nil {
		if callee.Type() == "member_expression" {
			if prop := callee.ChildByFieldName("property"); prop != nil {
				calleeMethod = strings.TrimSpace(prop.Text())
			}
		}
	}
	for _, arg := range args.NamedChildren() {
		switch arg.Type() {
		case "arrow_function", "function_expression", "function":
			// Anonymous or named function. Use the inner name when present
			// (function expressions support a leading name); else synthesise
			// "<method>@<line>" so each handler is uniquely named.
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
			if sig := jsSignatureFromFunction(arg, fullName); sig != nil {
				*sigs = append(*sigs, *sig)
			}
		case "object":
			// `server.route({ handler: (request, h) => ... })` — Hapi.
			walkJSObjectLiteral(arg, prefix, sigs)
		}
	}
}

// jsHandleAssignment handles `LHS = RHS`, the assignment_expression form
// CommonJS exports use. We care about three target shapes:
//
//	module.exports        = <fn>          → "default"
//	module.exports.NAME   = <fn>          → "NAME"
//	exports.NAME          = <fn>          → "NAME"
//	some.thing.deeply.NAME = <fn>         → "NAME" (best effort)
//
// Anything else (plain identifier assignment in a loose context) is
// skipped — those would be top-level reassignments that the const/let
// path already covers.
func jsHandleAssignment(n *ast.Node, prefix string, sigs *[]FuncSignature) {
	lhs := n.ChildByFieldName("left")
	rhs := n.ChildByFieldName("right")
	if lhs == nil || rhs == nil {
		return
	}
	// Drill into the RHS first — we only act on function-shaped values.
	switch rhs.Type() {
	case "arrow_function", "function_expression", "function",
		"generator_function":
		// ok — fall through to determine the name.
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
	if sig := jsSignatureFromFunction(rhs, name); sig != nil {
		*sigs = append(*sigs, *sig)
	}
}

// jsCommonJSExportName extracts the export key from a CommonJS-style LHS
// member_expression. Returns:
//
//	module.exports         → "default"
//	module.exports.handler → "handler"
//	exports.handler        → "handler"
//	deeply.nested.foo      → "foo" (last component, best effort)
//
// Returns "" for anything we don't recognize.
func jsCommonJSExportName(lhs *ast.Node) string {
	if lhs == nil {
		return ""
	}
	switch lhs.Type() {
	case "member_expression":
		obj := lhs.ChildByFieldName("object")
		prop := lhs.ChildByFieldName("property")
		if obj == nil || prop == nil {
			return ""
		}
		objText := strings.TrimSpace(obj.Text())
		propText := strings.TrimSpace(prop.Text())
		// `module.exports = ...` — the LHS is `module.exports` (object is
		// `module`, property is `exports`). No further property; treat as
		// the default export.
		if objText == "module" && propText == "exports" {
			return "default"
		}
		// `exports.handler = ...` — object is `exports`, property is the
		// export name.
		if objText == "exports" {
			return propText
		}
		// `module.exports.handler = ...` — object is itself
		// member_expression `module.exports`; property is `handler`.
		if obj.Type() == "member_expression" {
			innerObj := obj.ChildByFieldName("object")
			innerProp := obj.ChildByFieldName("property")
			if innerObj != nil && innerProp != nil &&
				strings.TrimSpace(innerObj.Text()) == "module" &&
				strings.TrimSpace(innerProp.Text()) == "exports" {
				return propText
			}
		}
		// Anything else: best-effort, just take the final property name.
		return propText
	}
	return ""
}

// walkJSClassBody walks a class_body, emitting one signature per
// method_definition. The classPrefix is the canonical class name
// ("Cls" or "Outer.Inner").
func walkJSClassBody(body *ast.Node, classPrefix string, sigs *[]FuncSignature) {
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
			if sig := jsSignatureFromFunction(child, fullName); sig != nil {
				*sigs = append(*sigs, *sig)
			}
		case "field_definition":
			// `class Foo { handler = (req) => {} }` — a field whose value
			// is an arrow function is effectively a method. Emit it under
			// the class prefix.
			name := nodeFieldText(child, "property")
			if name == "" {
				name = nodeFieldText(child, "name")
			}
			val := child.ChildByFieldName("value")
			if name == "" || val == nil {
				continue
			}
			switch val.Type() {
			case "arrow_function", "function_expression", "function":
				fullName := name
				if classPrefix != "" {
					fullName = classPrefix + "." + name
				}
				if sig := jsSignatureFromFunction(val, fullName); sig != nil {
					*sigs = append(*sigs, *sig)
				}
			}
		}
	}
}

// walkJSObjectLiteral walks an `object` literal looking for property
// values that are function-shaped, emitting signatures named
// "<objPrefix>.<key>". Handles both the long form
// (`{ foo: function () {} }`) and the method shorthand (`{ foo() {} }`).
func walkJSObjectLiteral(obj *ast.Node, objPrefix string, sigs *[]FuncSignature) {
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
			keyName := strings.TrimSpace(key.Text())
			// Strip surrounding quotes if the key is a string literal
			// (`{ "handler": ... }`).
			keyName = strings.Trim(keyName, `"'`)
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
				if sig := jsSignatureFromFunction(val, fullName); sig != nil {
					*sigs = append(*sigs, *sig)
				}
			}
		case "method_definition":
			// Shorthand methods inside an object literal:
			// `{ async foo(req) {} }`.
			name := nodeFieldText(child, "name")
			if name == "" {
				continue
			}
			fullName := name
			if objPrefix != "" {
				fullName = objPrefix + "." + name
			}
			if sig := jsSignatureFromFunction(child, fullName); sig != nil {
				*sigs = append(*sigs, *sig)
			}
		}
	}
}

// jsSignatureFromFunction builds a FuncSignature from a node whose shape
// is one of:
//
//	function_declaration / generator_function_declaration
//	function_expression / function / generator_function
//	arrow_function
//	method_definition
//
// All of these expose `parameters` (and `body`) via the same field
// names in tree-sitter-javascript and tree-sitter-typescript.
func jsSignatureFromFunction(n *ast.Node, fullName string) *FuncSignature {
	if n == nil || fullName == "" {
		return nil
	}
	sig := &FuncSignature{
		Name:      fullName,
		StartLine: int(n.StartRow()) + 1,
		EndLine:   int(n.EndRow()) + 1,
	}
	if params := n.ChildByFieldName("parameters"); params != nil {
		sig.Params = jsExtractParamTaints(params)
	} else if param := n.ChildByFieldName("parameter"); param != nil {
		// Single-arg arrow without parens: `x => x + 1`. tree-sitter
		// surfaces this as the `parameter` field on arrow_function.
		if param.Type() == "identifier" {
			sig.Params = []ParamTaint{{Index: 0, Name: strings.TrimSpace(param.Text())}}
		}
	}
	// PR-BBjs: apply the name-based framework-handler heuristic when no
	// TypeScript annotation already marked a parameter as a source. The
	// catalog lookup inside jsExtractParamTaints handles the TS-typed
	// path (`req: Request`); the heuristic here handles plain JS where
	// the parameter has no type and Express-style names are the only
	// signal we have.
	//
	// PR-CATjs-6: when a candidate handler param carries an explicit TS
	// type annotation that is NEITHER in the framework catalog NOR a
	// primitive/generic type variable, the developer has told us the
	// param is a project-defined interface like `IRestApiContext` — not a
	// framework Request/Context. In that case the name-based fallback
	// would be a false positive (see n8n's `(context: IRestApiContext)`),
	// so we skip it. Plain JS, untyped TS params, primitive-typed params,
	// and generic-type-variable-typed params still fall through to the
	// heuristic — those are the cases where the name signal is all we have.
	if !jsAnyParamIsSource(sig.Params) {
		if idx, cat, ok := jsFrameworkHandlerCategory(sig.Params); ok && idx >= 0 && idx < len(sig.Params) {
			if !jsParamHasCustomTypeAnnotation(sig.Params[idx]) {
				sig.Params[idx].IsSourceType = true
				sig.Params[idx].SourceCategory = cat
			}
		}
	}
	return sig
}

// jsTypePrimitives is the set of TypeScript type-annotation tokens that
// we treat as "no information" — they don't tell us whether the param
// is a framework request or not, so the name-based heuristic remains
// the best signal we have.
//
// Single-letter UPPERCASE names (T, U, K, V, …) are assumed to be
// generic type variables and are handled by jsTypeIsGenericVariable.
var jsTypePrimitives = map[string]bool{
	"string":    true,
	"number":    true,
	"boolean":   true,
	"bigint":    true,
	"symbol":    true,
	"undefined": true,
	"null":      true,
	"void":      true,
	"never":     true,
	"unknown":   true,
	"any":       true,
	"object":    true,
	"Object":    true,
}

// jsTypeIsGenericVariable reports whether a canonicalised TS type looks
// like a single-letter or short-uppercase generic type parameter (T, U,
// TKey, TValue, K, V, …). Generic type variables carry no information
// about whether the runtime value is a framework request, so they
// behave like primitives for the purpose of the name heuristic.
func jsTypeIsGenericVariable(canonical string) bool {
	if canonical == "" {
		return false
	}
	// Single uppercase letter — the dominant convention (T, U, K, V, E, R).
	if len(canonical) == 1 && canonical[0] >= 'A' && canonical[0] <= 'Z' {
		return true
	}
	// `T`-prefixed conventional names: TKey, TValue, TElement, …
	if len(canonical) >= 2 && canonical[0] == 'T' && canonical[1] >= 'A' && canonical[1] <= 'Z' {
		return true
	}
	return false
}

// jsParamHasCustomTypeAnnotation reports whether a param carries a TS
// type annotation that is a project-defined interface/class (i.e. NOT a
// primitive and NOT a generic type variable). Such annotations are a
// stronger signal than the parameter name: if the developer wrote
// `context: IRestApiContext`, the param is NOT a Koa Context regardless
// of what it's named. The catalog-match path (jsExtractParamTaints)
// has already had its chance to tag the param positively; reaching this
// helper means no allowlisted framework type matched.
func jsParamHasCustomTypeAnnotation(p ParamTaint) bool {
	if p.CanonicalType == "" {
		return false
	}
	if jsTypePrimitives[p.CanonicalType] {
		return false
	}
	if jsTypeIsGenericVariable(p.CanonicalType) {
		return false
	}
	return true
}

// jsAnyParamIsSource reports whether any element of params already has
// IsSourceType set — used to suppress the name-based heuristic when a
// stronger TS-annotation-based signal landed first.
func jsAnyParamIsSource(params []ParamTaint) bool {
	for i := range params {
		if params[i].IsSourceType {
			return true
		}
	}
	return false
}

// jsExtractParamTaints walks a formal_parameters node and emits one
// ParamTaint per positional parameter. Handles the common parameter
// shapes:
//
//	identifier             — `(x)`
//	required_parameter     — `(x: string)` (TS)
//	optional_parameter     — `(x?: string)` (TS)
//	assignment_pattern     — `(x = 1)`
//	rest_pattern           — `(...rest)`
//	object_pattern         — `({ a, b })` — flattened to one param named ""
//	array_pattern          — `([a, b])` — flattened to one param named ""
//
// Type annotations (TS) and default values are captured for the typed
// shapes when present.
func jsExtractParamTaints(params *ast.Node) []ParamTaint {
	var out []ParamTaint
	idx := 0
	for _, child := range params.NamedChildren() {
		var name, rawType string
		switch child.Type() {
		case "identifier":
			name = strings.TrimSpace(child.Text())

		case "required_parameter", "optional_parameter":
			// TS: typed params. The pattern is under `pattern`; the type
			// (when present) under `type` which itself wraps a
			// `type_annotation` whose first named child is the actual type.
			if pat := child.ChildByFieldName("pattern"); pat != nil {
				if pat.Type() == "identifier" {
					name = strings.TrimSpace(pat.Text())
				} else if pat.Type() == "rest_pattern" {
					for _, c := range pat.NamedChildren() {
						if c.Type() == "identifier" {
							name = strings.TrimSpace(c.Text())
							break
						}
					}
				}
			}
			if typeNode := child.ChildByFieldName("type"); typeNode != nil {
				rawType = jsExtractTypeAnnotation(typeNode)
			}

		case "assignment_pattern":
			// `(x = 1)` — `left` is the binding, `right` is the default
			// value. We only care about the binding name.
			if lhs := child.ChildByFieldName("left"); lhs != nil {
				if lhs.Type() == "identifier" {
					name = strings.TrimSpace(lhs.Text())
				}
			}

		case "rest_pattern":
			// `(...rest)` — wraps an identifier.
			for _, c := range child.NamedChildren() {
				if c.Type() == "identifier" {
					name = strings.TrimSpace(c.Text())
					break
				}
			}

		case "object_pattern", "array_pattern":
			// Destructured param. Without resolving each binding to its
			// type we can't usefully name it; emit a placeholder param so
			// the index counter stays accurate.

		default:
			// Skip unknown nodes (commas, comments) — they aren't named
			// children of formal_parameters in any practical case but
			// the catch-all here keeps us future-proof.
			continue
		}

		canonical := canonicalizeJSType(rawType)
		p := ParamTaint{
			Index:         idx,
			Name:          name,
			Type:          rawType,
			CanonicalType: canonical,
		}
		// PR-BBjs: when the TS annotation matches a known framework
		// Request / Context type, mark the param as a source.
		if canonical != "" {
			if cat, ok := javascriptTypeCatalog.LookupSource(canonical); ok {
				p.IsSourceType = true
				p.SourceCategory = cat
			}
		}
		out = append(out, p)
		idx++
	}
	return out
}

// jsExtractTypeAnnotation pulls the raw type text out of a `type` field
// node attached to a typed_parameter. The shape in tree-sitter-typescript
// is `type_annotation` → first named child is the actual type expression
// (predefined_type, type_identifier, generic_type, …). When the node is
// already the type expression (no wrapper), use its text directly.
func jsExtractTypeAnnotation(n *ast.Node) string {
	if n == nil {
		return ""
	}
	if n.Type() == "type_annotation" {
		for _, c := range n.NamedChildren() {
			// Skip the leading ':' which isn't a named child but tolerate
			// any wrapper grammar variants.
			return strings.TrimSpace(c.Text())
		}
		return ""
	}
	return strings.TrimSpace(n.Text())
}

func init() {
	RegisterExtractor(jsExtractor{lang: rules.LangJavaScript})
	RegisterExtractor(jsExtractor{lang: rules.LangTypeScript})
}

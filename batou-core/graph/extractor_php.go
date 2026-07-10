// Per-language extractor: PHP.
//
// Walks a tree-sitter PHP tree and emits a FuncSignature for every
// callable declaration the cross-file graph needs to track. PHP combines
// Java-style namespaces and class hierarchies with JavaScript-style
// closures/anonymous functions, so this extractor borrows from both
// (closest in shape to extractor_java.go, with closure handling inspired
// by extractor_javascript.go).
//
// Coverage targets the dominant shapes you'll find in real-world PHP
// projects (Laravel, Symfony, custom MVC):
//
//   - Top-level function declarations: `function handler($req) { ... }`.
//     Qualified with namespace as "App\Controllers\handler".
//   - Class methods (public/private/protected, static, instance,
//     constructors): emitted as "App\Foo\Cls::method".
//   - Abstract methods and interface methods: skipped (no body, no FuncNode).
//   - Closures bound to a variable:
//       `$cb = function($x) use ($s) { ... };`     → "$cb"
//       `$cb = fn($x) => $x * 2;`                  → "$cb"
//     (PHP 7.4+ arrow functions and anonymous functions both supported.)
//   - Laravel-style route closures passed as args:
//       `Route::get('/u/{id}', function($id) { ... });`
//     The closure becomes "<receiver>::<method>@<line>" (synthetic name)
//     so the cross-file framework can reach the body via the synthetic
//     edge — same pattern the JS extractor uses for Express callbacks.
//
// What this extractor does NOT do (documented as follow-up work):
//
//   - Anonymous classes (`$x = new class { ... };`): the anonymous class
//     body's methods aren't emitted as nodes. Rare in practice; a follow-
//     up PR can extend extractor_php.go to walk the body and qualify
//     with a synthetic "@anon<line>" prefix.
//   - Method receiver-type tracking through `$this->...` chains. The
//     resolver handles the easy cases via the existing per-file taint
//     walker; cross-class field-type propagation needs a type environment.
//   - Traits: methods in a trait are emitted under "TraitName::method"
//     just like a class, but `use TraitName;` inside a class doesn't
//     re-emit those methods under the class. The cross-file resolver can
//     still resolve direct `TraitName::method()` calls.
//   - PHP attribute-based parameter sources (`#[Route]` on a method) —
//     PR-BBphp territory.
package graph

import (
	"fmt"
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// phpExtractor implements TypeExtractor for PHP.
type phpExtractor struct{}

func (phpExtractor) Language() rules.Language { return rules.LangPHP }

func (phpExtractor) ExtractFunctions(ctx *ExtractContext) []FuncSignature {
	tree := phpTree(ctx)
	if tree == nil {
		return nil
	}
	root := tree.Root()
	ns := extractPHPNamespace(root)
	imports := extractPHPUseImports(root, ns)
	var sigs []FuncSignature
	walkPHPTopLevel(root, ns, "", imports, &sigs)
	return sigs
}

// ResolveVarType is a no-op for PHP. Type tracking across `$x =
// new Foo(); $x->m();` needs a flow-sensitive type environment, which
// is a follow-up. Returning "" cleanly skips the confidence-bump path
// in interprocedural analysis (same as Python/JS/Java extractors).
func (phpExtractor) ResolveVarType(ctx *ExtractContext, varName string, line int) string {
	return ""
}

// phpTree returns the parsed tree-sitter tree for ctx, parsing fresh from
// ctx.Content when TSTree is unset.
func phpTree(ctx *ExtractContext) *ast.Tree {
	if ctx == nil {
		return nil
	}
	if t, ok := ctx.TSTree.(*ast.Tree); ok && t != nil {
		return t
	}
	if ctx.Content == nil {
		return nil
	}
	return ast.Parse(ctx.Content, rules.LangPHP)
}

// extractPHPNamespace reads the file's `namespace App\Foo\Bar;` declaration,
// returning the dotted-backslash form. Empty string when the file has no
// namespace.
//
// PHP allows multiple namespaces per file via braced bodies
// (`namespace A { ... } namespace B { ... }`). That form is exceedingly
// rare in modern code; we record only the first top-level namespace.
func extractPHPNamespace(root *ast.Node) string {
	if root == nil {
		return ""
	}
	for _, c := range root.NamedChildren() {
		if c.Type() != "namespace_definition" {
			continue
		}
		if name := c.ChildByFieldName("name"); name != nil {
			return strings.TrimSpace(name.Text())
		}
	}
	return ""
}

// extractPHPUseImports walks `use` statements and returns a map from the
// short class/function name visible in this file to its fully-qualified
// namespace path. Handles:
//
//   - `use App\Foo\Bar;`              → "Bar"  → "App\Foo\Bar"
//   - `use App\Foo\Bar as B;`         → "B"    → "App\Foo\Bar"
//   - `use App\Util\{Helper, Logger}` → "Helper" → "App\Util\Helper",
//                                       "Logger" → "App\Util\Logger"
//   - `use App\Util\{Logger as L}`    → "L"    → "App\Util\Logger"
//
// `use function ...` and `use const ...` are recorded too — even though
// they're out of scope for class-call resolution, they're a small amount
// of extra data and downstream consumers (PR-BBphp framework annotations
// etc.) may consult them.
//
// currentNS is recorded for context but unused at this level — short
// names imported via `use` always shadow the current namespace.
func extractPHPUseImports(root *ast.Node, currentNS string) map[string]string {
	imports := map[string]string{}
	if root == nil {
		return imports
	}
	root.Walk(func(n *ast.Node) bool {
		if n.Type() != "namespace_use_declaration" {
			return true
		}
		collectPHPUseDeclaration(n, imports)
		return false
	})
	return imports
}

// collectPHPUseDeclaration parses one `use ...;` statement and merges its
// alias→FQN entries into imports. Tree-sitter PHP layout:
//
//	namespace_use_declaration
//	  [unnamed "function" | "const" tokens — skipped]
//	  namespace_use_clause   ─── one clause per non-grouped use
//	    qualified_name       ─── "App\\Foo\\Bar"
//	    [namespace_aliasing_clause "as X"] (optional)
//	  | namespace_name       ─── prefix for grouped use ("App\\Util")
//	    namespace_use_group  ─── "{...}"
//	      namespace_use_group_clause
//	        namespace_name   ─── "Helper" / "Logger"
//	        [namespace_aliasing_clause "as L"]
func collectPHPUseDeclaration(n *ast.Node, imports map[string]string) {
	// Two top-level shapes: list of namespace_use_clause children, OR a
	// namespace_name prefix followed by a namespace_use_group.
	var prefix string
	var group *ast.Node
	for _, c := range n.NamedChildren() {
		switch c.Type() {
		case "namespace_name":
			// Prefix for grouped use.
			prefix = strings.TrimSpace(c.Text())
		case "namespace_use_group":
			group = c
		case "namespace_use_clause":
			fqn, alias := parsePHPUseClause(c)
			if fqn == "" {
				continue
			}
			if alias == "" {
				alias = phpShortName(fqn)
			}
			if alias != "" {
				imports[alias] = fqn
			}
		}
	}
	if group != nil {
		for _, gc := range group.NamedChildren() {
			if gc.Type() != "namespace_use_group_clause" {
				continue
			}
			suffix, alias := parsePHPUseGroupClause(gc)
			if suffix == "" {
				continue
			}
			fqn := suffix
			if prefix != "" {
				fqn = prefix + `\` + suffix
			}
			if alias == "" {
				alias = phpShortName(suffix)
			}
			if alias != "" {
				imports[alias] = fqn
			}
		}
	}
}

// parsePHPUseClause returns (fqn, alias) for one namespace_use_clause node.
// alias is "" when the clause has no `as` part.
func parsePHPUseClause(n *ast.Node) (string, string) {
	var fqn, alias string
	for _, c := range n.NamedChildren() {
		switch c.Type() {
		case "qualified_name":
			fqn = strings.TrimSpace(c.Text())
		case "name":
			// Bare-name use (no namespace prefix): `use Foo;`
			if fqn == "" {
				fqn = strings.TrimSpace(c.Text())
			}
		case "namespace_aliasing_clause":
			alias = phpExtractAliasName(c)
		}
	}
	return fqn, alias
}

// parsePHPUseGroupClause returns the (suffix, alias) for one element of a
// `use App\Util\{Helper, Logger as L}` group. suffix is the relative
// namespace path under the group's prefix; alias is "" when absent.
func parsePHPUseGroupClause(n *ast.Node) (string, string) {
	var suffix, alias string
	for _, c := range n.NamedChildren() {
		switch c.Type() {
		case "namespace_name":
			if suffix == "" {
				suffix = strings.TrimSpace(c.Text())
			}
		case "name":
			if suffix == "" {
				suffix = strings.TrimSpace(c.Text())
			}
		case "namespace_aliasing_clause":
			alias = phpExtractAliasName(c)
		}
	}
	return suffix, alias
}

// phpExtractAliasName pulls the alias identifier out of a
// namespace_aliasing_clause node ("as X" → "X").
func phpExtractAliasName(n *ast.Node) string {
	for _, c := range n.NamedChildren() {
		if c.Type() == "name" {
			return strings.TrimSpace(c.Text())
		}
	}
	return ""
}

// phpShortName returns the trailing component of a backslash-qualified
// namespace path. `App\Foo\Bar` → `Bar`.
func phpShortName(fqn string) string {
	if i := strings.LastIndex(fqn, `\`); i >= 0 {
		return fqn[i+1:]
	}
	return fqn
}

// walkPHPTopLevel walks the program-level children (and any namespace_definition
// braced bodies) and emits FuncSignatures for top-level functions, class
// methods, and closures bound to top-level assignments.
//
// ns: the current PHP namespace (e.g. "App\Controllers"); used to qualify
// top-level function and class names.
// prefix: the current class-chain prefix used for nested types (rare in
// PHP but supported via `class Outer { class Inner ... }` syntax in PHP
// 8.4's anonymous-class proposal; today this stays empty at the root).
func walkPHPTopLevel(n *ast.Node, ns, prefix string, imports map[string]string, sigs *[]FuncSignature) {
	if n == nil {
		return
	}
	for _, child := range n.NamedChildren() {
		switch child.Type() {

		case "function_definition":
			// Top-level function. Qualify with namespace.
			name := nodeFieldText(child, "name")
			if name == "" {
				continue
			}
			fullName := name
			if ns != "" {
				fullName = ns + `\` + name
			}
			if sig := phpSignatureFromFunction(child, fullName, false); sig != nil {
				*sigs = append(*sigs, *sig)
			}

		case "class_declaration", "interface_declaration", "trait_declaration",
			"enum_declaration":
			className := nodeFieldText(child, "name")
			if className == "" {
				continue
			}
			// Qualified class name: "App\Controllers\UserController".
			classPath := className
			if ns != "" {
				classPath = ns + `\` + className
			}
			if prefix != "" {
				// Highly unusual but tree-sitter can produce nested types
				// inside an anonymous-class body. Keep prefix stable.
				classPath = prefix + `\` + className
			}
			if body := child.ChildByFieldName("body"); body != nil {
				walkPHPClassBody(body, classPath, child.Type() == "interface_declaration",
					imports, sigs)
			}

		case "namespace_definition":
			// Braced namespace body: `namespace A { ... }`. The
			// declaration also carries the namespace name in field "name";
			// we shadow ns for the duration of the body.
			innerNS := ns
			if name := child.ChildByFieldName("name"); name != nil {
				innerNS = strings.TrimSpace(name.Text())
			}
			if body := child.ChildByFieldName("body"); body != nil {
				walkPHPTopLevel(body, innerNS, prefix, imports, sigs)
			}

		case "expression_statement":
			// Assignments at the file level: `$cb = function() { ... };`
			// or `Route::get(..., function() { ... });`.
			for _, gc := range child.NamedChildren() {
				switch gc.Type() {
				case "assignment_expression":
					phpHandleAssignment(gc, ns, imports, sigs)
				case "scoped_call_expression", "function_call_expression",
					"member_call_expression":
					phpHandleCallExpressionCallbacks(gc, ns, imports, sigs)
				}
			}

		default:
			// Descend through anything else (compound_statement etc.).
			walkPHPTopLevel(child, ns, prefix, imports, sigs)
		}
	}
}

// walkPHPClassBody emits one FuncSignature per method in body. Skips
// abstract / interface methods (no body → no node).
//
// inInterface: true when the body is from an interface_declaration, where
// every method is implicitly abstract.
func walkPHPClassBody(body *ast.Node, classPath string, inInterface bool,
	imports map[string]string, sigs *[]FuncSignature) {
	if body == nil {
		return
	}
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
			if sig := phpSignatureFromFunction(child, fullName, false); sig != nil {
				*sigs = append(*sigs, *sig)
			}
		case "property_declaration":
			// `public Closure $fn = fn() => 1;` — emit a node for the
			// property binding when its initialiser is an arrow/closure.
			phpHandlePropertyClosure(child, classPath, sigs)
		}
	}
}

// phpMethodIsAbstract reports whether a method_declaration carries an
// `abstract` modifier.
func phpMethodIsAbstract(method *ast.Node) bool {
	if method == nil {
		return false
	}
	for _, c := range method.NamedChildren() {
		if c.Type() == "abstract_modifier" {
			return true
		}
	}
	return false
}

// phpHandleAssignment handles top-level `$lhs = $rhs` expressions, emitting
// a FuncSignature when rhs is a closure or arrow function.
func phpHandleAssignment(n *ast.Node, ns string, imports map[string]string, sigs *[]FuncSignature) {
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
		if sig := phpSignatureFromFunction(rhs, fullName, true); sig != nil {
			*sigs = append(*sigs, *sig)
		}
	}
}

// phpHandlePropertyClosure walks a class property_declaration and emits a
// FuncSignature when the initialiser of a single property element is a
// closure/arrow function. Property syntax in PHP 8.x:
//
//	public Closure $fn = fn() => 1;
//	private static Closure $cb = function() { ... };
func phpHandlePropertyClosure(decl *ast.Node, classPath string, sigs *[]FuncSignature) {
	for _, c := range decl.NamedChildren() {
		if c.Type() != "property_element" {
			continue
		}
		var propName string
		var init *ast.Node
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
		if sig := phpSignatureFromFunction(init, fullName, true); sig != nil {
			*sigs = append(*sigs, *sig)
		}
	}
}

// phpHandleCallExpressionCallbacks recognises framework route registrations
// where a closure is passed inline as an argument:
//
//	Route::get('/u/{id}', function($id) { ... });
//	$app->get('/x', fn() => ...);
//	$this->router->add(function($req) { ... });
//
// Each anonymous-function argument becomes a FuncSignature with a synthetic
// name `<callee>@<line>` (mirrors the JS extractor's Express handler shape).
// The framework consumes this via the call-graph dispatch path.
func phpHandleCallExpressionCallbacks(call *ast.Node, ns string, imports map[string]string, sigs *[]FuncSignature) {
	if call == nil {
		return
	}
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return
	}
	// Best-effort callee method name for synthetic naming.
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
		// arg is an argument node wrapping the actual expression.
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
			if sig := phpSignatureFromFunction(inner, fullName, true); sig != nil {
				*sigs = append(*sigs, *sig)
			}
		}
	}
}

// phpSignatureFromFunction builds a FuncSignature from a function-shaped
// node:
//
//	function_definition / method_declaration
//	anonymous_function_creation_expression
//	arrow_function
//
// All four expose `parameters` via the same `parameters` field; methods
// and named functions also have `body`.
func phpSignatureFromFunction(n *ast.Node, fullName string, isClosure bool) *FuncSignature {
	if n == nil || fullName == "" {
		return nil
	}
	sig := &FuncSignature{
		Name:      fullName,
		StartLine: int(n.StartRow()) + 1,
		EndLine:   int(n.EndRow()) + 1,
		IsClosure: isClosure,
	}
	if params := n.ChildByFieldName("parameters"); params != nil {
		sig.Params = phpExtractParams(params)
	}
	return sig
}

// phpExtractParams extracts ParamTaint records from a formal_parameters
// node. Handles:
//
//	simple_parameter            — `($x)`, `(int $x)`, `($x = 1)`
//	variadic_parameter          — `(...$args)`
//	property_promotion_parameter — `(public int $x)` (PHP 8 ctor promotion)
func phpExtractParams(params *ast.Node) []ParamTaint {
	var out []ParamTaint
	idx := 0
	for _, child := range params.NamedChildren() {
		switch child.Type() {
		case "simple_parameter", "variadic_parameter", "property_promotion_parameter":
			var name, rawType string
			if nameNode := child.ChildByFieldName("name"); nameNode != nil {
				// PHP `name` field on simple_parameter is the variable_name.
				name = strings.TrimSpace(nameNode.Text())
			} else {
				// Fallback: first variable_name child.
				for _, gc := range child.NamedChildren() {
					if gc.Type() == "variable_name" {
						name = strings.TrimSpace(gc.Text())
						break
					}
				}
			}
			if typeNode := child.ChildByFieldName("type"); typeNode != nil {
				rawType = strings.TrimSpace(typeNode.Text())
			} else {
				// Type might be a primitive_type / named_type / union_type
				// without a named field — scan named children.
				for _, gc := range child.NamedChildren() {
					switch gc.Type() {
					case "primitive_type", "named_type", "union_type",
						"intersection_type", "optional_type":
						rawType = strings.TrimSpace(gc.Text())
					}
					if rawType != "" {
						break
					}
				}
			}
			p := ParamTaint{
				Index:         idx,
				Name:          name,
				Type:          rawType,
				CanonicalType: rawType, // PHP doesn't need import canonicalization at this level.
			}
			out = append(out, p)
			idx++
		}
	}
	return out
}

func init() {
	RegisterExtractor(phpExtractor{})
}

package tsflow

import (
	"strings"

	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// langConfig defines how to interpret tree-sitter AST nodes for a specific language.
type langConfig struct {
	language     rules.Language
	funcTypes    map[string]bool // node types that define functions/methods
	callTypes    map[string]bool // node types for function/method calls
	assignTypes  map[string]bool // node types for assignments
	varDeclTypes map[string]bool // node types for variable declarations
	identType    string          // node type for identifiers
	attrTypes    map[string]bool // node types for attribute/member access (sources like request.args)

	// Allowlist/validation-aware sanitization config.
	ifTypes map[string]bool // node types for if statements (e.g., "if_statement")

	// classTypes are node types that define a class/struct whose method
	// bodies are already analyzed as their own scopes by the per-function
	// pass. The flat-script top-level walk (walkTopLevelScript) skips these
	// so it does not descend into method bodies — descending would both
	// double-report a method's internal flows and let a top-level variable
	// leak taint into a method that shadows it via a parameter. Empty for
	// languages that don't run the top-level walk.
	classTypes map[string]bool

	// instanceReceivers is the set of receiver tokens that name the current
	// object instance (`self`, `this`, …). A field-access whose base segment
	// is one of these (`self.x`, `this.data`) refers to instance state that is
	// stable across the methods of a class, so the cross-method stored-state
	// channel (field_global_state.go) treats `self.x` as a file-level field key
	// that can carry taint from a writer method to a reader method. A bare
	// function-local `obj.attr` is NOT promoted — its base is function-scoped.
	// Empty for languages without a stored-state channel.
	instanceReceivers map[string]bool

	// extractCallName returns the method/function name from a call node.
	extractCallName func(*ast.Node) string
	// extractCallReceiver returns the receiver/object name from a call node.
	extractCallReceiver func(*ast.Node) string
	// extractAssignLHS returns the variable name from the left side of an assignment.
	extractAssignLHS func(*ast.Node) string
	// extractAssignRHS returns the right-side node from an assignment.
	extractAssignRHS func(*ast.Node) *ast.Node
	// extractAttrName returns the attribute/property name from an attribute node.
	extractAttrName func(*ast.Node) string
	// extractAttrReceiver returns the receiver name from an attribute node.
	extractAttrReceiver func(*ast.Node) string
	// extractCallArgs returns the argument nodes from a call node.
	extractCallArgs func(*ast.Node) []*ast.Node
	// extractFuncName returns the function name from a function definition node.
	extractFuncName func(*ast.Node) string
	// extractFuncBody returns the body node from a function definition node.
	extractFuncBody func(*ast.Node) *ast.Node
	// extractFuncParams returns parameter names from a function definition.
	extractFuncParams func(*ast.Node) []string
	// extractIfCondition returns the condition node from an if-statement node.
	extractIfCondition func(*ast.Node) *ast.Node
	// extractIfConsequence returns the "then" body node from an if-statement.
	extractIfConsequence func(*ast.Node) *ast.Node
	// extractIfAlternative returns the "else" body node (may be nil).
	extractIfAlternative func(*ast.Node) *ast.Node

	// findExtraScopes is an optional hook returning extra "function-like"
	// AST nodes that the walker should treat as analysis scopes alongside
	// the normal funcTypes set. Used for languages with DSL block handlers
	// that aren't formal function definitions but DO carry per-block taint
	// (e.g., Ruby Sinatra/Roda `get '/x' do ... end` route blocks). The
	// returned nodes are passed through extractFuncName / extractFuncBody /
	// extractFuncParams the same way regular func nodes are — those
	// helpers must accept the extra node types too. Return nil when there
	// are no extras.
	findExtraScopes func(root *ast.Node) []*ast.Node

	// barrierGuards describes the language-specific "barrier guard" shapes
	// the walker recognises in an if-condition. A barrier
	// guard is a validation check that constrains a tainted value to a safe
	// character set or value domain on the guarded path — e.g.
	// `if (/^[0-9]+$/.test(id)) { ... }` (JS strict-charset regex) or
	// `if (id.matches("[A-Za-z0-9]+")) { ... }` (Java). When recognised, the
	// SPECIFIC validated variable is marked sanitized for the SPECIFIC sink
	// categories the guard neutralises (category-scoped, not wholesale taint
	// deletion — mirroring inferPythonPathGuard's design). nil for languages
	// that don't opt in, so their flows are byte-unchanged.
	barrierGuards *barrierGuardConfig
}

// configs maps languages to their configurations.
var configs = map[rules.Language]*langConfig{
	rules.LangPython:     pythonConfig(),
	rules.LangJavaScript: jsConfig(),
	rules.LangTypeScript: tsConfig(),
	rules.LangJava:       javaConfig(),
	rules.LangPHP:        phpConfig(),
	rules.LangRuby:       rubyConfig(),
	rules.LangC:          cConfig(),
	rules.LangCPP:        cppConfig(),
	rules.LangCSharp:     csharpConfig(),
	rules.LangKotlin:     kotlinConfig(),
	rules.LangRust:       rustConfig(),
	rules.LangSwift:      swiftConfig(),
	rules.LangLua:        luaConfig(),
	rules.LangGroovy:     groovyConfig(),
	rules.LangPerl:       perlConfig(),
	rules.LangZig:        zigConfig(),
	rules.LangShell:      shellConfig(),
}

func getConfig(lang rules.Language) *langConfig {
	return configs[lang]
}

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

func pythonConfig() *langConfig {
	return &langConfig{
		language:  rules.LangPython,
		funcTypes: map[string]bool{"function_definition": true, "decorated_definition": true},
		callTypes: map[string]bool{"call": true},
		// `named_expression` is the walrus operator `x := expr` (PEP 572).
		// Treating it as an assignment seeds the target `x` from the value's
		// taint, so `if (data := request.get_json()):` / `while (line :=
		// f.readline()):` propagate. The node is Python-unique, so other
		// languages are unaffected.
		assignTypes:       map[string]bool{"assignment": true, "augmented_assignment": true, "named_expression": true},
		varDeclTypes:      map[string]bool{},
		identType:         "identifier",
		attrTypes:         map[string]bool{"attribute": true},
		ifTypes:           map[string]bool{"if_statement": true},
		classTypes:        map[string]bool{"class_definition": true},
		instanceReceivers: map[string]bool{"self": true, "cls": true},

		extractCallName: func(n *ast.Node) string {
			fn := n.ChildByFieldName("function")
			if fn == nil {
				return ""
			}
			switch fn.Type() {
			case "identifier":
				return fn.Text()
			case "attribute":
				attr := fn.ChildByFieldName("attribute")
				if attr != nil {
					return attr.Text()
				}
			}
			return ""
		},
		extractCallReceiver: func(n *ast.Node) string {
			fn := n.ChildByFieldName("function")
			if fn == nil {
				return ""
			}
			if fn.Type() == "attribute" {
				obj := fn.ChildByFieldName("object")
				if obj != nil {
					return obj.Text()
				}
			}
			return ""
		},
		extractAssignLHS: func(n *ast.Node) string {
			// Walrus `x := expr` (named_expression) uses the "name" field for
			// its target rather than "left".
			if n.Type() == "named_expression" {
				if name := n.ChildByFieldName("name"); name != nil && name.Type() == "identifier" {
					return name.Text()
				}
				return ""
			}
			lhs := n.ChildByFieldName("left")
			if lhs == nil {
				return ""
			}
			if lhs.Type() == "identifier" {
				return lhs.Text()
			}
			// Subscript LHS: d['key'] = val → use full text "d['key']"
			// for per-key taint tracking (avoids over-tainting the whole dict).
			// Attribute LHS: obj.attr = val → use full text "obj.attr"
			if lhs.Type() == "subscript" || lhs.Type() == "attribute" {
				return lhs.Text()
			}
			return ""
		},
		extractAssignRHS: func(n *ast.Node) *ast.Node {
			// Walrus `x := expr` stores the assigned expression in "value".
			if n.Type() == "named_expression" {
				return n.ChildByFieldName("value")
			}
			return n.ChildByFieldName("right")
		},
		extractAttrName: func(n *ast.Node) string {
			attr := n.ChildByFieldName("attribute")
			if attr != nil {
				return attr.Text()
			}
			return ""
		},
		extractAttrReceiver: func(n *ast.Node) string {
			obj := n.ChildByFieldName("object")
			if obj != nil {
				return obj.Text()
			}
			return ""
		},
		extractCallArgs: func(n *ast.Node) []*ast.Node {
			args := n.ChildByFieldName("arguments")
			if args == nil {
				return nil
			}
			var out []*ast.Node
			for i := 0; i < args.ChildCount(); i++ {
				c := args.Child(i)
				if c.IsNamed() {
					out = append(out, c)
				}
			}
			return out
		},
		extractFuncName: func(n *ast.Node) string {
			// decorated_definition wraps function_definition
			if n.Type() == "decorated_definition" {
				for i := 0; i < n.ChildCount(); i++ {
					c := n.Child(i)
					if c.Type() == "function_definition" {
						return pyFuncName(c)
					}
				}
				return ""
			}
			return pyFuncName(n)
		},
		extractFuncBody: func(n *ast.Node) *ast.Node {
			if n.Type() == "decorated_definition" {
				for i := 0; i < n.ChildCount(); i++ {
					c := n.Child(i)
					if c.Type() == "function_definition" {
						return pyResolveSuite(c, "body")
					}
				}
				return nil
			}
			return pyResolveSuite(n, "body")
		},
		extractFuncParams:    pyExtractParams,
		extractIfCondition:   pyExtractIfCondition,
		extractIfConsequence: pyExtractIfConsequence,
		extractIfAlternative: pyExtractIfAlternative,
	}
}

// pyResolveSuite returns the real `block` suite for a Python compound
// statement's body-like field (e.g. a function_definition's "body" or an
// if_statement's "consequence").
//
// tree-sitter-python has a parser quirk: when a suite's first physical line is a
// comment, the grammar assigns the body-like FIELD to the leading `comment`
// node and emits the real `block` suite as a SEPARATE child that carries the
// SAME field name. A plain `ChildByFieldName(fieldName)` therefore returns the
// childless `comment` node, and every statement in the suite (the whole
// function/if body) is silently dropped from Layer-3 dataflow — a severe,
// Python-only recall loss.
//
// This helper recovers the block in that case and is byte-identical otherwise:
// when the field already resolves to a `block` (the overwhelmingly common case)
// it is returned unchanged; only a field that landed on a `comment` triggers the
// sibling-block lookup. The lookup is scoped to the SAME field name, so an
// if_statement's "consequence" never resolves to an unrelated suite.
func pyResolveSuite(n *ast.Node, fieldName string) *ast.Node {
	field := n.ChildByFieldName(fieldName)
	if field == nil || field.Type() == "block" {
		return field
	}
	if field.Type() == "comment" {
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.Type() == "block" && c.FieldName() == fieldName {
				return c
			}
		}
	}
	return field
}

func pyExtractIfCondition(n *ast.Node) *ast.Node {
	return n.ChildByFieldName("condition")
}

func pyExtractIfConsequence(n *ast.Node) *ast.Node {
	// EXTENSION of the leading-comment suite fix: an if-body whose first line is
	// a comment puts the "consequence" field on the comment node and emits the
	// real block as a same-field sibling. processIfBranchAware walks ONLY the
	// consequence node (and `return false`s), so without this recovery the whole
	// if-body is dropped. Byte-identical when the consequence is already a block.
	return pyResolveSuite(n, "consequence")
}

func pyExtractIfAlternative(n *ast.Node) *ast.Node {
	// The "alternative" field resolves to an else_clause / elif_clause (never a
	// bare comment), and the walker descends those via its all-named-children
	// pass, so the leading-comment quirk does not drop else/elif bodies. Left
	// as a plain field access intentionally — verified no loss here.
	return n.ChildByFieldName("alternative")
}

func pyFuncName(n *ast.Node) string {
	name := n.ChildByFieldName("name")
	if name != nil {
		return name.Text()
	}
	return ""
}

func pyExtractParams(n *ast.Node) []string {
	fn := n
	if n.Type() == "decorated_definition" {
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.Type() == "function_definition" {
				fn = c
				break
			}
		}
	}
	params := fn.ChildByFieldName("parameters")
	if params == nil {
		return nil
	}
	var names []string
	for i := 0; i < params.ChildCount(); i++ {
		p := params.Child(i)
		if p.Type() == "identifier" {
			names = append(names, p.Text())
		} else if p.Type() == "typed_parameter" || p.Type() == "default_parameter" {
			nameNode := p.ChildByFieldName("name")
			if nameNode == nil {
				// fallback: first child
				nameNode = p.Child(0)
			}
			if nameNode != nil && nameNode.Type() == "identifier" {
				names = append(names, nameNode.Text())
			}
		}
	}
	return names
}

// ---------------------------------------------------------------------------
// JavaScript
// ---------------------------------------------------------------------------

func jsConfig() *langConfig {
	return &langConfig{
		language:          rules.LangJavaScript,
		instanceReceivers: map[string]bool{"this": true},
		// function_expression: named/anonymous function literals used as
		// callback arguments (Express, Mocha, Promise.then, etc.). Without
		// this, the walker never recurses into `app.get("/...", function
		// serveFile(req, res) { ... })` and multi-line indirection chains
		// like CVE-2017-1000220 (`const name = req.params.name; const full
		// = path.join(root, name); fs.readFile(full)`) are missed.
		// generator_function_declaration: `function* foo() {...}`.
		funcTypes: map[string]bool{"function_declaration": true, "function_expression": true, "generator_function_declaration": true, "arrow_function": true, "method_definition": true, "function": true},
		callTypes: map[string]bool{"call_expression": true, "new_expression": true},
		// augmented_assignment_expression: `q += tainted` is the dominant
		// JS/TS string-building idiom (SQL/HTML/shell concatenation). It shares
		// the `left`/`right` fields with assignment_expression, so the JS
		// extractors handle it unchanged. Without this entry the `+=` node is
		// never processed and an untainted-then-`+= param` accumulation is a
		// silent false negative (the desugared `q = q + param` is detected).
		// Mirrors PHP's config, which lists augmented_assignment_expression.
		// The untainted-RHS taint-clear is Python-gated (walker.go), so a base
		// `q = tainted; q += " safe"` correctly keeps its accumulated taint.
		assignTypes:  map[string]bool{"assignment_expression": true, "augmented_assignment_expression": true},
		varDeclTypes: map[string]bool{"variable_declarator": true},
		identType:    "identifier",
		attrTypes:    map[string]bool{"member_expression": true},
		ifTypes:      map[string]bool{"if_statement": true},

		extractCallName: func(n *ast.Node) string {
			fn := n.ChildByFieldName("function")
			if fn == nil {
				fn = n.ChildByFieldName("constructor") // new_expression fallback
			}
			if fn == nil {
				return ""
			}
			switch fn.Type() {
			case "identifier":
				return fn.Text()
			case "member_expression":
				prop := fn.ChildByFieldName("property")
				if prop != nil {
					return prop.Text()
				}
			}
			return ""
		},
		extractCallReceiver: func(n *ast.Node) string {
			fn := n.ChildByFieldName("function")
			if fn == nil {
				fn = n.ChildByFieldName("constructor") // new_expression fallback
			}
			if fn == nil {
				return ""
			}
			if fn.Type() == "member_expression" {
				obj := fn.ChildByFieldName("object")
				if obj != nil {
					return obj.Text()
				}
			}
			return ""
		},
		extractAssignLHS: func(n *ast.Node) string {
			lhs := n.ChildByFieldName("left")
			if lhs == nil {
				return ""
			}
			if lhs.Type() == "identifier" {
				return lhs.Text()
			}
			// Shallow field-sensitive LHS: `obj.attr = val` →
			// store under "obj.attr" so attribute reads at sinks can
			// resolve the per-field taint. Matches Python's behaviour.
			if lhs.Type() == "member_expression" {
				return lhs.Text()
			}
			return ""
		},
		extractAssignRHS: func(n *ast.Node) *ast.Node {
			return n.ChildByFieldName("right")
		},
		extractAttrName: func(n *ast.Node) string {
			prop := n.ChildByFieldName("property")
			if prop != nil {
				return prop.Text()
			}
			return ""
		},
		extractAttrReceiver: func(n *ast.Node) string {
			obj := n.ChildByFieldName("object")
			if obj != nil {
				return obj.Text()
			}
			return ""
		},
		extractCallArgs: jsExtractCallArgs,
		extractFuncName: func(n *ast.Node) string {
			name := n.ChildByFieldName("name")
			if name != nil {
				return name.Text()
			}
			return ""
		},
		extractFuncBody: func(n *ast.Node) *ast.Node {
			return n.ChildByFieldName("body")
		},
		extractFuncParams:    jsExtractParams,
		extractIfCondition:   genericExtractIfCondition,
		extractIfConsequence: genericExtractIfConsequence,
		extractIfAlternative: genericExtractIfAlternative,
		barrierGuards:        jsBarrierGuardConfig(),
	}
}

func jsExtractCallArgs(n *ast.Node) []*ast.Node {
	args := n.ChildByFieldName("arguments")
	if args == nil {
		return nil
	}
	var out []*ast.Node
	for i := 0; i < args.ChildCount(); i++ {
		c := args.Child(i)
		if c.IsNamed() {
			out = append(out, c)
		}
	}
	return out
}

func jsExtractParams(n *ast.Node) []string {
	params := n.ChildByFieldName("parameters")
	if params == nil {
		// arrow_function: first child might be params or single identifier
		params = n.ChildByFieldName("parameter")
		if params != nil && params.Type() == "identifier" {
			return []string{params.Text()}
		}
		return nil
	}
	var names []string
	for i := 0; i < params.ChildCount(); i++ {
		p := params.Child(i)
		if p.Type() == "identifier" {
			names = append(names, p.Text())
		} else if p.Type() == "assignment_pattern" {
			left := p.ChildByFieldName("left")
			if left != nil && left.Type() == "identifier" {
				names = append(names, left.Text())
			}
		}
	}
	return names
}

// ---------------------------------------------------------------------------
// TypeScript (inherits from JavaScript config)
// ---------------------------------------------------------------------------

func tsConfig() *langConfig {
	cfg := jsConfig()
	cfg.language = rules.LangTypeScript
	// TS adds typed_parameters but structure is compatible with JS extractors
	cfg.funcTypes["function_signature"] = true
	return cfg
}

// ---------------------------------------------------------------------------
// Java
// ---------------------------------------------------------------------------

func javaConfig() *langConfig {
	return &langConfig{
		language:          rules.LangJava,
		instanceReceivers: map[string]bool{"this": true},
		funcTypes:         map[string]bool{"method_declaration": true, "constructor_declaration": true},
		callTypes:         map[string]bool{"method_invocation": true, "object_creation_expression": true},
		assignTypes:       map[string]bool{"assignment_expression": true},
		varDeclTypes:      map[string]bool{"variable_declarator": true},
		identType:         "identifier",
		attrTypes:         map[string]bool{"field_access": true},
		ifTypes:           map[string]bool{"if_statement": true},

		extractCallName: func(n *ast.Node) string {
			name := n.ChildByFieldName("name")
			if name != nil {
				return name.Text()
			}
			// object_creation_expression: type is the "name"
			typ := n.ChildByFieldName("type")
			if typ != nil {
				return typ.Text()
			}
			return ""
		},
		extractCallReceiver: func(n *ast.Node) string {
			obj := n.ChildByFieldName("object")
			if obj != nil {
				return obj.Text()
			}
			return ""
		},
		extractAssignLHS: func(n *ast.Node) string {
			lhs := n.ChildByFieldName("left")
			if lhs == nil {
				return ""
			}
			if lhs.Type() == "identifier" {
				return lhs.Text()
			}
			// Shallow field-sensitive LHS: `obj.f = src` / `this.data = src`
			// parse to a `field_access` node whose Text() is the dotted path
			// ("obj.f", "this.data"). Returning that text seeds the per-field
			// key so a later attribute read (`stmt.executeQuery(obj.f)`,
			// resolved via prefixTainted) and a bare-object read (resolved via
			// anyFieldTainted, fromFieldAssign-stamped in processAssign) both
			// surface the taint — without tainting a sibling `obj.g`. Without
			// this branch the field write returned "" and the taint was
			// silently dropped (a missed detection). Mirrors the JS, C#, and
			// Python configs; the engine machinery is language-agnostic.
			if lhs.Type() == "field_access" {
				return lhs.Text()
			}
			return ""
		},
		extractAssignRHS: func(n *ast.Node) *ast.Node {
			return n.ChildByFieldName("right")
		},
		extractAttrName: func(n *ast.Node) string {
			field := n.ChildByFieldName("field")
			if field != nil {
				return field.Text()
			}
			return ""
		},
		extractAttrReceiver: func(n *ast.Node) string {
			obj := n.ChildByFieldName("object")
			if obj != nil {
				return obj.Text()
			}
			return ""
		},
		extractCallArgs: func(n *ast.Node) []*ast.Node {
			args := n.ChildByFieldName("arguments")
			if args == nil {
				return nil
			}
			var out []*ast.Node
			for i := 0; i < args.ChildCount(); i++ {
				c := args.Child(i)
				if c.IsNamed() {
					out = append(out, c)
				}
			}
			return out
		},
		extractFuncName: func(n *ast.Node) string {
			name := n.ChildByFieldName("name")
			if name != nil {
				return name.Text()
			}
			return ""
		},
		extractFuncBody: func(n *ast.Node) *ast.Node {
			return n.ChildByFieldName("body")
		},
		extractFuncParams:    javaExtractParams,
		extractIfCondition:   genericExtractIfCondition,
		extractIfConsequence: genericExtractIfConsequence,
		extractIfAlternative: genericExtractIfAlternative,
		barrierGuards:        javaBarrierGuardConfig(),
	}
}

func javaExtractParams(n *ast.Node) []string {
	params := n.ChildByFieldName("parameters")
	if params == nil {
		return nil
	}
	var names []string
	for i := 0; i < params.ChildCount(); i++ {
		p := params.Child(i)
		if p.Type() == "formal_parameter" || p.Type() == "spread_parameter" {
			name := p.ChildByFieldName("name")
			if name != nil {
				names = append(names, name.Text())
			}
		}
	}
	return names
}

// ---------------------------------------------------------------------------
// PHP
// ---------------------------------------------------------------------------

func phpConfig() *langConfig {
	return &langConfig{
		language:     rules.LangPHP,
		funcTypes:    map[string]bool{"function_definition": true, "method_declaration": true},
		callTypes:    map[string]bool{"function_call_expression": true, "member_call_expression": true, "scoped_call_expression": true, "object_creation_expression": true},
		assignTypes:  map[string]bool{"assignment_expression": true, "augmented_assignment_expression": true},
		varDeclTypes: map[string]bool{},
		identType:    "variable_name",
		attrTypes:    map[string]bool{"member_access_expression": true},
		ifTypes:      map[string]bool{"if_statement": true},

		extractCallName: func(n *ast.Node) string {
			// function_call_expression: function field
			fn := n.ChildByFieldName("function")
			if fn != nil {
				if fn.Type() == "name" || fn.Type() == "variable_name" {
					return fn.Text()
				}
				if fn.Type() == "qualified_name" {
					// Last name component
					for i := fn.ChildCount() - 1; i >= 0; i-- {
						c := fn.Child(i)
						if c.Type() == "name" {
							return c.Text()
						}
					}
				}
			}
			// member_call_expression: name field
			name := n.ChildByFieldName("name")
			if name != nil {
				return name.Text()
			}
			// object_creation_expression: "new ClassName(...)" — class name is a "name" child node
			if n.Type() == "object_creation_expression" {
				for i := 0; i < n.ChildCount(); i++ {
					c := n.Child(i)
					if c.Type() == "name" || c.Type() == "qualified_name" {
						return c.Text()
					}
				}
			}
			return ""
		},
		extractCallReceiver: func(n *ast.Node) string {
			obj := n.ChildByFieldName("object")
			if obj != nil {
				return obj.Text()
			}
			// scoped_call_expression (Class::method) — scope field holds the class name
			scope := n.ChildByFieldName("scope")
			if scope != nil {
				return scope.Text()
			}
			return ""
		},
		extractAssignLHS: func(n *ast.Node) string {
			lhs := n.ChildByFieldName("left")
			if lhs != nil && (lhs.Type() == "variable_name" || lhs.Type() == "name") {
				return lhs.Text()
			}
			return ""
		},
		extractAssignRHS: func(n *ast.Node) *ast.Node {
			return n.ChildByFieldName("right")
		},
		extractAttrName: func(n *ast.Node) string {
			name := n.ChildByFieldName("name")
			if name != nil {
				return name.Text()
			}
			return ""
		},
		extractAttrReceiver: func(n *ast.Node) string {
			obj := n.ChildByFieldName("object")
			if obj != nil {
				return obj.Text()
			}
			return ""
		},
		extractCallArgs: phpExtractCallArgs,
		extractFuncName: func(n *ast.Node) string {
			name := n.ChildByFieldName("name")
			if name != nil {
				return name.Text()
			}
			return ""
		},
		extractFuncBody: func(n *ast.Node) *ast.Node {
			return n.ChildByFieldName("body")
		},
		extractFuncParams:  phpExtractParams,
		extractIfCondition: genericExtractIfCondition,
		// PHP's if_statement names the consequence block "body" (not the
		// generic "consequence"), and the else side as an `else_clause` /
		// `else_if_clause` wrapper under "alternative". Use PHP-specific
		// extractors so branch-aware walking actually descends into the
		// if-body — the dominant guard idiom `if (isset($_GET['x'])) { ...
		// sink ... }` lives entirely inside that block.
		extractIfConsequence: phpExtractIfConsequence,
		extractIfAlternative: genericExtractIfAlternative,
		barrierGuards:        phpBarrierGuardConfig(),
	}
}

// phpExtractIfConsequence returns the consequence block of a PHP if_statement.
// Tree-sitter-php names it "body" rather than the "consequence" field used by
// most other grammars.
func phpExtractIfConsequence(n *ast.Node) *ast.Node {
	return n.ChildByFieldName("body")
}

func phpExtractCallArgs(n *ast.Node) []*ast.Node {
	args := n.ChildByFieldName("arguments")
	if args == nil {
		// object_creation_expression: arguments is a positional child, not a field
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.Type() == "arguments" {
				args = c
				break
			}
		}
	}
	if args == nil {
		return nil
	}
	var out []*ast.Node
	for i := 0; i < args.ChildCount(); i++ {
		c := args.Child(i)
		if c.IsNamed() {
			out = append(out, c)
		}
	}
	return out
}

func phpExtractParams(n *ast.Node) []string {
	params := n.ChildByFieldName("parameters")
	if params == nil {
		return nil
	}
	var names []string
	for i := 0; i < params.ChildCount(); i++ {
		p := params.Child(i)
		if p.Type() == "simple_parameter" || p.Type() == "variadic_parameter" || p.Type() == "property_promotion_parameter" {
			name := p.ChildByFieldName("name")
			if name != nil {
				names = append(names, name.Text())
			}
		}
	}
	return names
}

// ---------------------------------------------------------------------------
// Ruby
// ---------------------------------------------------------------------------

func rubyConfig() *langConfig {
	return &langConfig{
		language:     rules.LangRuby,
		funcTypes:    map[string]bool{"method": true, "singleton_method": true},
		callTypes:    map[string]bool{"call": true, "method_call": true},
		assignTypes:  map[string]bool{"assignment": true, "operator_assignment": true},
		varDeclTypes: map[string]bool{},
		identType:    "identifier",
		attrTypes:    map[string]bool{}, // Ruby attribute access is a method call
		ifTypes:      map[string]bool{"if": true},

		extractCallName: func(n *ast.Node) string {
			// Ruby call: object.method(args)
			method := n.ChildByFieldName("method")
			if method != nil {
				return method.Text()
			}
			// method_call: method(args) — bare function call
			methodNode := n.ChildByFieldName("method")
			if methodNode != nil {
				return methodNode.Text()
			}
			// Fallback: look for identifier children
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "identifier" {
					return c.Text()
				}
			}
			return ""
		},
		extractCallReceiver: func(n *ast.Node) string {
			recv := n.ChildByFieldName("receiver")
			if recv != nil {
				return recv.Text()
			}
			return ""
		},
		extractAssignLHS: func(n *ast.Node) string {
			lhs := n.ChildByFieldName("left")
			if lhs == nil {
				return ""
			}
			switch lhs.Type() {
			case "identifier":
				return lhs.Text()
			case "instance_variable", "class_variable", "global_variable":
				// `@q = ...`, `@@cache = ...`, `$g = ...`. These are plain
				// (dot-free) taint-map keys — `@q` reads resolve via the
				// instance_variable branch in nodeIsTainted (Ruby-gated).
				return lhs.Text()
			case "call":
				// Attribute setter `obj.cmd = ...`. Tree-sitter models a
				// Ruby attribute write as a `call` node whose receiver is the
				// object and whose method is the attribute name, with NO
				// argument list. Use the full text ("obj.cmd") as a shallow
				// field-sensitive key (isFieldKey splits on the dot), so
				// assigning `obj.cmd` does NOT taint a sibling `obj.other`.
				// Guard against real method calls (`obj.run(x)`): those have
				// an `arguments` field and must not be treated as an l-value.
				if lhs.ChildByFieldName("arguments") != nil {
					return ""
				}
				if recv := lhs.ChildByFieldName("receiver"); recv != nil {
					if m := lhs.ChildByFieldName("method"); m != nil {
						return recv.Text() + "." + m.Text()
					}
				}
				return ""
			}
			return ""
		},
		extractAssignRHS: func(n *ast.Node) *ast.Node {
			return n.ChildByFieldName("right")
		},
		extractAttrName: func(n *ast.Node) string {
			return "" // Ruby uses method calls for attribute access
		},
		extractAttrReceiver: func(n *ast.Node) string {
			return ""
		},
		extractCallArgs: func(n *ast.Node) []*ast.Node {
			args := n.ChildByFieldName("arguments")
			if args == nil {
				return nil
			}
			var out []*ast.Node
			for i := 0; i < args.ChildCount(); i++ {
				c := args.Child(i)
				if c.IsNamed() {
					out = append(out, c)
				}
			}
			return out
		},
		extractFuncName: func(n *ast.Node) string {
			// Regular method or singleton_method.
			name := n.ChildByFieldName("name")
			if name != nil {
				return name.Text()
			}
			// Sinatra/Roda DSL block: `get "/x" do |params| ... end`. The
			// node passed in is the wrapping `call` (parent of the
			// do_block) — use the call's method name as the scope name
			// so summaries are keyed deterministically.
			if n.Type() == "call" {
				m := n.ChildByFieldName("method")
				if m != nil {
					return m.Text()
				}
			}
			return ""
		},
		extractFuncBody: func(n *ast.Node) *ast.Node {
			// Regular method body.
			if b := n.ChildByFieldName("body"); b != nil {
				return b
			}
			// Sinatra/Roda DSL: the body is the do_block's body.
			if n.Type() == "call" {
				if blk := n.ChildByFieldName("block"); blk != nil {
					if b := blk.ChildByFieldName("body"); b != nil {
						return b
					}
					return blk
				}
			}
			return nil
		},
		extractFuncParams:    rubyExtractParams,
		extractIfCondition:   genericExtractIfCondition,
		extractIfConsequence: genericExtractIfConsequence,
		extractIfAlternative: genericExtractIfAlternative,
		findExtraScopes:      rubyFindDSLScopes,
		barrierGuards:        rubyBarrierGuardConfig(),
	}
}

// rubyDSLRouteVerbsTaint is the set of Sinatra/Roda HTTP-verb DSL
// handlers the tsflow walker treats as additional function-like scopes.
// Mirrors graph/extractor_ruby.go's rubyDSLRouteVerbs (the canonical
// list). Kept duplicated here to avoid an import cycle.
var rubyDSLRouteVerbsTaint = map[string]bool{
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

// rubyFindDSLScopes walks the tree-sitter Ruby tree and returns every
// Sinatra/Roda DSL route call (`get "/x" do ... end`, `post ...`, etc.)
// whose method name matches an HTTP verb AND has a `do_block`. These
// `call` nodes are then treated as analysis scopes by the walker — the
// block body carries the request-handling taint that would otherwise be
// invisible to the per-file tsflow walker because Sinatra apps don't
// wrap routes in a `def`.
//
// Conservative: only bare-name verbs at the program / class-body level.
// Receiver-style DSL calls (`Some::Router.get '/'`) are out of scope.
func rubyFindDSLScopes(root *ast.Node) []*ast.Node {
	if root == nil {
		return nil
	}
	var out []*ast.Node
	var visit func(n *ast.Node)
	visit = func(n *ast.Node) {
		if n == nil {
			return
		}
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c == nil || !c.IsNamed() {
				continue
			}
			switch c.Type() {
			case "method", "singleton_method":
				// Already covered by funcTypes — don't recurse into the
				// method body looking for nested DSL blocks (those would
				// be DSL inside a method, which is rare and not worth
				// modeling as a separate scope).
				continue
			case "class", "module":
				if body := c.ChildByFieldName("body"); body != nil {
					visit(body)
				}
			case "call":
				// Sinatra DSL detection.
				if recv := c.ChildByFieldName("receiver"); recv == nil {
					if m := c.ChildByFieldName("method"); m != nil {
						if rubyDSLRouteVerbsTaint[m.Text()] {
							if blk := c.ChildByFieldName("block"); blk != nil {
								out = append(out, c)
							}
						}
					}
				}
			default:
				visit(c)
			}
		}
	}
	visit(root)
	return out
}

func rubyExtractParams(n *ast.Node) []string {
	params := n.ChildByFieldName("parameters")
	if params == nil {
		// Sinatra/Roda DSL scope: a `call` node carrying a `do_block`. The
		// block parameters live on the do_block child, not on the call.
		if n.Type() == "call" {
			if blk := n.ChildByFieldName("block"); blk != nil {
				params = blk.ChildByFieldName("parameters")
			}
		}
		if params == nil {
			return nil
		}
	}
	var names []string
	for i := 0; i < params.ChildCount(); i++ {
		p := params.Child(i)
		if p.Type() == "identifier" {
			names = append(names, p.Text())
		} else if p.Type() == "optional_parameter" || p.Type() == "keyword_parameter" || p.Type() == "splat_parameter" || p.Type() == "hash_splat_parameter" {
			name := p.ChildByFieldName("name")
			if name != nil {
				names = append(names, name.Text())
			}
		}
	}
	return names
}

// ---------------------------------------------------------------------------
// C
// ---------------------------------------------------------------------------

func cConfig() *langConfig {
	return &langConfig{
		language:     rules.LangC,
		funcTypes:    map[string]bool{"function_definition": true},
		callTypes:    map[string]bool{"call_expression": true},
		assignTypes:  map[string]bool{"assignment_expression": true},
		varDeclTypes: map[string]bool{"init_declarator": true},
		identType:    "identifier",
		attrTypes:    map[string]bool{"field_expression": true},
		ifTypes:      map[string]bool{"if_statement": true},

		extractCallName: func(n *ast.Node) string {
			fn := n.ChildByFieldName("function")
			if fn == nil {
				return ""
			}
			if fn.Type() == "identifier" {
				return fn.Text()
			}
			// field_expression: obj.method or obj->method
			if fn.Type() == "field_expression" {
				f := fn.ChildByFieldName("field")
				if f != nil {
					return f.Text()
				}
			}
			return ""
		},
		extractCallReceiver: func(n *ast.Node) string {
			fn := n.ChildByFieldName("function")
			if fn != nil && fn.Type() == "field_expression" {
				arg := fn.ChildByFieldName("argument")
				if arg != nil {
					// A call-expression receiver — e.g. the inherited accessor
					// chain `request().get(...)` in CppCMS, or `foo().bar()` —
					// otherwise yields the full text "request()" (parens
					// included), which can never match a catalog ObjectType.
					// Use the CALLED function's name ("request") so the receiver
					// resolves to its base object. Plain receivers
					// (`obj.method()`) are unaffected.
					if arg.Type() == "call_expression" {
						if af := arg.ChildByFieldName("function"); af != nil {
							return af.Text()
						}
					}
					return arg.Text()
				}
			}
			return ""
		},
		extractAssignLHS: func(n *ast.Node) string {
			lhs := n.ChildByFieldName("left")
			if lhs != nil && lhs.Type() == "identifier" {
				return lhs.Text()
			}
			return ""
		},
		extractAssignRHS: func(n *ast.Node) *ast.Node {
			return n.ChildByFieldName("right")
		},
		extractAttrName: func(n *ast.Node) string {
			f := n.ChildByFieldName("field")
			if f != nil {
				return f.Text()
			}
			return ""
		},
		extractAttrReceiver: func(n *ast.Node) string {
			arg := n.ChildByFieldName("argument")
			if arg != nil {
				return arg.Text()
			}
			return ""
		},
		extractCallArgs:      genericExtractCallArgs,
		extractFuncName:      cExtractFuncName,
		extractFuncBody:      genericExtractFuncBody,
		extractFuncParams:    cExtractParams,
		extractIfCondition:   genericExtractIfCondition,
		extractIfConsequence: genericExtractIfConsequence,
		extractIfAlternative: genericExtractIfAlternative,
	}
}

func cExtractFuncName(n *ast.Node) string {
	decl := n.ChildByFieldName("declarator")
	if decl == nil {
		return ""
	}
	// function_declarator → declarator (identifier)
	if decl.Type() == "function_declarator" {
		inner := decl.ChildByFieldName("declarator")
		if inner != nil && inner.Type() == "identifier" {
			return inner.Text()
		}
	}
	// pointer_declarator wrapping function_declarator
	if decl.Type() == "pointer_declarator" {
		for i := 0; i < decl.ChildCount(); i++ {
			c := decl.Child(i)
			if c.Type() == "function_declarator" {
				inner := c.ChildByFieldName("declarator")
				if inner != nil && inner.Type() == "identifier" {
					return inner.Text()
				}
			}
		}
	}
	return ""
}

func cExtractParams(n *ast.Node) []string {
	decl := n.ChildByFieldName("declarator")
	if decl == nil {
		return nil
	}
	if decl.Type() == "pointer_declarator" {
		for i := 0; i < decl.ChildCount(); i++ {
			if decl.Child(i).Type() == "function_declarator" {
				decl = decl.Child(i)
				break
			}
		}
	}
	params := decl.ChildByFieldName("parameters")
	if params == nil {
		return nil
	}
	var names []string
	for i := 0; i < params.ChildCount(); i++ {
		p := params.Child(i)
		if p.Type() != "parameter_declaration" {
			continue
		}
		// The declarator may be a bare identifier (`int n`) or wrapped in a
		// pointer_declarator (`char *s`), reference_declarator (`const T &r`),
		// or array_declarator (`char *argv[]`). C/C++ parameters are positional,
		// so each parameter_declaration contributes exactly one slot — drill
		// through the wrappers with extractIdentText to recover the parameter
		// name. An unnamed parameter (`void f(int)`) yields "_" so later
		// parameters keep their correct positional index for arg→param
		// interprocedural mapping. Without this, pointer/reference/array params
		// (the overwhelmingly common C++ shape `void f(const std::string &s)`)
		// were dropped entirely, so the callee had no parameters and no
		// interprocedural arg→param→sink flow could be observed.
		d := p.ChildByFieldName("declarator")
		if d == nil {
			names = append(names, "_")
			continue
		}
		if name := extractIdentText(d, "identifier"); name != "" {
			names = append(names, name)
		} else {
			names = append(names, "_")
		}
	}
	return names
}

// ---------------------------------------------------------------------------
// C++
// ---------------------------------------------------------------------------

func cppConfig() *langConfig {
	cfg := cConfig()
	cfg.language = rules.LangCPP
	// C++ adds qualified names (namespace::function) and scope resolution.
	// tree-sitter-cpp parses `a::b::c` as right-leaning:
	//   qualified_identifier(scope=a, name=qualified_identifier(scope=b, name=c))
	// so we recurse through nested qualified_identifiers to reach the final
	// identifier and concatenate the scope chain.
	origExtractCallName := cfg.extractCallName
	cfg.extractCallName = func(n *ast.Node) string {
		fn := n.ChildByFieldName("function")
		if fn != nil && fn.Type() == "qualified_identifier" {
			cur := fn
			for cur != nil && cur.Type() == "qualified_identifier" {
				nm := cur.ChildByFieldName("name")
				if nm == nil {
					break
				}
				if nm.Type() == "qualified_identifier" {
					cur = nm
					continue
				}
				return nm.Text()
			}
		}
		return origExtractCallName(n)
	}
	// Extract namespace/scope as receiver for qualified_identifier calls
	// e.g., YAML::Load → receiver "YAML", boost::archive::text_iarchive → receiver "boost::archive",
	// crow::mustache::compile → receiver "crow::mustache".
	origExtractCallReceiver := cfg.extractCallReceiver
	cfg.extractCallReceiver = func(n *ast.Node) string {
		fn := n.ChildByFieldName("function")
		if fn != nil && fn.Type() == "qualified_identifier" {
			var parts []string
			cur := fn
			for cur != nil && cur.Type() == "qualified_identifier" {
				scope := cur.ChildByFieldName("scope")
				if scope != nil {
					parts = append(parts, scope.Text())
				}
				nm := cur.ChildByFieldName("name")
				if nm != nil && nm.Type() == "qualified_identifier" {
					cur = nm
					continue
				}
				break
			}
			if len(parts) > 0 {
				return strings.Join(parts, "::")
			}
		}
		return origExtractCallReceiver(n)
	}
	return cfg
}

// ---------------------------------------------------------------------------
// C#
// ---------------------------------------------------------------------------

func csharpConfig() *langConfig {
	return &langConfig{
		language:          rules.LangCSharp,
		instanceReceivers: map[string]bool{"this": true},
		funcTypes:         map[string]bool{"method_declaration": true, "local_function_statement": true, "constructor_declaration": true},
		callTypes:         map[string]bool{"invocation_expression": true, "object_creation_expression": true},
		assignTypes:       map[string]bool{"assignment_expression": true},
		varDeclTypes:      map[string]bool{"variable_declarator": true},
		identType:         "identifier",
		attrTypes:         map[string]bool{"member_access_expression": true},
		ifTypes:           map[string]bool{"if_statement": true},

		extractCallName: func(n *ast.Node) string {
			fn := n.ChildByFieldName("function")
			if fn != nil {
				if fn.Type() == "identifier" {
					return fn.Text()
				}
				if fn.Type() == "generic_name" {
					// Foo<T>() at call site — return bare identifier.
					if id := fn.ChildByFieldName("name"); id != nil {
						return id.Text()
					}
					if fn.ChildCount() > 0 {
						return fn.Child(0).Text()
					}
				}
				if fn.Type() == "member_access_expression" {
					name := fn.ChildByFieldName("name")
					if name != nil {
						// Strip generic type arguments: GetJsonAsync<object> -> GetJsonAsync.
						if name.Type() == "generic_name" {
							if id := name.ChildByFieldName("name"); id != nil {
								return id.Text()
							}
							if name.ChildCount() > 0 {
								return name.Child(0).Text()
							}
						}
						return name.Text()
					}
				}
			}
			// object_creation_expression: type field
			typ := n.ChildByFieldName("type")
			if typ != nil {
				return typ.Text()
			}
			return ""
		},
		extractCallReceiver: func(n *ast.Node) string {
			fn := n.ChildByFieldName("function")
			if fn != nil && fn.Type() == "member_access_expression" {
				expr := fn.ChildByFieldName("expression")
				if expr != nil {
					return expr.Text()
				}
			}
			return ""
		},
		extractAssignLHS: func(n *ast.Node) string {
			lhs := n.ChildByFieldName("left")
			if lhs == nil {
				return ""
			}
			switch lhs.Type() {
			case "identifier":
				return lhs.Text()
			case "member_access_expression":
				// Attribute write `obj.field = source` — mirror Ruby's
				// attribute-setter handling. Return the full dotted text
				// ("obj.field") as a shallow field-sensitive key (isFieldKey
				// splits on the dot), so assigning `obj.field` does NOT taint
				// a sibling `obj.other`. The receiver lives on field
				// "expression" and the attribute on field "name" (same shape
				// extractCallReceiver/extractAttrName above use).
				expr := lhs.ChildByFieldName("expression")
				name := lhs.ChildByFieldName("name")
				if expr != nil && name != nil {
					return expr.Text() + "." + name.Text()
				}
				// Fall back to the node's full text when the field shape is
				// unexpected; boundAccessPath / isFieldKey will normalise it.
				return lhs.Text()
			}
			return ""
		},
		extractAssignRHS: func(n *ast.Node) *ast.Node {
			return n.ChildByFieldName("right")
		},
		extractAttrName: func(n *ast.Node) string {
			name := n.ChildByFieldName("name")
			if name != nil {
				return name.Text()
			}
			return ""
		},
		extractAttrReceiver: func(n *ast.Node) string {
			expr := n.ChildByFieldName("expression")
			if expr != nil {
				return expr.Text()
			}
			return ""
		},
		extractCallArgs: func(n *ast.Node) []*ast.Node {
			args := n.ChildByFieldName("arguments")
			if args == nil {
				return nil
			}
			var out []*ast.Node
			for i := 0; i < args.ChildCount(); i++ {
				c := args.Child(i)
				if c.IsNamed() {
					out = append(out, c)
				}
			}
			return out
		},
		extractFuncName: func(n *ast.Node) string {
			name := n.ChildByFieldName("name")
			if name != nil {
				return name.Text()
			}
			return ""
		},
		extractFuncBody:      genericExtractFuncBody,
		extractFuncParams:    csharpExtractParams,
		extractIfCondition:   genericExtractIfCondition,
		extractIfConsequence: genericExtractIfConsequence,
		extractIfAlternative: genericExtractIfAlternative,
	}
}

func csharpExtractParams(n *ast.Node) []string {
	params := n.ChildByFieldName("parameters")
	if params == nil {
		return nil
	}
	var names []string
	for i := 0; i < params.ChildCount(); i++ {
		p := params.Child(i)
		if p.Type() == "parameter" {
			name := p.ChildByFieldName("name")
			if name != nil {
				names = append(names, name.Text())
			}
		}
	}
	return names
}

// ---------------------------------------------------------------------------
// Kotlin
// ---------------------------------------------------------------------------

func kotlinConfig() *langConfig {
	return &langConfig{
		language:     rules.LangKotlin,
		funcTypes:    map[string]bool{"function_declaration": true, "lambda_literal": true, "anonymous_function": true},
		callTypes:    map[string]bool{"call_expression": true},
		assignTypes:  map[string]bool{"assignment": true},
		varDeclTypes: map[string]bool{"property_declaration": true},
		identType:    "simple_identifier",
		attrTypes:    map[string]bool{"navigation_expression": true},
		ifTypes:      map[string]bool{"if_expression": true},

		extractCallName: func(n *ast.Node) string {
			// Kotlin call_expression: function part + call_suffix
			// The function part is the first child (identifier or navigation_expression)
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "simple_identifier" {
					return c.Text()
				}
				if c.Type() == "navigation_expression" {
					// Get the last simple_identifier in the navigation chain
					return lastIdentInNav(c)
				}
			}
			return ""
		},
		extractCallReceiver: func(n *ast.Node) string {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "navigation_expression" {
					// First child is the receiver
					if c.ChildCount() > 0 {
						return c.Child(0).Text()
					}
				}
			}
			return ""
		},
		extractAssignLHS: func(n *ast.Node) string {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "simple_identifier" {
					return c.Text()
				}
			}
			return ""
		},
		extractAssignRHS: func(n *ast.Node) *ast.Node {
			// RHS is typically the last named child after the "=" operator
			named := n.NamedChildren()
			if len(named) >= 2 {
				return named[len(named)-1]
			}
			return nil
		},
		extractAttrName: func(n *ast.Node) string {
			return lastIdentInNav(n)
		},
		extractAttrReceiver: func(n *ast.Node) string {
			if n.ChildCount() > 0 {
				return n.Child(0).Text()
			}
			return ""
		},
		extractCallArgs: kotlinExtractCallArgs,
		extractFuncName: func(n *ast.Node) string {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "simple_identifier" {
					return c.Text()
				}
			}
			return ""
		},
		extractFuncBody:      genericExtractFuncBody,
		extractFuncParams:    kotlinExtractParams,
		extractIfCondition:   genericExtractIfCondition,
		extractIfConsequence: genericExtractIfConsequence,
		extractIfAlternative: genericExtractIfAlternative,
	}
}

func lastIdentInNav(n *ast.Node) string {
	// Walk navigation_suffix children to find the last simple_identifier
	var last string
	n.Walk(func(child *ast.Node) bool {
		if child.Type() == "simple_identifier" {
			last = child.Text()
		}
		return true
	})
	return last
}

func kotlinExtractCallArgs(n *ast.Node) []*ast.Node {
	// call_suffix → value_arguments → value_argument
	var out []*ast.Node
	n.Walk(func(child *ast.Node) bool {
		if child.Type() == "value_argument" {
			v := child.ChildByFieldName("value")
			if v == nil {
				// Fallback: first named child
				named := child.NamedChildren()
				if len(named) > 0 {
					v = named[0]
				}
			}
			if v != nil {
				out = append(out, v)
			}
			return false
		}
		return true
	})
	return out
}

func kotlinExtractParams(n *ast.Node) []string {
	var names []string
	n.Walk(func(child *ast.Node) bool {
		if child.Type() == "parameter" {
			for i := 0; i < child.ChildCount(); i++ {
				c := child.Child(i)
				if c.Type() == "simple_identifier" {
					names = append(names, c.Text())
					break
				}
			}
			return false
		}
		return true
	})
	return names
}

// ---------------------------------------------------------------------------
// Rust
// ---------------------------------------------------------------------------

// rustUnwrapTurbofishMethod unwraps a `generic_function` node (a turbofish
// call such as `result.first_row_typed::<(String,)>()`) to the inner callee
// ONLY when that callee is a `field_expression` (i.e. a method call on a
// receiver). Method-call turbofish is the idiom data-extraction APIs use
// (scylla `rows_typed::<T>()`, redis `get::<T>()`), and was previously
// invisible to the matcher because the walker stopped at `generic_function`.
//
// Free-function turbofish (`serde_yaml::from_str::<Config>()`, inner =
// scoped_identifier) is deliberately NOT unwrapped: typed deserialization into
// a concrete struct is safe in Rust, and leaving those calls unmatched
// preserves that contract without a separate type-argument sanitizer.
func rustUnwrapTurbofishMethod(fn *ast.Node) *ast.Node {
	if fn != nil && fn.Type() == "generic_function" {
		if inner := fn.ChildByFieldName("function"); inner != nil && inner.Type() == "field_expression" {
			return inner
		}
	}
	return fn
}

func rustConfig() *langConfig {
	return &langConfig{
		language:          rules.LangRust,
		instanceReceivers: map[string]bool{"self": true},
		funcTypes:         map[string]bool{"function_item": true},
		callTypes:         map[string]bool{"call_expression": true},
		// compound_assignment_expr: `q += &tainted` is the dominant Rust
		// string-building idiom (String implements AddAssign<&str>), used to
		// assemble SQL/shell/URL strings. tree-sitter-rust parses it as a
		// distinct node from `assignment_expression`, but it shares the
		// `left`/`right` fields, so the Rust extractAssignLHS/RHS handle it
		// unchanged. Without this entry the `+=` node is never processed and an
		// untainted-then-`+= tainted` accumulation is a silent false negative
		// (the desugared `q = q + &tainted` form is already detected). Mirrors
		// the JS/PHP configs. The untainted-RHS taint-clear is Python-gated
		// (walker.go), so a base `q = tainted; q += " safe"` keeps its taint.
		assignTypes:  map[string]bool{"assignment_expression": true, "compound_assignment_expr": true},
		varDeclTypes: map[string]bool{"let_declaration": true},
		identType:    "identifier",
		attrTypes:    map[string]bool{"field_expression": true},
		ifTypes:      map[string]bool{"if_expression": true},

		extractCallName: func(n *ast.Node) string {
			fn := n.ChildByFieldName("function")
			fn = rustUnwrapTurbofishMethod(fn)
			if fn == nil {
				return ""
			}
			switch fn.Type() {
			case "identifier":
				return fn.Text()
			case "field_expression":
				f := fn.ChildByFieldName("field")
				if f != nil {
					return f.Text()
				}
			case "scoped_identifier":
				name := fn.ChildByFieldName("name")
				if name != nil {
					return name.Text()
				}
			}
			return ""
		},
		extractCallReceiver: func(n *ast.Node) string {
			fn := n.ChildByFieldName("function")
			fn = rustUnwrapTurbofishMethod(fn)
			if fn != nil && fn.Type() == "field_expression" {
				v := fn.ChildByFieldName("value")
				if v != nil {
					return v.Text()
				}
			}
			if fn != nil && fn.Type() == "scoped_identifier" {
				p := fn.ChildByFieldName("path")
				if p != nil {
					return p.Text()
				}
			}
			return ""
		},
		extractAssignLHS: func(n *ast.Node) string {
			lhs := n.ChildByFieldName("left")
			if lhs == nil {
				return ""
			}
			if lhs.Type() == "identifier" {
				return lhs.Text()
			}
			// Shallow field-sensitive LHS: `obj.f = src` / `self.data = src`
			// parse to a `field_expression` node whose Text() is the dotted
			// path ("obj.f", "self.data"). Returning that text seeds the
			// per-field key so a later field read (resolved via prefixTainted
			// on the attrTypes branch) and a bare-object read (resolved via
			// anyFieldTainted, fromFieldAssign-stamped in processAssign) both
			// surface the taint without tainting a sibling `obj.g`. Without
			// this branch the field write returned "" and the taint was
			// silently dropped (a missed detection). Mirrors the JS, C#, Java,
			// and Python configs; the engine machinery is language-agnostic.
			if lhs.Type() == "field_expression" {
				return lhs.Text()
			}
			return ""
		},
		extractAssignRHS: func(n *ast.Node) *ast.Node {
			return n.ChildByFieldName("right")
		},
		extractAttrName: func(n *ast.Node) string {
			f := n.ChildByFieldName("field")
			if f != nil {
				return f.Text()
			}
			return ""
		},
		extractAttrReceiver: func(n *ast.Node) string {
			v := n.ChildByFieldName("value")
			if v != nil {
				return v.Text()
			}
			return ""
		},
		extractCallArgs: func(n *ast.Node) []*ast.Node {
			args := n.ChildByFieldName("arguments")
			if args == nil {
				return nil
			}
			var out []*ast.Node
			for i := 0; i < args.ChildCount(); i++ {
				c := args.Child(i)
				if c.IsNamed() {
					out = append(out, c)
				}
			}
			return out
		},
		extractFuncName: func(n *ast.Node) string {
			name := n.ChildByFieldName("name")
			if name != nil {
				return name.Text()
			}
			return ""
		},
		extractFuncBody:      genericExtractFuncBody,
		extractFuncParams:    rustExtractParams,
		extractIfCondition:   genericExtractIfCondition,
		extractIfConsequence: genericExtractIfConsequence,
		extractIfAlternative: genericExtractIfAlternative,
	}
}

func rustExtractParams(n *ast.Node) []string {
	params := n.ChildByFieldName("parameters")
	if params == nil {
		return nil
	}
	var names []string
	for i := 0; i < params.ChildCount(); i++ {
		p := params.Child(i)
		if p.Type() == "parameter" {
			pat := p.ChildByFieldName("pattern")
			if pat == nil {
				continue
			}
			switch pat.Type() {
			case "identifier":
				names = append(names, pat.Text())
			case "tuple_struct_pattern":
				// Handles Axum extractors like Query(params), Path(id), Json(body)
				rustCollectIdentifiers(pat, &names)
			case "tuple_pattern":
				// Handles (a, b) destructuring
				rustCollectIdentifiers(pat, &names)
			}
		}
	}
	return names
}

// rustCollectIdentifiers recursively collects identifier names from a pattern node.
func rustCollectIdentifiers(n *ast.Node, names *[]string) {
	if n == nil {
		return
	}
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c.Type() == "identifier" {
			text := c.Text()
			// Skip the type name in tuple_struct_pattern (e.g., "Query" in "Query(params)")
			if i == 0 && n.Type() == "tuple_struct_pattern" {
				continue
			}
			*names = append(*names, text)
		} else if c.IsNamed() {
			rustCollectIdentifiers(c, names)
		}
	}
}

// ---------------------------------------------------------------------------
// Swift
// ---------------------------------------------------------------------------

func swiftConfig() *langConfig {
	return &langConfig{
		language:     rules.LangSwift,
		funcTypes:    map[string]bool{"function_declaration": true},
		callTypes:    map[string]bool{"call_expression": true},
		assignTypes:  map[string]bool{"assignment": true},
		varDeclTypes: map[string]bool{"property_declaration": true},
		identType:    "simple_identifier",
		attrTypes:    map[string]bool{"navigation_expression": true},
		ifTypes:      map[string]bool{"if_statement": true},

		extractCallName: func(n *ast.Node) string {
			// Swift call_expression: function_expression + call_suffix
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "simple_identifier" {
					return c.Text()
				}
				if c.Type() == "navigation_expression" {
					return lastNavSuffix(c)
				}
			}
			return ""
		},
		extractCallReceiver: func(n *ast.Node) string {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "navigation_expression" {
					target := c.ChildByFieldName("target")
					if target != nil {
						return target.Text()
					}
				}
			}
			return ""
		},
		extractAssignLHS: func(n *ast.Node) string {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "simple_identifier" {
					return c.Text()
				}
			}
			return ""
		},
		extractAssignRHS: func(n *ast.Node) *ast.Node {
			named := n.NamedChildren()
			if len(named) >= 2 {
				return named[len(named)-1]
			}
			return nil
		},
		extractAttrName: func(n *ast.Node) string {
			return lastNavSuffix(n)
		},
		extractAttrReceiver: func(n *ast.Node) string {
			target := n.ChildByFieldName("target")
			if target != nil {
				return target.Text()
			}
			return ""
		},
		extractCallArgs: swiftExtractCallArgs,
		extractFuncName: func(n *ast.Node) string {
			name := n.ChildByFieldName("name")
			if name != nil {
				return name.Text()
			}
			return ""
		},
		extractFuncBody:      genericExtractFuncBody,
		extractFuncParams:    swiftExtractParams,
		extractIfCondition:   genericExtractIfCondition,
		extractIfConsequence: genericExtractIfConsequence,
		extractIfAlternative: genericExtractIfAlternative,
	}
}

func lastNavSuffix(n *ast.Node) string {
	var last string
	n.Walk(func(child *ast.Node) bool {
		if child.Type() == "navigation_suffix" {
			for i := 0; i < child.ChildCount(); i++ {
				c := child.Child(i)
				if c.Type() == "simple_identifier" {
					last = c.Text()
				}
			}
		}
		return true
	})
	return last
}

func swiftExtractCallArgs(n *ast.Node) []*ast.Node {
	var out []*ast.Node
	n.Walk(func(child *ast.Node) bool {
		if child.Type() == "value_argument" {
			v := child.ChildByFieldName("value")
			if v == nil {
				named := child.NamedChildren()
				if len(named) > 0 {
					v = named[len(named)-1]
				}
			}
			if v != nil {
				out = append(out, v)
			}
			return false
		}
		return true
	})
	return out
}

func swiftExtractParams(n *ast.Node) []string {
	var names []string
	n.Walk(func(child *ast.Node) bool {
		if child.Type() == "parameter" {
			for i := 0; i < child.ChildCount(); i++ {
				c := child.Child(i)
				if c.Type() == "simple_identifier" {
					names = append(names, c.Text())
					break
				}
			}
			return false
		}
		return true
	})
	return names
}

// ---------------------------------------------------------------------------
// Lua
// ---------------------------------------------------------------------------

func luaConfig() *langConfig {
	return &langConfig{
		language:     rules.LangLua,
		funcTypes:    map[string]bool{"function_statement": true, "local_function_statement": true},
		callTypes:    map[string]bool{"function_call": true},
		assignTypes:  map[string]bool{"variable_assignment": true},
		varDeclTypes: map[string]bool{"variable_declaration": true},
		identType:    "identifier",
		attrTypes:    map[string]bool{"dot_index_expression": true},
		ifTypes:      map[string]bool{"if_statement": true},

		extractCallName: func(n *ast.Node) string {
			// Lua function_call: prefix contains the function expression.
			// Dot calls: identifier("os"), ".", identifier("execute") → "execute"
			// Colon calls: identifier("conn"), self_call_colon(":"), identifier("search") → "search"
			// The last identifier child is the method name in both cases.
			var last string
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				switch c.Type() {
				case "dot_index_expression":
					last = luaDotLast(c)
				case "identifier":
					last = c.Text()
				}
			}
			return last
		},
		extractCallReceiver: func(n *ast.Node) string {
			// Handle dot_index_expression children.
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "dot_index_expression" {
					table := c.ChildByFieldName("table")
					if table != nil {
						return table.Text()
					}
				}
			}
			// Flat structure: identifier + separator + identifier + args.
			// Works for both dot calls (identifier "." identifier) and
			// colon calls (identifier self_call_colon identifier).
			for i := 0; i+2 < n.ChildCount(); i++ {
				c := n.Child(i)
				sep := n.Child(i + 1)
				next := n.Child(i + 2)
				if c.Type() == "identifier" &&
					(sep.Type() == "." || sep.Type() == "self_call_colon") &&
					next.Type() == "identifier" {
					return c.Text()
				}
			}
			return ""
		},
		extractAssignLHS: func(n *ast.Node) string {
			// variable_assignment: first named child is variable_list
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "variable_list" || c.FieldName() == "name" {
					for j := 0; j < c.ChildCount(); j++ {
						cc := c.Child(j)
						if cc.Type() == "identifier" {
							return cc.Text()
						}
					}
					if c.Type() == "identifier" {
						return c.Text()
					}
				}
			}
			return ""
		},
		extractAssignRHS: func(n *ast.Node) *ast.Node {
			// Last named child is the expression_list or value
			named := n.NamedChildren()
			if len(named) >= 2 {
				rhs := named[len(named)-1]
				// expression_list: return first child
				if rhs.Type() == "expression_list" && rhs.ChildCount() > 0 {
					for i := 0; i < rhs.ChildCount(); i++ {
						c := rhs.Child(i)
						if c.IsNamed() {
							return c
						}
					}
				}
				return rhs
			}
			return nil
		},
		extractAttrName: func(n *ast.Node) string {
			return luaDotLast(n)
		},
		extractAttrReceiver: func(n *ast.Node) string {
			table := n.ChildByFieldName("table")
			if table != nil {
				return table.Text()
			}
			return ""
		},
		extractCallArgs: func(n *ast.Node) []*ast.Node {
			// function_arguments child
			var out []*ast.Node
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "arguments" || c.Type() == "function_arguments" {
					for j := 0; j < c.ChildCount(); j++ {
						cc := c.Child(j)
						if cc.IsNamed() {
							out = append(out, cc)
						}
					}
					return out
				}
			}
			return nil
		},
		extractFuncName: func(n *ast.Node) string {
			name := n.ChildByFieldName("name")
			if name != nil {
				if name.Type() == "identifier" {
					return name.Text()
				}
				// function_name may contain dot-separated parts
				for i := 0; i < name.ChildCount(); i++ {
					c := name.Child(i)
					if c.Type() == "identifier" {
						return c.Text()
					}
				}
			}
			return ""
		},
		extractFuncBody: func(n *ast.Node) *ast.Node {
			if body := n.ChildByFieldName("body"); body != nil {
				return body
			}
			// Lua: function_body is a child type, not a named field.
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "function_body" {
					return c
				}
			}
			return nil
		},
		extractFuncParams:    luaExtractParams,
		extractIfCondition:   genericExtractIfCondition,
		extractIfConsequence: genericExtractIfConsequence,
		extractIfAlternative: genericExtractIfAlternative,
	}
}

func luaDotLast(n *ast.Node) string {
	field := n.ChildByFieldName("field")
	if field != nil {
		return field.Text()
	}
	return ""
}

func luaExtractParams(n *ast.Node) []string {
	var params *ast.Node
	// function_statement: body contains parameter_list
	n.Walk(func(child *ast.Node) bool {
		if child.Type() == "parameters" {
			params = child
			return false
		}
		return true
	})
	if params == nil {
		return nil
	}
	var names []string
	for i := 0; i < params.ChildCount(); i++ {
		p := params.Child(i)
		if p.Type() == "identifier" {
			names = append(names, p.Text())
		}
	}
	return names
}

// ---------------------------------------------------------------------------
// Groovy
// ---------------------------------------------------------------------------

func groovyConfig() *langConfig {
	return &langConfig{
		language:     rules.LangGroovy,
		funcTypes:    map[string]bool{"function_definition": true, "method_definition": true},
		callTypes:    map[string]bool{"function_call": true},
		assignTypes:  map[string]bool{"assignment": true},
		varDeclTypes: map[string]bool{"declaration": true},
		identType:    "identifier",
		attrTypes:    map[string]bool{"dotted_identifier": true},
		ifTypes:      map[string]bool{"if_statement": true},

		extractCallName: func(n *ast.Node) string {
			fn := n.ChildByFieldName("function")
			if fn == nil {
				return ""
			}
			if fn.Type() == "identifier" {
				return fn.Text()
			}
			if fn.Type() == "dotted_identifier" {
				// Last identifier in the chain
				var last string
				for i := 0; i < fn.ChildCount(); i++ {
					c := fn.Child(i)
					if c.Type() == "identifier" {
						last = c.Text()
					}
				}
				return last
			}
			return ""
		},
		extractCallReceiver: func(n *ast.Node) string {
			fn := n.ChildByFieldName("function")
			if fn != nil && fn.Type() == "dotted_identifier" {
				// First identifier is the receiver
				for i := 0; i < fn.ChildCount(); i++ {
					c := fn.Child(i)
					if c.Type() == "identifier" {
						return c.Text()
					}
				}
			}
			return ""
		},
		extractAssignLHS: func(n *ast.Node) string {
			lhs := n.ChildByFieldName("left")
			if lhs != nil && lhs.Type() == "identifier" {
				return lhs.Text()
			}
			return ""
		},
		extractAssignRHS: func(n *ast.Node) *ast.Node {
			return n.ChildByFieldName("right")
		},
		extractAttrName: func(n *ast.Node) string {
			// Last identifier in dotted chain
			var last string
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "identifier" {
					last = c.Text()
				}
			}
			return last
		},
		extractAttrReceiver: func(n *ast.Node) string {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "identifier" {
					return c.Text()
				}
			}
			return ""
		},
		extractCallArgs: func(n *ast.Node) []*ast.Node {
			args := n.ChildByFieldName("args")
			if args == nil {
				return nil
			}
			var out []*ast.Node
			for i := 0; i < args.ChildCount(); i++ {
				c := args.Child(i)
				if c.IsNamed() {
					out = append(out, c)
				}
			}
			return out
		},
		extractFuncName: func(n *ast.Node) string {
			fn := n.ChildByFieldName("function")
			if fn != nil {
				return fn.Text()
			}
			name := n.ChildByFieldName("name")
			if name != nil {
				return name.Text()
			}
			return ""
		},
		extractFuncBody:      genericExtractFuncBody,
		extractFuncParams:    groovyExtractParams,
		extractIfCondition:   genericExtractIfCondition,
		extractIfConsequence: genericExtractIfConsequence,
		extractIfAlternative: genericExtractIfAlternative,
	}
}

func groovyExtractParams(n *ast.Node) []string {
	params := n.ChildByFieldName("parameters")
	if params == nil {
		return nil
	}
	var names []string
	for i := 0; i < params.ChildCount(); i++ {
		p := params.Child(i)
		if p.Type() == "parameter" || p.Type() == "identifier" {
			name := p.ChildByFieldName("name")
			if name != nil {
				names = append(names, name.Text())
			} else if p.Type() == "identifier" {
				names = append(names, p.Text())
			}
		}
	}
	return names
}

// ---------------------------------------------------------------------------
// Perl
// ---------------------------------------------------------------------------

func perlConfig() *langConfig {
	return &langConfig{
		language:  rules.LangPerl,
		funcTypes: map[string]bool{"subroutine_declaration_statement": true},
		ifTypes:   map[string]bool{"if_statement": true},
		callTypes: map[string]bool{
			"function_call_expression":           true,
			"method_call_expression":             true,
			"ambiguous_function_call_expression": true,
			"eval_expression":                    true,
			"substitution_regexp":                true, // s///e — replacement evaluated as code
		},
		assignTypes:  map[string]bool{"assignment_expression": true},
		varDeclTypes: map[string]bool{},
		identType:    "varname",
		attrTypes:    map[string]bool{"hash_element_expression": true, "array_element_expression": true},

		extractCallName: func(n *ast.Node) string {
			switch n.Type() {
			case "method_call_expression":
				m := n.ChildByFieldName("method")
				if m != nil {
					return m.Text()
				}
			case "function_call_expression", "ambiguous_function_call_expression":
				fn := n.ChildByFieldName("function")
				if fn != nil {
					return fn.Text()
				}
			case "eval_expression":
				return "eval"
			case "substitution_regexp":
				// s/pattern/replacement/e — only flag when /e modifier is present
				// (the replacement is evaluated as Perl code).
				for i := 0; i < n.ChildCount(); i++ {
					c := n.Child(i)
					if c.Type() == "substitution_regexp_modifiers" {
						mods := c.Text()
						for _, ch := range mods {
							if ch == 'e' {
								return "subst_eval"
							}
						}
					}
				}
				return "" // no /e modifier — not a code execution sink
			}
			return ""
		},
		extractCallReceiver: func(n *ast.Node) string {
			if n.Type() != "method_call_expression" {
				return ""
			}
			inv := n.ChildByFieldName("invocant")
			if inv == nil {
				return ""
			}
			return perlVarName(inv)
		},
		extractAssignLHS: func(n *ast.Node) string {
			lhs := n.ChildByFieldName("left")
			if lhs == nil {
				return ""
			}
			// my $x = ... → variable_declaration wrapping a scalar
			if lhs.Type() == "variable_declaration" {
				v := lhs.ChildByFieldName("variable")
				if v == nil {
					v = lhs.ChildByFieldName("variables")
				}
				if v != nil {
					return perlVarName(v)
				}
				// Fallback: find first scalar child
				for i := 0; i < lhs.ChildCount(); i++ {
					c := lhs.Child(i)
					if c.Type() == "scalar" || c.Type() == "array" || c.Type() == "hash" {
						return perlVarName(c)
					}
				}
				return ""
			}
			return perlVarName(lhs)
		},
		extractAssignRHS: func(n *ast.Node) *ast.Node {
			return n.ChildByFieldName("right")
		},
		extractAttrName: func(n *ast.Node) string {
			// hash_element_expression: return "%VARNAME" to match catalog entries like "%ENV"
			if n.Type() == "hash_element_expression" {
				h := n.ChildByFieldName("hash")
				if h != nil {
					name := perlVarName(h)
					if name != "" {
						return "%" + name
					}
				}
				return ""
			}
			// array_element_expression: return "@VARNAME" to match catalog entries like "@ARGV"
			if n.Type() == "array_element_expression" {
				a := n.ChildByFieldName("array")
				if a != nil {
					name := perlVarName(a)
					if name != "" {
						return "@" + name
					}
				}
				return ""
			}
			return ""
		},
		extractAttrReceiver: func(n *ast.Node) string {
			if n.Type() == "hash_element_expression" {
				h := n.ChildByFieldName("hash")
				if h != nil {
					return perlVarName(h)
				}
			}
			if n.Type() == "array_element_expression" {
				a := n.ChildByFieldName("array")
				if a != nil {
					return perlVarName(a)
				}
			}
			return ""
		},
		extractCallArgs: perlExtractCallArgs,
		extractFuncName: func(n *ast.Node) string {
			name := n.ChildByFieldName("name")
			if name != nil {
				return name.Text()
			}
			return ""
		},
		extractFuncBody: func(n *ast.Node) *ast.Node {
			return n.ChildByFieldName("body")
		},
		extractFuncParams:    perlExtractParams,
		extractIfCondition:   genericExtractIfCondition,
		extractIfConsequence: genericExtractIfConsequence,
		extractIfAlternative: genericExtractIfAlternative,
	}
}

// perlVarName extracts the bare variable name from a Perl variable node.
// Handles scalar ($x), array (@a), hash (%h), container_variable, and bareword nodes.
func perlVarName(n *ast.Node) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "scalar", "array", "hash", "container_variable":
		// These nodes contain a sigil child (anon) and a varname child (named).
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.Type() == "varname" {
				return c.Text()
			}
		}
	case "bareword":
		return n.Text()
	case "varname":
		return n.Text()
	}
	// Fallback: try to find a varname descendant.
	var name string
	n.Walk(func(c *ast.Node) bool {
		if c.Type() == "varname" {
			name = c.Text()
			return false
		}
		return true
	})
	return name
}

func perlExtractCallArgs(n *ast.Node) []*ast.Node {
	// eval_expression: arguments are unnamed named children (skip the 'eval' keyword)
	if n.Type() == "eval_expression" {
		var out []*ast.Node
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.IsNamed() {
				out = append(out, c)
			}
		}
		return out
	}

	// substitution_regexp (s///e): the "replacement" child is evaluated as code.
	// Extract named children of the replacement node as taint-trackable arguments.
	if n.Type() == "substitution_regexp" {
		for i := 0; i < n.ChildCount(); i++ {
			c := n.Child(i)
			if c.Type() == "replacement" {
				var out []*ast.Node
				for j := 0; j < c.ChildCount(); j++ {
					gc := c.Child(j)
					if gc.IsNamed() {
						out = append(out, gc)
					}
				}
				return out
			}
		}
		return nil
	}

	args := n.ChildByFieldName("arguments")
	if args == nil {
		return nil
	}

	// If arguments is a list_expression, return its named children.
	if args.Type() == "list_expression" {
		var out []*ast.Node
		for i := 0; i < args.ChildCount(); i++ {
			c := args.Child(i)
			if c.IsNamed() {
				out = append(out, c)
			}
		}
		return out
	}

	// Single argument.
	return []*ast.Node{args}
}

func perlExtractParams(n *ast.Node) []string {
	// Modern Perl signatures: sub foo ($name, $age) { ... }
	// Look for a signature or prototype_or_signature child.
	var sigNode *ast.Node
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		if c.Type() == "signature" || c.Type() == "prototype_or_signature" {
			sigNode = c
			break
		}
	}
	if sigNode == nil {
		return nil
	}
	var names []string
	sigNode.Walk(func(c *ast.Node) bool {
		if c.Type() == "varname" {
			names = append(names, c.Text())
		}
		return true
	})
	return names
}

// ---------------------------------------------------------------------------
// Zig
// TODO: Exact node types should be verified against tree-sitter-zig grammar
// once the binding is integrated. The types below are based on the
// tree-sitter-zig grammar (maxxnino/tree-sitter-zig).
// ---------------------------------------------------------------------------

func zigConfig() *langConfig {
	return &langConfig{
		language:     rules.LangZig,
		funcTypes:    map[string]bool{"function_declaration": true},
		callTypes:    map[string]bool{"call_expression": true, "builtin_call_expression": true},
		assignTypes:  map[string]bool{"assignment_expression": true},
		varDeclTypes: map[string]bool{"variable_declaration": true},
		identType:    "identifier",
		attrTypes:    map[string]bool{"field_expression": true},
		ifTypes:      map[string]bool{"if_expression": true},

		extractCallName: func(n *ast.Node) string {
			fn := n.ChildByFieldName("function")
			if fn == nil {
				// builtin_call_expression: look for builtin identifier (e.g., @ptrCast)
				for i := 0; i < n.ChildCount(); i++ {
					c := n.Child(i)
					if c.Type() == "builtin_identifier" || c.Type() == "identifier" {
						return c.Text()
					}
				}
				return ""
			}
			switch fn.Type() {
			case "identifier":
				return fn.Text()
			case "field_expression":
				f := fn.ChildByFieldName("field")
				if f != nil {
					return f.Text()
				}
			}
			return ""
		},
		extractCallReceiver: func(n *ast.Node) string {
			fn := n.ChildByFieldName("function")
			if fn != nil && fn.Type() == "field_expression" {
				obj := fn.ChildByFieldName("operand")
				if obj == nil {
					// Fallback: try "value" field name used by some grammar versions
					obj = fn.ChildByFieldName("value")
				}
				if obj != nil {
					return obj.Text()
				}
			}
			return ""
		},
		extractAssignLHS: func(n *ast.Node) string {
			lhs := n.ChildByFieldName("left")
			if lhs != nil && lhs.Type() == "identifier" {
				return lhs.Text()
			}
			return ""
		},
		extractAssignRHS: func(n *ast.Node) *ast.Node {
			return n.ChildByFieldName("right")
		},
		extractAttrName: func(n *ast.Node) string {
			f := n.ChildByFieldName("field")
			if f != nil {
				return f.Text()
			}
			return ""
		},
		extractAttrReceiver: func(n *ast.Node) string {
			obj := n.ChildByFieldName("operand")
			if obj == nil {
				obj = n.ChildByFieldName("value")
			}
			if obj != nil {
				return obj.Text()
			}
			return ""
		},
		extractCallArgs: func(n *ast.Node) []*ast.Node {
			args := n.ChildByFieldName("arguments")
			if args == nil {
				return nil
			}
			var out []*ast.Node
			for i := 0; i < args.ChildCount(); i++ {
				c := args.Child(i)
				if c.IsNamed() {
					out = append(out, c)
				}
			}
			return out
		},
		extractFuncName: func(n *ast.Node) string {
			name := n.ChildByFieldName("name")
			if name != nil {
				return name.Text()
			}
			return ""
		},
		extractFuncBody:      genericExtractFuncBody,
		extractFuncParams:    zigExtractParams,
		extractIfCondition:   genericExtractIfCondition,
		extractIfConsequence: genericExtractIfConsequence,
		extractIfAlternative: genericExtractIfAlternative,
	}
}

func zigExtractParams(n *ast.Node) []string {
	params := n.ChildByFieldName("parameters")
	if params == nil {
		return nil
	}
	var names []string
	for i := 0; i < params.ChildCount(); i++ {
		p := params.Child(i)
		if p.Type() == "parameter" || p.Type() == "parameter_declaration" {
			name := p.ChildByFieldName("name")
			if name != nil && name.Type() == "identifier" {
				names = append(names, name.Text())
			}
		}
	}
	return names
}

// ---------------------------------------------------------------------------
// Shell / Bash (tree-sitter-bash grammar)
//
// Node types verified against smacker/go-tree-sitter/bash by parsing sample
// scripts:
//   - command:              command_name(field "name") + args(field "argument")
//   - command_name:         wraps a `word` whose text is the command (eval, curl…)
//   - variable_assignment:  variable_name(field "name") "=" value(field "value")
//   - command_substitution: $(...) and `...`
//   - simple_expansion:     $x / $1 ;  expansion: ${x}
//   - function_definition:  name(field "name", a word) + body(field "body")
//   - if_statement:         condition(field "condition") + body commands
//
// Matching model: the walker resolves a call's name via extractCallName, which
// for a `command` node returns the command word (eval, sh, cp, curl, …). The
// shell catalog's sink/source MethodName carries that bare command word, so
// receiver-less command sinks fire. Variable expansions ($1, $VAR) are not
// call nodes; those sources are caught by the regex-fallback engine via their
// verified Pattern.
// ---------------------------------------------------------------------------

func shellConfig() *langConfig {
	return &langConfig{
		language:     rules.LangShell,
		funcTypes:    map[string]bool{"function_definition": true},
		callTypes:    map[string]bool{"command": true},
		assignTypes:  map[string]bool{"variable_assignment": true},
		varDeclTypes: map[string]bool{},
		identType:    "variable_name",
		attrTypes:    map[string]bool{},
		ifTypes:      map[string]bool{"if_statement": true},

		extractCallName: func(n *ast.Node) string {
			// command → command_name(field "name") → word
			cn := n.ChildByFieldName("name")
			if cn == nil {
				// Fallback: first command_name child.
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
				// Unwrap to the inner word/identifier text.
				for i := 0; i < cn.ChildCount(); i++ {
					c := cn.Child(i)
					if c.Type() == "word" || c.Type() == "command_name" {
						return c.Text()
					}
				}
				return cn.Text()
			}
			return cn.Text()
		},
		// Shell commands have no method receiver/object.
		extractCallReceiver: func(n *ast.Node) string {
			return ""
		},
		extractAssignLHS: func(n *ast.Node) string {
			lhs := n.ChildByFieldName("name")
			if lhs != nil && lhs.Type() == "variable_name" {
				return lhs.Text()
			}
			return ""
		},
		extractAssignRHS: func(n *ast.Node) *ast.Node {
			return n.ChildByFieldName("value")
		},
		extractAttrName: func(n *ast.Node) string {
			return ""
		},
		extractAttrReceiver: func(n *ast.Node) string {
			return ""
		},
		extractCallArgs: func(n *ast.Node) []*ast.Node {
			// command arguments are children carried under the "argument"
			// field (word / string / simple_expansion / concatenation / …).
			var out []*ast.Node
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.FieldName() == "argument" {
					out = append(out, c)
				}
			}
			return out
		},
		extractFuncName: func(n *ast.Node) string {
			// Synthetic top-level scope (the program root).
			if n.Type() == "program" {
				return "__toplevel__"
			}
			name := n.ChildByFieldName("name")
			if name != nil {
				return name.Text()
			}
			return ""
		},
		extractFuncBody: func(n *ast.Node) *ast.Node {
			// Synthetic top-level scope: the program node IS its own body.
			if n.Type() == "program" {
				return n
			}
			if body := n.ChildByFieldName("body"); body != nil {
				return body
			}
			// Fallback: compound_statement child.
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "compound_statement" {
					return c
				}
			}
			return nil
		},
		// Bash functions have no formal parameter list; positional params
		// ($1, $2, …) are referenced directly inside the body.
		extractFuncParams: func(n *ast.Node) []string {
			return nil
		},
		extractIfCondition:   genericExtractIfCondition,
		extractIfConsequence: genericExtractIfConsequence,
		extractIfAlternative: genericExtractIfAlternative,
		findExtraScopes:      shellFindTopLevelScope,
	}
}

// shellFindTopLevelScope returns the `program` root node as a synthetic
// analysis scope. Unlike most languages, the bulk of a shell script's logic
// (and its source→sink flows) lives at the top level, not inside a
// function_definition. Treating the program root as a scope lets the walker
// track `arg="$1"; curl "$arg"` written directly in the script body. Nested
// function bodies are also reachable from here; they are additionally analysed
// as their own scopes, and identical flows collapse during dedup.
func shellFindTopLevelScope(root *ast.Node) []*ast.Node {
	if root == nil || root.Type() != "program" {
		return nil
	}
	return []*ast.Node{root}
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Generic if-statement extraction (condition/consequence/alternative fields)
// Works for JS, Java, PHP, C, C++, C#, Kotlin, Rust, Groovy.
// ---------------------------------------------------------------------------

func genericExtractIfCondition(n *ast.Node) *ast.Node {
	return n.ChildByFieldName("condition")
}

func genericExtractIfConsequence(n *ast.Node) *ast.Node {
	return n.ChildByFieldName("consequence")
}

func genericExtractIfAlternative(n *ast.Node) *ast.Node {
	return n.ChildByFieldName("alternative")
}

func genericExtractCallArgs(n *ast.Node) []*ast.Node {
	args := n.ChildByFieldName("arguments")
	if args == nil {
		return nil
	}
	var out []*ast.Node
	for i := 0; i < args.ChildCount(); i++ {
		c := args.Child(i)
		if c.IsNamed() {
			out = append(out, c)
		}
	}
	return out
}

func genericExtractFuncBody(n *ast.Node) *ast.Node {
	if body := n.ChildByFieldName("body"); body != nil {
		return body
	}
	// Fallback: some grammars (Lua, Kotlin) use body-like child types
	// without a named "body" field.
	for i := 0; i < n.ChildCount(); i++ {
		c := n.Child(i)
		switch c.Type() {
		case "function_body", "block", "compound_statement", "statement_block", "statements":
			return c
		}
	}
	return nil
}

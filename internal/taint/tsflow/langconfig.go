package tsflow

import (
	"github.com/turenlabs/batou/internal/ast"
	"github.com/turenlabs/batou/internal/rules"
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
}

func getConfig(lang rules.Language) *langConfig {
	return configs[lang]
}

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

func pythonConfig() *langConfig {
	return &langConfig{
		language:     rules.LangPython,
		funcTypes:    map[string]bool{"function_definition": true, "decorated_definition": true},
		callTypes:    map[string]bool{"call": true},
		assignTypes:  map[string]bool{"assignment": true, "augmented_assignment": true},
		varDeclTypes: map[string]bool{},
		identType:    "identifier",
		attrTypes:    map[string]bool{"attribute": true},
		ifTypes:      map[string]bool{"if_statement": true},

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
			lhs := n.ChildByFieldName("left")
			if lhs == nil {
				return ""
			}
			if lhs.Type() == "identifier" {
				return lhs.Text()
			}
			return ""
		},
		extractAssignRHS: func(n *ast.Node) *ast.Node {
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
						return c.ChildByFieldName("body")
					}
				}
				return nil
			}
			return n.ChildByFieldName("body")
		},
		extractFuncParams:    pyExtractParams,
		extractIfCondition:   pyExtractIfCondition,
		extractIfConsequence: pyExtractIfConsequence,
		extractIfAlternative: pyExtractIfAlternative,
	}
}

func pyExtractIfCondition(n *ast.Node) *ast.Node {
	return n.ChildByFieldName("condition")
}

func pyExtractIfConsequence(n *ast.Node) *ast.Node {
	return n.ChildByFieldName("consequence")
}

func pyExtractIfAlternative(n *ast.Node) *ast.Node {
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
		language:     rules.LangJavaScript,
		funcTypes:    map[string]bool{"function_declaration": true, "arrow_function": true, "method_definition": true, "function": true},
		callTypes:    map[string]bool{"call_expression": true, "new_expression": true},
		assignTypes:  map[string]bool{"assignment_expression": true},
		varDeclTypes: map[string]bool{"variable_declarator": true},
		identType:    "identifier",
		attrTypes:    map[string]bool{"member_expression": true},
		ifTypes:      map[string]bool{"if_statement": true},

		extractCallName: func(n *ast.Node) string {
			fn := n.ChildByFieldName("function")
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
			if lhs != nil && lhs.Type() == "identifier" {
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
		language:     rules.LangJava,
		funcTypes:    map[string]bool{"method_declaration": true, "constructor_declaration": true},
		callTypes:    map[string]bool{"method_invocation": true, "object_creation_expression": true},
		assignTypes:  map[string]bool{"assignment_expression": true},
		varDeclTypes: map[string]bool{"variable_declarator": true},
		identType:    "identifier",
		attrTypes:    map[string]bool{"field_access": true},
		ifTypes:      map[string]bool{"if_statement": true},

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
			if lhs != nil && lhs.Type() == "identifier" {
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
		callTypes:    map[string]bool{"function_call_expression": true, "member_call_expression": true, "scoped_call_expression": true},
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
		extractFuncParams:    phpExtractParams,
		extractIfCondition:   genericExtractIfCondition,
		extractIfConsequence: genericExtractIfConsequence,
		extractIfAlternative: genericExtractIfAlternative,
	}
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
			if lhs != nil && lhs.Type() == "identifier" {
				return lhs.Text()
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
			name := n.ChildByFieldName("name")
			if name != nil {
				return name.Text()
			}
			return ""
		},
		extractFuncBody: func(n *ast.Node) *ast.Node {
			return n.ChildByFieldName("body")
		},
		extractFuncParams:    rubyExtractParams,
		extractIfCondition:   genericExtractIfCondition,
		extractIfConsequence: genericExtractIfConsequence,
		extractIfAlternative: genericExtractIfAlternative,
	}
}

func rubyExtractParams(n *ast.Node) []string {
	params := n.ChildByFieldName("parameters")
	if params == nil {
		return nil
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
		if p.Type() == "parameter_declaration" {
			d := p.ChildByFieldName("declarator")
			if d != nil && d.Type() == "identifier" {
				names = append(names, d.Text())
			}
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
	// C++ adds qualified names (namespace::function) and scope resolution
	origExtractCallName := cfg.extractCallName
	cfg.extractCallName = func(n *ast.Node) string {
		fn := n.ChildByFieldName("function")
		if fn != nil && fn.Type() == "qualified_identifier" {
			name := fn.ChildByFieldName("name")
			if name != nil {
				return name.Text()
			}
		}
		return origExtractCallName(n)
	}
	return cfg
}

// ---------------------------------------------------------------------------
// C#
// ---------------------------------------------------------------------------

func csharpConfig() *langConfig {
	return &langConfig{
		language:     rules.LangCSharp,
		funcTypes:    map[string]bool{"method_declaration": true, "local_function_statement": true, "constructor_declaration": true},
		callTypes:    map[string]bool{"invocation_expression": true, "object_creation_expression": true},
		assignTypes:  map[string]bool{"assignment_expression": true},
		varDeclTypes: map[string]bool{"variable_declarator": true},
		identType:    "identifier",
		attrTypes:    map[string]bool{"member_access_expression": true},
		ifTypes:      map[string]bool{"if_statement": true},

		extractCallName: func(n *ast.Node) string {
			fn := n.ChildByFieldName("function")
			if fn != nil {
				if fn.Type() == "identifier" {
					return fn.Text()
				}
				if fn.Type() == "member_access_expression" {
					name := fn.ChildByFieldName("name")
					if name != nil {
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
			if lhs != nil && lhs.Type() == "identifier" {
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
		funcTypes:    map[string]bool{"function_declaration": true},
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

func rustConfig() *langConfig {
	return &langConfig{
		language:     rules.LangRust,
		funcTypes:    map[string]bool{"function_item": true},
		callTypes:    map[string]bool{"call_expression": true},
		assignTypes:  map[string]bool{"assignment_expression": true},
		varDeclTypes: map[string]bool{"let_declaration": true},
		identType:    "identifier",
		attrTypes:    map[string]bool{"field_expression": true},
		ifTypes:      map[string]bool{"if_expression": true},

		extractCallName: func(n *ast.Node) string {
			fn := n.ChildByFieldName("function")
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
			if pat != nil && pat.Type() == "identifier" {
				names = append(names, pat.Text())
			}
		}
	}
	return names
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
			// Lua function_call: prefix contains the function expression
			// For "os.execute(x)", prefix children are: identifier("os"), ".", identifier("execute")
			// The last identifier in prefix is the method name
			var last string
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "identifier" || c.Type() == "dot_index_expression" {
					if c.Type() == "dot_index_expression" {
						last = luaDotLast(c)
					} else {
						last = c.Text()
					}
				}
			}
			return last
		},
		extractCallReceiver: func(n *ast.Node) string {
			for i := 0; i < n.ChildCount(); i++ {
				c := n.Child(i)
				if c.Type() == "dot_index_expression" {
					// Return the table part
					table := c.ChildByFieldName("table")
					if table != nil {
						return table.Text()
					}
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
			"function_call_expression":            true,
			"method_call_expression":              true,
			"ambiguous_function_call_expression":  true,
			"eval_expression":                     true,
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

// Python (Flask / Blueprint) capture helper for cross-language service-
// boundary taint. Runs inside the Python builder
// (builder_python.go) and reads a route decorator into the language-
// agnostic FuncNode.RoutePath / RouteMethod the matcher consumes.
//
// Recognised decorator shapes (the dominant Flask family):
//
//	@app.route("/api/items")
//	@app.route("/api/items", methods=["GET", "POST"])
//	@app.get("/api/items")            # Flask 2.x verb shortcuts
//	@bp.route("/items")               # Blueprint
//	@api.post("/items")
//
// The path comes from the first string-literal argument; the method comes
// from a verb-shortcut decorator name (`.get`/`.post`/...) when present,
// else "" (route() registers all methods → matches any outbound method).

package graph

import (
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
)

// pythonRouteVerbShortcuts maps Flask 2.x verb-shortcut decorator names to
// their HTTP method.
var pythonRouteVerbShortcuts = map[string]string{
	"get": "get", "post": "post", "put": "put",
	"delete": "delete", "patch": "patch",
}

// pythonRouteFromDecorators scans a decorated_definition node's decorators
// for a Flask-style route registration and returns the normalised route
// path plus HTTP method ("" = any). Returns ("", "") when no route
// decorator is present.
func pythonRouteFromDecorators(decorated *tsast.Node) (string, string) {
	if decorated == nil {
		return "", ""
	}
	for i := 0; i < decorated.ChildCount(); i++ {
		dec := decorated.Child(i)
		if dec == nil || dec.Type() != "decorator" {
			continue
		}
		if path, method, ok := pythonRouteFromDecorator(dec); ok {
			return path, method
		}
	}
	return "", ""
}

// pythonRouteFromDecorator parses a single `decorator` node. A decorator
// wraps an expression; for a route it is a `call` node whose function is
// an `attribute` (`app.route` / `bp.get` / ...).
func pythonRouteFromDecorator(dec *tsast.Node) (string, string, bool) {
	// The decorator's meaningful child is the call expression (the `@`
	// token is an unnamed child).
	var call *tsast.Node
	for _, c := range dec.NamedChildren() {
		if c.Type() == "call" {
			call = c
			break
		}
	}
	if call == nil {
		return "", "", false
	}
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Type() != "attribute" {
		return "", "", false
	}
	attr := fn.ChildByFieldName("attribute")
	if attr == nil {
		return "", "", false
	}
	member := strings.TrimSpace(attr.Text())

	method := ""
	switch {
	case member == "route":
		// methods=[...] keyword refines the method; absent means all.
		method = pythonRouteMethodsKeyword(call)
	case pythonRouteVerbShortcuts[strings.ToLower(member)] != "":
		method = pythonRouteVerbShortcuts[strings.ToLower(member)]
	default:
		return "", "", false
	}

	args := call.ChildByFieldName("arguments")
	if args == nil {
		return "", "", false
	}
	rawPath := ""
	for _, a := range args.NamedChildren() {
		if a.Type() == "string" {
			rawPath = pythonStringLiteralValue(a)
			break
		}
	}
	normPath := NormalizeRoutePath(rawPath)
	if normPath == "" {
		return "", "", false
	}
	return normPath, method, true
}

// pythonRouteMethodsKeyword returns the single HTTP method declared in a
// `methods=["X"]` keyword argument when exactly one is present; "" when
// absent or multiple (multiple → matches any outbound method, the
// permissive default).
func pythonRouteMethodsKeyword(call *tsast.Node) string {
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return ""
	}
	for _, a := range args.NamedChildren() {
		if a.Type() != "keyword_argument" {
			continue
		}
		name := a.ChildByFieldName("name")
		val := a.ChildByFieldName("value")
		if name == nil || val == nil || strings.TrimSpace(name.Text()) != "methods" {
			continue
		}
		if val.Type() != "list" {
			return ""
		}
		var methods []string
		for _, e := range val.NamedChildren() {
			if e.Type() == "string" {
				methods = append(methods, strings.ToLower(pythonStringLiteralValue(e)))
			}
		}
		if len(methods) == 1 {
			return methods[0]
		}
		return ""
	}
	return ""
}

// pythonStringLiteralValue returns the unquoted value of a Python string
// node. tree-sitter Python wraps the inner text in a string_content
// child; fall back to trimming quotes off the raw text.
func pythonStringLiteralValue(n *tsast.Node) string {
	if n == nil {
		return ""
	}
	for _, c := range n.NamedChildren() {
		if c.Type() == "string_content" {
			return c.Text()
		}
	}
	return strings.Trim(strings.TrimSpace(n.Text()), "\"'")
}

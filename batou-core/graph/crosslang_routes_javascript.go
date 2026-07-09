// JavaScript / TypeScript capture helpers for cross-language service-
// boundary taint. These run inside the JS builder
// (builder_javascript.go) and populate the language-agnostic node
// metadata the matcher in crosslang_routes.go consumes:
//
//   - route paths from `app.get("/x", handler)` → FuncNode.RoutePath
//   - outbound request sites `fetch("/x?q=" + req.query.q)` /
//     `axios.post("/x", userInput)` → FuncNode.OutboundRequests
//
// The matcher itself never inspects language; only this capture layer is
// JS-specific. A Python/Flask analog lives in
// crosslang_routes_python.go.

package graph

import (
	"regexp"
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/taint"
)

// jsRouteVerbs is the set of router-method names that register an HTTP
// route whose first argument is the path literal. `use`/`all` cover
// middleware/catch-all registrations.
var jsRouteVerbs = map[string]bool{
	"get": true, "post": true, "put": true, "delete": true,
	"patch": true, "options": true, "head": true, "all": true,
}

// jsIsRouteVerb reports whether method names an HTTP route-registration
// verb (Express / Fastify / Koa-router share these names).
func jsIsRouteVerb(method string) bool {
	return jsRouteVerbs[strings.ToLower(strings.TrimSpace(method))]
}

// jsRouteMethod normalises a route verb to the lower-case HTTP method, or
// "" for `use`/`all` (which match any outbound method).
func jsRouteMethod(verb string) string {
	v := strings.ToLower(strings.TrimSpace(verb))
	if v == "all" || v == "use" {
		return ""
	}
	return v
}

// firstNamedArg returns the first named child of an `arguments` node, or
// nil when there are none.
func firstNamedArg(args *tsast.Node) *tsast.Node {
	if args == nil {
		return nil
	}
	for _, c := range args.NamedChildren() {
		return c
	}
	return nil
}

// jsIsStringLiteral reports whether n is a plain JS string literal.
func jsIsStringLiteral(n *tsast.Node) bool {
	return n != nil && n.Type() == "string"
}

// jsStringLiteralValue returns the unquoted text of a JS string literal
// (or the literal's raw text trimmed of surrounding quotes when the
// fragment child isn't present).
func jsStringLiteralValue(n *tsast.Node) string {
	if n == nil {
		return ""
	}
	// tree-sitter JS wraps the inner text in a string_fragment child.
	for _, c := range n.NamedChildren() {
		if c.Type() == "string_fragment" {
			return c.Text()
		}
	}
	return strings.Trim(strings.TrimSpace(n.Text()), "\"'`")
}

// jsOutboundClientRe matches the receiver of an outbound HTTP-client call
// whose member name is an HTTP verb: `axios.post(...)`, `client.get(...)`,
// `http.put(...)`. The bare `fetch(...)` form is handled separately.
var jsOutboundClientRe = regexp.MustCompile(`^(axios|http|https|client|api|request|got|superagent|ky)$`)

// jsOutboundRequest inspects a call_expression and, when it is an outbound
// HTTP request (`fetch(...)`, `axios.<verb>(...)`, `axios(...)`) whose
// argument list targets an in-repo path with a tainted argument, returns
// the OutboundRequest describing it.
//
// Recognised shapes:
//
//	fetch("/api/x?q=" + req.query.q)
//	fetch(`/api/x/${id}`, { ... })
//	axios.post("/api/x", userInput)
//	axios.get("/api/x?id=" + req.params.id)
//
// The path literal is taken from the first string/template argument; the
// tainted argument is any argument expression matching a request-source
// shape (javascriptSourceExprRe) or a bare user-input identifier. Returns
// ok=false when the call is not an outbound request, has no static path,
// or carries no tainted data.
func jsOutboundRequest(call *tsast.Node) (OutboundRequest, bool) {
	if call == nil {
		return OutboundRequest{}, false
	}
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return OutboundRequest{}, false
	}

	method := ""
	isOutbound := false
	switch fn.Type() {
	case "identifier":
		if strings.TrimSpace(fn.Text()) == "fetch" {
			isOutbound = true
		}
	case "member_expression":
		obj := fn.ChildByFieldName("object")
		prop := fn.ChildByFieldName("property")
		if obj != nil && prop != nil && obj.Type() == "identifier" {
			recv := strings.TrimSpace(obj.Text())
			verb := strings.ToLower(strings.TrimSpace(prop.Text()))
			if jsOutboundClientRe.MatchString(recv) {
				switch verb {
				case "get", "post", "put", "delete", "patch", "request", "head", "options":
					isOutbound = true
					if verb != "request" {
						method = verb
					}
				}
			}
		}
	}
	if !isOutbound {
		return OutboundRequest{}, false
	}

	args := call.ChildByFieldName("arguments")
	if args == nil {
		return OutboundRequest{}, false
	}

	// First argument: the URL/path. Accept a plain string, a
	// concatenation whose left side is a string, or a template string.
	pathArg := firstNamedArg(args)
	if pathArg == nil {
		return OutboundRequest{}, false
	}
	rawPath := jsExtractStaticPathPrefix(pathArg)
	normPath := NormalizeRoutePath(rawPath)
	if normPath == "" {
		return OutboundRequest{}, false
	}

	// Tainted argument: scan every argument's text for a request-source
	// expression. The path arg itself may carry it (`"/x?q=" + req.query.q`)
	// or it may be a later body argument (`axios.post("/x", req.body)`).
	tainted := ""
	for _, a := range args.NamedChildren() {
		txt := a.Text()
		if m := javascriptSourceExprRe.FindString(txt); m != "" {
			tainted = strings.TrimSpace(m)
			break
		}
	}
	if tainted == "" {
		return OutboundRequest{}, false
	}

	return OutboundRequest{
		Path:           normPath,
		Method:         method,
		Line:           int(call.StartRow()) + 1,
		TaintedArg:     tainted,
		SourceCategory: string(taint.SrcUserInput),
	}, true
}

// jsExtractStaticPathPrefix returns the static leading path of a URL
// argument expression. For a plain string it's the string value; for a
// `"prefix" + dynamic` concatenation it's the left string operand; for a
// template string (e.g. /x/${id} in backticks) it's everything up to the
// first interpolation.
func jsExtractStaticPathPrefix(n *tsast.Node) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "string":
		return jsStringLiteralValue(n)
	case "binary_expression":
		// `"/api/x?q=" + req.query.q` — recurse into the left operand,
		// which holds the static prefix.
		if left := n.ChildByFieldName("left"); left != nil {
			return jsExtractStaticPathPrefix(left)
		}
	case "template_string":
		// `` `/api/x/${id}` `` — concatenate leading string_fragment
		// children until the first interpolation. NormalizeRoutePath
		// trims the "${...}" tail too, but cutting here keeps the prefix
		// clean even for nested templates.
		var b strings.Builder
		for _, c := range n.NamedChildren() {
			if c.Type() == "template_substitution" || c.Type() == "interpolation" {
				break
			}
			if c.Type() == "string_fragment" {
				b.WriteString(c.Text())
			}
		}
		return b.String()
	}
	return ""
}

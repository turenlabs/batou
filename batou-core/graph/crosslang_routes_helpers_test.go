package graph

import (
	"testing"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for the cross-language route-capture helpers
// (crosslang_routes_javascript.go). The pure verb/method helpers take
// plain strings; the AST-driven helpers are exercised against a parsed
// JavaScript tree.

func TestJSIsRouteVerb(t *testing.T) {
	truthy := []string{"get", "post", "put", "delete", "patch", "options", "head", "all", "GET", " Post "}
	for _, v := range truthy {
		if !jsIsRouteVerb(v) {
			t.Errorf("jsIsRouteVerb(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"connect", "fetch", "", "send"} {
		if jsIsRouteVerb(v) {
			t.Errorf("jsIsRouteVerb(%q) = true, want false", v)
		}
	}
}

func TestJSRouteMethod(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"GET", "get"},
		{"post", "post"},
		{"all", ""}, // any-method wildcard
		{"use", ""}, // middleware wildcard
		{" Put ", "put"},
	}
	for _, tc := range cases {
		if got := jsRouteMethod(tc.in); got != tc.want {
			t.Errorf("jsRouteMethod(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// findFirstNode does a depth-first search for the first node whose Type()
// matches typ, used to reach a specific node in a parsed JS tree.
func findFirstNode(n *tsast.Node, typ string) *tsast.Node {
	if n == nil {
		return nil
	}
	if n.Type() == typ {
		return n
	}
	for _, c := range n.NamedChildren() {
		if hit := findFirstNode(c, typ); hit != nil {
			return hit
		}
	}
	return nil
}

func parseJS(t *testing.T, src string) *tsast.Node {
	t.Helper()
	tree := tsast.Parse([]byte(src), rules.LangJavaScript)
	if tree == nil || tree.Root() == nil {
		t.Fatalf("failed to parse JS: %q", src)
	}
	return tree.Root()
}

func TestJSStringLiteralValue(t *testing.T) {
	root := parseJS(t, `const p = "/api/items";`)
	str := findFirstNode(root, "string")
	if str == nil {
		t.Fatal("no string node found")
	}
	if !jsIsStringLiteral(str) {
		t.Error("jsIsStringLiteral should be true for a string node")
	}
	if got := jsStringLiteralValue(str); got != "/api/items" {
		t.Errorf("jsStringLiteralValue = %q, want /api/items", got)
	}
	// A non-string node is not a string literal.
	if jsIsStringLiteral(root) {
		t.Error("program node should not be a string literal")
	}
	if jsStringLiteralValue(nil) != "" {
		t.Error("jsStringLiteralValue(nil) should be empty")
	}
}

func TestJSExtractStaticPathPrefix(t *testing.T) {
	// Plain string literal argument.
	root := parseJS(t, `fetch("/api/items?q=" + req.query.q);`)
	bin := findFirstNode(root, "binary_expression")
	if bin == nil {
		t.Fatal("no binary_expression node found")
	}
	if got := jsExtractStaticPathPrefix(bin); got != "/api/items?q=" {
		t.Errorf("jsExtractStaticPathPrefix(concat) = %q, want /api/items?q=", got)
	}

	// Template string prefix up to the first interpolation.
	root = parseJS(t, "fetch(`/api/items/${id}`);")
	tmpl := findFirstNode(root, "template_string")
	if tmpl == nil {
		t.Fatal("no template_string node found")
	}
	if got := jsExtractStaticPathPrefix(tmpl); got != "/api/items/" {
		t.Errorf("jsExtractStaticPathPrefix(template) = %q, want /api/items/", got)
	}

	if jsExtractStaticPathPrefix(nil) != "" {
		t.Error("jsExtractStaticPathPrefix(nil) should be empty")
	}
}

func TestJSOutboundRequest_FetchWithTaint(t *testing.T) {
	root := parseJS(t, `function h(req){ fetch("/api/items?q=" + req.query.q); }`)
	call := findFirstNode(root, "call_expression")
	if call == nil {
		t.Fatal("no call_expression node found")
	}
	got, ok := jsOutboundRequest(call)
	if !ok {
		t.Fatal("jsOutboundRequest should recognise a tainted fetch")
	}
	if got.Path != "/api/items" {
		t.Errorf("OutboundRequest.Path = %q, want /api/items", got.Path)
	}
	if got.TaintedArg == "" {
		t.Errorf("OutboundRequest.TaintedArg should be populated, got empty")
	}
}

func TestJSOutboundRequest_AxiosVerb(t *testing.T) {
	root := parseJS(t, `function h(req){ axios.post("/api/x", req.body); }`)
	call := findFirstNode(root, "call_expression")
	if call == nil {
		t.Fatal("no call_expression node found")
	}
	got, ok := jsOutboundRequest(call)
	if !ok {
		t.Fatal("jsOutboundRequest should recognise axios.post with tainted body")
	}
	if got.Method != "post" {
		t.Errorf("OutboundRequest.Method = %q, want post", got.Method)
	}
	if got.Path != "/api/x" {
		t.Errorf("OutboundRequest.Path = %q, want /api/x", got.Path)
	}
}

func TestJSOutboundRequest_NotOutbound(t *testing.T) {
	// A plain local function call is not an outbound request.
	root := parseJS(t, `function h(req){ doThing(req.query.q); }`)
	call := findFirstNode(root, "call_expression")
	if call == nil {
		t.Fatal("no call_expression node found")
	}
	if _, ok := jsOutboundRequest(call); ok {
		t.Error("doThing(...) must not be classified as an outbound request")
	}
	// nil is safe.
	if _, ok := jsOutboundRequest(nil); ok {
		t.Error("jsOutboundRequest(nil) should be ok=false")
	}
}

func TestJSOutboundRequest_FetchNoTaint(t *testing.T) {
	// fetch with a static path and no tainted argument -> not flagged.
	root := parseJS(t, `fetch("/api/items");`)
	call := findFirstNode(root, "call_expression")
	if call == nil {
		t.Fatal("no call_expression node found")
	}
	if _, ok := jsOutboundRequest(call); ok {
		t.Error("fetch with no tainted arg must not be an outbound request finding")
	}
}

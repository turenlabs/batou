package graph

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// TestJSBuilder_RouteCallback: an Express-style route registration with an
// inline arrow handler (`app.get('/users', (req, res) => {...})`) emits a
// synthetic `get@<line>` FuncNode tagged with the route path and method
// (handleJSCallExpressionCallbackForBuilder).
func TestJSBuilder_RouteCallback(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "routes.js")
	src := `app.get('/users', (req, res) => {
  const id = req.query.id;
  res.send(findUser(id));
});
`
	UpdateFile(cg, filePath, src, rules.LangJavaScript)

	var handler *FuncNode
	for _, n := range cg.NodesInFile(filePath) {
		if strings.HasPrefix(n.Name, "get@") {
			handler = n
			break
		}
	}
	if handler == nil {
		t.Fatalf("get@<line> handler node not emitted; have %v", nodeIDsInFile(cg, filePath))
	}
	if handler.RoutePath != "/users" {
		t.Errorf("RoutePath = %q, want /users", handler.RoutePath)
	}
	if handler.RouteMethod == "" {
		t.Errorf("RouteMethod empty; want the HTTP verb derived from 'get'")
	}
	if !containsStr(handler.RawCalls, "findUser") {
		t.Errorf("handler RawCalls missing 'findUser' (got %v)", handler.RawCalls)
	}
}

// TestJSBuilder_NonRouteCallback: a callback passed to a non-HTTP-verb
// method still gets a synthetic node, but no RoutePath (jsIsRouteVerb
// gate).
func TestJSBuilder_NonRouteCallback(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "jobs.js")
	src := `queue.process('emails', (job) => {
  deliver(job.data);
});
`
	UpdateFile(cg, filePath, src, rules.LangJavaScript)

	var handler *FuncNode
	for _, n := range cg.NodesInFile(filePath) {
		if strings.HasPrefix(n.Name, "process@") {
			handler = n
			break
		}
	}
	if handler == nil {
		t.Fatalf("process@<line> callback node not emitted; have %v", nodeIDsInFile(cg, filePath))
	}
	if handler.RoutePath != "" {
		t.Errorf("RoutePath = %q, want empty (process is not an HTTP verb)", handler.RoutePath)
	}
}

// TestJSBuilder_ObjectLiteralCallbackArg: function-valued properties and
// shorthand methods of an object literal passed as a call argument each
// get their own FuncNode (walkJSObjectLiteralForBuilder).
func TestJSBuilder_ObjectLiteralCallbackArg(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "plugin.js")
	src := `register({
  handler: function(req) {
    return lookup(req.params.id);
  },
  teardown() {
    close();
  },
});
`
	UpdateFile(cg, filePath, src, rules.LangJavaScript)

	handler := cg.GetNode(filePath + ":handler")
	if handler == nil {
		t.Fatalf("object-literal 'handler' property node not emitted; have %v", nodeIDsInFile(cg, filePath))
	}
	if !containsStr(handler.RawCalls, "lookup") {
		t.Errorf("handler RawCalls missing 'lookup' (got %v)", handler.RawCalls)
	}
	if n := cg.GetNode(filePath + ":teardown"); n == nil {
		t.Errorf("object-literal shorthand method 'teardown' not emitted; have %v", nodeIDsInFile(cg, filePath))
	}
}

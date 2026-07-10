package graph

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// TestPHPBuilder_AssignedClosure: `$handler = function(...) {...};` at
// file level emits a FuncNode named after the variable (with its `$`
// sigil), and its RawCalls capture the body's calls.
func TestPHPBuilder_AssignedClosure(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "bootstrap.php")
	src := `<?php
$handler = function($req) {
    return render($req);
};
`
	UpdateFile(cg, filePath, src, rules.LangPHP)

	n := cg.GetNode(filePath + ":$handler")
	if n == nil {
		t.Fatalf("$handler closure node not emitted; have %v", nodeIDsInFile(cg, filePath))
	}
	if !containsStr(n.RawCalls, "render") {
		t.Errorf("$handler RawCalls missing 'render' (got %v)", n.RawCalls)
	}
}

// TestPHPBuilder_AssignedArrowFunction_Namespaced: `$fn = fn(...) => ...;`
// under `namespace App;` qualifies as `App\$fn`.
func TestPHPBuilder_AssignedArrowFunction_Namespaced(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "helpers.php")
	src := `<?php
namespace App;

$fn = fn($x) => trim($x);
`
	UpdateFile(cg, filePath, src, rules.LangPHP)

	if n := cg.GetNode(filePath + `:App\$fn`); n == nil {
		t.Errorf(`App\$fn arrow-function node not emitted; have %v`, nodeIDsInFile(cg, filePath))
	}
}

// TestPHPBuilder_RouteCallbackClosure: a framework route registration
// with an inline closure (`$app->get('/users', function(...) {...})`)
// emits a synthetic `<callee>@<line>` handler node so the closure body
// has a landing pad in the graph.
func TestPHPBuilder_RouteCallbackClosure(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "routes.php")
	src := `<?php
$app->get('/users', function($request) {
    return findUser($request);
});
`
	UpdateFile(cg, filePath, src, rules.LangPHP)

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
	if !containsStr(handler.RawCalls, "findUser") {
		t.Errorf("handler RawCalls missing 'findUser' (got %v)", handler.RawCalls)
	}
}

// TestPHPBuilder_RouteCallbackClosure_FunctionCallForm: the bare-function
// registration form (`route('/x', fn(...) => ...)`) uses the function
// name for the synthetic handler.
func TestPHPBuilder_RouteCallbackClosure_FunctionCallForm(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "web.php")
	src := `<?php
route('/health', fn($req) => status($req));
`
	UpdateFile(cg, filePath, src, rules.LangPHP)

	found := false
	for _, n := range cg.NodesInFile(filePath) {
		if strings.HasPrefix(n.Name, "route@") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("route@<line> handler node not emitted; have %v", nodeIDsInFile(cg, filePath))
	}
}

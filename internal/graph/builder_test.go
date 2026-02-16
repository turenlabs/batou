package graph_test

import (
	"testing"

	"github.com/turenlabs/batou/internal/graph"
	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// UpdateFile with Go source (uses go/ast)
// ---------------------------------------------------------------------------

func TestUpdateFileGoBasic(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	content := `package main

func Foo() {
	Bar()
}

func Bar() {
	println("hello")
}
`

	updated := graph.UpdateFile(cg, "/project/main.go", content, rules.LangGo)

	if len(updated) != 2 {
		t.Errorf("UpdateFile returned %d updated IDs, want 2", len(updated))
	}

	foo := cg.GetNode("/project/main.go:Foo")
	if foo == nil {
		t.Fatal("expected Foo node to exist")
	}
	if foo.Package != "main" {
		t.Errorf("Foo.Package = %q, want %q", foo.Package, "main")
	}

	bar := cg.GetNode("/project/main.go:Bar")
	if bar == nil {
		t.Fatal("expected Bar node to exist")
	}

	// Foo should call Bar.
	if len(foo.Calls) != 1 || foo.Calls[0] != "/project/main.go:Bar" {
		t.Errorf("Foo.Calls = %v, want [/project/main.go:Bar]", foo.Calls)
	}
}

func TestUpdateFileGoMethodReceiver(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	content := `package main

type Server struct{}

func (s *Server) Handle() {
	s.process()
}

func (s *Server) process() {}
`

	graph.UpdateFile(cg, "/project/server.go", content, rules.LangGo)

	handle := cg.GetNode("/project/server.go:Server.Handle")
	if handle == nil {
		t.Fatal("expected Server.Handle node")
	}

	process := cg.GetNode("/project/server.go:Server.process")
	if process == nil {
		t.Fatal("expected Server.process node")
	}
}

func TestUpdateFileGoUnchangedContent(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	content := `package main

func Foo() {}
`

	// First call creates the node.
	updated1 := graph.UpdateFile(cg, "/project/main.go", content, rules.LangGo)
	if len(updated1) != 1 {
		t.Fatalf("first UpdateFile should return 1, got %d", len(updated1))
	}

	// Second call with same content should detect no changes.
	updated2 := graph.UpdateFile(cg, "/project/main.go", content, rules.LangGo)
	if len(updated2) != 0 {
		t.Errorf("second UpdateFile with same content returned %d, want 0", len(updated2))
	}
}

func TestUpdateFileGoParseError(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	// Invalid Go code.
	content := `package main
func { broken syntax
`

	updated := graph.UpdateFile(cg, "/project/bad.go", content, rules.LangGo)
	if updated != nil {
		t.Errorf("expected nil for parse error, got %v", updated)
	}
}

// ---------------------------------------------------------------------------
// UpdateFile with generic (non-Go) languages
// ---------------------------------------------------------------------------

func TestUpdateFilePython(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	content := `def handler(request):
    data = request.args.get("q")
    return process(data)

def process(data):
    return data.strip()
`

	updated := graph.UpdateFile(cg, "/project/app.py", content, rules.LangPython)

	// Should detect at least the handler and process functions.
	if len(updated) == 0 {
		t.Error("expected at least one updated function for Python")
	}

	nodes := cg.NodesInFile("/project/app.py")
	if len(nodes) == 0 {
		t.Error("expected nodes in file after UpdateFile for Python")
	}
}

func TestUpdateFileJavaScript(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	content := `function handleRequest(req, res) {
    const data = req.body;
    processData(data);
}

function processData(data) {
    return data.trim();
}
`

	updated := graph.UpdateFile(cg, "/project/app.js", content, rules.LangJavaScript)

	if len(updated) == 0 {
		t.Error("expected at least one updated function for JavaScript")
	}
}

// ---------------------------------------------------------------------------
// extractCalls (tested indirectly through UpdateFile)
// ---------------------------------------------------------------------------

func TestExtractCallsFiltersKeywords(t *testing.T) {
	cg := graph.NewCallGraph("/project", "s1")

	content := `function handler(req, res) {
    if (true) {
        for (let i = 0; i < 10; i++) {
            customFunc();
        }
    }
}
`

	graph.UpdateFile(cg, "/project/app.js", content, rules.LangJavaScript)

	handler := cg.GetNode("/project/app.js:handler")
	if handler == nil {
		t.Fatal("expected handler node")
	}

	// customFunc should be in calls but keywords (if, for, let) should not.
	for _, callID := range handler.Calls {
		node := cg.GetNode(callID)
		if node != nil {
			name := node.Name
			if name == "if" || name == "for" || name == "let" {
				t.Errorf("keyword %q should not appear as a call edge", name)
			}
		}
	}
}

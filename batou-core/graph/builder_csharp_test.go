package graph

import (
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// TestCSharpBuilder_FileScopedNamespace: `namespace App.Web;` (the C# 10
// file-scoped form — no braces) threads the namespace prefix onto every
// sibling type that follows, via walkCSharpBuilderTypeOrContainer.
func TestCSharpBuilder_FileScopedNamespace(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "Handler.cs")
	src := `namespace App.Web;

public class Handler
{
    public string Run(string input)
    {
        return Sanitize(input);
    }

    private string Sanitize(string s)
    {
        return s.Trim();
    }
}

public class Metrics
{
    public void Record(string name)
    {
    }
}
`
	UpdateFile(cg, filePath, src, rules.LangCSharp)

	run := cg.GetNode(filePath + ":App.Web.Handler.Run")
	if run == nil {
		t.Fatalf("App.Web.Handler.Run not emitted (file-scoped namespace not threaded); have %v",
			nodeIDsInFile(cg, filePath))
	}
	if !containsStr(run.RawCalls, "Sanitize") {
		t.Errorf("Run.RawCalls missing 'Sanitize' (got %v)", run.RawCalls)
	}
	// The SECOND sibling class after the file-scoped declaration must get
	// the same prefix — walkCSharpBuilderTypeOrContainer handles each
	// trailing sibling individually.
	if n := cg.GetNode(filePath + ":App.Web.Metrics.Record"); n == nil {
		t.Errorf("App.Web.Metrics.Record not emitted; have %v", nodeIDsInFile(cg, filePath))
	}
}

// TestCSharpBuilder_FileScopedNamespace_NestedType: a nested type inside
// a class that follows a file-scoped namespace keeps the full dotted
// prefix chain.
func TestCSharpBuilder_FileScopedNamespace_NestedType(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "Service.cs")
	src := `namespace App.Core;

public class Service
{
    public class Inner
    {
        public void Work()
        {
        }
    }
}
`
	UpdateFile(cg, filePath, src, rules.LangCSharp)

	if n := cg.GetNode(filePath + ":App.Core.Service.Inner.Work"); n == nil {
		t.Errorf("App.Core.Service.Inner.Work not emitted; have %v", nodeIDsInFile(cg, filePath))
	}
}

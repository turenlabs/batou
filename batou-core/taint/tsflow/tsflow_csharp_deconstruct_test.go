package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// C# tuple deconstruction recall-FN fix.
//
// Before this fix the walker only handled single-name bindings: the LHS of a
// `var (a, b) = ...` declaration is a tuple_pattern and the LHS of a
// `(a, b) = ...` re-assignment is a tuple_expression, neither of which yields
// an identifier through extractVarDeclParts / extractAssignLHS. Every
// deconstructed local therefore silently lost taint, producing zero flows for
// the very common modern-C# idiom of deconstructing a parsed request.

// var (a, b) = Parse(userInput) — declaration form, command-injection sink.
func TestCSharp_TupleDeconstruct_VarDecl_Command(t *testing.T) {
	code := `
public class Handler {
    public void Run() {
        string input = Console.ReadLine();
        var (cmd, arg) = SplitInput(input);
        Process.Start(cmd, arg);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("expected command-injection flow through `var (cmd, arg) = SplitInput(input)`; got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.MethodName, f.Sink.MethodName)
		}
	}
}

// (a, b) = Parse(userInput) — re-assignment form, SQL-injection sink.
func TestCSharp_TupleDeconstruct_Assignment_SQL(t *testing.T) {
	code := `
public class Handler {
    public void Run() {
        string table;
        string col;
        string input = Console.ReadLine();
        (table, col) = SplitInput(input);
        var q = "SELECT " + col + " FROM " + table;
        var cmd = new SqlCommand(q, conn);
        cmd.ExecuteReader();
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Errorf("expected SQL-injection flow through `(table, col) = SplitInput(input)`; got %d flows", len(flows))
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.MethodName, f.Sink.MethodName)
		}
	}
}

// Nested deconstruction `var (x, (y, z)) = Parse(input)` — taint must reach the
// innermost binding `z`.
func TestCSharp_TupleDeconstruct_Nested(t *testing.T) {
	code := `
public class Handler {
    public void Run() {
        string input = Console.ReadLine();
        var (x, (y, z)) = Nested(input);
        Log.Information("value: " + z);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Errorf("expected log-injection flow to nested binding `z`; got %d flows", len(flows))
	}
}

// Discard `_` and an untainted sibling must not falsely taint: only `name`
// derives from the tainted RHS, and the discard target is skipped entirely.
func TestCSharp_TupleDeconstruct_DiscardAndUse(t *testing.T) {
	code := `
public class Handler {
    public void Run() {
        string input = Console.ReadLine();
        var (_, name) = SplitInput(input);
        Log.Information("user: " + name);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Errorf("expected flow through `var (_, name) = SplitInput(input)`; got %d flows", len(flows))
	}
}

// Negative control: a constant RHS must not taint the deconstructed locals.
func TestCSharp_TupleDeconstruct_Constant_NoFlow(t *testing.T) {
	code := `
public class Handler {
    public void Run() {
        var (a, b) = SplitInput("static-literal");
        Process.Start(a, b);
    }
}
`
	flows := Analyze(code, "/app/Handler.cs", rules.LangCSharp)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Errorf("constant RHS must not produce a command-injection flow; got %d flows", len(flows))
	}
}

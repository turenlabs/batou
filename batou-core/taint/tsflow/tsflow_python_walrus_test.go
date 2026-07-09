package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Python walrus operator (PEP 572, `x := expr`) recall-FN regression tests.
//
// Before the fix, `named_expression` was absent from Python's assignTypes and
// unhandled in nodeIsTainted / findSourceInExpr, so the walrus target was never
// seeded and taint dropped. These cover the idiomatic positions where a walrus
// binds user input: an `if` guard, a `while` read loop, and a walrus in an
// expression statement whose target is later used at a sink.

// `if (data := source()):` — bind in the if-condition, use in the body.
func TestPythonWalrus_IfConditionFromSource(t *testing.T) {
	code := `
import os
def handler():
    if (data := input()):
        os.system(data)
`
	flows := Analyze(code, "/app/h.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for walrus `if (data := input())` -> os.system(data)")
	}
}

// `if (x := taintedVar):` — bind a previously-tainted variable in the condition.
func TestPythonWalrus_IfConditionFromVar(t *testing.T) {
	code := `
import os
def handler():
    name = input()
    if (x := name):
        os.system(x)
`
	flows := Analyze(code, "/app/h.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for walrus `if (x := name)` -> os.system(x)")
	}
}

// `while (line := source()):` — the canonical read-loop idiom.
func TestPythonWalrus_WhileReadLoop(t *testing.T) {
	code := `
import os
def handler():
    while (line := input()):
        os.system(line)
`
	flows := Analyze(code, "/app/h.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for walrus `while (line := input())` -> os.system(line)")
	}
}

// Walrus in an expression statement, target used later (SQL sink).
func TestPythonWalrus_ExprStatementThenSink(t *testing.T) {
	code := `
def handler():
    print(name := input())
    query = "SELECT * FROM users WHERE n = '" + name + "'"
    cursor.execute(query)
`
	flows := Analyze(code, "/app/h.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL-injection flow for walrus `print(name := input())` -> cursor.execute")
	}
}

// Walrus directly at a sink, value is a previously-tainted variable:
// `os.system(x := name)`. Exercises the nodeIsTainted named_expression handler.
func TestPythonWalrus_AtSinkFromVar(t *testing.T) {
	code := `
import os
def handler():
    name = input()
    os.system(x := name)
`
	flows := Analyze(code, "/app/h.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command-injection flow for `os.system(x := name)` with tainted name")
	}
}

// Negative control: a walrus binding a constant must NOT taint the target,
// proving the seeding does not blindly over-taint walrus targets.
func TestPythonWalrus_ConstantNoFlow(t *testing.T) {
	code := `
import os
def handler():
    if (x := "id"):
        os.system(x)
`
	flows := Analyze(code, "/app/h.py", rules.LangPython)
	if hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("did not expect a flow — walrus bound a constant string, target is not tainted")
	}
}

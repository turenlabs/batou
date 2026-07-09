// batou:ignore-start all -- intentional vulnerable patterns embedded in inline Python strings for taint-flow unit tests
package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// =========================================================================
// Python LLM-agent code-execution sinks
//
// Covers explicit eval/exec/SQL surfaces exposed by agentic frameworks:
//   - smolagents.local_python_executor.evaluate_python_code   (CWE-94)
//   - autogen CodeExecutor.execute_code_blocks                (CWE-94)
//   - LangChain SQLDatabase.run_no_throw                      (CWE-89)
//
// Real-world CVEs in this surface: CVE-2023-29374, CVE-2023-39659,
// CVE-2024-21513, CVE-2024-36480.
//
// Note: only sinks with library-unique method names are added. LangChain
// .run() variants (PythonREPL.run, ShellTool.run, BashProcess.run,
// SQLDatabase.run) collide with py.subprocess.call's broad MethodName
// match and would be misclassified as OS-command execution by that earlier
// sink — same convention the Neo4j section in python_sinks.go documents
// for session.run / tx.run.
// =========================================================================

func TestPython_Smolagents_EvaluatePythonCode_CodeInjection(t *testing.T) {
	code := `
from flask import request
from smolagents.local_python_executor import evaluate_python_code

def endpoint():
    user_code = request.args.get("code")
    output, _ = evaluate_python_code(user_code, static_tools={}, custom_tools={})
    return {"result": output}
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow: request.args -> evaluate_python_code()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_Autogen_ExecuteCodeBlocks_CodeInjection(t *testing.T) {
	code := `
from flask import request
from autogen.coding import LocalCommandLineCodeExecutor, CodeBlock

def endpoint():
    snippet = request.form.get("py")
    executor = LocalCommandLineCodeExecutor(work_dir=".")
    blocks = [CodeBlock(language="python", code=snippet)]
    result = executor.execute_code_blocks(blocks)
    return {"output": result.output}
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected SnkEval flow: request.form -> executor.execute_code_blocks()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestPython_LangChain_SQLDatabase_RunNoThrow_SQLi(t *testing.T) {
	code := `
from flask import request
from langchain_community.utilities import SQLDatabase

def endpoint():
    name = request.args.get("name")
    db = SQLDatabase.from_uri("sqlite:///app.db")
    sql = "SELECT * FROM users WHERE name = '" + name + "'"
    return db.run_no_throw(sql)
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SnkSQLQuery flow: request.args -> SQLDatabase.run_no_throw()")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative: constant SQL passed to run_no_throw must NOT produce a flow.
func TestPython_LangChain_SQLDatabase_RunNoThrow_ConstantSQL_NoFlow(t *testing.T) {
	code := `
from langchain_community.utilities import SQLDatabase

def report():
    db = SQLDatabase.from_uri("sqlite:///app.db")
    return db.run_no_throw("SELECT COUNT(*) FROM users")
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery {
			t.Errorf("did NOT expect SnkSQLQuery flow for constant SQL; got %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}

// Negative: constant code passed to evaluate_python_code must NOT produce a flow.
func TestPython_Smolagents_EvaluatePythonCode_Constant_NoFlow(t *testing.T) {
	code := `
from smolagents.local_python_executor import evaluate_python_code

def warm_up():
    output, _ = evaluate_python_code("print('hello')", static_tools={}, custom_tools={})
    return output
`
	flows := Analyze(code, "/app/views.py", rules.LangPython)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkEval {
			t.Errorf("did NOT expect SnkEval flow for constant code; got %s -> %s",
				f.Source.Category, f.Sink.Category)
		}
	}
}

// batou:ignore-end

package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

func TestIsCLIScript_PythonIfMain(t *testing.T) {
	content := `import sys

def main():
    print(sys.argv)

if __name__ == "__main__":
    main()
`
	if !isCLIScript(content, rules.LangPython) {
		t.Error("expected Python file with if __name__ == \"__main__\" to be detected as CLI")
	}
}

func TestIsCLIScript_PythonIfMainSingleQuoted(t *testing.T) {
	content := `if __name__ == '__main__':
    pass
`
	if !isCLIScript(content, rules.LangPython) {
		t.Error("single-quoted __main__ should also detect as CLI")
	}
}

func TestIsCLIScript_PythonShebang(t *testing.T) {
	content := `#!/usr/bin/env python3
print("hi")
`
	if !isCLIScript(content, rules.LangPython) {
		t.Error("expected shebang-only Python file to be detected as CLI")
	}
}

func TestIsCLIScript_PythonLibraryModule(t *testing.T) {
	// A library module with no __main__ and no shebang should NOT be CLI.
	content := `def helper(x):
    return x + 1

def another():
    return helper(2)
`
	if isCLIScript(content, rules.LangPython) {
		t.Error("pure library module should not be detected as CLI")
	}
}

func TestIsCLIScript_NonPythonLanguageIgnored(t *testing.T) {
	content := `if __name__ == "__main__": pass`
	// We only recognize CLI scripts for Python right now — other languages
	// must return false even if the content happens to contain Python syntax.
	if isCLIScript(content, rules.LangJava) {
		t.Error("Java should not be detected as CLI even when content looks Python-y")
	}
}

func TestIsCLIScript_PythonFlaskDevServer(t *testing.T) {
	// Flask apps commonly have `if __name__ == "__main__": app.run()` for
	// dev-mode boot. That file handles web requests — demoting its file
	// sinks would hide real traversal vulnerabilities. Must NOT be CLI.
	content := `from flask import Flask, request
app = Flask(__name__)

@app.route("/download")
def download():
    path = request.args.get("path")
    with open(path) as f:
        return f.read()

if __name__ == "__main__":
    app.run()
`
	if isCLIScript(content, rules.LangPython) {
		t.Error("Flask app with __main__ dev-server block must not be classified as CLI")
	}
}

func TestIsCLIScript_PythonDjangoManage(t *testing.T) {
	// Django's manage.py has a shebang AND __main__, but imports django.
	content := `#!/usr/bin/env python
import django
if __name__ == "__main__":
    django.setup()
`
	if isCLIScript(content, rules.LangPython) {
		t.Error("Django-importing file must not be treated as a pure CLI")
	}
}

// Direct unit test of the demotion logic: same underlying flow state
// produces different confidence depending on the cliScript flag.
func TestFlowBuilder_DemotesCLIArgToFileSinkWhenCLIScript(t *testing.T) {
	cliSrc := &taint.SourceDef{Category: taint.SrcCLIArg, Description: "argparse"}
	fileSink := &taint.SinkDef{Category: taint.SnkFileRead, MethodName: "read_text"}

	// CLI script: demoted.
	fb := newFlowBuilder("/app/cli.py")
	fb.cliScript = true
	ts := &taintState{source: cliSrc, confidence: 1.0}
	fb.addFlow(ts, fileSink, 10, "main")

	if len(fb.flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(fb.flows))
	}
	if got := fb.flows[0].Confidence; got >= 0.7 {
		t.Errorf("CLI-arg→file-sink flow in CLI script should be demoted <0.7; got %.2f", got)
	}

	// Library module: full confidence preserved.
	fb2 := newFlowBuilder("/pkg/lib.py")
	fb2.cliScript = false
	ts2 := &taintState{source: cliSrc, confidence: 1.0}
	fb2.addFlow(ts2, fileSink, 10, "helper")

	if got := fb2.flows[0].Confidence; got < 1.0 {
		t.Errorf("library-module flow should retain full confidence; got %.2f", got)
	}
}

func TestFlowBuilder_DoesNotDemoteNonFileSinks(t *testing.T) {
	// CLI-arg → SQL sink is still a real vulnerability and should NOT be demoted,
	// even in a CLI script. Guards against the demotion being too broad.
	cliSrc := &taint.SourceDef{Category: taint.SrcCLIArg, Description: "argparse"}
	sqlSink := &taint.SinkDef{Category: taint.SnkSQLQuery, MethodName: "execute"}

	fb := newFlowBuilder("/app/cli.py")
	fb.cliScript = true
	ts := &taintState{source: cliSrc, confidence: 1.0}
	fb.addFlow(ts, sqlSink, 10, "main")

	if got := fb.flows[0].Confidence; got < 1.0 {
		t.Errorf("CLI-arg→SQL flow should keep full confidence even in a CLI script; got %.2f", got)
	}
}

func TestFlowBuilder_DoesNotDemoteWhenNotCLIScript(t *testing.T) {
	// A flow that would match the user-input→file-sink pattern must NOT be
	// demoted when the file isn't classified as a CLI script (e.g. a Flask
	// handler). The CLI classification gate is what keeps web traversal
	// findings at full confidence.
	userSrc := &taint.SourceDef{Category: taint.SrcUserInput, Description: "flask request"}
	fileSink := &taint.SinkDef{Category: taint.SnkFileRead, MethodName: "read_text"}

	fb := newFlowBuilder("/app/handler.py")
	fb.cliScript = false // web handler, not CLI
	ts := &taintState{source: userSrc, confidence: 1.0}
	fb.addFlow(ts, fileSink, 10, "handler")

	if got := fb.flows[0].Confidence; got < 1.0 {
		t.Errorf("web-handler flow must keep full confidence; got %.2f", got)
	}
}

func TestFlowBuilder_DemotesUserInputInCLIScript(t *testing.T) {
	// In a CLI script the tsflow matcher may classify the argparse value as
	// SrcUserInput (a quirk of the `input(` builtin pattern matching nearby
	// tokens). We demote both SrcCLIArg AND SrcUserInput in CLI scripts so
	// the real user-visible effect — "block on a CLI arg → pathlib read" —
	// goes away.
	userSrc := &taint.SourceDef{Category: taint.SrcUserInput, Description: "input()"}
	fileSink := &taint.SinkDef{Category: taint.SnkFileRead, MethodName: "read_text"}

	fb := newFlowBuilder("/app/cli.py")
	fb.cliScript = true
	ts := &taintState{source: userSrc, confidence: 1.0}
	fb.addFlow(ts, fileSink, 10, "main")

	if got := fb.flows[0].Confidence; got >= 0.7 {
		t.Errorf("user_input→file flow in CLI script should be demoted <0.7; got %.2f", got)
	}
}

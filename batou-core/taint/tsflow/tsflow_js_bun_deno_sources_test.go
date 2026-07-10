package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for Bun and Deno modern-runtime taint SOURCES.
//
// Bun (https://bun.sh) and Deno (https://deno.land) are JavaScript runtimes
// alternative to Node.js. Their request handlers receive Web API Request
// objects (covered by js.webapi.req.*), but each runtime exposes additional
// runtime-level APIs — CLI args, env, stdin, file I/O, subprocess output —
// that are independent attacker surface (CLI tools, scripts, server-side
// helpers). This file exercises the sources added in javascript_sources.go.
//
// Each test wires a new source to a well-established sink (eval / db.query /
// child_process.exec) and asserts both:
//   1. the resulting flow's source ID matches the new entry
//   2. the sink category fires (proving end-to-end propagation)

func flowFromSourceID(flows []taint.TaintFlow, sourceID string) *taint.TaintFlow {
	for i := range flows {
		if flows[i].Source.ID == sourceID {
			return &flows[i]
		}
	}
	return nil
}

// --- Bun.argv ---

func TestJS_Bun_Argv_Source_FlowsToEval(t *testing.T) {
	code := `
function main() {
    const arg = Bun.argv[2];
    eval(arg);
}
`
	flows := Analyze(code, "/app/cli.js", rules.LangJavaScript)
	if flowFromSourceID(flows, "js.bun.argv") == nil {
		t.Error("expected js.bun.argv source flow into eval()")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s)", f.Source.ID, f.Source.Category, f.Sink.ID, f.Sink.Category)
		}
	}
}

// --- Bun.env ---

func TestJS_Bun_Env_Source_FlowsToCommand(t *testing.T) {
	code := `
const child_process = require("child_process");
function main() {
    const path = Bun.env.SCRIPT_PATH;
    child_process.exec(path);
}
`
	flows := Analyze(code, "/app/runner.js", rules.LangJavaScript)
	if flowFromSourceID(flows, "js.bun.env") == nil {
		t.Error("expected js.bun.env source flow into child_process.exec()")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s)", f.Source.ID, f.Source.Category, f.Sink.ID, f.Sink.Category)
		}
	}
}

// --- Bun.stdin ---

func TestJS_Bun_Stdin_Source_FlowsToEval(t *testing.T) {
	code := `
async function main() {
    const input = Bun.stdin;
    eval(input);
}
`
	flows := Analyze(code, "/app/repl.js", rules.LangJavaScript)
	if flowFromSourceID(flows, "js.bun.stdin") == nil {
		t.Error("expected js.bun.stdin source flow into eval()")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s)", f.Source.ID, f.Source.Category, f.Sink.ID, f.Sink.Category)
		}
	}
}

// --- Bun.spawn return value (Subprocess.stdout) ---

func TestJS_Bun_Spawn_Result_Source_FlowsToEval(t *testing.T) {
	code := `
async function main() {
    const proc = Bun.spawn(["echo", "hi"]);
    eval(proc.stdout);
}
`
	flows := Analyze(code, "/app/exec.js", rules.LangJavaScript)
	if flowFromSourceID(flows, "js.bun.spawn.result") == nil {
		t.Error("expected js.bun.spawn.result source flow into eval()")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s)", f.Source.ID, f.Source.Category, f.Sink.ID, f.Sink.Category)
		}
	}
}

// --- Bun.spawnSync return value ---

func TestJS_Bun_SpawnSync_Result_Source_FlowsToEval(t *testing.T) {
	code := `
function main() {
    const result = Bun.spawnSync(["uname"]);
    eval(result.stdout);
}
`
	flows := Analyze(code, "/app/exec.js", rules.LangJavaScript)
	if flowFromSourceID(flows, "js.bun.spawnsync.result") == nil {
		t.Error("expected js.bun.spawnsync.result source flow into eval()")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s)", f.Source.ID, f.Source.Category, f.Sink.ID, f.Sink.Category)
		}
	}
}

// --- Deno.stdin ---

func TestJS_Deno_Stdin_Source_FlowsToEval(t *testing.T) {
	code := `
async function main() {
    const input = Deno.stdin;
    eval(input);
}
`
	flows := Analyze(code, "/app/repl.js", rules.LangJavaScript)
	if flowFromSourceID(flows, "js.deno.stdin") == nil {
		t.Error("expected js.deno.stdin source flow into eval()")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s)", f.Source.ID, f.Source.Category, f.Sink.ID, f.Sink.Category)
		}
	}
}

// --- Deno.env.toObject() ---

func TestJS_Deno_EnvToObject_Source_FlowsToEval(t *testing.T) {
	code := `
function main() {
    const env = Deno.env.toObject();
    eval(env.SCRIPT);
}
`
	flows := Analyze(code, "/app/runner.js", rules.LangJavaScript)
	if flowFromSourceID(flows, "js.deno.env.toobject") == nil {
		t.Error("expected js.deno.env.toobject source flow into eval()")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s)", f.Source.ID, f.Source.Category, f.Sink.ID, f.Sink.Category)
		}
	}
}

// --- Deno.readTextFile() return value ---

func TestJS_Deno_ReadTextFile_Result_Source_FlowsToEval(t *testing.T) {
	code := `
async function main() {
    const data = await Deno.readTextFile("/etc/config");
    eval(data);
}
`
	flows := Analyze(code, "/app/loader.js", rules.LangJavaScript)
	if flowFromSourceID(flows, "js.deno.readtextfile.result") == nil {
		t.Error("expected js.deno.readtextfile.result source flow into eval()")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s)", f.Source.ID, f.Source.Category, f.Sink.ID, f.Sink.Category)
		}
	}
}

// --- Deno.readTextFileSync() return value ---

func TestJS_Deno_ReadTextFileSync_Result_Source_FlowsToEval(t *testing.T) {
	code := `
function main() {
    const data = Deno.readTextFileSync("/etc/config");
    eval(data);
}
`
	flows := Analyze(code, "/app/loader.js", rules.LangJavaScript)
	if flowFromSourceID(flows, "js.deno.readtextfilesync.result") == nil {
		t.Error("expected js.deno.readtextfilesync.result source flow into eval()")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s)", f.Source.ID, f.Source.Category, f.Sink.ID, f.Sink.Category)
		}
	}
}

// --- Deno.readFile() return value ---

func TestJS_Deno_ReadFile_Result_Source_FlowsToEval(t *testing.T) {
	code := `
async function main() {
    const bytes = await Deno.readFile("/etc/config");
    eval(bytes);
}
`
	flows := Analyze(code, "/app/loader.js", rules.LangJavaScript)
	if flowFromSourceID(flows, "js.deno.readfile.result") == nil {
		t.Error("expected js.deno.readfile.result source flow into eval()")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s)", f.Source.ID, f.Source.Category, f.Sink.ID, f.Sink.Category)
		}
	}
}

// --- new Deno.Command(...) instance — subprocess output via .output() ---

func TestJS_Deno_Command_Result_Source_FlowsToEval(t *testing.T) {
	code := `
async function main() {
    const cmd = new Deno.Command("ls", { args: ["-la"] });
    const out = await cmd.output();
    eval(out);
}
`
	flows := Analyze(code, "/app/exec.js", rules.LangJavaScript)
	if flowFromSourceID(flows, "js.deno.command.result") == nil {
		t.Error("expected js.deno.command.result source flow into eval()")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s)", f.Source.ID, f.Source.Category, f.Sink.ID, f.Sink.Category)
		}
	}
}

// --- Deno.run() (legacy) — Process.output() ---

func TestJS_Deno_Run_Result_Source_FlowsToEval(t *testing.T) {
	code := `
async function main() {
    const proc = Deno.run({ cmd: ["uname"], stdout: "piped" });
    const out = await proc.output();
    eval(out);
}
`
	flows := Analyze(code, "/app/exec.js", rules.LangJavaScript)
	if flowFromSourceID(flows, "js.deno.run.result") == nil {
		t.Error("expected js.deno.run.result source flow into eval()")
		for _, f := range flows {
			t.Logf("  flow: %s (%s) -> %s (%s)", f.Source.ID, f.Source.Category, f.Sink.ID, f.Sink.Category)
		}
	}
}

// --- Negative: hardcoded literal must not flow ---

func TestJS_Bun_Deno_Sources_NoFlowFromConstant(t *testing.T) {
	code := `
function main() {
    const arg = "static-config";
    eval(arg);
}
`
	flows := Analyze(code, "/app/cli.js", rules.LangJavaScript)
	for _, f := range flows {
		switch f.Source.ID {
		case "js.bun.argv", "js.bun.env", "js.bun.stdin",
			"js.bun.spawn.result", "js.bun.spawnsync.result",
			"js.deno.stdin", "js.deno.env.toobject",
			"js.deno.readtextfile.result", "js.deno.readtextfilesync.result", "js.deno.readfile.result",
			"js.deno.command.result", "js.deno.run.result":
			t.Errorf("unexpected new Bun/Deno source flow from a hardcoded literal: %s -> %s", f.Source.ID, f.Sink.ID)
		}
	}
}

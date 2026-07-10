package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- Bun runtime sinks ---

func TestJS_Bun_Spawn_CommandInjection(t *testing.T) {
	code := `
function handler(req, res) {
    const cmd = req.body.cmd;
    Bun.spawn([cmd]);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from req.body -> Bun.spawn")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Bun_SpawnSync_CommandInjection(t *testing.T) {
	code := `
function handler(req, res) {
    const cmd = req.body.cmd;
    const result = Bun.spawnSync([cmd]);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from req.body -> Bun.spawnSync")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Bun_File_PathTraversal(t *testing.T) {
	code := `
function handler(req, res) {
    const filename = req.query.file;
    const content = Bun.file(filename);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow from req.query -> Bun.file")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Bun_Write_PathTraversal(t *testing.T) {
	code := `
function handler(req, res) {
    const path = req.query.path;
    Bun.write(path, "data");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow from req.query -> Bun.write")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Deno runtime sinks ---

func TestJS_Deno_Command_Injection(t *testing.T) {
	code := `
function handler(req, res) {
    const userCmd = req.body.cmd;
    const command = new Deno.Command(userCmd, { args: ["--verbose"] });
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from req.body -> Deno.Command")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Deno_Run_CommandInjection(t *testing.T) {
	code := `
function handler(req, res) {
    const cmd = req.body.command;
    Deno.run({ cmd: [cmd] });
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from req.body -> Deno.run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Deno_ReadTextFile_PathTraversal(t *testing.T) {
	code := `
function handler(req, res) {
    const filepath = req.query.path;
    Deno.readTextFile(filepath);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("expected file read flow from req.query -> Deno.readTextFile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Deno_WriteTextFile_PathTraversal(t *testing.T) {
	code := `
function handler(req, res) {
    const filepath = req.query.path;
    Deno.writeTextFile(filepath, "data");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow from req.query -> Deno.writeTextFile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Deno_Remove_PathTraversal(t *testing.T) {
	code := `
function handler(req, res) {
    const filepath = req.query.path;
    Deno.remove(filepath);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow from req.query -> Deno.remove")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Deno_Dlopen_CodeExecution(t *testing.T) {
	code := `
function handler(req, res) {
    const libPath = req.query.lib;
    Deno.dlopen(libPath, { add: { parameters: ["i32"], result: "i32" } });
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected eval flow from req.query -> Deno.dlopen")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_Deno_Connect_SSRF(t *testing.T) {
	code := `
function handler(req, res) {
    const host = req.query.host;
    Deno.connect({ hostname: host, port: 80 });
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow from req.query -> Deno.connect")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Web API Request sources ---

func TestJS_WebAPI_RequestJson_SQLInjection(t *testing.T) {
	code := `
async function handler(req, res) {
    const body = await req.json();
    const name = body.name;
    db.query("SELECT * FROM users WHERE name = '" + name + "'");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow from req.json() -> db.query")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_WebAPI_RequestText_CommandInjection(t *testing.T) {
	code := `
async function handler(request, res) {
    const input = await request.text();
    Bun.spawn(["grep", input, "/var/log/app.log"]);
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from request.text() -> Bun.spawn")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestJS_WebAPI_RequestFormData_FileWrite(t *testing.T) {
	code := `
async function handler(request, res) {
    const formData = await request.formData();
    const filename = formData.get('filename');
    Deno.writeTextFile("/uploads/" + filename, "content");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkFileWrite) {
		t.Error("expected file write flow from request.formData() -> Deno.writeTextFile")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Deno-specific sources ---

func TestJS_Deno_EnvGet_CommandInjection(t *testing.T) {
	code := `
function main() {
    const cmd = Deno.env.get("SCRIPT_PATH");
    Deno.run({ cmd: [cmd] });
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command injection flow from Deno.env.get -> Deno.run")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Sanitizer tests ---

func TestJS_Bun_EscapeHTML_Safe(t *testing.T) {
	code := `
function handler(req, res) {
    const input = req.query.name;
    const safe = Bun.escapeHTML(input);
    res.send("<p>" + safe + "</p>");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput {
			t.Error("expected Bun.escapeHTML to sanitize XSS flow, but found:", f.Sink.MethodName)
		}
	}
}

func TestJS_Bun_PasswordHash_Safe(t *testing.T) {
	code := `
async function handler(req, res) {
    const password = req.body.password;
    const hashed = await Bun.password.hash(password);
    db.query("INSERT INTO users (pass) VALUES ('" + hashed + "')");
}
`
	flows := Analyze(code, "/app/handler.js", rules.LangJavaScript)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCrypto {
			t.Error("expected Bun.password.hash to sanitize crypto flow, but found:", f.Sink.MethodName)
		}
	}
}

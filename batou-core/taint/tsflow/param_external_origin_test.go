package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"

	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Regression tests for the parameter external-origin gate.
//
// Real-world FP shape (smoke test, Nextcloud PHP + Keycloak Java): a bare
// function parameter named $path / $query / String path was seeded as an
// EXTERNAL user-input source with no caller proving external origin. Two
// distinct mechanisms drove the flood:
//
//  1. PHP: the storage/DB abstraction layer is saturated with method-name
//     SUFFIXES like getAppPath( / executeQuery( / createForm(, which collided
//     with the parenHandlerAnnotations substring markers Path( / Query( /
//     Form( / Json( — so isWebHandlerFunc tagged every internal helper a "web
//     handler" and seeded its parameters as user input.
//  2. Java: a bare `String path` / `String data` parameter matched
//     isInputParamName purely on its name, in non-handler internal helpers
//     carrying config-derived paths.
//
// The gate: a bare parameter becomes tainted only when a real external-origin
// signal is present (route/listener annotation via the AST, or an input-binding
// annotation). Genuine interprocedural callers that pass request data into the
// parameter are still proven by the Layer-4 / buildTaintSummaries machinery, so
// cross-file true positives are unaffected.
//
// Each "FP stays clean" case is paired with a "TP still fires" case on the same
// sink/source to prove the gate tightened detection rather than disabling it.

// --- PHP: storage-abstraction substring collision (FP stays clean) ---

// getAppPath( contains the substring "Path(", which used to make
// isWebHandlerFunc tag loadApp() as a web handler and seed $app as user input,
// emitting a bogus CWE-22 path-traversal finding on an internal app id.
func TestParamGate_PHP_StorageHelper_PathCollision_Clean(t *testing.T) {
	code := `<?php
class AppManager {
    public function loadApp(string $app): void {
        $appPath = $this->getAppPath($app);
        if (is_file($appPath . '/appinfo/app.php')) {
            return;
        }
    }
}
?>`
	flows := Analyze(code, "/app/lib/private/App/AppManager.php", rules.LangPHP)
	for _, f := range flows {
		if f.Source.MethodName == "parameter:$app" {
			t.Errorf("FP: internal $app param seeded as user input via getAppPath( substring collision; flow -> %s", f.Sink.Category)
		}
	}
}

// $qb->createNamedParameter( and getQueryBuilder( contain "Form("? no — they
// contain "Query("/"Parameter(": this exercises the Query( collision on an
// internal query-builder helper.
func TestParamGate_PHP_QueryBuilderHelper_QueryCollision_Clean(t *testing.T) {
	code := `<?php
class Storage {
    public function readByPath(string $path): string {
        $qb = $this->getQueryBuilder();
        $qb->select('*')->from('files');
        return file_get_contents($path);
    }
}
?>`
	flows := Analyze(code, "/app/lib/private/Files/Storage.php", rules.LangPHP)
	for _, f := range flows {
		if f.Source.MethodName == "parameter:$path" {
			t.Errorf("FP: internal $path param seeded via getQueryBuilder( substring collision; flow -> %s", f.Sink.Category)
		}
	}
}

// --- PHP: genuine handler / source still fires (TP) ---

// A genuine PHP superglobal source ($_GET) reaching a file sink must still be
// detected — the gate must not suppress real external input.
func TestParamGate_PHP_SuperglobalSource_StillFires(t *testing.T) {
	code := `<?php
function download() {
    $path = $_GET['file'];
    readfile($path);
}
?>`
	flows := Analyze(code, "/app/lib/download.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkFileRead) {
		t.Error("TP regression: $_GET -> readfile should still produce a path-traversal/file-read flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.MethodName, f.Sink.Category)
		}
	}
}

// The Drupal FormStateInterface user-input source must still fire on a
// conventionally-named $form_state parameter even in a method whose name does
// NOT contain the Form( handler marker — proving detection now rests on the
// real receiver match, not the substring collision.
func TestParamGate_PHP_FormStateSource_StillFires_NonFormMethodName(t *testing.T) {
	code := `<?php
use Drupal\Core\Form\FormStateInterface;

function handleSubmission(FormStateInterface $form_state) {
    $name = $form_state->getValue('name');
    $db = \Drupal::database();
    $db->query("SELECT * FROM users WHERE name = '" . $name . "'");
}
?>`
	flows := Analyze(code, "/app/modules/custom/m/src/MyHandler.php", rules.LangPHP)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("TP regression: FormState::getValue -> db->query must still fire (receiver match, not Form( collision)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.MethodName, f.Sink.Category)
		}
	}
}

// --- Java: bare input-named param in internal helper (FP stays clean) ---

// `String path` in an internal helper that builds a SQL string. The body
// contains executeQuery( ("Query(" substring) but there is NO real handler
// annotation, and `path` here is config-derived (e.g. truststore path), not
// remote input. Neither the substring collision nor the bare-name heuristic
// may seed it.
func TestParamGate_Java_InternalHelper_StringPath_Clean(t *testing.T) {
	code := `
public class Storage {
    private java.sql.Connection conn;
    public String readInternal(String path) throws Exception {
        java.sql.Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT data FROM files WHERE path='" + path + "'").toString();
    }
}
`
	flows := Analyze(code, "/app/Storage.java", rules.LangJava)
	for _, f := range flows {
		if f.Source.MethodName == "parameter:path" {
			t.Errorf("FP: internal Java `String path` param seeded as user input on name alone; flow -> %s", f.Sink.Category)
		}
	}
}

// `String data` in an internal template helper (no handler annotation).
func TestParamGate_Java_InternalHelper_StringData_Clean(t *testing.T) {
	code := `
public class TemplateRenderer {
    public String render(String data) throws Exception {
        java.io.FileReader r = new java.io.FileReader(data);
        return r.toString();
    }
}
`
	flows := Analyze(code, "/app/TemplateRenderer.java", rules.LangJava)
	for _, f := range flows {
		if f.Source.MethodName == "parameter:data" {
			t.Errorf("FP: internal Java `String data` param seeded as user input on name alone; flow -> %s", f.Sink.Category)
		}
	}
}

// --- Java: genuine handler param still fires (TP) ---

// A method annotated @PulsarListener is a true message-listener handler: its
// String parameter IS external input and the param->executeQuery flow must
// still fire. This proves isWebHandlerFunc's AST-based annotation check keeps
// genuine handlers tainted after the substring tightening.
func TestParamGate_Java_PulsarListenerHandler_StillFires(t *testing.T) {
	code := `
import org.springframework.pulsar.annotation.PulsarListener;
import java.sql.*;

public class TopicHandler {
    private Connection conn;

    @PulsarListener(topics = "users")
    public void handle(String userId) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM accounts WHERE user_id = '" + userId + "'");
    }
}
`
	flows := Analyze(code, "/app/TopicHandler.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("TP regression: @PulsarListener handler param -> executeQuery must still fire")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.MethodName, f.Sink.Category)
		}
	}
}

// A Spring @GetMapping controller action with an @RequestParam-annotated String
// must still be seeded (input-binding annotation = real external origin).
func TestParamGate_Java_RequestParamHandler_StillFires(t *testing.T) {
	code := `
import org.springframework.web.bind.annotation.*;
import java.sql.*;

@RestController
public class UserController {
    private Connection conn;

    @GetMapping("/u")
    public void get(@RequestParam String name) throws Exception {
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM u WHERE name = '" + name + "'");
    }
}
`
	flows := Analyze(code, "/app/UserController.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("TP regression: @GetMapping/@RequestParam handler param -> executeQuery must still fire")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.MethodName, f.Sink.Category)
		}
	}
}

// --- Ruby: the gate is NOT applied (params is a real Rails source) ---

// `params` is the idiomatic Rails controller user-input object. A bare `params`
// parameter must STILL be treated as external (params[:q] -> sink is a real
// flow) — the Java-only gate must not touch Ruby.
func TestParamGate_Ruby_ParamsSource_StillFires(t *testing.T) {
	code := `
def handler(params)
  q = params[:q]
  system(q)
end
`
	flows := Analyze(code, "/app/h.rb", rules.LangRuby)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("TP regression: Ruby params[:q] -> system must still fire (Ruby is excluded from the gate)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.MethodName, f.Sink.Category)
		}
	}
}

// =============================================================================
// false-handler-tighten (Py / JS-TS / C#): a param earns the conf-0.9,
// block-eligible "parameter:" seed only with REAL AST handler evidence
// (route/binding decorator or ASP.NET attribute). A non-handler whose body
// merely CONTAINS a handler substring (`db.executeQuery(` → "Query(") falls to
// the weak conf-0.6 "param-name:" seed that the external-origin gate caps.
//
// Each "FP demoted" case asserts the seed is NOT "parameter:<name>" (it is
// either dropped or demoted to "param-name:<name>", both non-block-eligible);
// each paired "TP still fires" case proves a genuinely-decorated handler keeps
// the block-eligible "parameter:" seed.
// =============================================================================

// hasParamSource reports whether any flow's source is the conf-0.9
// block-eligible "parameter:<name>" seed (NOT the weak "param-name:" variant —
// the "parameter:" prefix is a strict prefix of "param-name:" only by accident,
// so match exactly).
func hasParamSourceExact(flows []taint.TaintFlow, name string) bool {
	for _, f := range flows {
		if f.Source.MethodName == "parameter:"+name {
			return true
		}
	}
	return false
}

// --- Python: substring false-handler (FP demoted) ---

// `db.executeQuery(` contains the substring "Query(", which made
// isWebHandlerFunc tag run_report() as a web handler and seed `path` as a
// conf-0.9 block-eligible user-input source. There is no real route decorator,
// so `path` must fall to the weak "param-name:" seed.
func TestParamGate_Python_FalseHandler_QueryCollision_Demoted(t *testing.T) {
	code := `
def run_report(path, query):
    rows = db.executeQuery("SELECT * FROM t")
    import os
    os.system("ls " + path)
    return rows
`
	flows := Analyze(code, "/app/report.py", rules.LangPython)
	if hasParamSourceExact(flows, "path") {
		t.Error("FP: Python non-handler `path` param promoted to block-eligible parameter: seed via executeQuery( substring collision")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f)", f.Source.MethodName, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Python: genuine route handler still fires (TP) ---

// A real Flask @app.route handler: its `path` parameter IS user-controlled and
// the block-eligible "parameter:" seed must survive.
func TestParamGate_Python_FlaskRouteHandler_StillBlockEligible(t *testing.T) {
	code := `
from flask import Flask
app = Flask(__name__)

@app.route("/run")
def run_report(path):
    import os
    os.system("ls " + path)
    return "ok"
`
	flows := Analyze(code, "/app/web.py", rules.LangPython)
	if !hasParamSourceExact(flows, "path") {
		t.Error("TP regression: real @app.route handler `path` must keep the block-eligible parameter: seed")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f)", f.Source.MethodName, f.Sink.Category, f.Confidence)
		}
	}
}

// A FastAPI @app.get handler with a primitive path param must also keep the
// block-eligible seed (decorator route evidence, not substring).
func TestParamGate_Python_FastAPIRouteHandler_StillBlockEligible(t *testing.T) {
	code := `
from fastapi import FastAPI
app = FastAPI()

@app.get("/run")
def run_report(path: str):
    import os
    os.system("ls " + path)
    return "ok"
`
	flows := Analyze(code, "/app/api.py", rules.LangPython)
	if !hasParamSourceExact(flows, "path") {
		t.Error("TP regression: real @app.get handler `path` must keep the block-eligible parameter: seed")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f)", f.Source.MethodName, f.Sink.Category, f.Confidence)
		}
	}
}

// --- C#: substring false-handler (FP demoted) ---

// `db.ExecuteQuery(` contains "Query("; with no [HttpGet]/[FromQuery]/[Route]
// attribute, the internal Helper() method must not promote `path` to the
// block-eligible "parameter:" seed.
func TestParamGate_CSharp_FalseHandler_QueryCollision_Demoted(t *testing.T) {
	code := `
public class Storage {
    public string Helper(string path) {
        var rows = db.ExecuteQuery("SELECT");
        return System.Diagnostics.Process.Start(path).ToString();
    }
}
`
	flows := Analyze(code, "/app/Storage.cs", rules.LangCSharp)
	if hasParamSourceExact(flows, "path") {
		t.Error("FP: C# non-handler `path` param promoted to block-eligible parameter: seed via ExecuteQuery( substring collision")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f)", f.Source.MethodName, f.Sink.Category, f.Confidence)
		}
	}
}

// --- C#: genuine ASP.NET action still fires (TP) ---

// A real [HttpGet] action with a [FromQuery]-bound param: the block-eligible
// "parameter:" seed must survive on the AST attribute evidence.
func TestParamGate_CSharp_AspNetAction_StillBlockEligible(t *testing.T) {
	code := `
public class FilesController {
    [HttpGet]
    public string Get([FromQuery] string path) {
        return System.Diagnostics.Process.Start(path).ToString();
    }
}
`
	flows := Analyze(code, "/app/FilesController.cs", rules.LangCSharp)
	if !hasParamSourceExact(flows, "path") {
		t.Error("TP regression: [HttpGet]/[FromQuery] action `path` must keep the block-eligible parameter: seed")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f)", f.Source.MethodName, f.Sink.Category, f.Confidence)
		}
	}
}

// --- JS/TS: genuine NestJS @Query() param decorator still fires (TP) ---

// The NestJS @Query() parameter decorator is genuine AST handler evidence
// (seeded by seedJSParamBindings, independent of the substring path). It must
// keep the block-eligible "parameter:" seed after the tightening.
func TestParamGate_JS_NestQueryDecorator_StillBlockEligible(t *testing.T) {
	code := `
class SearchController {
  run(@Query() q: string) {
    eval(q);
  }
}
`
	flows := Analyze(code, "/app/search.ts", rules.LangTypeScript)
	if !hasParamSourceExact(flows, "q") {
		t.Error("TP regression: NestJS @Query() decorated param must keep the block-eligible parameter: seed")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf %.2f)", f.Source.MethodName, f.Sink.Category, f.Confidence)
		}
	}
}

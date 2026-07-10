package tsflow

import (
	"testing"

	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// Android dynamic code-loading sinks (CWE-94). DexClassLoader /
// PathClassLoader / InMemoryDexClassLoader load Dalvik bytecode at runtime;
// a tainted dex path (or in-memory dex buffer) is arbitrary code execution.
// The dex source is the first constructor argument in every case.

func TestKotlin_Android_DexClassLoader_RCE(t *testing.T) {
	code := `
import dalvik.system.DexClassLoader

fun handler(request: HttpServletRequest) {
    val dexPath = request.getParameter("plugin")
    val loader = DexClassLoader(dexPath, optDir, null, parentLoader)
}
`
	flows := Analyze(code, "/app/PluginLoader.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code-execution flow for getParameter -> DexClassLoader(dexPath)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Android_PathClassLoader_RCE(t *testing.T) {
	code := `
import dalvik.system.PathClassLoader

fun handler(request: HttpServletRequest) {
    val dexPath = request.getParameter("dex")
    val loader = PathClassLoader(dexPath, parentLoader)
}
`
	flows := Analyze(code, "/app/PluginLoader.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code-execution flow for getParameter -> PathClassLoader(dexPath)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_Android_InMemoryDexClassLoader_RCE(t *testing.T) {
	code := `
import dalvik.system.InMemoryDexClassLoader

fun handler(request: HttpServletRequest) {
    val dexBytes = request.getParameter("payload")
    val loader = InMemoryDexClassLoader(dexBytes, parentLoader)
}
`
	flows := Analyze(code, "/app/PluginLoader.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkEval) {
		t.Error("expected code-execution flow for getParameter -> InMemoryDexClassLoader(dexBytes)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Android WebView.postUrl (CWE-79): a tainted URL permits a
// javascript:/data: scheme or attacker-chosen origin, same as loadUrl.
func TestKotlin_Android_WebView_PostUrl_XSS(t *testing.T) {
	code := `
import android.webkit.WebView

fun handler(request: HttpServletRequest) {
    val target = request.getParameter("u")
    webView.postUrl(target, postData)
}
`
	flows := Analyze(code, "/app/BrowserActivity.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS/content-injection flow for getParameter -> WebView.postUrl(url)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Android SQLiteDatabase.compileStatement (CWE-89): a concatenated SQL
// string compiled into a SQLiteStatement is SQL injection.
func TestKotlin_Android_SQLite_CompileStatement_SQLi(t *testing.T) {
	code := `
import android.database.sqlite.SQLiteDatabase

fun handler(request: HttpServletRequest) {
    val name = request.getParameter("name")
    val sql = "INSERT INTO users(name) VALUES('" + name + "')"
    val stmt = db.compileStatement(sql)
}
`
	flows := Analyze(code, "/app/UserDao.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQL injection flow for getParameter -> SQLiteDatabase.compileStatement(sql)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control: a constant dex path (no tainted input) must NOT produce a
// code-execution flow, confirming the sink fires on taint rather than on the
// mere presence of the API.
func TestKotlin_Android_DexClassLoader_ConstantPath_NoFlow(t *testing.T) {
	code := `
import dalvik.system.DexClassLoader

fun handler(request: HttpServletRequest) {
    val loader = DexClassLoader("/data/app/trusted.apk", optDir, null, parentLoader)
}
`
	flows := Analyze(code, "/app/PluginLoader.kt", rules.LangKotlin)
	if hasTaintFlow(flows, taint.SnkEval) {
		t.Error("did NOT expect a code-execution flow for a constant dex path")
		for _, f := range flows {
			t.Logf("  unexpected flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

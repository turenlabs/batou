package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Android platform output-encoding sanitizers.
//
// These complement the Android SQLiteDatabase sinks (execSQL/rawQuery) and the
// WebView / Ktor HTML-output sinks already in the catalog. Each test pairs a
// "safe" case (sanitizer in the source->sink path neutralizes the flow) with a
// negative control (identical structure, no sanitizer) proving the sanitizer is
// what suppressed the flow rather than the flow being absent to begin with.

// --- DatabaseUtils.sqlEscapeString (CWE-89) ---

func TestKotlin_SQLi_Safe_DatabaseUtilsSqlEscapeString(t *testing.T) {
	// DatabaseUtils.sqlEscapeString quotes/escapes a value as an SQL literal,
	// so interpolating it into execSQL is safe.
	code := `
import android.database.DatabaseUtils

fun handler(db: SQLiteDatabase) {
    val name = readLine()
    val safe = DatabaseUtils.sqlEscapeString(name)
    db.execSQL("INSERT INTO users (name) VALUES (" + safe + ")")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkSQLQuery && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence SQLi flow when DatabaseUtils.sqlEscapeString() escapes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestKotlin_SQLi_Unsafe_NoSqlEscapeControl(t *testing.T) {
	// Control: identical structure without the sanitizer must still flag.
	code := `
fun handler(db: SQLiteDatabase) {
    val name = readLine()
    db.execSQL("INSERT INTO users (name) VALUES ('" + name + "')")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkSQLQuery) {
		t.Error("expected SQLi flow for readLine -> execSQL() without any sanitizer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Uri.encode (CWE-79 / CWE-601) ---

func TestKotlin_XSS_Safe_UriEncode(t *testing.T) {
	// Uri.encode percent-encodes reserved/unsafe characters, so the result can
	// no longer break out of an HTML context.
	code := `
import android.net.Uri

fun handler() {
    val userInput = readLine()
    val safe = Uri.encode(userInput)
    call.respond("<a href=\"/q?term=" + safe + "\">link</a>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when Uri.encode() percent-encodes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestKotlin_XSS_Unsafe_NoUriEncodeControl(t *testing.T) {
	// Control: identical structure without the sanitizer must still flag.
	code := `
fun handler() {
    val userInput = readLine()
    call.respond("<a href=\"/q?term=" + userInput + "\">link</a>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for readLine -> call.respond() without any sanitizer")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

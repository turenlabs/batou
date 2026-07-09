package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// OWASP Java Encoder context-aware sanitizers — verify each new entry
// neutralizes the SnkHTMLOutput flow when applied between source and sink.
//
// Sink used: call.respondText(...) — Ktor SnkHTMLOutput sink (kotlin.ktor.respondtext).

func TestKotlin_XSS_Safe_OWASPEncodeForHtmlContent(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

fun handler() {
    val userInput = readLine()
    val safe = Encode.forHtmlContent(userInput)
    call.respondText("<p>" + safe + "</p>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when Encode.forHtmlContent() sanitizes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestKotlin_XSS_Safe_OWASPEncodeForHtmlAttribute(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

fun handler() {
    val userInput = readLine()
    val safe = Encode.forHtmlAttribute(userInput)
    call.respondText("<a title=\"" + safe + "\">x</a>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when Encode.forHtmlAttribute() sanitizes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestKotlin_XSS_Safe_OWASPEncodeForHtmlUnquotedAttribute(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

fun handler() {
    val userInput = readLine()
    val safe = Encode.forHtmlUnquotedAttribute(userInput)
    call.respondText("<a title=" + safe + ">x</a>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when Encode.forHtmlUnquotedAttribute() sanitizes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestKotlin_XSS_Safe_OWASPEncodeForJavaScriptAttribute(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

fun handler() {
    val userInput = readLine()
    val safe = Encode.forJavaScriptAttribute(userInput)
    call.respondText("<a onclick=\"f('" + safe + "')\">x</a>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when Encode.forJavaScriptAttribute() sanitizes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestKotlin_XSS_Safe_OWASPEncodeForJavaScriptBlock(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

fun handler() {
    val userInput = readLine()
    val safe = Encode.forJavaScriptBlock(userInput)
    call.respondText("<script>var x = '" + safe + "';</script>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when Encode.forJavaScriptBlock() sanitizes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestKotlin_XSS_Safe_OWASPEncodeForCssString(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

fun handler() {
    val userInput = readLine()
    val safe = Encode.forCssString(userInput)
    call.respondText("<style>.x { content: '" + safe + "'; }</style>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when Encode.forCssString() sanitizes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestKotlin_XSS_Safe_OWASPEncodeForXmlContent(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

fun handler() {
    val userInput = readLine()
    val safe = Encode.forXmlContent(userInput)
    call.respondText("<note>" + safe + "</note>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when Encode.forXmlContent() sanitizes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestKotlin_XSS_Safe_OWASPEncodeForXmlAttribute(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

fun handler() {
    val userInput = readLine()
    val safe = Encode.forXmlAttribute(userInput)
    call.respondText("<note id=\"" + safe + "\">ok</note>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when Encode.forXmlAttribute() sanitizes input, got conf %.2f", f.Confidence)
		}
	}
}

// Negative regression: same fixture without the sanitizer must still produce
// a high-confidence XSS flow — proves the absence of flow above is due to the
// sanitizer, not a broken test setup.
func TestKotlin_XSS_Unsafe_OWASPEncodeMissing(t *testing.T) {
	code := `
fun handler() {
    val userInput = readLine()
    call.respondText("<p>" + userInput + "</p>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	found := false
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a high-confidence XSS flow when no sanitizer is applied (regression check)")
	}
}

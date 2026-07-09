package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// Ktor io.ktor.http URL-encoding String extensions (Codecs.kt). They
// percent-encode a value for safe inclusion in a URL component, neutralizing
// open-redirect (SnkRedirect) and URL-in-HTML (SnkHTMLOutput) injection. The
// tainted value is the call receiver, resolved via the walker's
// callReceiverTainted fallback.

func TestKotlin_Redirect_Safe_KtorEncodeURLParameter(t *testing.T) {
	code := `
import io.ktor.http.*

fun handler() {
    val next = readLine()
    val safe = next.encodeURLParameter()
    call.respondRedirect("/dashboard?next=" + safe)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence open-redirect flow when encodeURLParameter() encodes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestKotlin_Redirect_Safe_KtorEncodeURLParameterValue(t *testing.T) {
	code := `
import io.ktor.http.*

fun handler() {
    val next = readLine()
    val safe = next.encodeURLParameterValue()
    call.respondRedirect("/go?to=" + safe)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence open-redirect flow when encodeURLParameterValue() encodes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestKotlin_Redirect_Safe_KtorEncodeURLPathPart(t *testing.T) {
	code := `
import io.ktor.http.*

fun handler() {
    val seg = readLine()
    val safe = seg.encodeURLPathPart()
    call.respondRedirect("/files/" + safe)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkRedirect && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence open-redirect flow when encodeURLPathPart() encodes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestKotlin_XSS_Safe_KtorEncodeURLPath(t *testing.T) {
	code := `
import io.ktor.http.*

fun handler() {
    val p = readLine()
    val safe = p.encodeURLPath()
    call.respond("<a href=\"/view/" + safe + "\">open</a>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when encodeURLPath() encodes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestKotlin_XSS_Safe_KtorEncodeURLQueryComponent(t *testing.T) {
	code := `
import io.ktor.http.*

fun handler() {
    val q = readLine()
    val safe = q.encodeURLQueryComponent()
    call.respond("<a href=\"/search?q=" + safe + "\">results</a>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when encodeURLQueryComponent() encodes input, got conf %.2f", f.Confidence)
		}
	}
}

// --- Negative regression controls: identical shape, no sanitizer, must flag ---

func TestKotlin_Redirect_Unsafe_KtorNoEncodeControl(t *testing.T) {
	code := `
fun handler() {
    val next = readLine()
    call.respondRedirect("/dashboard?next=" + next)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected open-redirect flow for readLine -> call.respondRedirect() without any encoding")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestKotlin_XSS_Unsafe_KtorNoEncodeControl(t *testing.T) {
	code := `
fun handler() {
    val q = readLine()
    call.respond("<a href=\"/search?q=" + q + "\">results</a>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for readLine -> call.respond() without any encoding")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// --- Jsoup ---

func TestKotlin_XSS_Safe_JsoupClean(t *testing.T) {
	code := `
import org.jsoup.Jsoup
import org.jsoup.safety.Safelist

fun handler() {
    val userHtml = readLine()
    val safe = Jsoup.clean(userHtml, Safelist.basic())
    call.respond(safe)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when Jsoup.clean() sanitizes input, got conf %.2f", f.Confidence)
		}
	}
}

// --- OWASP Java HTML Sanitizer ---

func TestKotlin_XSS_Safe_OwaspHtmlSanitizerPolicy(t *testing.T) {
	code := `
import org.owasp.html.HtmlPolicyBuilder
import org.owasp.html.PolicyFactory

fun handler() {
    val userHtml = readLine()
    val policy = HtmlPolicyBuilder().allowElements("a", "b").toFactory()
    val safe = policy.sanitize(userHtml)
    call.respond(safe)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when PolicyFactory.sanitize() neutralizes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestKotlin_XSS_Safe_OwaspHtmlSanitizerSanitizers(t *testing.T) {
	code := `
import org.owasp.html.Sanitizers

fun handler() {
    val userHtml = readLine()
    val safe = Sanitizers.FORMATTING.sanitize(userHtml)
    call.respond(safe)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when Sanitizers.FORMATTING.sanitize() neutralizes input, got conf %.2f", f.Confidence)
		}
	}
}

// --- Google Guava escapers ---

func TestKotlin_XSS_Safe_GuavaHtmlEscaper(t *testing.T) {
	code := `
import com.google.common.html.HtmlEscapers

fun handler() {
    val userInput = readLine()
    val safe = HtmlEscapers.htmlEscaper().escape(userInput)
    call.respond("<p>" + safe + "</p>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when HtmlEscapers.htmlEscaper().escape() escapes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestKotlin_SSRF_Safe_GuavaUrlPathEscaper(t *testing.T) {
	code := `
import com.google.common.net.UrlEscapers
import java.net.URL

fun handler() {
    val userInput = readLine()
    val safe = UrlEscapers.urlPathSegmentEscaper().escape(userInput)
    val url = "https://api.example.com/" + safe
    URL(url).openConnection().getInputStream()
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence SSRF flow when UrlEscapers.urlPathSegmentEscaper().escape() encodes input, got conf %.2f", f.Confidence)
		}
	}
}

// --- java.net.IDN ---

func TestKotlin_SSRF_Safe_IDNToASCII(t *testing.T) {
	// IDN.toASCII validates that the hostname is well-formed Unicode and converts
	// it to ASCII. Combined with a host allowlist this defends against a class of
	// hostname-confusion SSRF attacks.
	code := `
import java.net.IDN
import java.net.URL

fun handler() {
    val userHost = readLine()
    val asciiHost = IDN.toASCII(userHost)
    if (asciiHost != "api.example.com") {
        throw IllegalArgumentException("forbidden host")
    }
    URL("https://" + asciiHost + "/path").openConnection().getInputStream()
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkURLFetch && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence SSRF flow when IDN.toASCII() + allowlist validates host, got conf %.2f", f.Confidence)
		}
	}
}

// --- Apache Commons Text additional escapers ---

func TestKotlin_XSS_Safe_StringEscapeUtilsEscapeJson(t *testing.T) {
	code := `
import org.apache.commons.text.StringEscapeUtils

fun handler() {
    val userInput = readLine()
    val safe = StringEscapeUtils.escapeJson(userInput)
    call.respond("{\"name\":\"" + safe + "\"}")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when StringEscapeUtils.escapeJson() escapes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestKotlin_XSS_Safe_StringEscapeUtilsEscapeEcmaScript(t *testing.T) {
	code := `
import org.apache.commons.text.StringEscapeUtils

fun handler() {
    val userInput = readLine()
    val safe = StringEscapeUtils.escapeEcmaScript(userInput)
    call.respond("<script>var x = '" + safe + "';</script>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when StringEscapeUtils.escapeEcmaScript() escapes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestKotlin_XSS_Safe_StringEscapeUtilsEscapeXml11(t *testing.T) {
	code := `
import org.apache.commons.text.StringEscapeUtils

fun handler() {
    val userInput = readLine()
    val safe = StringEscapeUtils.escapeXml11(userInput)
    call.respond("<feed><title>" + safe + "</title></feed>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when StringEscapeUtils.escapeXml11() escapes input, got conf %.2f", f.Confidence)
		}
	}
}

// --- Spring HtmlUtils numeric variants ---

func TestKotlin_XSS_Safe_SpringHtmlUtilsHtmlEscapeHex(t *testing.T) {
	code := `
import org.springframework.web.util.HtmlUtils

fun handler() {
    val userInput = readLine()
    val safe = HtmlUtils.htmlEscapeHex(userInput)
    call.respond("<div>" + safe + "</div>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when HtmlUtils.htmlEscapeHex() escapes input, got conf %.2f", f.Confidence)
		}
	}
}

func TestKotlin_XSS_Safe_SpringHtmlUtilsHtmlEscapeDecimal(t *testing.T) {
	code := `
import org.springframework.web.util.HtmlUtils

fun handler() {
    val userInput = readLine()
    val safe = HtmlUtils.htmlEscapeDecimal(userInput)
    call.respond("<div>" + safe + "</div>")
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkHTMLOutput && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence XSS flow when HtmlUtils.htmlEscapeDecimal() escapes input, got conf %.2f", f.Confidence)
		}
	}
}

// --- Negative regression: same code without sanitizer must still flag ---

func TestKotlin_XSS_Unsafe_NoSanitizerControl(t *testing.T) {
	// Control: identical structure to the sanitized tests but with no sanitizer
	// in the path. Ensures the sanitizers above neutralized a flow that would
	// otherwise be reported (i.e. they aren't trivially passing because no flow
	// exists in the first place).
	code := `
fun handler() {
    val userHtml = readLine()
    call.respond("<p>" + userHtml + "</p>")
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

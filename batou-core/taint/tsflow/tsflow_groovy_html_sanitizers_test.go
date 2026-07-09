package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Groovy modern HTML / URL / IDN sanitizer tests
// Mirrors PR #520 (kotlin-html-url-sanitizers) for Groovy. JSoup, OWASP Java
// HTML Sanitizer, Guava HtmlEscapers/UrlEscapers, java.net.IDN, and Apache
// Commons Text are JVM-wide and used identically across Java/Kotlin/Groovy.
// =========================================================================

// Baseline: confirms the underlying XSS flow fires without any sanitizer.
// If this test ever stops firing, the safe-tests below could pass trivially.
func TestGroovy_XSS_Baseline_Unsanitized(t *testing.T) {
	code := `
def handler(input) {
    ctx.render(input)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("expected XSS flow for parameter -> ctx.render (baseline must fire so safe tests aren't trivially passing)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- JSoup ---

func TestGroovy_XSS_Safe_JsoupClean(t *testing.T) {
	code := `
import org.jsoup.Jsoup
import org.jsoup.safety.Safelist

def handler(input) {
    def safe = Jsoup.clean(input, Safelist.basic())
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Jsoup.clean() should sanitize XSS flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- OWASP Java HTML Sanitizer (PolicyFactory) ---

func TestGroovy_XSS_Safe_OwaspHtmlSanitizerPolicy(t *testing.T) {
	code := `
import org.owasp.html.HtmlPolicyBuilder
import org.owasp.html.PolicyFactory

def handler(input) {
    def policy = new HtmlPolicyBuilder().allowElements("a", "b").toFactory()
    def safe = policy.sanitize(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("PolicyFactory.sanitize() should sanitize XSS flow")
	}
}

// --- OWASP Java HTML Sanitizer (prebuilt Sanitizers) ---

func TestGroovy_XSS_Safe_OwaspSanitizersFormatting(t *testing.T) {
	code := `
import org.owasp.html.Sanitizers

def handler(input) {
    def safe = Sanitizers.FORMATTING.sanitize(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Sanitizers.FORMATTING.sanitize() should sanitize XSS flow")
	}
}

// --- Guava HtmlEscapers ---

func TestGroovy_XSS_Safe_GuavaHtmlEscapers(t *testing.T) {
	code := `
import com.google.common.html.HtmlEscapers

def handler(input) {
    def safe = HtmlEscapers.htmlEscaper().escape(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("HtmlEscapers.htmlEscaper().escape() should sanitize XSS flow")
	}
}

// --- Guava UrlEscapers ---

func TestGroovy_SSRF_Baseline_Unsanitized(t *testing.T) {
	code := `
def handler(input) {
    def restTemplate = new RestTemplate()
    def result = restTemplate.getForObject(input, String.class)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("expected SSRF flow for parameter -> restTemplate.getForObject (baseline must fire)")
	}
}

func TestGroovy_SSRF_Safe_GuavaUrlEscapers(t *testing.T) {
	// Use an intermediate Escaper variable named "urlEscapers" so the
	// receiver of .escape(...) matches ObjectType "UrlEscapers" via the
	// matcher's direct-name match. This is a realistic Groovy idiom (callers
	// often hold an Escaper instance for repeated use).
	code := `
import com.google.common.net.UrlEscapers

def handler(input) {
    def urlEscapers = UrlEscapers.urlPathSegmentEscaper()
    def safe = urlEscapers.escape(input)
    def restTemplate = new RestTemplate()
    def result = restTemplate.getForObject(safe, String.class)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("UrlEscapers.urlPathSegmentEscaper() then escape() should sanitize SSRF flow")
	}
}

// --- java.net.IDN ---

func TestGroovy_SSRF_Safe_IdnToAscii(t *testing.T) {
	code := `
import java.net.IDN

def handler(input) {
    def safeHost = IDN.toASCII(input)
    def restTemplate = new RestTemplate()
    def result = restTemplate.getForObject(safeHost, String.class)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkURLFetch) {
		t.Error("IDN.toASCII() should sanitize SSRF flow")
	}
}

// --- Apache Commons Text — escapeJson ---

func TestGroovy_XSS_Safe_StringEscapeUtilsEscapeJson(t *testing.T) {
	code := `
import org.apache.commons.text.StringEscapeUtils

def handler(input) {
    def safe = StringEscapeUtils.escapeJson(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("StringEscapeUtils.escapeJson() should sanitize XSS flow")
	}
}

// --- Apache Commons Text — escapeEcmaScript ---

func TestGroovy_XSS_Safe_StringEscapeUtilsEscapeEcmaScript(t *testing.T) {
	code := `
import org.apache.commons.text.StringEscapeUtils

def handler(input) {
    def safe = StringEscapeUtils.escapeEcmaScript(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("StringEscapeUtils.escapeEcmaScript() should sanitize XSS flow")
	}
}

// --- Apache Commons Text — escapeXml11 ---

func TestGroovy_XSS_Safe_StringEscapeUtilsEscapeXml11(t *testing.T) {
	code := `
import org.apache.commons.text.StringEscapeUtils

def handler(input) {
    def safe = StringEscapeUtils.escapeXml11(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("StringEscapeUtils.escapeXml11() should sanitize XSS flow")
	}
}

// --- Spring HtmlUtils numeric escape variants ---

func TestGroovy_XSS_Safe_SpringHtmlUtilsHtmlEscapeHex(t *testing.T) {
	code := `
import org.springframework.web.util.HtmlUtils

def handler(input) {
    def safe = HtmlUtils.htmlEscapeHex(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("HtmlUtils.htmlEscapeHex() should sanitize XSS flow")
	}
}

func TestGroovy_XSS_Safe_SpringHtmlUtilsHtmlEscapeDecimal(t *testing.T) {
	code := `
import org.springframework.web.util.HtmlUtils

def handler(input) {
    def safe = HtmlUtils.htmlEscapeDecimal(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("HtmlUtils.htmlEscapeDecimal() should sanitize XSS flow")
	}
}

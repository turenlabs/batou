package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Groovy: Apache Commons Text + OWASP Java Encoder gap-fill sanitizer tests.
//
// The existing groovy.stringescapeutils entry only catches the legacy
// StringEscapeUtils.escapeHtml/escapeXml (deprecated in Apache Commons Lang 3
// when the API moved to Commons Text). Modern Groovy/Grails code uses
// escapeHtml4/escapeHtml3 and escapeJava, and OWASP Encoder users routinely
// reach for forCss*, forUri*, forXml*, and forCDATA. Without these as
// recognized sanitizers, taint-tracked XSS / log / redirect / SSRF / header
// flows produced false positives even when the developer applied the canonical
// JVM encoder for the context.
// =========================================================================

// --- Baselines: ensure the underlying flows fire without any sanitizer ---

func TestGroovy_Log_Baseline_Unsanitized(t *testing.T) {
	code := `
def handler(input) {
    log.info(input)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log injection flow for parameter -> log.info (baseline must fire so safe tests aren't trivially passing)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_Redirect_Baseline_Unsanitized(t *testing.T) {
	code := `
def handler(input) {
    response.sendRedirect(input)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("expected redirect flow for parameter -> response.sendRedirect (baseline must fire so safe tests aren't trivially passing)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- Apache Commons Text — escapeHtml4 / escapeHtml3 ---

func TestGroovy_XSS_Safe_StringEscapeUtilsEscapeHtml4(t *testing.T) {
	code := `
import org.apache.commons.text.StringEscapeUtils

def handler(input) {
    def safe = StringEscapeUtils.escapeHtml4(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("StringEscapeUtils.escapeHtml4() should sanitize XSS flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_XSS_Safe_StringEscapeUtilsEscapeHtml3(t *testing.T) {
	code := `
import org.apache.commons.text.StringEscapeUtils

def handler(input) {
    def safe = StringEscapeUtils.escapeHtml3(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("StringEscapeUtils.escapeHtml3() should sanitize XSS flow")
	}
}

// --- Apache Commons Text — escapeJava (log injection defense) ---

func TestGroovy_Log_Safe_StringEscapeUtilsEscapeJava(t *testing.T) {
	code := `
import org.apache.commons.text.StringEscapeUtils

def handler(input) {
    def safe = StringEscapeUtils.escapeJava(input)
    log.info(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkLog) {
		t.Error("StringEscapeUtils.escapeJava() should sanitize log injection flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- OWASP Java Encoder — forCssString / forCssUrl ---

func TestGroovy_XSS_Safe_OwaspEncoderForCssString(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

def handler(input) {
    def safe = Encode.forCssString(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forCssString() should sanitize XSS-in-CSS flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_XSS_Safe_OwaspEncoderForCssUrl(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

def handler(input) {
    def safe = Encode.forCssUrl(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forCssUrl() should sanitize XSS-in-CSS-url flow")
	}
}

// --- OWASP Java Encoder — forUri / forUriComponent ---

func TestGroovy_Redirect_Safe_OwaspEncoderForUri(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

def handler(input) {
    def safe = Encode.forUri(input)
    response.sendRedirect(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("Encode.forUri() should sanitize redirect flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_Redirect_Safe_OwaspEncoderForUriComponent(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

def handler(input) {
    def safe = Encode.forUriComponent(input)
    response.sendRedirect(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkRedirect) {
		t.Error("Encode.forUriComponent() should sanitize redirect flow")
	}
}

// --- OWASP Java Encoder — forXml / forXmlContent / forXmlAttribute / forCDATA ---

func TestGroovy_XSS_Safe_OwaspEncoderForXml(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

def handler(input) {
    def safe = Encode.forXml(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forXml() should sanitize XSS flow")
	}
}

func TestGroovy_XSS_Safe_OwaspEncoderForXmlContent(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

def handler(input) {
    def safe = Encode.forXmlContent(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forXmlContent() should sanitize XSS flow")
	}
}

func TestGroovy_XSS_Safe_OwaspEncoderForXmlAttribute(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

def handler(input) {
    def safe = Encode.forXmlAttribute(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forXmlAttribute() should sanitize XSS flow")
	}
}

func TestGroovy_XSS_Safe_OwaspEncoderForCDATA(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

def handler(input) {
    def safe = Encode.forCDATA(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forCDATA() should sanitize XSS flow")
	}
}

// --- Negative regression: an unrelated method named escapeHtml4 on a
// non-StringEscapeUtils receiver MUST NOT be treated as a sanitizer.
// This guards against catastrophic over-broadness if someone later widens
// the matcher. ---

func TestGroovy_XSS_NotSanitized_UnrelatedReceiverEscapeHtml4(t *testing.T) {
	code := `
def handler(input) {
    def attacker = new MyShim()
    def stillTainted = attacker.escapeHtml4(input)
    ctx.render(stillTainted)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("attacker.escapeHtml4() (non-StringEscapeUtils receiver) should NOT be treated as a sanitizer; XSS flow must still fire")
	}
}

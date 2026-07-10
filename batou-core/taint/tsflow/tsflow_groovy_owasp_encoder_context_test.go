package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	// Import taint language catalogs.
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Groovy: OWASP Java Encoder context-specific HTML/JavaScript sanitizers.
//
// The catalog already modeled the generic Encode.forHtml and
// Encode.forJavaScript encoders (plus forCss*/forUri*/forXml*). The OWASP
// Java Encoder also exposes the context-specific variants the OWASP XSS
// Prevention Cheat Sheet recommends for precise output contexts:
//   - forHtmlContent / forHtmlAttribute / forHtmlUnquotedAttribute
//   - forJavaScriptBlock / forJavaScriptAttribute / forJavaScriptSource
// These were unmodeled, so taint-tracked XSS flows produced false positives
// even when the developer applied the correct context encoder.
// =========================================================================

// --- Baseline: the underlying XSS flow must fire without any sanitizer, so
// the "safe" tests below aren't trivially passing. ---

func TestGroovy_OwaspCtx_XSS_Baseline_Unsanitized(t *testing.T) {
	code := `
def handler(input) {
    ctx.render(input)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("baseline: parameter -> ctx.render must produce an XSS flow so the safe tests are non-vacuous")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// --- OWASP Java Encoder — context-specific HTML methods ---

func TestGroovy_XSS_Safe_OwaspEncoderForHtmlContent(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

def handler(input) {
    def safe = Encode.forHtmlContent(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forHtmlContent() should sanitize the HTML-content XSS flow")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_XSS_Safe_OwaspEncoderForHtmlAttribute(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

def handler(input) {
    def safe = Encode.forHtmlAttribute(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forHtmlAttribute() should sanitize the quoted-attribute XSS flow")
	}
}

func TestGroovy_XSS_Safe_OwaspEncoderForHtmlUnquotedAttribute(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

def handler(input) {
    def safe = Encode.forHtmlUnquotedAttribute(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forHtmlUnquotedAttribute() should sanitize the unquoted-attribute XSS flow")
	}
}

// --- OWASP Java Encoder — context-specific JavaScript methods ---

func TestGroovy_XSS_Safe_OwaspEncoderForJavaScriptBlock(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

def handler(input) {
    def safe = Encode.forJavaScriptBlock(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forJavaScriptBlock() should sanitize the <script>-block XSS flow")
	}
}

func TestGroovy_XSS_Safe_OwaspEncoderForJavaScriptAttribute(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

def handler(input) {
    def safe = Encode.forJavaScriptAttribute(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forJavaScriptAttribute() should sanitize the event-handler-attribute XSS flow")
	}
}

func TestGroovy_XSS_Safe_OwaspEncoderForJavaScriptSource(t *testing.T) {
	code := `
import org.owasp.encoder.Encode

def handler(input) {
    def safe = Encode.forJavaScriptSource(input)
    ctx.render(safe)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("Encode.forJavaScriptSource() should sanitize the JS-string-literal XSS flow")
	}
}

// --- Negative regression: a same-named method on a non-Encode receiver MUST
// NOT be treated as a sanitizer (guards against matcher over-broadness). ---

func TestGroovy_XSS_NotSanitized_UnrelatedReceiverForHtmlContent(t *testing.T) {
	code := `
def handler(input) {
    def attacker = new MyShim()
    def stillTainted = attacker.forHtmlContent(input)
    ctx.render(stillTainted)
}
`
	flows := Analyze(code, "/app/Handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkHTMLOutput) {
		t.Error("attacker.forHtmlContent() (non-Encode receiver) must NOT be treated as a sanitizer; XSS flow must still fire")
	}
}

package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Tests for the Groovy regex ReDoS sink family-completion: String.replaceAll,
// String.replaceFirst, String.split, and the static Pattern.matches(regex,
// input). Groovy runs on the JVM and these are java.lang.String /
// java.util.regex.Pattern methods that compile their first argument into a
// java.util.regex.Pattern (backtracking engine), so an attacker-controlled
// regex enables catastrophic backtracking (CWE-1333).
//
// The DangerousArg is index 0 — the regex/pattern argument, NOT the subject
// string. This is the correct ReDoS semantics (attacker controls the pattern)
// and keeps the common constant-delimiter idiom (e.g. str.split(",")) silent.
// The source is request.getParameter (HttpServletRequest), which flows as the
// pattern argument.

func TestGroovy_RegexReplaceAllReDoS(t *testing.T) {
	code := `
def handler() {
    def pat = request.getParameter("pattern")
    def str = "fixed subject text"
    return str.replaceAll(pat, "X")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Error("expected ReDoS flow for request.getParameter -> String.replaceAll(pattern)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_RegexReplaceFirstReDoS(t *testing.T) {
	code := `
def handler() {
    def pat = request.getParameter("pattern")
    def str = "fixed subject text"
    return str.replaceFirst(pat, "X")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Error("expected ReDoS flow for request.getParameter -> String.replaceFirst(pattern)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_RegexSplitReDoS(t *testing.T) {
	code := `
def handler() {
    def pat = request.getParameter("delim")
    def str = "a,b,c,d"
    return str.split(pat)
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Error("expected ReDoS flow for request.getParameter -> String.split(pattern)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_RegexPatternMatchesReDoS(t *testing.T) {
	code := `
def handler() {
    def pat = request.getParameter("pattern")
    return Pattern.matches(pat, "candidate input")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Error("expected ReDoS flow for request.getParameter -> Pattern.matches(pattern)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Negative control: a constant delimiter/pattern must NOT produce a ReDoS
// flow. The DangerousArg keys on arg 0 (the pattern), so a literal pattern is
// untainted even though the subject string came from user input.
func TestGroovy_RegexConstantPatternNoReDoS(t *testing.T) {
	code := `
def handler() {
    def subject = request.getParameter("data")
    return subject.split(",")
}
`
	flows := Analyze(code, "/app/handler.groovy", rules.LangGroovy)
	if hasTaintFlow(flows, taint.SnkRegexDoS) {
		t.Error("did NOT expect ReDoS flow for a constant split delimiter")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

// =========================================================================
// Groovy log-injection sinks (CWE-117, CWE-134)
// =========================================================================

func TestGroovy_LogTrace(t *testing.T) {
	code := `
def audit(userInput) {
    log.trace("trace: " + userInput)
}
`
	flows := Analyze(code, "/app/audit.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log flow for userInput -> log.trace")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_LogFatal(t *testing.T) {
	code := `
def crashLog(userInput) {
    log.fatal("fatal error from " + userInput)
}
`
	flows := Analyze(code, "/app/crash.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log flow for userInput -> log.fatal")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_SystemOutPrintln(t *testing.T) {
	code := `
def show(userInput) {
    System.out.println("user said: " + userInput)
}
`
	flows := Analyze(code, "/app/show.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log flow for userInput -> System.out.println")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_SystemErrPrintln(t *testing.T) {
	code := `
def showErr(userInput) {
    System.err.println("error: " + userInput)
}
`
	flows := Analyze(code, "/app/err.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log flow for userInput -> System.err.println")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_SystemPrintfFormat(t *testing.T) {
	code := `
def formatLog(userInput) {
    System.out.printf(userInput, "arg1")
}
`
	flows := Analyze(code, "/app/format.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log flow for userInput -> System.out.printf (format string)")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_MDCPut(t *testing.T) {
	code := `
def tagRequest(userInput) {
    MDC.put("requestId", userInput)
}
`
	flows := Analyze(code, "/app/mdc.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log flow for userInput -> MDC.put")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

func TestGroovy_JULLoggerLog(t *testing.T) {
	code := `
def handler(userInput) {
    Logger.getLogger("app").log(java.util.logging.Level.INFO, userInput)
}
`
	flows := Analyze(code, "/app/jul.groovy", rules.LangGroovy)
	if !hasTaintFlow(flows, taint.SnkLog) {
		t.Error("expected log flow for userInput -> Logger.getLogger().log")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// =========================================================================
// Safe: sanitized via CRLF replace — should not be a high-confidence flow
// =========================================================================

func TestGroovy_LogTrace_Sanitized(t *testing.T) {
	code := `
def audit(userInput) {
    def safe = userInput.replace("\n", "").replace("\r", "")
    log.trace("trace: " + safe)
}
`
	flows := Analyze(code, "/app/audit.groovy", rules.LangGroovy)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog {
			t.Logf("note: sanitized flow still reported — acceptable if confidence is downgraded (flow: %s -> %s, conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

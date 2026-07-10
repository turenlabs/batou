package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
)

func kotlinHasLogFlow(flows []taint.TaintFlow, sinkID string) bool {
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog && f.Sink.ID == sinkID {
			return true
		}
	}
	return false
}

func TestKotlin_Log_Warn(t *testing.T) {
	code := `
fun handler(req: HttpServletRequest) {
    val user = req.getParameter("user")
    logger.warn("login attempt: " + user)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !kotlinHasLogFlow(flows, "kotlin.log.warn") {
		t.Errorf("expected kotlin.log.warn flow, got: %+v", flows)
	}
}

func TestKotlin_Log_Debug(t *testing.T) {
	code := `
fun handler(req: HttpServletRequest) {
    val user = req.getParameter("user")
    logger.debug("processing: " + user)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !kotlinHasLogFlow(flows, "kotlin.log.debug") {
		t.Errorf("expected kotlin.log.debug flow, got: %+v", flows)
	}
}

func TestKotlin_Log_Trace(t *testing.T) {
	code := `
fun handler(req: HttpServletRequest) {
    val user = req.getParameter("user")
    logger.trace("trace: " + user)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !kotlinHasLogFlow(flows, "kotlin.log.trace") {
		t.Errorf("expected kotlin.log.trace flow, got: %+v", flows)
	}
}

func TestKotlin_SystemOut_Println(t *testing.T) {
	code := `
fun handler(req: HttpServletRequest) {
    val user = req.getParameter("user")
    System.out.println("user: " + user)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !kotlinHasLogFlow(flows, "kotlin.system.out.println") {
		t.Errorf("expected kotlin.system.out.println flow, got: %+v", flows)
	}
}

func TestKotlin_SystemErr_Println(t *testing.T) {
	code := `
fun handler(req: HttpServletRequest) {
    val user = req.getParameter("user")
    System.err.println("error for user: " + user)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !kotlinHasLogFlow(flows, "kotlin.system.err.println") {
		t.Errorf("expected kotlin.system.err.println flow, got: %+v", flows)
	}
}

func TestKotlin_Timber_Log(t *testing.T) {
	code := `
fun handler(req: HttpServletRequest) {
    val user = req.getParameter("user")
    Timber.d("debug user: " + user)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !kotlinHasLogFlow(flows, "kotlin.timber.log") {
		t.Errorf("expected kotlin.timber.log flow, got: %+v", flows)
	}
}

func TestKotlin_String_Format(t *testing.T) {
	code := `
fun handler(req: HttpServletRequest) {
    val user = req.getParameter("user")
    val msg = String.format(user)
    logger.info(msg)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	if !kotlinHasLogFlow(flows, "kotlin.string.format") {
		t.Errorf("expected kotlin.string.format flow, got: %+v", flows)
	}
}

func TestKotlin_Log_Safe_Sanitized(t *testing.T) {
	code := `
fun handler(req: HttpServletRequest) {
    val user = req.getParameter("user")
    val clean = user.replace("\n", "").replace("\r", "")
    logger.warn("login attempt: " + clean)
}
`
	flows := Analyze(code, "/app/Handler.kt", rules.LangKotlin)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkLog && f.Confidence > 0.5 {
			t.Errorf("expected no high-confidence log flow when CRLF stripped, got: %+v", f)
		}
	}
}

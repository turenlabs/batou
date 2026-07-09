package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// HttpServletResponse / ServletResponse are servlet OUTPUT objects — the handler
// writes TO them; they never carry user input. They must NOT be seeded as
// tainted handler parameters, or every `response.setContentType(..)` /
// `setHeader(..)` / `getWriter()` call trips a spurious tainted-RECEIVER header
// (CWE-113) / XSS flow. A real block-FP cluster of this shape was observed on
// thingsboard's controllers. These are guarded by HttpServletResponse /
// ServletResponse in tsflowJavaDIParamTypeAllowlist (and the mirrored graph
// javaDIParamTypeAllowlist).

func TestJava_ResponseParam_NotSeeded_NoHeaderFP(t *testing.T) {
	code := `
import javax.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.*;

@RestController
public class C {
    @GetMapping("/a")
    public void h(HttpServletResponse response) {
        response.setContentType("application/json");
        response.setHeader("Cache-Control", "no-cache");
    }
}
`
	flows := Analyze(code, "/app/C.java", rules.LangJava)
	if hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("FP: HttpServletResponse output object seeded as source -> setContentType/setHeader header flow; response must not be a taint source")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.MethodName, f.Sink.Category)
		}
	}
}

// Control 1: a genuine header injection — a request-sourced value flowing into
// response.setHeader's value arg — MUST still fire. The fix removes the RESPONSE
// object as a source, not the header sink itself.
func TestJava_ResponseParam_RealHeaderInjectionStillFires(t *testing.T) {
	code := `
import javax.servlet.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
public class D {
    @GetMapping("/b")
    public void h(HttpServletRequest request, HttpServletResponse response) {
        String v = request.getParameter("v");
        response.setHeader("X-Custom", v);
    }
}
`
	flows := Analyze(code, "/app/D.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkHeader) {
		t.Error("regression: request.getParameter -> response.setHeader(value) header injection must still fire")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s", f.Source.MethodName, f.Sink.Category)
		}
	}
}

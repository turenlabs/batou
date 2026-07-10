package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// A local variable named `args` is NOT the main(String[] args) parameter.
// The java.main.args catalog entry (SrcCLIArg, ObjectType "") must not
// bare-name-match arbitrary locals: `String[] args = {"sh", "-c", cmd}`
// passed to ProcessBuilder was firing command_exec at confidence 1.0 on
// every safe OWASP cmdi case (38 FPs).
func TestJava_LocalArgsVariable_NotCLISource(t *testing.T) {
	code := `
public class Runner {
    public void run(HttpServletRequest request, HttpServletResponse response) {
        String a1 = "sh";
        String a2 = "-c";
        String[] args = {a1, a2, "echo hello"};
        ProcessBuilder pb = new ProcessBuilder(args);
        pb.start();
    }
}
`
	flows := Analyze(code, "/app/Runner.java", rules.LangJava)
	for _, f := range flows {
		if f.Sink.Category == taint.SnkCommand && f.Source.Category == taint.SrcCLIArg {
			t.Errorf("local `args` variable wrongly seeded as CLI-arg source: %s -> %s (conf %.2f)",
				f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

// Genuinely tainted data flowing into ProcessBuilder must keep firing — the
// fix is scoped to the bare-name CLI-arg seeding, not command sinks.
func TestJava_TaintedProcessBuilder_StillFires(t *testing.T) {
	code := `
public class Runner {
    public void run(HttpServletRequest request) {
        String cmd = request.getParameter("cmd");
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", cmd);
        pb.start();
    }
}
`
	flows := Analyze(code, "/app/Runner.java", rules.LangJava)
	if !hasTaintFlow(flows, taint.SnkCommand) {
		t.Error("expected command_exec flow for request.getParameter -> ProcessBuilder")
		for _, f := range flows {
			t.Logf("  flow: %s -> %s (conf: %.2f)", f.Source.Category, f.Sink.Category, f.Confidence)
		}
	}
}

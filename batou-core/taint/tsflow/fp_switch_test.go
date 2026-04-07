package tsflow

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
)

func TestFPSwitchCharAt(t *testing.T) {
	code := `
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BenchmarkTest extends javax.servlet.http.HttpServlet {
    public void doPost(HttpServletRequest request, HttpServletResponse response) {
        String param = request.getHeader("BenchmarkTest");
        String bar;
        String guess = "ABC";
        char switchTarget = guess.charAt(1);
        switch (switchTarget) {
            case 'A':
                bar = param;
                break;
            case 'B':
                bar = "bob";
                break;
            case 'C':
            case 'D':
                bar = param;
                break;
            default:
                bar = "bob's your uncle";
                break;
        }
        response.getWriter().println(bar);
    }
}
`
	flows := Analyze(code, "/app/Test.java", rules.LangJava)
	t.Logf("Switch charAt flows: %d", len(flows))
	for i, f := range flows {
		t.Logf("  Flow %d: src=%s sink=%s conf=%.2f", i, f.Source.ID, f.Sink.ID, f.Confidence)
	}
	if len(flows) > 0 {
		t.Errorf("Expected 0 flows for switch on charAt('B') = safe case, got %d", len(flows))
	}
}

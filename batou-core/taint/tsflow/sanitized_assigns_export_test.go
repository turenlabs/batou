package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// factsForVar filters facts to one variable, preserving order.
func factsForVar(facts []AssignFact, v string) []AssignFact {
	var out []AssignFact
	for _, f := range facts {
		if f.Var == v {
			out = append(out, f)
		}
	}
	return out
}

func TestAssignmentFacts_Python_SanitizingAndPlain(t *testing.T) {
	content := `import html

def handler(request):
    user = request.args.get("q")
    safe = html.escape(user)
    plain = user
    run(safe, plain)
`
	facts := AssignmentFacts(content, "/app/handler.py", rules.LangPython, nil)
	if len(facts) == 0 {
		t.Fatal("expected facts, got none")
	}

	safe := factsForVar(facts, "safe")
	if len(safe) != 1 {
		t.Fatalf("expected 1 fact for safe, got %d (%v)", len(safe), facts)
	}
	if safe[0].SanitizedCats == nil {
		t.Fatal("safe = html.escape(user) should be a sanitizing fact")
	}
	if !safe[0].SanitizedCats[taint.SnkHTMLOutput] {
		t.Fatalf("html.escape should neutralize SnkHTMLOutput, got %v", safe[0].SanitizedCats)
	}
	// Category pairing: no python catalog sanitizer keyed under "escape"
	// neutralizes command execution. (SnkSQLQuery IS unioned in via
	// py.re.escape, which has ObjectType "" — same answer
	// matchSanitizerForCategory gives for this call.)
	if safe[0].SanitizedCats[taint.SnkCommand] {
		t.Fatal("html.escape must NOT neutralize SnkCommand (category pairing)")
	}
	if safe[0].Line != 5 {
		t.Fatalf("safe fact line = %d, want 5", safe[0].Line)
	}

	plain := factsForVar(facts, "plain")
	if len(plain) != 1 {
		t.Fatalf("expected 1 fact for plain, got %d", len(plain))
	}
	if plain[0].SanitizedCats != nil {
		t.Fatalf("plain = user must be a plain fact, got cats %v", plain[0].SanitizedCats)
	}

	// The source assignment is also a plain fact.
	user := factsForVar(facts, "user")
	if len(user) != 1 || user[0].SanitizedCats != nil {
		t.Fatalf("user = request... should be a single plain fact, got %v", user)
	}
}

func TestAssignmentFacts_Python_RebindOrderingPreserved(t *testing.T) {
	content := `def handler(request):
    y = shlex.quote(request.args.get("q"))
    y = request.args.get("q")
    run(y)
`
	facts := factsForVar(AssignmentFacts(content, "/app/h.py", rules.LangPython, nil), "y")
	if len(facts) != 2 {
		t.Fatalf("expected 2 facts for y, got %d", len(facts))
	}
	if facts[0].Line >= facts[1].Line {
		t.Fatalf("facts out of line order: %d then %d", facts[0].Line, facts[1].Line)
	}
	if facts[0].SanitizedCats == nil || !facts[0].SanitizedCats[taint.SnkCommand] {
		t.Fatalf("first fact should sanitize SnkCommand (shlex.quote), got %v", facts[0].SanitizedCats)
	}
	if facts[1].SanitizedCats != nil {
		t.Fatalf("rebind fact must be plain, got %v", facts[1].SanitizedCats)
	}
}

func TestAssignmentFacts_Python_AugmentedAssignIsPlain(t *testing.T) {
	content := `def handler(request):
    y = "a"
    y += html.escape(request.args.get("q"))
`
	facts := factsForVar(AssignmentFacts(content, "/app/h.py", rules.LangPython, nil), "y")
	if len(facts) != 2 {
		t.Fatalf("expected 2 facts for y, got %d", len(facts))
	}
	if facts[1].SanitizedCats != nil {
		t.Fatalf("y += escape(...) must be a PLAIN fact (compound keeps prior taint), got %v", facts[1].SanitizedCats)
	}
}

func TestAssignmentFacts_Python_FieldPathLHSReducesToBase(t *testing.T) {
	content := `class C:
    def m(self, request):
        self.q = html.escape(request.args.get("q"))
        d["k"] = request.args.get("x")
`
	facts := AssignmentFacts(content, "/app/h.py", rules.LangPython, nil)
	selfFacts := factsForVar(facts, "self")
	if len(selfFacts) != 1 {
		t.Fatalf("self.q LHS should reduce to base var 'self': %v", facts)
	}
	if !selfFacts[0].SanitizedCats[taint.SnkHTMLOutput] {
		t.Fatalf("self.q = html.escape(...) should sanitize HTML, got %v", selfFacts[0].SanitizedCats)
	}
	dFacts := factsForVar(facts, "d")
	if len(dFacts) != 1 || dFacts[0].SanitizedCats != nil {
		t.Fatalf("d[\"k\"] subscript LHS should reduce to plain fact on 'd': %v", dFacts)
	}
}

func TestAssignmentFacts_JavaScript(t *testing.T) {
	content := `function handler(req, res) {
  const safe = escapeHtml(req.query.name);
  let idNum = parseInt(req.query.id);
  var plain = req.query.raw;
  use(safe, idNum, plain);
}
`
	facts := AssignmentFacts(content, "/app/h.js", rules.LangJavaScript, nil)

	safe := factsForVar(facts, "safe")
	if len(safe) != 1 || safe[0].SanitizedCats == nil || !safe[0].SanitizedCats[taint.SnkHTMLOutput] {
		t.Fatalf("const safe = escapeHtml(...) should sanitize SnkHTMLOutput, got %v", safe)
	}

	id := factsForVar(facts, "idNum")
	if len(id) != 1 || id[0].SanitizedCats == nil ||
		!id[0].SanitizedCats[taint.SnkSQLQuery] || !id[0].SanitizedCats[taint.SnkCommand] {
		t.Fatalf("parseInt should sanitize SQL+Command, got %v", id)
	}
	if id[0].SanitizedCats[taint.SnkHTMLOutput] {
		t.Fatal("parseInt must not claim SnkHTMLOutput")
	}

	plain := factsForVar(facts, "plain")
	if len(plain) != 1 || plain[0].SanitizedCats != nil {
		t.Fatalf("var plain = req.query.raw must be plain, got %v", plain)
	}
}

func TestAssignmentFacts_JavaScript_ReassignmentAndCompound(t *testing.T) {
	content := `function handler(req) {
  let y = escapeHtml(req.query.name);
  y = req.query.name;
  let z = "";
  z += escapeHtml(req.query.other);
}
`
	facts := AssignmentFacts(content, "/app/h.js", rules.LangJavaScript, nil)
	y := factsForVar(facts, "y")
	if len(y) != 2 {
		t.Fatalf("expected 2 facts for y, got %v", y)
	}
	if y[0].SanitizedCats == nil || y[1].SanitizedCats != nil {
		t.Fatalf("y facts should be [sanitizing, plain], got %v", y)
	}
	z := factsForVar(facts, "z")
	if len(z) != 2 {
		t.Fatalf("expected 2 facts for z, got %v", z)
	}
	if z[1].SanitizedCats != nil {
		t.Fatalf("z += escapeHtml(...) must be plain (compound), got %v", z[1].SanitizedCats)
	}
}

func TestAssignmentFacts_Ruby(t *testing.T) {
	content := `def handler(params)
  safe = Shellwords.escape(params[:cmd])
  plain = params[:cmd]
  run(safe, plain)
end
`
	facts := AssignmentFacts(content, "/app/h.rb", rules.LangRuby, nil)
	safe := factsForVar(facts, "safe")
	if len(safe) != 1 || safe[0].SanitizedCats == nil || !safe[0].SanitizedCats[taint.SnkCommand] {
		t.Fatalf("Shellwords.escape should sanitize SnkCommand, got %v", safe)
	}
	plain := factsForVar(facts, "plain")
	if len(plain) != 1 || plain[0].SanitizedCats != nil {
		t.Fatalf("plain = params[:cmd] must be plain, got %v", plain)
	}
}

func TestAssignmentFacts_Java(t *testing.T) {
	content := `public class H {
  void handler(HttpServletRequest request) {
    String safe = StringEscapeUtils.escapeHtml4(request.getParameter("q"));
    String plain = request.getParameter("q");
    int id = Integer.parseInt(request.getParameter("id"));
    use(safe, plain, id);
  }
}
`
	facts := AssignmentFacts(content, "/app/H.java", rules.LangJava, nil)
	safe := factsForVar(facts, "safe")
	if len(safe) != 1 || safe[0].SanitizedCats == nil || !safe[0].SanitizedCats[taint.SnkHTMLOutput] {
		t.Fatalf("StringEscapeUtils.escapeHtml4 should sanitize SnkHTMLOutput, got %v", safe)
	}
	plain := factsForVar(facts, "plain")
	if len(plain) != 1 || plain[0].SanitizedCats != nil {
		t.Fatalf("plain decl must be plain fact, got %v", plain)
	}
	id := factsForVar(facts, "id")
	if len(id) != 1 || id[0].SanitizedCats == nil || !id[0].SanitizedCats[taint.SnkSQLQuery] {
		t.Fatalf("Integer.parseInt should sanitize SnkSQLQuery, got %v", id)
	}
}

func TestAssignmentFacts_UnsupportedOrUnparseable(t *testing.T) {
	if facts := AssignmentFacts("x = 1", "/app/x.zig", rules.LangZig, nil); facts != nil {
		// Zig has a config but no grammar; parse returns nil → nil facts.
		t.Fatalf("Zig (no grammar) should yield nil facts, got %v", facts)
	}
	if facts := AssignmentFacts("package main", "/app/x.go", rules.LangGo, nil); facts != nil {
		t.Fatalf("Go (no tsflow config) should yield nil facts, got %v", facts)
	}
}

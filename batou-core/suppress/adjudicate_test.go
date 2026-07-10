package suppress

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// sqlTaintFinding builds a representative suppressed SQL-injection taint finding
// whose sink argument is string-concatenated and whose path has no sanitizer.
func sqlTaintFinding(line int) rules.Finding {
	return rules.Finding{
		RuleID:         "BATOU-TAINT-sql_query",
		FilePath:       "/app/dao.py",
		LineNumber:     line,
		CWEID:          "CWE-89",
		SourceCategory: "user_input",
		SinkCategory:   "sql_query",
		MatchedText:    "args.get (line 5) → uid → query → execute (line 9)",
		TaintPath: []rules.TaintStep{
			{Line: 5, Kind: rules.TaintStepSource, Label: "args.get"},
			{Line: 6, Kind: rules.TaintStepPropagation, Label: `assigned to query ("..." + uid)`},
			{Line: line, Kind: rules.TaintStepSink, Label: "execute"},
		},
		Tags: []string{"taint-analysis", "dataflow"},
	}
}

func TestClassifyReason(t *testing.T) {
	cases := []struct {
		reason string
		want   claimKind
	}{
		{"parameterized query", claimParameterized},
		{"uses prepared statement", claimParameterized},
		{"bound parameters", claimParameterized},
		{"input is sanitized before use", claimSanitized},
		{"value is validated", claimSanitized},
		{"output is escaped", claimSanitized},
		{"not user input", claimTrustedInput},
		{"value is hardcoded", claimTrustedInput},
		{"trusted internal source", claimTrustedInput},
		// Unverifiable — must NOT be judged.
		{"false positive", claimNone},
		{"test fixture", claimNone},
		{"by design", claimNone},
		{"acceptable risk", claimNone},
		{"", claimNone},
		// Unverifiable wins even when a checkable keyword also appears.
		{"false positive, sanitized elsewhere", claimNone},
	}
	for _, c := range cases {
		if got := classifyReason(c.reason); got != c.want {
			t.Errorf("classifyReason(%q) = %v, want %v", c.reason, got, c.want)
		}
	}
}

func TestContradicts_ParameterizedConcat(t *testing.T) {
	f := sqlTaintFinding(9)
	msg, contradicted := contradicts(claimParameterized, f)
	if !contradicted {
		t.Fatalf("concatenated SQL flow with 'parameterized' claim should be contradicted")
	}
	if msg == "" {
		t.Errorf("expected a contradiction message")
	}
}

func TestContradicts_SanitizedNoSanitizer(t *testing.T) {
	f := sqlTaintFinding(9)
	if _, contradicted := contradicts(claimSanitized, f); !contradicted {
		t.Errorf("taint flow with no sanitizer should contradict a 'sanitized' claim")
	}
}

func TestContradicts_TrustedUserInput(t *testing.T) {
	f := sqlTaintFinding(9)
	if _, contradicted := contradicts(claimTrustedInput, f); !contradicted {
		t.Errorf("user_input source should contradict a 'trusted/not user input' claim")
	}
}

func TestContradicts_NonTaintFinding_NotJudged(t *testing.T) {
	// A regex/AST finding carries no verifiable flow properties.
	f := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 9, Tags: []string{"regex"}}
	if _, contradicted := contradicts(claimSanitized, f); contradicted {
		t.Errorf("non-taint finding must not be adjudicated")
	}
}

func TestContradicts_FlowWithSanitizer_NotJudged(t *testing.T) {
	f := sqlTaintFinding(9)
	// Inject a recorded bypassed-sanitizer node: the author may legitimately be
	// asserting a sanitizer is present, so we must not flag a 'sanitized' claim.
	f.TaintPath = append(f.TaintPath, rules.TaintStep{
		Line: 7, Kind: rules.TaintStepSanitizerBypassed, Label: "escape()",
	})
	if _, contradicted := contradicts(claimSanitized, f); contradicted {
		t.Errorf("flow that records a sanitizer node must not contradict a 'sanitized' claim")
	}
}

// TestAdjudicate_EndToEnd_Parse drives the actual parse → suppress → adjudicate
// path within the package: build Suppressions from source text containing the
// directive, confirm the reason maps back to the finding, and confirm Adjudicate
// emits exactly one BATOU-SUPPRESS-UNJUSTIFIED.
func TestAdjudicate_EndToEnd_Parse(t *testing.T) {
	src := `def lookup(request, conn):
    uid = request.args.get("id")
    query = "SELECT * FROM t WHERE id = '" + uid + "'"
    cur = conn.cursor()
    # batou:ignore BATOU-TAINT-sql_query -- parameterized query
    cur.execute(query)
`
	s := Parse(src)

	// The directive is on line 5; nextCodeLine extends it to line 6 (the sink).
	f := sqlTaintFinding(6)

	reason, ok := s.reasonForFinding(f)
	if !ok || reason != "parameterized query" {
		t.Fatalf("reasonForFinding = %q, %v; want 'parameterized query', true", reason, ok)
	}

	adj := Adjudicate(s, []rules.Finding{f})
	if len(adj) != 1 {
		t.Fatalf("expected 1 adjudication, got %d", len(adj))
	}
	got := adj[0].Finding
	if got.RuleID != UnjustifiedRuleID {
		t.Errorf("rule ID = %q, want %q", got.RuleID, UnjustifiedRuleID)
	}
	if got.LineNumber != 6 {
		t.Errorf("line = %d, want 6 (the sink)", got.LineNumber)
	}
	if got.SinkCategory != "sql_query" {
		t.Errorf("sink category lost: %q", got.SinkCategory)
	}
}

func TestAdjudicate_TruthfulUnverifiable_NoFlag(t *testing.T) {
	src := `def lookup(request, conn):
    uid = request.args.get("id")
    query = "SELECT * FROM t WHERE id = '" + uid + "'"
    cur = conn.cursor()
    # batou:ignore BATOU-TAINT-sql_query -- false positive, validated upstream
    cur.execute(query)
`
	s := Parse(src)
	f := sqlTaintFinding(6)
	if adj := Adjudicate(s, []rules.Finding{f}); len(adj) != 0 {
		t.Fatalf("unverifiable reason must not be adjudicated; got %d findings", len(adj))
	}
}

// TestAdjudicate_MismatchedTarget_NoFlag confirms that a directive whose target
// does not match the finding's rule/category is not used to adjudicate it.
func TestAdjudicate_MismatchedTarget_NoFlag(t *testing.T) {
	src := `def lookup(request, conn):
    uid = request.args.get("id")
    query = "SELECT * FROM t WHERE id = '" + uid + "'"
    cur = conn.cursor()
    # batou:ignore BATOU-TAINT-command_exec -- parameterized query
    cur.execute(query)
`
	s := Parse(src)
	f := sqlTaintFinding(6) // sql_query rule, but directive targets command_exec
	if _, ok := s.reasonForFinding(f); ok {
		t.Errorf("reasonForFinding should not match a mismatched target")
	}
	if adj := Adjudicate(s, []rules.Finding{f}); len(adj) != 0 {
		t.Fatalf("mismatched target must not adjudicate; got %d findings", len(adj))
	}
}

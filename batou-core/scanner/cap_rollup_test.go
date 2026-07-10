package scanner

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// MarkCrossFileSinkRollups groups BATOU-INTERPROC-* findings by leaf
// sink + rule_id and tags the (cap+1)th and beyond RolledUp=true.
// These tests pin the four shapes that the production scan paths hit:
//
//  1. middleware-chain explosion: 12 findings into one leaf sink →
//     10 kept un-tagged, 2 marked rolled-up.
//  2. multi-handler distinct flows: 4 different handlers reaching the
//     same leaf sink → all 4 kept un-tagged (below cap).
//  3. multi-rule co-existence: separate rule_ids on the same leaf line
//     don't share a group.
//  4. non-INTERPROC and TaintPath-less findings pass through unchanged.

func mkFinding(rule, src string, sevf rules.Severity, conf float64, callerFile string, callerLine int, sinkFile string, sinkLine int) rules.Finding {
	return rules.Finding{
		RuleID:          rule,
		Severity:        sevf,
		ConfidenceScore: conf,
		FilePath:        callerFile,
		LineNumber:      callerLine,
		SourceCategory:  src,
		TaintPath: []rules.TaintStep{
			{File: callerFile, Line: callerLine, Kind: rules.TaintStepSource, Label: "source"},
			{File: sinkFile, Line: sinkLine, Kind: rules.TaintStepSink, Label: "sink"},
		},
	}
}

func TestMarkCrossFileSinkRollups_MiddlewareChain(t *testing.T) {
	var findings []rules.Finding
	// 12 caller files all funnelling into the same leaf sink. The
	// middleware-chain pathology on Coder produced exactly this shape
	// with 200+ entries in a single group.
	for i := 0; i < 12; i++ {
		callerFile := "/proj/middleware/" + string('a'+rune(i)) + ".go"
		findings = append(findings, mkFinding(
			"BATOU-INTERPROC-LOG_OUTPUT",
			"external",
			rules.High,
			0.8,
			callerFile, 10,
			"/proj/pkg/logger.go", 42,
		))
	}

	_, tagged := MarkCrossFileSinkRollups(findings, 10)
	if tagged != 2 {
		t.Fatalf("tagged=%d, want 2", tagged)
	}
	rolled := 0
	for _, f := range findings {
		if f.RolledUp {
			rolled++
		}
	}
	if rolled != 2 {
		t.Fatalf("RolledUp count=%d, want 2", rolled)
	}
}

func TestMarkCrossFileSinkRollups_DistinctFlowsUnderCap(t *testing.T) {
	// 4 different distinct flows (different handlers) each reaching the
	// same leaf sink. Below the cap → all kept un-tagged. This is the
	// harness shape PR-NN destroyed by collapsing on sourceCategory.
	findings := []rules.Finding{
		mkFinding("BATOU-INTERPROC-DESERIALIZE", "user_input", rules.Critical, 0.9, "/proj/handler/a.go", 10, "/proj/yaml/decode.go", 46),
		mkFinding("BATOU-INTERPROC-DESERIALIZE", "user_input", rules.Critical, 0.9, "/proj/handler/b.go", 20, "/proj/yaml/decode.go", 46),
		mkFinding("BATOU-INTERPROC-DESERIALIZE", "external", rules.Critical, 0.9, "/proj/handler/c.go", 30, "/proj/yaml/decode.go", 46),
		mkFinding("BATOU-INTERPROC-DESERIALIZE", "user_input", rules.Critical, 0.85, "/proj/handler/d.go", 40, "/proj/yaml/decode.go", 46),
	}
	_, tagged := MarkCrossFileSinkRollups(findings, 10)
	if tagged != 0 {
		t.Fatalf("tagged=%d, want 0 (under cap)", tagged)
	}
	for i, f := range findings {
		if f.RolledUp {
			t.Errorf("findings[%d].RolledUp=true, want false (group below cap)", i)
		}
	}
}

func TestMarkCrossFileSinkRollups_MultiRulePerLeafLine(t *testing.T) {
	// Same leaf-sink line, different rule_ids — must be two independent
	// groups, both below the cap.
	findings := []rules.Finding{
		mkFinding("BATOU-INTERPROC-LOG_OUTPUT", "external", rules.High, 0.8, "/proj/a.go", 1, "/proj/sink.go", 99),
		mkFinding("BATOU-INTERPROC-HTML_OUTPUT", "external", rules.High, 0.8, "/proj/b.go", 2, "/proj/sink.go", 99),
	}
	_, tagged := MarkCrossFileSinkRollups(findings, 1)
	if tagged != 0 {
		t.Fatalf("tagged=%d, want 0 (each rule-id is its own group)", tagged)
	}
}

func TestMarkCrossFileSinkRollups_NonInterprocUntouched(t *testing.T) {
	findings := []rules.Finding{
		// 3 AST findings on the same line + rule — should NOT be
		// touched by the cross-file cap.
		{RuleID: "BATOU-AST-001", FilePath: "/proj/a.go", LineNumber: 5},
		{RuleID: "BATOU-AST-001", FilePath: "/proj/a.go", LineNumber: 5},
		{RuleID: "BATOU-AST-001", FilePath: "/proj/a.go", LineNumber: 5},
	}
	_, tagged := MarkCrossFileSinkRollups(findings, 1)
	if tagged != 0 {
		t.Fatalf("tagged=%d, want 0 (non-INTERPROC pass-through)", tagged)
	}
}

func TestMarkCrossFileSinkRollups_NoLeafSinkPassThrough(t *testing.T) {
	// A BATOU-INTERPROC-* finding whose TaintPath has no TaintStepSink
	// must pass through un-tagged even when there are many of them —
	// missing leaf-sink would otherwise hash to the same key and
	// silently collapse unrelated findings.
	findings := []rules.Finding{
		{RuleID: "BATOU-INTERPROC-LOG_OUTPUT", FilePath: "/proj/a.go", LineNumber: 1, TaintPath: []rules.TaintStep{}},
		{RuleID: "BATOU-INTERPROC-LOG_OUTPUT", FilePath: "/proj/b.go", LineNumber: 2, TaintPath: nil},
		{RuleID: "BATOU-INTERPROC-LOG_OUTPUT", FilePath: "/proj/c.go", LineNumber: 3, TaintPath: []rules.TaintStep{{Kind: rules.TaintStepSource}}},
	}
	_, tagged := MarkCrossFileSinkRollups(findings, 1)
	if tagged != 0 {
		t.Fatalf("tagged=%d, want 0 (no leaf-sink → no dedup)", tagged)
	}
}

func TestMarkCrossFileSinkRollups_DisabledByZeroCap(t *testing.T) {
	findings := []rules.Finding{
		mkFinding("BATOU-INTERPROC-LOG_OUTPUT", "external", rules.High, 0.8, "/p/a.go", 1, "/p/s.go", 9),
		mkFinding("BATOU-INTERPROC-LOG_OUTPUT", "external", rules.High, 0.8, "/p/b.go", 2, "/p/s.go", 9),
	}
	_, tagged := MarkCrossFileSinkRollups(findings, 0)
	if tagged != 0 {
		t.Fatalf("tagged=%d, want 0 (cap=0 disables)", tagged)
	}
	for _, f := range findings {
		if f.RolledUp {
			t.Errorf("RolledUp=true with cap=0; want false")
		}
	}
}

func TestMarkCrossFileSinkRollups_SelectionPriority(t *testing.T) {
	// When cap=2 and 4 entries exist in a group, the top 2 by
	// (severity DESC, confidence DESC) stay un-tagged.
	findings := []rules.Finding{
		mkFinding("BATOU-INTERPROC-FILE_WRITE", "external", rules.Low, 0.3, "/p/a.go", 1, "/p/s.go", 9),       // tag
		mkFinding("BATOU-INTERPROC-FILE_WRITE", "external", rules.High, 0.8, "/p/b.go", 2, "/p/s.go", 9),     // keep
		mkFinding("BATOU-INTERPROC-FILE_WRITE", "external", rules.Critical, 0.7, "/p/c.go", 3, "/p/s.go", 9), // keep
		mkFinding("BATOU-INTERPROC-FILE_WRITE", "external", rules.Medium, 0.5, "/p/d.go", 4, "/p/s.go", 9),   // tag
	}
	_, tagged := MarkCrossFileSinkRollups(findings, 2)
	if tagged != 2 {
		t.Fatalf("tagged=%d, want 2", tagged)
	}
	// Critical & High must be un-rolled; Medium & Low must be rolled.
	for i, f := range findings {
		switch f.Severity {
		case rules.Critical, rules.High:
			if f.RolledUp {
				t.Errorf("findings[%d] sev=%s RolledUp=true, want false (top-by-priority)", i, f.Severity)
			}
		case rules.Medium, rules.Low:
			if !f.RolledUp {
				t.Errorf("findings[%d] sev=%s RolledUp=false, want true (below-priority)", i, f.Severity)
			}
		}
	}
}

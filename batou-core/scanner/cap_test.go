package scanner

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
)

func makeFinding(ruleID string, sev rules.Severity, conf float64) rules.Finding {
	return rules.Finding{
		RuleID:          ruleID,
		Severity:        sev,
		ConfidenceScore: conf,
		RiskScore:       sev.ImpactWeight() * conf,
	}
}

func makeBlockingFinding(ruleID string) rules.Finding {
	return rules.Finding{
		RuleID:          ruleID,
		Severity:        rules.Critical,
		ConfidenceScore: 0.9,
		RiskScore:       0.9,
	}
}

func TestCapFindings_PerRuleCap(t *testing.T) {
	// 10 findings from the same rule — only top 3 by confidence should survive.
	var findings []rules.Finding
	for i := 0; i < 10; i++ {
		findings = append(findings, makeFinding("BATOU-RS-007", rules.Medium, 0.3+float64(i)*0.05))
	}

	kept, capped := CapFindings(findings, 3, 100)
	if len(kept) != 3 {
		t.Errorf("expected 3 kept, got %d", len(kept))
	}
	if capped != 7 {
		t.Errorf("expected 7 capped, got %d", capped)
	}

	// Verify the top 3 by confidence were kept (indices 7, 8, 9 → conf 0.65, 0.70, 0.75).
	for _, f := range kept {
		if f.ConfidenceScore < 0.65 {
			t.Errorf("expected only top confidence findings, got %.2f", f.ConfidenceScore)
		}
	}
}

func TestCapFindings_PerFileCap(t *testing.T) {
	// 30 findings from different rules — only top 20 by severity should survive.
	var findings []rules.Finding
	for i := 0; i < 10; i++ {
		findings = append(findings, makeFinding("BATOU-CRY-001", rules.High, 0.5))
	}
	for i := 0; i < 10; i++ {
		findings = append(findings, makeFinding("BATOU-INJ-001", rules.Medium, 0.4))
	}
	for i := 0; i < 10; i++ {
		findings = append(findings, makeFinding("BATOU-LOG-001", rules.Low, 0.3))
	}

	kept, capped := CapFindings(findings, 100, 20)
	if len(kept) != 20 {
		t.Errorf("expected 20 kept, got %d", len(kept))
	}
	if capped != 10 {
		t.Errorf("expected 10 capped, got %d", capped)
	}

	// All Low-severity findings should have been dropped.
	for _, f := range kept {
		if f.Severity == rules.Low {
			t.Error("expected Low severity findings to be capped")
		}
	}
}

func TestCapFindings_BothCaps(t *testing.T) {
	// 15 findings from one rule + 10 from another = 25 total.
	// Per-rule cap (3) reduces both rules to 3 each = 6.
	// Per-file cap (10) doesn't trigger since 6 < 10.
	// Total capped = 25 - 6 = 19.
	var findings []rules.Finding
	for i := 0; i < 15; i++ {
		findings = append(findings, makeFinding("BATOU-RS-007", rules.Medium, 0.3+float64(i)*0.01))
	}
	for i := 0; i < 10; i++ {
		findings = append(findings, makeFinding("BATOU-RS-008", rules.High, 0.5))
	}

	kept, capped := CapFindings(findings, 3, 10)
	if len(kept) != 6 {
		t.Errorf("expected 6 kept, got %d", len(kept))
	}
	if capped != 19 {
		t.Errorf("expected 19 capped, got %d", capped)
	}
}

func TestCapFindings_UnderLimits(t *testing.T) {
	findings := []rules.Finding{
		makeFinding("BATOU-INJ-001", rules.High, 0.5),
		makeFinding("BATOU-INJ-002", rules.Medium, 0.4),
	}

	kept, capped := CapFindings(findings, 3, 20)
	if len(kept) != 2 {
		t.Errorf("expected 2 kept, got %d", len(kept))
	}
	if capped != 0 {
		t.Errorf("expected 0 capped, got %d", capped)
	}
}

func TestCapFindings_BlockingAlwaysKept(t *testing.T) {
	// 5 blocking findings from the same rule should all survive per-rule cap.
	var findings []rules.Finding
	for i := 0; i < 5; i++ {
		findings = append(findings, makeBlockingFinding("BATOU-INJ-001"))
	}
	// Add 5 non-blocking from the same rule.
	for i := 0; i < 5; i++ {
		findings = append(findings, makeFinding("BATOU-INJ-001", rules.Medium, 0.4))
	}

	kept, capped := CapFindings(findings, 3, 100)

	// All 5 blockers + top 3 non-blockers = 8.
	if len(kept) != 8 {
		t.Errorf("expected 8 kept (5 blockers + 3 non-blockers), got %d", len(kept))
	}
	if capped != 2 {
		t.Errorf("expected 2 capped, got %d", capped)
	}

	// Verify all blockers survived.
	blockers := 0
	for _, f := range kept {
		if f.ShouldBlock() {
			blockers++
		}
	}
	if blockers != 5 {
		t.Errorf("expected 5 blocking findings kept, got %d", blockers)
	}
}

func TestCapFindings_Empty(t *testing.T) {
	kept, capped := CapFindings(nil, 3, 20)
	if len(kept) != 0 {
		t.Errorf("expected 0 kept, got %d", len(kept))
	}
	if capped != 0 {
		t.Errorf("expected 0 capped, got %d", capped)
	}
}

func TestCapFindings_TierPriority(t *testing.T) {
	// Taint and AST findings should survive over regex findings even at
	// lower severity, because they are higher-fidelity analysis.
	findings := []rules.Finding{
		// 5 regex findings at High severity
		makeFinding("BATOU-INJ-001", rules.High, 0.5),
		makeFinding("BATOU-INJ-002", rules.High, 0.5),
		makeFinding("BATOU-INJ-003", rules.High, 0.5),
		makeFinding("BATOU-INJ-004", rules.High, 0.5),
		makeFinding("BATOU-INJ-005", rules.High, 0.5),
		// 2 taint findings at Medium severity
		{RuleID: "BATOU-TAINT-sqli", Severity: rules.Medium, ConfidenceScore: 0.7, Tags: []string{"taint-analysis"}},
		{RuleID: "BATOU-TAINT-xss", Severity: rules.Medium, ConfidenceScore: 0.6, Tags: []string{"taint-analysis"}},
		// 1 AST finding at Medium severity
		{RuleID: "BATOU-AST-001", Severity: rules.Medium, ConfidenceScore: 0.7, Tags: []string{"ast"}},
	}

	// Cap to 5 total — all 3 taint/AST findings must survive.
	kept, capped := CapFindings(findings, 100, 5)
	if len(kept) != 5 {
		t.Fatalf("expected 5 kept, got %d", len(kept))
	}
	if capped != 3 {
		t.Errorf("expected 3 capped, got %d", capped)
	}

	taintCount, astCount := 0, 0
	for _, f := range kept {
		if hasTag(f.Tags, "taint-analysis") {
			taintCount++
		}
		if hasTag(f.Tags, "ast") {
			astCount++
		}
	}
	if taintCount != 2 {
		t.Errorf("expected 2 taint findings kept, got %d", taintCount)
	}
	if astCount != 1 {
		t.Errorf("expected 1 AST finding kept, got %d", astCount)
	}
}

func TestCapFindings_PreservesOrder(t *testing.T) {
	findings := []rules.Finding{
		makeFinding("BATOU-A", rules.High, 0.6),
		makeFinding("BATOU-B", rules.Critical, 0.5),
		makeFinding("BATOU-C", rules.Medium, 0.4),
	}

	kept, _ := CapFindings(findings, 3, 20)
	if len(kept) != 3 {
		t.Fatalf("expected 3 kept, got %d", len(kept))
	}
	if kept[0].RuleID != "BATOU-A" || kept[1].RuleID != "BATOU-B" || kept[2].RuleID != "BATOU-C" {
		t.Errorf("expected original order preserved, got %s, %s, %s",
			kept[0].RuleID, kept[1].RuleID, kept[2].RuleID)
	}
}

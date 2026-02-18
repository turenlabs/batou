package scanner

import (
	"testing"

	"github.com/turenlabs/batou/internal/rules"
)

// ---------------------------------------------------------------------------
// AssignBaseConfidenceScore
// ---------------------------------------------------------------------------

func TestAssignBaseConfidenceScore_Regex(t *testing.T) {
	tests := []struct {
		name string
		conf string
		want float64
	}{
		{"low confidence regex", "low", ConfBaseRegexLow},
		{"medium confidence regex", "medium", ConfBaseRegexMedium},
		{"high confidence regex", "high", ConfBaseRegexHigh},
		{"empty confidence regex", "", ConfBaseRegexLow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rules.Finding{
				RuleID:     "BATOU-INJ-001",
				Confidence: tt.conf,
			}
			AssignBaseConfidenceScore(&f)
			if f.ConfidenceScore != tt.want {
				t.Errorf("got %.2f, want %.2f", f.ConfidenceScore, tt.want)
			}
		})
	}
}

func TestAssignBaseConfidenceScore_AST(t *testing.T) {
	f := rules.Finding{
		RuleID: "BATOU-AST-001",
		Tags:   []string{"ast"},
	}
	AssignBaseConfidenceScore(&f)
	if f.ConfidenceScore != ConfBaseAST {
		t.Errorf("AST score = %.2f, want %.2f", f.ConfidenceScore, ConfBaseAST)
	}
}

func TestAssignBaseConfidenceScore_Taint(t *testing.T) {
	// Taint findings already have a score set — preserve it.
	f := rules.Finding{
		RuleID:          "BATOU-TAINT-sqli",
		Tags:            []string{"taint-analysis", "dataflow"},
		ConfidenceScore: 0.85,
	}
	AssignBaseConfidenceScore(&f)
	if f.ConfidenceScore != 0.85 {
		t.Errorf("taint score should be preserved: got %.2f, want 0.85", f.ConfidenceScore)
	}
}

func TestAssignBaseConfidenceScore_Interproc(t *testing.T) {
	// Interprocedural findings already have ConfidenceScore set at creation.
	f := rules.Finding{
		RuleID:          "BATOU-INTERPROC-SQLI",
		Tags:            []string{"interprocedural", "taint-analysis"},
		ConfidenceScore: 0.8,
	}
	AssignBaseConfidenceScore(&f)
	if f.ConfidenceScore != 0.8 {
		t.Errorf("interproc score should be preserved: got %.2f, want 0.80", f.ConfidenceScore)
	}
}

func TestAssignBaseConfidenceScore_InterprocWithoutPreset(t *testing.T) {
	// Edge case: interprocedural finding without pre-set score.
	f := rules.Finding{
		RuleID: "BATOU-INTERPROC-SQLI",
		Tags:   []string{"interprocedural", "taint-analysis"},
	}
	AssignBaseConfidenceScore(&f)
	if f.ConfidenceScore != ConfBaseInterproc {
		t.Errorf("interproc fallback score = %.2f, want %.2f", f.ConfidenceScore, ConfBaseInterproc)
	}
}

// ---------------------------------------------------------------------------
// BoostConfidenceForMultiLayer
// ---------------------------------------------------------------------------

func TestBoostConfidenceForMultiLayer(t *testing.T) {
	tests := []struct {
		name     string
		base     float64
		tiers    int
		expected float64
	}{
		{"single tier — no boost", 0.5, 1, 0.5},
		{"two tiers — +0.1", 0.5, 2, 0.6},
		{"three tiers — +0.2", 0.5, 3, 0.7},
		{"four tiers — +0.3", 0.5, 4, 0.8},
		{"cap at 1.0", 0.85, 4, 1.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rules.Finding{ConfidenceScore: tt.base}
			BoostConfidenceForMultiLayer(&f, tt.tiers)
			if f.ConfidenceScore != tt.expected {
				t.Errorf("got %.2f, want %.2f", f.ConfidenceScore, tt.expected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// countDistinctTiers
// ---------------------------------------------------------------------------

func TestCountDistinctTiers(t *testing.T) {
	findings := []rules.Finding{
		regexFinding(10, "CWE-89", rules.High, "high"),
		taintFinding(10, "CWE-89", rules.High, "high"),
		astFinding(10, "CWE-89", rules.High, "high"),
	}

	got := countDistinctTiers([]int{0, 1, 2}, findings)
	if got != 3 {
		t.Errorf("expected 3 distinct tiers, got %d", got)
	}

	// Same tier repeated.
	got = countDistinctTiers([]int{0}, findings)
	if got != 1 {
		t.Errorf("expected 1 distinct tier, got %d", got)
	}
}

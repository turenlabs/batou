package scanner

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// FindingTier must be the exported alias of the in-package findingTier and the
// Tier* constants must mirror the unexported tier values, so callers outside
// the package (dirscan) classify findings the same way dedup does.
func TestFindingTier_ExportedMatchesInternal(t *testing.T) {
	cases := []struct {
		name string
		f    rules.Finding
		want int
	}{
		{"regex", regexFinding(10, "CWE-89", rules.High, "medium"), TierRegex},
		{"ast", astFinding(10, "CWE-89", rules.High, "high"), TierAST},
		{"taint", taintFinding(10, "CWE-89", rules.High, "high"), TierTaint},
		{"interproc", interprocFinding(10, "CWE-89", rules.High, "high"), TierInterprocedural},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := FindingTier(&c.f)
			if got != c.want {
				t.Errorf("FindingTier = %d, want %d", got, c.want)
			}
			if got != findingTier(&c.f) {
				t.Errorf("FindingTier (%d) != findingTier (%d)", got, findingTier(&c.f))
			}
		})
	}
	// Constant identities (compile-time + runtime sanity).
	if TierRegex != tierRegex || TierAST != tierAST || TierTaint != tierTaint || TierInterprocedural != tierInterprocedural {
		t.Fatal("exported Tier* constants drifted from unexported tier* values")
	}
	if TierRegex >= TierInterprocedural || TierInterprocedural >= TierAST || TierAST >= TierTaint {
		t.Fatalf("tier ordering broken: regex=%d interproc=%d ast=%d taint=%d", TierRegex, TierInterprocedural, TierAST, TierTaint)
	}
}

// A regex finding that a higher layer confirmed on the same (line, CWE) is
// replaced by the higher-tier winner during DeduplicateFindings, so after
// dedup it is no longer regex-tier — i.e. --no-regex (which keys off the
// post-dedup tier) must NOT drop it.
func TestFindingTier_MultiLayerWinnerIsNotRegexTier(t *testing.T) {
	findings := []rules.Finding{
		regexFinding(10, "CWE-89", rules.High, "medium", "sql"),
		taintFinding(10, "CWE-89", rules.High, "high", "sql"),
	}
	got := DeduplicateFindings(findings)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding after dedup, got %d", len(got))
	}
	if FindingTier(&got[0]) != TierTaint {
		t.Fatalf("post-dedup winner tier = %d, want TierTaint (%d) — --no-regex would wrongly drop a confirmed finding", FindingTier(&got[0]), TierTaint)
	}
	// Sanity: FilterByMinTier(TierInterprocedural) keeps it.
	if len(FilterByMinTier(got, TierInterprocedural)) != 1 {
		t.Error("multi-layer winner dropped by FilterByMinTier(TierInterprocedural)")
	}
}

func TestFilterByMinTier(t *testing.T) {
	in := []rules.Finding{
		regexFinding(1, "CWE-89", rules.High, "medium"),
		astFinding(2, "CWE-79", rules.High, "high"),
		taintFinding(3, "CWE-89", rules.High, "high"),
		interprocFinding(4, "CWE-78", rules.High, "high"),
	}

	// minTier <= TierRegex is a no-op (returns input unchanged, same slice).
	if got := FilterByMinTier(in, 0); len(got) != len(in) {
		t.Fatalf("min 0: got %d findings, want %d", len(got), len(in))
	}
	if got := FilterByMinTier(in, TierRegex); len(got) != len(in) {
		t.Fatalf("min TierRegex: got %d findings, want %d", len(got), len(in))
	}

	// Drop regex-tier only: interproc(20), ast(30), taint(40) survive.
	got := FilterByMinTier(in, TierInterprocedural)
	if len(got) != 3 {
		t.Fatalf("min TierInterprocedural: got %d findings, want 3 (%v)", len(got), ruleIDs(got))
	}
	for _, f := range got {
		if FindingTier(&f) == TierRegex {
			t.Errorf("regex-tier finding leaked through min TierInterprocedural: %s", f.RuleID)
		}
	}

	// Only AST + taint survive.
	got = FilterByMinTier(in, TierAST)
	if len(got) != 2 {
		t.Fatalf("min TierAST: got %d findings, want 2 (%v)", len(got), ruleIDs(got))
	}

	// Only taint survives.
	got = FilterByMinTier(in, TierTaint)
	if len(got) != 1 || FindingTier(&got[0]) != TierTaint {
		t.Fatalf("min TierTaint: got %v, want single taint finding", ruleIDs(got))
	}
}

func TestFilterByMinConfidence(t *testing.T) {
	mk := func(score float64) rules.Finding {
		f := regexFinding(1, "CWE-89", rules.High, "low")
		f.ConfidenceScore = score
		return f
	}
	in := []rules.Finding{mk(0.3), mk(0.5), mk(0.7), mk(0.95)}

	// min <= 0 is a no-op.
	if got := FilterByMinConfidence(in, 0); len(got) != len(in) {
		t.Fatalf("min 0: got %d, want %d", len(got), len(in))
	}
	if got := FilterByMinConfidence(in, -1); len(got) != len(in) {
		t.Fatalf("min -1: got %d, want %d", len(got), len(in))
	}

	// 0.7 keeps the 0.7 and 0.95 ones.
	got := FilterByMinConfidence(in, 0.7)
	if len(got) != 2 {
		t.Fatalf("min 0.7: got %d, want 2", len(got))
	}
	for _, f := range got {
		if f.ConfidenceScore < 0.7 {
			t.Errorf("finding below 0.7 leaked: %.2f", f.ConfidenceScore)
		}
	}

	// 0.5 keeps three; 1.0 keeps none.
	if got := FilterByMinConfidence(in, 0.5); len(got) != 3 {
		t.Fatalf("min 0.5: got %d, want 3", len(got))
	}
	if got := FilterByMinConfidence(in, 1.0); len(got) != 0 {
		t.Fatalf("min 1.0: got %d, want 0", len(got))
	}
}

func ruleIDs(fs []rules.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.RuleID
	}
	return out
}

package scanner

import (
	"github.com/turenlabs/batou-rules/rules"
	"testing"
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
// CapLowValueHeuristicConfidence
// ---------------------------------------------------------------------------

// TestCapLowValueHeuristicConfidence_DemotesStyleRules is the real-world FP
// regression guard. Grafana/Keycloak smoke tests showed Go goroutine/defer/
// weak-crypto lints (AST-005/007/008) and CWE-117 log injection
// (TAINT-log_output) as the #1-#2 HIGH-confidence finding volume despite being
// pure style or true-but-trivial. They must be capped to <0.7 so they never
// block a write (RiskScore = ImpactWeight × cs stays < 0.7) or headline a scan.
func TestCapLowValueHeuristicConfidence_DemotesStyleRules(t *testing.T) {
	demoted := []string{
		"BATOU-AST-005",          // weak-crypto import lint
		"BATOU-AST-007",          // defer-in-loop lint
		"BATOU-AST-008",          // goroutine-without-context lint
		"BATOU-TAINT-log_output", // CWE-117 log injection
	}
	for _, ruleID := range demoted {
		t.Run(ruleID, func(t *testing.T) {
			// Start at the worst case: a taint flow at full 1.0 confidence
			// (the cs=1.0 log_output findings seen in Keycloak) or AST tier
			// boosted to 1.0 by a co-located multi-layer agreement.
			f := rules.Finding{RuleID: ruleID, Severity: rules.High, ConfidenceScore: 1.0}
			CapLowValueHeuristicConfidence(&f)
			if f.ConfidenceScore > StyleHeuristicCap {
				t.Errorf("%s not demoted: cs=%.2f, want <= %.2f", ruleID, f.ConfidenceScore, StyleHeuristicCap)
			}
			// Even at High severity, the capped score must keep RiskScore
			// below the 0.7 block threshold.
			ComputeRiskScore(&f)
			if f.ShouldBlock() {
				t.Errorf("%s still blocks after demotion: risk=%.2f", ruleID, f.RiskScore)
			}
			// Demotion must NOT zero the finding out — it still emits as a
			// hint, so recall measured at minConf=0 is unchanged.
			if f.ConfidenceScore <= 0 {
				t.Errorf("%s zeroed out (recall lost), cs=%.2f", ruleID, f.ConfidenceScore)
			}
		})
	}
}

// TestAssignBaseConfidenceScore_RegexPresetClamped is the regex-never-blocks
// invariant guard (4-layer review DN2). A regex rule must NOT be able to reach
// the 0.70 block lane by pre-setting its own ConfidenceScore — BATOU-INJ-027
// pre-set 0.8 and verified-blocked a write at the hook. The base assignment now
// recomputes the regex tier from the tier floor regardless of any preset.
func TestAssignBaseConfidenceScore_RegexPresetClamped(t *testing.T) {
	for _, conf := range []string{"high", "medium", "low", ""} {
		t.Run("conf="+conf, func(t *testing.T) {
			// A regex-tier finding (no taint tag, not an AST rule ID) that
			// pre-set a blocking 0.8 score.
			f := rules.Finding{RuleID: "BATOU-INJ-027", Severity: rules.Critical, Confidence: conf, ConfidenceScore: 0.8}
			AssignBaseConfidenceScore(&f)
			if f.ConfidenceScore > ConfBaseRegexHigh {
				t.Errorf("regex preset not clamped: cs=%.2f, want <= %.2f", f.ConfidenceScore, ConfBaseRegexHigh)
			}
			ComputeRiskScore(&f)
			if f.ShouldBlock() {
				t.Errorf("regex rule still blocks after clamp: risk=%.2f", f.RiskScore)
			}
		})
	}
}

// A taint finding's engine-set score must still be preserved (the clamp is
// regex-tier-only).
func TestAssignBaseConfidenceScore_TaintScorePreserved(t *testing.T) {
	f := rules.Finding{RuleID: "BATOU-TAINT-sql_query", Tags: []string{"taint-analysis"}, Severity: rules.Critical, ConfidenceScore: 0.95}
	AssignBaseConfidenceScore(&f)
	if f.ConfidenceScore != 0.95 {
		t.Errorf("taint score not preserved: cs=%.2f, want 0.95", f.ConfidenceScore)
	}
}

// AST-structural cap subsumed by the external-origin invariant
// ---------------------------------------------------------------------------
//
// The per-rule AST-structural denylist (CapASTStructuralConfidence /
// astStructuralBlockingRules) was deleted: the external-origin invariant
// (CapNonExternalOriginConfidence, case (A) NO-FLOW → NO-BLOCK) now caps every
// pure-AST-structural Critical, because each carries a NULL taint path and so
// has no confirming external-origin flow. These two tests are the load-bearing
// regression that the deletion is finding-identical: they shape each formerly
// denylisted rule ID exactly as its AST analyzer emits it (no taint/interproc
// tag, empty TaintPath, empty SourceCategory) and assert the surviving gate
// demotes it below the 0.70 block threshold to a hint — the same demotion the
// denylist used to perform, to the same ExternalOriginCap (0.65) value.

// TestASTStructuralSubsumed_DemotesStructuralBlocks is the real-world FP
// regression guard from the 20-repo adversarial audit: pure-AST-structural
// dangerous-construct rules (dynamic include, SQL-shaped template literal,
// structural JNDI/exec/memcpy, variable command name) fired Critical findings
// at the AST base tier (0.7) and hard-blocked benign writes with a null taint
// path (symfony PHPAST, typeorm JSAST-006, git CAST-002, tcpdump CAST-004).
// They must be capped below the 0.7 block threshold by the external-origin gate.
func TestASTStructuralSubsumed_DemotesStructuralBlocks(t *testing.T) {
	demoted := []string{
		"BATOU-PHPAST-003",  // dynamic include/require (CWE-98)
		"BATOU-PHPAST-006",  // AST-only SQL interpolation (CWE-89)
		"BATOU-JSAST-006",   // SQL-shaped template literal, any ${} (CWE-89)
		"BATOU-CAST-002",    // format string (gettext literal misparse) (CWE-134)
		"BATOU-CAST-004",    // attacker-size memcpy, guard-blind (CWE-787)
		"BATOU-JAVAAST-004", // structural JNDI lookup (CWE-917)
		"BATOU-AST-003",     // Go variable command name (CWE-78)
		"BATOU-GVY-AST-004", // Groovy GString in sh() (CWE-78)
		// 2026-06-18 4-layer review additions (verified 100% null-taint Critical):
		"BATOU-PYAST-005",    // f-string-as-SQL, prose-keyword match (CWE-89)
		"BATOU-JAVAAST-009",  // SpEL/OGNL parseExpression of a config literal (CWE-917)
		"BATOU-RUST-AST-002", // format!()-as-SQL (CWE-89)
		"BATOU-LUA-AST-003",  // loadfile of a config path (CWE-22)
		"BATOU-RUBYAST-001",  // eval of a non-literal (CWE-95)
		"BATOU-PYAST-001",    // exec/eval of a non-literal (CWE-78/95)
	}
	for _, ruleID := range demoted {
		t.Run(ruleID, func(t *testing.T) {
			// Worst case: a Critical structural finding at full 1.0 (e.g. boosted
			// by a co-located regex tier — still no taint dataflow). Shaped exactly
			// as the AST analyzers emit: only an "ast" tag, no TaintPath, no
			// SourceCategory → no confirming external-origin flow.
			f := rules.Finding{
				RuleID:          ruleID,
				Severity:        rules.Critical,
				ConfidenceScore: 1.0,
				Tags:            []string{"ast"},
			}
			if hasExternalOrigin(&f) {
				t.Fatalf("%s (null-taint structural) must NOT be external-origin", ruleID)
			}
			CapNonExternalOriginConfidence(&f)
			if f.ConfidenceScore > ExternalOriginCap {
				t.Errorf("%s not demoted: cs=%.2f, want <= %.2f", ruleID, f.ConfidenceScore, ExternalOriginCap)
			}
			ComputeRiskScore(&f)
			if f.ShouldBlock() {
				t.Errorf("%s still blocks after demotion: risk=%.2f", ruleID, f.RiskScore)
			}
			// Demotion, not deletion — still emits as a hint (recall at minConf=0
			// unchanged, OWASP/CVE benches byte-identical).
			if f.ConfidenceScore <= 0 {
				t.Errorf("%s zeroed out (recall lost), cs=%.2f", ruleID, f.ConfidenceScore)
			}
		})
	}
}

// TestASTStructuralSubsumed_LeavesTaintFindings proves a genuinely reachable
// instance still blocks: the taint engine emits a separate BATOU-TAINT-* /
// BATOU-INTERPROC-* finding on the same (line, CWE) that wins dedup at the
// taint/interproc tier with a real external-source flow, and the external-origin
// gate leaves it untouched.
func TestASTStructuralSubsumed_LeavesTaintFindings(t *testing.T) {
	cases := []struct {
		ruleID string
		tags   []string
	}{
		{"BATOU-TAINT-sql_query", []string{"taint-analysis"}},
		{"BATOU-TAINT-command_exec", []string{"taint-analysis"}},
		{"BATOU-INTERPROC-URL_FETCH", []string{"interprocedural", "taint-analysis"}},
	}
	for _, tc := range cases {
		t.Run(tc.ruleID, func(t *testing.T) {
			f := rules.Finding{
				RuleID:          tc.ruleID,
				Severity:        rules.Critical,
				ConfidenceScore: 0.85,
				Tags:            tc.tags,
				SourceCategory:  "user_input",
				TaintPath: []rules.TaintStep{
					{Kind: rules.TaintStepSource, Label: "request.getParameter", Line: 1},
					{Kind: rules.TaintStepSink, Label: "execute", Line: 3},
				},
			}
			if !hasExternalOrigin(&f) {
				t.Fatalf("%s real external flow must BE external-origin", tc.ruleID)
			}
			CapNonExternalOriginConfidence(&f)
			if f.ConfidenceScore != 0.85 {
				t.Errorf("%s wrongly demoted: cs=%.2f, want 0.85", tc.ruleID, f.ConfidenceScore)
			}
		})
	}
}

// TestCapLowValueHeuristicConfidence_LeavesRealFindings proves the cap is
// narrow: genuine high-signal rules (a real SQLi taint flow, a Critical AST
// finding) keep their full confidence and blocking power.
func TestCapLowValueHeuristicConfidence_LeavesRealFindings(t *testing.T) {
	keep := []string{
		"BATOU-TAINT-sql_query",
		"BATOU-TAINT-command_exec",
		"BATOU-AST-002",
		"BATOU-INTERPROC-URL_FETCH",
	}
	for _, ruleID := range keep {
		t.Run(ruleID, func(t *testing.T) {
			f := rules.Finding{RuleID: ruleID, Severity: rules.High, ConfidenceScore: 0.9}
			CapLowValueHeuristicConfidence(&f)
			if f.ConfidenceScore != 0.9 {
				t.Errorf("%s wrongly demoted: cs=%.2f, want 0.90", ruleID, f.ConfidenceScore)
			}
		})
	}
}

// TestCapLowValueHeuristicConfidence_NeverRaises confirms the cap only lowers:
// a finding already below the ceiling is untouched.
func TestCapLowValueHeuristicConfidence_NeverRaises(t *testing.T) {
	f := rules.Finding{RuleID: "BATOU-AST-008", Severity: rules.Medium, ConfidenceScore: 0.3}
	CapLowValueHeuristicConfidence(&f)
	if f.ConfidenceScore != 0.3 {
		t.Errorf("cap raised a low score: cs=%.2f, want 0.30", f.ConfidenceScore)
	}
}

// ---------------------------------------------------------------------------
// CapInterprocConfidenceForTestPaths
// ---------------------------------------------------------------------------

func TestCapInterprocConfidenceForTestPaths(t *testing.T) {
	tests := []struct {
		name     string
		ruleID   string
		filePath string
		start    float64
		want     float64
	}{
		{
			name:     "production path keeps full interproc score",
			ruleID:   "BATOU-INTERPROC-SQLI",
			filePath: "/app/handler.go",
			start:    0.8,
			want:     0.8,
		},
		{
			name:     "scaletest path caps interproc at 0.3",
			ruleID:   "BATOU-INTERPROC-SQLI",
			filePath: "/scaletest/foo.go",
			start:    0.8,
			want:     InterprocTestInfraCap,
		},
		{
			name:     "_test.go path caps interproc at 0.3",
			ruleID:   "BATOU-INTERPROC-HTML_OUTPUT",
			filePath: "agent/foo_test.go",
			start:    0.8,
			want:     InterprocTestInfraCap,
		},
		{
			name:     "scripts path caps interproc at 0.3",
			ruleID:   "BATOU-INTERPROC-COMMAND_EXEC",
			filePath: "/repo/scripts/build/run.sh.go",
			start:    0.9,
			want:     InterprocTestInfraCap,
		},
		{
			name:     "non-interproc rule on test path is untouched",
			ruleID:   "BATOU-INJ-001",
			filePath: "agent/foo_test.go",
			start:    0.8,
			want:     0.8,
		},
		{
			name:     "interproc on test path already below cap is untouched",
			ruleID:   "BATOU-INTERPROC-LOG_OUTPUT",
			filePath: "agent/foo_test.go",
			start:    0.2,
			want:     0.2,
		},
		{
			name:     "test_fixtures path caps interproc at 0.3",
			ruleID:   "BATOU-INTERPROC-XSS",
			filePath: "/repo/test_fixtures/sample.go",
			start:    0.8,
			want:     InterprocTestInfraCap,
		},
		// Bug 3 verification: SSA-tier confidences (0.85 cross-package,
		// 0.9 intra-procedural) on test paths must be capped at 0.3.
		// These are the values emitted by the ssaflow engine when
		// BATOU_SSAFLOW=1, eventually rendered as BATOU-INTERPROC-*
		// findings by graph.WalkCrossFileTaintFlows.
		{
			name:     "ssa cross-package confidence (0.85) on _test.go caps at 0.3",
			ruleID:   "BATOU-INTERPROC-LOG_OUTPUT",
			filePath: "/repo/internal/handlers/handler_test.go",
			start:    0.85,
			want:     InterprocTestInfraCap,
		},
		{
			name:     "ssa intra-procedural confidence (0.9) on _test.go caps at 0.3",
			ruleID:   "BATOU-INTERPROC-DESERIALIZE",
			filePath: "/repo/api/server_test.go",
			start:    0.9,
			want:     InterprocTestInfraCap,
		},
		{
			name:     "ssa intra-procedural confidence (0.9) on production path keeps 0.9",
			ruleID:   "BATOU-INTERPROC-DESERIALIZE",
			filePath: "/repo/api/server.go",
			start:    0.9,
			want:     0.9,
		},
		// Python paths (PR-Zpy).
		{
			name:     "python test_*.py path caps interproc at 0.3",
			ruleID:   "BATOU-INTERPROC-SQLI",
			filePath: "/repo/app/tests/test_views.py",
			start:    0.85,
			want:     InterprocTestInfraCap,
		},
		{
			name:     "python conftest.py caps interproc at 0.3",
			ruleID:   "BATOU-INTERPROC-XSS",
			filePath: "/repo/conftest.py",
			start:    0.9,
			want:     InterprocTestInfraCap,
		},
		{
			name:     "python django migration caps interproc at 0.3",
			ruleID:   "BATOU-INTERPROC-SQLI",
			filePath: "/repo/app/migrations/0001_initial.py",
			start:    0.85,
			want:     InterprocTestInfraCap,
		},
		{
			name:     "python site-packages caps interproc at 0.3",
			ruleID:   "BATOU-INTERPROC-COMMAND_EXEC",
			filePath: "/repo/venv/lib/python3.11/site-packages/x.py",
			start:    0.9,
			want:     InterprocTestInfraCap,
		},
		{
			name:     "python setup.py caps interproc at 0.3",
			ruleID:   "BATOU-INTERPROC-COMMAND_EXEC",
			filePath: "setup.py",
			start:    0.8,
			want:     InterprocTestInfraCap,
		},
		{
			name:     "python manage.py caps interproc at 0.3",
			ruleID:   "BATOU-INTERPROC-COMMAND_EXEC",
			filePath: "backend/manage.py",
			start:    0.8,
			want:     InterprocTestInfraCap,
		},
		{
			name:     "python production handler keeps full interproc score",
			ruleID:   "BATOU-INTERPROC-SQLI",
			filePath: "/repo/app/views/contest.py",
			start:    0.9,
			want:     0.9,
		},
		{
			name:     "python production handler with 'protest' substring keeps score",
			ruleID:   "BATOU-INTERPROC-SQLI",
			filePath: "/repo/app/protested.py",
			start:    0.9,
			want:     0.9,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := rules.Finding{
				RuleID:          tt.ruleID,
				FilePath:        tt.filePath,
				ConfidenceScore: tt.start,
			}
			CapInterprocConfidenceForTestPaths(&f)
			if f.ConfidenceScore != tt.want {
				t.Errorf("got %.2f, want %.2f", f.ConfidenceScore, tt.want)
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

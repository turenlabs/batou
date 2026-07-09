package scanner

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// The external-origin block invariant: a finding is block-eligible (RiskScore
// may reach >=0.7) ONLY if a taint/interproc flow from a GENUINE external
// source confirms it. These unit tests pin the gate's three required cases
// directly against hasExternalOrigin / CapNonExternalOriginConfidence (the
// load-bearing core). The end-to-end pipeline counterparts live in
// external_origin_pipeline_test.go.

// (A) NO-FLOW -> NO-BLOCK. A Critical AST-structural finding with no taint tag
// and an empty TaintPath is not block-eligible and is capped to a hint.
func TestExternalOrigin_ASTStructuralNoFlow_CapsToHint(t *testing.T) {
	// A pure AST-structural Critical: AST rule ID, no taint-analysis tag, no
	// TaintPath. This is the shape every pure-AST-structural Critical takes (the
	// findings the removed per-rule astStructuralBlockingRules denylist capped).
	f := rules.Finding{
		RuleID:          "BATOU-PHPAST-001", // dynamic include — null taint
		Severity:        rules.Critical,
		ConfidenceScore: ConfBaseAST, // 0.70 -> RiskScore 0.70 -> would block
		Tags:            []string{"ast"},
	}
	if hasExternalOrigin(&f) {
		t.Fatal("AST-structural finding with no flow must NOT be external-origin")
	}
	CapNonExternalOriginConfidence(&f)
	ComputeRiskScore(&f)
	if f.ShouldBlock() {
		t.Errorf("AST-structural no-flow finding still blocks: conf=%.2f risk=%.2f", f.ConfidenceScore, f.RiskScore)
	}
	if f.ConfidenceScore > ExternalOriginCap {
		t.Errorf("conf %.2f not capped to <=%.2f", f.ConfidenceScore, ExternalOriginCap)
	}
}

// A plain regex Critical (no flow) is likewise not block-eligible. This is the
// generalisation of the regex-never-blocks invariant via the same gate.
func TestExternalOrigin_RegexNoFlow_CapsToHint(t *testing.T) {
	f := rules.Finding{
		RuleID:          "BATOU-INJ-001",
		Severity:        rules.Critical,
		ConfidenceScore: 0.9, // pretend something lifted it into the block lane
		Tags:            nil,
	}
	if hasExternalOrigin(&f) {
		t.Fatal("regex finding with no flow must NOT be external-origin")
	}
	CapNonExternalOriginConfidence(&f)
	ComputeRiskScore(&f)
	if f.ShouldBlock() {
		t.Errorf("regex no-flow finding still blocks: conf=%.2f", f.ConfidenceScore)
	}
}

// (B) WEAK-SOURCE -> NO-BLOCK: a param-NAME-as-source flow. The flow is real
// (taint-analysis tag, TaintPath present, SourceCategory looks external) but
// its source is the conf-0.6 name-only fabricator, marked "param-name:" on the
// source step label. It must cap to a hint.
func TestExternalOrigin_ParamNameSource_CapsToHint(t *testing.T) {
	f := rules.Finding{
		RuleID:          "BATOU-TAINT-sql_query",
		Severity:        rules.Critical,
		ConfidenceScore: 0.85,
		Tags:            []string{"taint-analysis", "dataflow"},
		SourceCategory:  "user_input", // genuine-LOOKING, but the source is a fabricator
		TaintPath: []rules.TaintStep{
			{Kind: rules.TaintStepSource, Label: "param-name:path", Line: 1},
			{Kind: rules.TaintStepSink, Label: "execute", Line: 3},
		},
	}
	if hasExternalOrigin(&f) {
		t.Fatal("param-name fabricator flow must NOT be external-origin")
	}
	CapNonExternalOriginConfidence(&f)
	ComputeRiskScore(&f)
	if f.ShouldBlock() {
		t.Errorf("param-name fabricator flow still blocks: conf=%.2f", f.ConfidenceScore)
	}
}

// (B) WEAK-SOURCE -> NO-BLOCK: ambient sources (env_var, cli_arg) are
// operator-controlled, not attacker-supplied, so they never confer a block.
func TestExternalOrigin_AmbientSource_CapsToHint(t *testing.T) {
	for _, cat := range []string{"env_var", "cli_arg"} {
		f := rules.Finding{
			RuleID:          "BATOU-TAINT-command_exec",
			Severity:        rules.Critical,
			ConfidenceScore: 0.9,
			Tags:            []string{"taint-analysis"},
			SourceCategory:  cat,
			TaintPath: []rules.TaintStep{
				{Kind: rules.TaintStepSource, Label: "os.Getenv", Line: 1},
				{Kind: rules.TaintStepSink, Label: "exec.Command", Line: 2},
			},
		}
		if hasExternalOrigin(&f) {
			t.Fatalf("ambient source %q must NOT be external-origin", cat)
		}
		CapNonExternalOriginConfidence(&f)
		ComputeRiskScore(&f)
		if f.ShouldBlock() {
			t.Errorf("ambient (%s) flow still blocks: conf=%.2f", cat, f.ConfidenceScore)
		}
	}
}

// RECALL PRESERVED: a real external-source flow (request.getParameter -> sink)
// stays block-eligible. SourceCategory is a genuine external class and the
// source step is NOT a param-name fabricator.
func TestExternalOrigin_RealExternalSource_StaysBlockEligible(t *testing.T) {
	cases := []struct {
		name     string
		srcCat   string
		srcLabel string
		tags     []string
	}{
		{"servlet-getParameter", "user_input", "getParameter", []string{"taint-analysis"}},
		{"genuine-handler-param", "user_input", "parameter:id", []string{"taint-analysis"}},
		{"network-read", "network", "conn.Read", []string{"taint-analysis"}},
		{"deserialized", "deserialized", "json.Unmarshal", []string{"taint-analysis"}},
		{"interproc-external", "user_input", "request.FormValue", []string{"interprocedural", "taint-analysis"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := rules.Finding{
				RuleID:          "BATOU-TAINT-sql_query",
				Severity:        rules.Critical,
				ConfidenceScore: 0.85,
				Tags:            tc.tags,
				SourceCategory:  tc.srcCat,
				TaintPath: []rules.TaintStep{
					{Kind: rules.TaintStepSource, Label: tc.srcLabel, Line: 1},
					{Kind: rules.TaintStepSink, Label: "execute", Line: 3},
				},
			}
			if !hasExternalOrigin(&f) {
				t.Fatalf("real external source %q must BE external-origin", tc.srcLabel)
			}
			pre := f.ConfidenceScore
			CapNonExternalOriginConfidence(&f)
			if f.ConfidenceScore != pre {
				t.Errorf("real external flow confidence was lowered %.2f -> %.2f", pre, f.ConfidenceScore)
			}
			ComputeRiskScore(&f)
			if !f.ShouldBlock() {
				t.Errorf("real external Critical flow no longer blocks: conf=%.2f risk=%.2f", f.ConfidenceScore, f.RiskScore)
			}
		})
	}
}

// (B) CLIENT-STORAGE -> NO-BLOCK: window.localStorage/sessionStorage reads are
// same-origin, client-persisted app state (SrcClientStorage / "client_storage"),
// not attacker-supplied request input. A taint-confirmed flow from them is NOT
// block-eligible but STILL emits as a hint. This is the Ghost list.js FP:
// JSON.parse(localStorage.getItem(...)) -> this.store.query(...).
func TestExternalOrigin_ClientStorageSource_CapsToHint(t *testing.T) {
	f := rules.Finding{
		RuleID:          "BATOU-TAINT-sql_query",
		Severity:        rules.Critical,
		ConfidenceScore: 1.0,
		Tags:            []string{"taint-analysis"},
		SourceCategory:  "client_storage",
		TaintPath: []rules.TaintStep{
			{Kind: rules.TaintStepSource, Label: "getItem", Line: 50},
			{Kind: rules.TaintStepSink, Label: "store.query", Line: 57},
		},
	}
	if hasExternalOrigin(&f) {
		t.Fatal("client_storage source must NOT be external-origin")
	}
	CapNonExternalOriginConfidence(&f)
	ComputeRiskScore(&f)
	if f.ShouldBlock() {
		t.Errorf("client_storage flow still blocks: conf=%.2f", f.ConfidenceScore)
	}
	// Still emitted (demotion, not deletion): score capped to the hint ceiling,
	// which is above zero so the finding survives at minConf=0.
	if f.ConfidenceScore == 0 {
		t.Error("client_storage finding was deleted, not demoted")
	}
	if f.ConfidenceScore > ExternalOriginCap {
		t.Errorf("client_storage finding not capped to hint ceiling: %.2f", f.ConfidenceScore)
	}
}

// PROOF the demotion is category-scoped, not a blanket SrcExternal demotion: a
// genuine "external" flow (S3 object / message-queue payload) STILL blocks.
func TestExternalOrigin_ExternalStorageStillBlocks(t *testing.T) {
	f := rules.Finding{
		RuleID:          "BATOU-TAINT-sql_query",
		Severity:        rules.Critical,
		ConfidenceScore: 0.9,
		Tags:            []string{"taint-analysis"},
		SourceCategory:  "external", // S3 object body, MQ payload, shared cache
		TaintPath: []rules.TaintStep{
			{Kind: rules.TaintStepSource, Label: "s3.getObject", Line: 1},
			{Kind: rules.TaintStepSink, Label: "execute", Line: 3},
		},
	}
	if !hasExternalOrigin(&f) {
		t.Fatal("genuine external (S3/MQ) source must remain external-origin")
	}
	CapNonExternalOriginConfidence(&f)
	ComputeRiskScore(&f)
	if !f.ShouldBlock() {
		t.Errorf("genuine external Critical flow no longer blocks: conf=%.2f", f.ConfidenceScore)
	}
}

// The cap only LOWERS: a non-external finding already below the ceiling is
// untouched (no spurious raise), and an external finding is never lowered.
func TestExternalOrigin_CapOnlyLowers(t *testing.T) {
	// Below-ceiling non-external: untouched.
	low := rules.Finding{RuleID: "BATOU-AST-003", Severity: rules.Critical, ConfidenceScore: 0.3, Tags: []string{"ast"}}
	CapNonExternalOriginConfidence(&low)
	if low.ConfidenceScore != 0.3 {
		t.Errorf("below-ceiling score changed: %.2f", low.ConfidenceScore)
	}
}

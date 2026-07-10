package reporter

import (
	"encoding/json"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// taintFinding builds a representative cross-file taint finding with a 3-step
// source→propagation→sink path spanning two files (interprocedural).
func taintFinding() rules.Finding {
	return rules.Finding{
		RuleID:          "BATOU-INTERPROC-SQL",
		Severity:        rules.Critical,
		SeverityLabel:   "CRITICAL",
		Title:           "Tainted data flows from user_input to sql_query",
		Description:     "Untrusted request data reaches a SQL query without sanitization.",
		FilePath:        "handlers/search.py",
		LineNumber:      42,
		CWEID:           "CWE-89",
		OWASPCategory:   "A03:2021",
		Confidence:      "high",
		ConfidenceScore: 0.95,
		RiskScore:       0.95,
		SourceCategory:  "user_input",
		SinkCategory:    "sql_query",
		TaintPath: []rules.TaintStep{
			{File: "handlers/search.py", Line: 10, Kind: rules.TaintStepSource, Label: "request.args.get('q')"},
			{File: "db/query.py", Line: 7, Kind: rules.TaintStepPropagation, Label: "passed to build_query(q)"},
			{File: "db/query.py", Line: 15, Kind: rules.TaintStepSink, Label: "cursor.execute(sql)"},
		},
	}
}

func TestToSARIF_BasicShape(t *testing.T) {
	res := &ScanResult{
		FilePath: "handlers/search.py",
		Language: rules.LangPython,
		Findings: []rules.Finding{taintFinding()},
	}
	log := ToSARIF(res)

	if log.Version != "2.1.0" {
		t.Fatalf("version = %q, want 2.1.0", log.Version)
	}
	if log.Schema == "" {
		t.Fatalf("missing $schema")
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "Batou" {
		t.Fatalf("driver name = %q, want Batou", run.Tool.Driver.Name)
	}
	if len(run.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(run.Results))
	}
}

// The differentiating artifact: the source→sink taint path must appear as a
// SARIF codeFlow/threadFlow with one location per step, preserving per-step
// file (proving the cross-file chain).
func TestToSARIF_TaintPathBecomesCodeFlow(t *testing.T) {
	res := &ScanResult{Findings: []rules.Finding{taintFinding()}}
	r := ToSARIF(res).Runs[0].Results[0]

	if len(r.CodeFlows) != 1 {
		t.Fatalf("codeFlows = %d, want 1", len(r.CodeFlows))
	}
	tf := r.CodeFlows[0].ThreadFlows
	if len(tf) != 1 {
		t.Fatalf("threadFlows = %d, want 1", len(tf))
	}
	locs := tf[0].Locations
	if len(locs) != 3 {
		t.Fatalf("threadFlow locations = %d, want 3 (source, prop, sink)", len(locs))
	}
	// Cross-file: source in search.py, sink in query.py.
	srcURI := locs[0].Location.PhysicalLocation.ArtifactLocation.URI
	sinkURI := locs[2].Location.PhysicalLocation.ArtifactLocation.URI
	if srcURI != "handlers/search.py" {
		t.Errorf("source uri = %q, want handlers/search.py", srcURI)
	}
	if sinkURI != "db/query.py" {
		t.Errorf("sink uri = %q, want db/query.py (cross-file)", sinkURI)
	}
	if locs[0].Location.PhysicalLocation.Region.StartLine != 10 {
		t.Errorf("source line = %d, want 10", locs[0].Location.PhysicalLocation.Region.StartLine)
	}
}

// Provenance: confidence, risk, tier, CWE must be carried as result properties.
func TestToSARIF_ConfidenceAndTierProvenance(t *testing.T) {
	res := &ScanResult{Findings: []rules.Finding{taintFinding()}}
	r := ToSARIF(res).Runs[0].Results[0]

	if got := r.Properties["confidenceScore"]; got != 0.95 {
		t.Errorf("confidenceScore = %v, want 0.95", got)
	}
	if got := r.Properties["analysisTier"]; got != string(TierInterproc) {
		t.Errorf("analysisTier = %v, want interproc", got)
	}
	if got := r.Properties["cwe"]; got != "CWE-89" {
		t.Errorf("cwe = %v, want CWE-89", got)
	}
	if got := r.Properties["shouldBlock"]; got != true {
		t.Errorf("shouldBlock = %v, want true (risk 0.95 >= 0.7)", got)
	}
	if r.Level != "error" {
		t.Errorf("level = %q, want error for Critical", r.Level)
	}
}

func TestTierForFinding(t *testing.T) {
	cases := []struct {
		ruleID   string
		path     bool
		expected AnalysisTier
	}{
		{"BATOU-INTERPROC-SQL", true, TierInterproc},
		{"BATOU-TAINT-sql_query", true, TierTaint},
		{"BATOU-AST-XSS-001", false, TierAST},
		{"BATOU-INJ-001", false, TierRegex},
		{"BATOU-INJ-001", true, TierTaint}, // regex rule confirmed by taint layer
		{"", false, TierUnknown},
	}
	for _, c := range cases {
		f := rules.Finding{RuleID: c.ruleID}
		if c.path {
			f.TaintPath = []rules.TaintStep{{Kind: rules.TaintStepSink}}
		}
		if got := TierForFinding(f); got != c.expected {
			t.Errorf("TierForFinding(%q, path=%v) = %v, want %v", c.ruleID, c.path, got, c.expected)
		}
	}
}

// Suppression provenance: suppressed findings emit a SARIF suppressions entry.
func TestToSARIF_SuppressionProvenance(t *testing.T) {
	f := taintFinding()
	f.Suggestion = "validated upstream by sanitize_id()"
	res := &ScanResult{
		Findings:           nil,
		SuppressedFindings: []rules.Finding{f},
	}
	r := ToSARIF(res).Runs[0].Results[0]
	if len(r.Suppressions) != 1 {
		t.Fatalf("suppressions = %d, want 1", len(r.Suppressions))
	}
	if r.Suppressions[0].Kind != "inSource" {
		t.Errorf("suppression kind = %q, want inSource", r.Suppressions[0].Kind)
	}
}

// A regex-only finding with no taint path must still produce valid SARIF with
// no codeFlow (no fabricated path).
func TestToSARIF_RegexOnlyNoCodeFlow(t *testing.T) {
	res := &ScanResult{Findings: []rules.Finding{{
		RuleID:          "BATOU-SEC-001",
		Severity:        rules.Medium,
		Title:           "Hardcoded secret",
		FilePath:        "config.go",
		LineNumber:      3,
		ConfidenceScore: 0.4,
		RiskScore:       0.2,
	}}}
	r := ToSARIF(res).Runs[0].Results[0]
	if len(r.CodeFlows) != 0 {
		t.Errorf("regex-only finding should have no codeFlow, got %d", len(r.CodeFlows))
	}
	if r.Properties["analysisTier"] != string(TierRegex) {
		t.Errorf("analysisTier = %v, want regex", r.Properties["analysisTier"])
	}
	if r.Level != "warning" {
		t.Errorf("level = %q, want warning for Medium", r.Level)
	}
}

// ---- partialFingerprints: stable content-based alert identity ----

// fingerprintOf extracts the primaryLocationLineHash partial fingerprint from
// the first result of a single-finding ScanResult.
func fingerprintOf(t *testing.T, f rules.Finding) string {
	t.Helper()
	r := ToSARIF(&ScanResult{Findings: []rules.Finding{f}}).Runs[0].Results[0]
	fp, ok := r.PartialFingerprints["primaryLocationLineHash"]
	if !ok || fp == "" {
		t.Fatalf("missing primaryLocationLineHash partial fingerprint: %#v", r.PartialFingerprints)
	}
	return fp
}

// Identity must survive line shifts: the same finding content at a different
// line (an edit elsewhere in the file pushed it down) yields the SAME
// fingerprint, so GitHub code scanning does not churn the alert.
func TestSARIF_FingerprintStableUnderLineShift(t *testing.T) {
	f1 := taintFinding()
	f1.MatchedText = "cursor.execute(sql)"
	f2 := f1
	f2.LineNumber = f1.LineNumber + 37
	f2.Column = 9
	// Taint-path line numbers shift too (same flow, file edited above it).
	for i := range f2.TaintPath {
		f2.TaintPath[i].Line += 37
	}

	fp1, fp2 := fingerprintOf(t, f1), fingerprintOf(t, f2)
	if fp1 != fp2 {
		t.Errorf("fingerprint churned on line shift: %q vs %q", fp1, fp2)
	}
}

// The taint engines embed "(line N)" decorations in MatchedText
// ("args.get (line 4) → uid → execute (line 6)") — exactly the shape the real
// pipeline emits. Those decorations must be normalized out or every line
// shift churns identity (caught end-to-end before this normalization existed).
func TestSARIF_FingerprintStripsBatouLineDecorations(t *testing.T) {
	f1 := taintFinding()
	f1.MatchedText = "args.get (line 4) → uid → query → execute (line 6)"
	f2 := f1
	f2.LineNumber = 13
	f2.MatchedText = "args.get (line 11) → uid → query → execute (line 13)"

	if fp1, fp2 := fingerprintOf(t, f1), fingerprintOf(t, f2); fp1 != fp2 {
		t.Errorf("fingerprint churned on (line N) decoration shift: %q vs %q", fp1, fp2)
	}

	// But a genuinely different flow (different variable chain) must differ.
	f3 := f1
	f3.MatchedText = "args.get (line 4) → other → execute (line 6)"
	if fp1, fp3 := fingerprintOf(t, f1), fingerprintOf(t, f3); fp1 == fp3 {
		t.Errorf("different flows produced the same fingerprint %q", fp1)
	}
}

// Reindenting / re-wrapping the same snippet must not churn identity either.
func TestSARIF_FingerprintStableUnderWhitespaceChange(t *testing.T) {
	f1 := taintFinding()
	f1.MatchedText = "cursor.execute(sql)"
	f2 := f1
	// Indentation / trailing-whitespace change only: must normalize equal.
	f2.MatchedText = "\t  cursor.execute(sql)  "

	if fp1, fp2 := fingerprintOf(t, f1), fingerprintOf(t, f2); fp1 != fp2 {
		t.Errorf("fingerprint churned on whitespace-only change: %q vs %q", fp1, fp2)
	}
}

// Different matched snippets are different findings: fingerprints must differ.
func TestSARIF_FingerprintDiffersForDifferentSnippet(t *testing.T) {
	f1 := taintFinding()
	f1.MatchedText = "cursor.execute(sql)"
	f2 := f1
	f2.MatchedText = "cursor.execute(other_sql)"

	if fp1, fp2 := fingerprintOf(t, f1), fingerprintOf(t, f2); fp1 == fp2 {
		t.Errorf("different snippets produced the same fingerprint %q", fp1)
	}
}

// Same rule + snippet in different files must not collide.
func TestSARIF_FingerprintDiffersAcrossFiles(t *testing.T) {
	f1 := taintFinding()
	f1.MatchedText = "cursor.execute(sql)"
	f2 := f1
	f2.FilePath = "handlers/other.py"

	if fp1, fp2 := fingerprintOf(t, f1), fingerprintOf(t, f2); fp1 == fp2 {
		t.Errorf("different files produced the same fingerprint %q", fp1)
	}
}

// Two identical occurrences in one scan (same rule, same snippet, same file,
// different lines) must stay distinct via stable ordinal suffixes — and the
// ordinals must be deterministic in input order.
func TestSARIF_FingerprintOrdinalsForIdenticalFindings(t *testing.T) {
	f1 := taintFinding()
	f1.MatchedText = "cursor.execute(sql)"
	f2 := f1
	f2.LineNumber = 99

	results := ToSARIF(&ScanResult{Findings: []rules.Finding{f1, f2}}).Runs[0].Results
	fp1 := results[0].PartialFingerprints["primaryLocationLineHash"]
	fp2 := results[1].PartialFingerprints["primaryLocationLineHash"]
	if fp1 == fp2 {
		t.Fatalf("identical findings share fingerprint %q — ordinal disambiguation missing", fp1)
	}
	if want := ":0"; len(fp1) < 2 || fp1[len(fp1)-2:] != want {
		t.Errorf("first occurrence fingerprint = %q, want %q suffix", fp1, want)
	}
	if want := ":1"; len(fp2) < 2 || fp2[len(fp2)-2:] != want {
		t.Errorf("second occurrence fingerprint = %q, want %q suffix", fp2, want)
	}
}

// A finding with no matched text (e.g. a pure interproc flow) must still get
// a non-empty fingerprint (anchored on the sink step / title).
func TestSARIF_FingerprintWithoutMatchedText(t *testing.T) {
	f := taintFinding() // MatchedText is empty in the fixture
	if fp := fingerprintOf(t, f); fp == "" {
		t.Errorf("empty fingerprint for finding without MatchedText")
	}
}

// ---- srcroot uriBaseId: repo-relative artifact URIs ----

func TestSARIFWithRoot_RelativizesURIs(t *testing.T) {
	root := t.TempDir()
	f := taintFinding()
	f.FilePath = root + "/handlers/search.py"
	f.TaintPath[0].File = root + "/handlers/search.py"
	f.TaintPath[1].File = root + "/db/query.py"
	f.TaintPath[2].File = root + "/db/query.py"

	log := ToSARIFWithRoot(&ScanResult{Findings: []rules.Finding{f}}, root)
	run := log.Runs[0]

	// originalUriBaseIds declares SRCROOT as an absolute file:// URI with a
	// trailing slash.
	base, ok := run.OriginalURIBaseIDs["SRCROOT"]
	if !ok {
		t.Fatalf("missing SRCROOT in originalUriBaseIds: %#v", run.OriginalURIBaseIDs)
	}
	if len(base.URI) == 0 || base.URI[len(base.URI)-1] != '/' {
		t.Errorf("SRCROOT uri %q must end with /", base.URI)
	}
	if got, want := base.URI[:7], "file://"; got != want {
		t.Errorf("SRCROOT uri %q must be an absolute file:// URI", base.URI)
	}

	// Primary location: relative URI + uriBaseId.
	art := run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation
	if art.URI != "handlers/search.py" {
		t.Errorf("primary uri = %q, want handlers/search.py (root-relative)", art.URI)
	}
	if art.URIBaseID != "SRCROOT" {
		t.Errorf("primary uriBaseId = %q, want SRCROOT", art.URIBaseID)
	}

	// codeFlow stays intact and its step URIs are relativized too.
	if len(run.Results[0].CodeFlows) != 1 {
		t.Fatalf("codeFlows = %d, want 1 (must stay intact under root mode)", len(run.Results[0].CodeFlows))
	}
	locs := run.Results[0].CodeFlows[0].ThreadFlows[0].Locations
	if len(locs) != 3 {
		t.Fatalf("threadFlow locations = %d, want 3", len(locs))
	}
	sinkArt := locs[2].Location.PhysicalLocation.ArtifactLocation
	if sinkArt.URI != "db/query.py" || sinkArt.URIBaseID != "SRCROOT" {
		t.Errorf("sink step artifact = %+v, want db/query.py under SRCROOT", sinkArt)
	}
}

// Paths outside the scan root fall back to pass-through URIs without a
// uriBaseId — never a bogus ../ escape.
func TestSARIFWithRoot_PathOutsideRootFallsBack(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir() + "/elsewhere/lib.py"
	f := taintFinding()
	f.FilePath = outside
	f.TaintPath = nil

	run := ToSARIFWithRoot(&ScanResult{Findings: []rules.Finding{f}}, root).Runs[0]
	art := run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation
	if art.URIBaseID != "" {
		t.Errorf("outside-root path got uriBaseId %q, want none", art.URIBaseID)
	}
	if art.URI != outside {
		t.Errorf("outside-root uri = %q, want pass-through %q", art.URI, outside)
	}
}

// No root (legacy ToSARIF): behavior unchanged — URIs pass through, no
// originalUriBaseIds, no uriBaseId.
func TestSARIF_NoRootKeepsLegacyURIs(t *testing.T) {
	run := ToSARIF(&ScanResult{Findings: []rules.Finding{taintFinding()}}).Runs[0]
	if run.OriginalURIBaseIDs != nil {
		t.Errorf("originalUriBaseIds = %#v, want absent without a root", run.OriginalURIBaseIDs)
	}
	art := run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation
	if art.URI != "handlers/search.py" || art.URIBaseID != "" {
		t.Errorf("artifact = %+v, want pass-through handlers/search.py with no uriBaseId", art)
	}
}

// Fingerprints must also be invariant to WHERE the repo is checked out: the
// same root-relative finding under two different absolute roots hashes the
// same (the fingerprint uses the relativized URI, not the absolute path).
func TestSARIFWithRoot_FingerprintInvariantToCheckoutLocation(t *testing.T) {
	mk := func(root string) string {
		f := taintFinding()
		f.MatchedText = "cursor.execute(sql)"
		f.FilePath = root + "/handlers/search.py"
		f.TaintPath = nil
		r := ToSARIFWithRoot(&ScanResult{Findings: []rules.Finding{f}}, root).Runs[0].Results[0]
		return r.PartialFingerprints["primaryLocationLineHash"]
	}
	fp1, fp2 := mk(t.TempDir()), mk(t.TempDir())
	if fp1 == "" || fp1 != fp2 {
		t.Errorf("fingerprint depends on checkout location: %q vs %q", fp1, fp2)
	}
}

// The output must be valid, round-trippable JSON conforming to the documented
// SARIF top-level keys.
func TestToSARIFJSON_ValidJSON(t *testing.T) {
	res := &ScanResult{Findings: []rules.Finding{taintFinding()}}
	b, err := ToSARIFJSON(res)
	if err != nil {
		t.Fatalf("ToSARIFJSON error: %v", err)
	}
	var generic map[string]interface{}
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if generic["version"] != "2.1.0" {
		t.Errorf("json version = %v, want 2.1.0", generic["version"])
	}
	if _, ok := generic["$schema"]; !ok {
		t.Errorf("json missing $schema")
	}
	if _, ok := generic["runs"]; !ok {
		t.Errorf("json missing runs")
	}
}

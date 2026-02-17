package suppress

import (
	"testing"

	"github.com/turenlabs/batou/internal/rules"
)

// =========================================================================
// Parse — comment styles
// =========================================================================

func TestParse_GoComment(t *testing.T) {
	s := Parse("// batou:ignore BATOU-INJ-001 -- validated by middleware\nquery := db.Query(sql)")
	if len(s.Directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(s.Directives))
	}
	d := s.Directives[0]
	if d.Line != 1 {
		t.Errorf("expected line 1, got %d", d.Line)
	}
	if len(d.Targets) != 1 || d.Targets[0] != "batou-inj-001" {
		t.Errorf("expected target batou-inj-001, got %v", d.Targets)
	}
	if d.Reason != "validated by middleware" {
		t.Errorf("expected reason 'validated by middleware', got %q", d.Reason)
	}
}

func TestParse_PythonComment(t *testing.T) {
	s := Parse("# batou:ignore injection -- parameterized in wrapper\ncursor.execute(sql)")
	if len(s.Directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(s.Directives))
	}
	if s.Directives[0].Targets[0] != "injection" {
		t.Errorf("expected target injection, got %v", s.Directives[0].Targets)
	}
}

func TestParse_RubyComment(t *testing.T) {
	s := Parse("# batou:ignore xss\nrender html: user_input")
	if len(s.Directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(s.Directives))
	}
}

func TestParse_JavaComment(t *testing.T) {
	s := Parse("// batou:ignore BATOU-INJ-002\nstmt.execute(sql);")
	if len(s.Directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(s.Directives))
	}
}

func TestParse_CBlockComment(t *testing.T) {
	s := Parse("/* batou:ignore memory */\nchar *buf = malloc(size);")
	if len(s.Directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(s.Directives))
	}
	if s.Directives[0].Targets[0] != "memory" {
		t.Errorf("expected target memory, got %v", s.Directives[0].Targets)
	}
}

func TestParse_PHPComment(t *testing.T) {
	s := Parse("// batou:ignore injection\n$stmt = $pdo->query($sql);")
	if len(s.Directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(s.Directives))
	}
}

func TestParse_LuaComment(t *testing.T) {
	s := Parse("-- batou:ignore BATOU-INJ-001\nos.execute(cmd)")
	if len(s.Directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(s.Directives))
	}
}

func TestParse_PerlComment(t *testing.T) {
	s := Parse("# batou:ignore injection\nsystem($cmd);")
	if len(s.Directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(s.Directives))
	}
}

func TestParse_HTMLComment(t *testing.T) {
	s := Parse("<!-- batou:ignore xss -->\n<div>{{ user_input }}</div>")
	if len(s.Directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(s.Directives))
	}
}

func TestParse_CaseInsensitive(t *testing.T) {
	s := Parse("// BATOU:IGNORE injection\ncode()")
	if len(s.Directives) != 1 {
		t.Fatalf("expected 1 directive (case insensitive), got %d", len(s.Directives))
	}
}

// =========================================================================
// Parse — target matching
// =========================================================================

func TestParse_MultipleTargets(t *testing.T) {
	s := Parse("// batou:ignore BATOU-INJ-001 injection\ncode()")
	if len(s.Directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(s.Directives))
	}
	if len(s.Directives[0].Targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(s.Directives[0].Targets))
	}
}

func TestParse_AllTarget(t *testing.T) {
	s := Parse("// batou:ignore all -- known safe\ncode()")
	if len(s.Directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(s.Directives))
	}
	if s.Directives[0].Targets[0] != "all" {
		t.Errorf("expected target 'all', got %v", s.Directives[0].Targets)
	}
}

// =========================================================================
// Parse — line suppression scope
// =========================================================================

func TestParse_SuppressesSameLineAndNext(t *testing.T) {
	content := "// batou:ignore injection\nquery := db.Query(sql)"
	s := Parse(content)

	// Line 1 (directive itself) should be suppressed.
	if _, ok := s.lineTargets[1]; !ok {
		t.Error("expected line 1 to be suppressed")
	}
	// Line 2 (next code line) should be suppressed.
	if _, ok := s.lineTargets[2]; !ok {
		t.Error("expected line 2 to be suppressed")
	}
	// Line 3 should NOT exist.
	if _, ok := s.lineTargets[3]; ok {
		t.Error("line 3 should not be suppressed")
	}
}

func TestParse_SkipsBlanksToFindNextCode(t *testing.T) {
	content := "// batou:ignore injection\n\n\nquery := db.Query(sql)"
	s := Parse(content)

	// Line 4 (next code line after blanks) should be suppressed.
	if _, ok := s.lineTargets[4]; !ok {
		t.Error("expected line 4 (next code line) to be suppressed")
	}
}

func TestParse_SkipsCommentsToFindNextCode(t *testing.T) {
	content := "// batou:ignore injection\n// another comment\nquery := db.Query(sql)"
	s := Parse(content)

	// Line 3 (next code line after comment) should be suppressed.
	if _, ok := s.lineTargets[3]; !ok {
		t.Error("expected line 3 (next code line after comment) to be suppressed")
	}
}

// =========================================================================
// Parse — block suppression
// =========================================================================

func TestParse_BlockSuppression(t *testing.T) {
	content := "line1\n// batou:ignore-start injection\nline3\nline4\n// batou:ignore-end\nline6"
	s := Parse(content)

	// Lines 2-5 should be suppressed.
	for _, ln := range []int{2, 3, 4, 5} {
		if _, ok := s.lineTargets[ln]; !ok {
			t.Errorf("expected line %d to be suppressed in block", ln)
		}
	}
	// Lines 1 and 6 should NOT be suppressed.
	if _, ok := s.lineTargets[1]; ok {
		t.Error("line 1 should not be suppressed")
	}
	if _, ok := s.lineTargets[6]; ok {
		t.Error("line 6 should not be suppressed")
	}
}

func TestParse_UnclosedBlock(t *testing.T) {
	content := "line1\n// batou:ignore-start injection\nline3\nline4"
	s := Parse(content)

	// Unclosed block should suppress from start to end of file.
	for _, ln := range []int{2, 3, 4} {
		if _, ok := s.lineTargets[ln]; !ok {
			t.Errorf("expected line %d to be suppressed in unclosed block", ln)
		}
	}
}

// =========================================================================
// Parse — edge cases
// =========================================================================

func TestParse_NoDirectives(t *testing.T) {
	s := Parse("func main() {\n    fmt.Println(\"hello\")\n}")
	if len(s.Directives) != 0 {
		t.Errorf("expected 0 directives, got %d", len(s.Directives))
	}
}

func TestParse_EmptyContent(t *testing.T) {
	s := Parse("")
	if len(s.Directives) != 0 {
		t.Errorf("expected 0 directives, got %d", len(s.Directives))
	}
}

func TestParse_ReasonOnly(t *testing.T) {
	// Ensure reason is parsed correctly.
	s := Parse("// batou:ignore BATOU-INJ-001 -- this is safe because X\ncode()")
	if len(s.Directives) == 0 {
		t.Fatal("expected at least 1 directive")
	}
	if s.Directives[0].Reason != "this is safe because X" {
		t.Errorf("expected reason 'this is safe because X', got %q", s.Directives[0].Reason)
	}
}

func TestParse_NoReason(t *testing.T) {
	s := Parse("// batou:ignore injection\ncode()")
	if len(s.Directives) == 0 {
		t.Fatal("expected at least 1 directive")
	}
	if s.Directives[0].Reason != "" {
		t.Errorf("expected empty reason, got %q", s.Directives[0].Reason)
	}
}

// =========================================================================
// IsSuppressed + matchesTargets
// =========================================================================

func TestIsSuppressed_ExactRuleID(t *testing.T) {
	s := Parse("// batou:ignore BATOU-INJ-001\nquery := db.Query(sql)")
	f := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 2}
	if !s.IsSuppressed(f) {
		t.Error("expected finding to be suppressed by exact rule ID")
	}
}

func TestIsSuppressed_Category(t *testing.T) {
	s := Parse("// batou:ignore injection\nquery := db.Query(sql)")
	f := rules.Finding{RuleID: "BATOU-INJ-042", LineNumber: 2}
	if !s.IsSuppressed(f) {
		t.Error("expected finding to be suppressed by category 'injection'")
	}
}

func TestIsSuppressed_All(t *testing.T) {
	s := Parse("// batou:ignore all\nquery := db.Query(sql)")
	f := rules.Finding{RuleID: "BATOU-XSS-001", LineNumber: 2}
	if !s.IsSuppressed(f) {
		t.Error("expected finding to be suppressed by 'all'")
	}
}

func TestIsSuppressed_NoMatch(t *testing.T) {
	s := Parse("// batou:ignore xss\nquery := db.Query(sql)")
	f := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 2}
	if s.IsSuppressed(f) {
		t.Error("finding should NOT be suppressed (xss directive doesn't cover injection)")
	}
}

func TestIsSuppressed_WrongLine(t *testing.T) {
	s := Parse("// batou:ignore injection\nline2\nline3")
	f := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 3}
	if s.IsSuppressed(f) {
		t.Error("finding on line 3 should NOT be suppressed (directive covers lines 1-2)")
	}
}

func TestIsSuppressed_CaseInsensitiveRuleID(t *testing.T) {
	s := Parse("// batou:ignore batou-inj-001\nquery := db.Query(sql)")
	f := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 2}
	if !s.IsSuppressed(f) {
		t.Error("expected case-insensitive rule ID match")
	}
}

// =========================================================================
// Apply
// =========================================================================

func TestApply_PartitionsFindings(t *testing.T) {
	s := Parse("// batou:ignore injection\nline2\nline3")
	findings := []rules.Finding{
		{RuleID: "BATOU-INJ-001", LineNumber: 2},
		{RuleID: "BATOU-XSS-001", LineNumber: 3},
	}

	kept, suppressed := Apply(s, findings)
	if len(kept) != 1 || kept[0].RuleID != "BATOU-XSS-001" {
		t.Errorf("expected XSS finding kept, got %v", kept)
	}
	if len(suppressed) != 1 || suppressed[0].RuleID != "BATOU-INJ-001" {
		t.Errorf("expected INJ finding suppressed, got %v", suppressed)
	}
}

func TestApply_NilSuppressions(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "BATOU-INJ-001", LineNumber: 1},
	}
	kept, suppressed := Apply(nil, findings)
	if len(kept) != 1 {
		t.Error("nil suppressions should keep all findings")
	}
	if len(suppressed) != 0 {
		t.Error("nil suppressions should produce no suppressed findings")
	}
}

func TestApply_EmptyFindings(t *testing.T) {
	s := Parse("// batou:ignore all\ncode()")
	kept, suppressed := Apply(s, nil)
	if len(kept) != 0 || len(suppressed) != 0 {
		t.Error("empty findings should produce empty results")
	}
}

// =========================================================================
// SuppressedLines
// =========================================================================

func TestSuppressedLines(t *testing.T) {
	s := Parse("// batou:ignore injection\nline2\nline3")
	lines := s.SuppressedLines()
	if !lines[1] || !lines[2] {
		t.Error("expected lines 1 and 2 in suppressed lines map")
	}
	if lines[3] {
		t.Error("line 3 should not be in suppressed lines map")
	}
}

func TestSuppressedLines_Nil(t *testing.T) {
	var s *Suppressions
	lines := s.SuppressedLines()
	if lines != nil {
		t.Error("nil suppressions should return nil lines")
	}
}

// =========================================================================
// Block suppression with IsSuppressed
// =========================================================================

func TestIsSuppressed_BlockRange(t *testing.T) {
	content := "line1\n// batou:ignore-start injection\nline3\nline4\n// batou:ignore-end\nline6"
	s := Parse(content)

	f3 := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 3}
	f4 := rules.Finding{RuleID: "BATOU-INJ-002", LineNumber: 4}
	f6 := rules.Finding{RuleID: "BATOU-INJ-003", LineNumber: 6}

	if !s.IsSuppressed(f3) {
		t.Error("line 3 should be suppressed inside block")
	}
	if !s.IsSuppressed(f4) {
		t.Error("line 4 should be suppressed inside block")
	}
	if s.IsSuppressed(f6) {
		t.Error("line 6 should NOT be suppressed (after block end)")
	}
}

// =========================================================================
// Same-line directive (directive on the code line itself)
// =========================================================================

func TestParse_SameLineDirective(t *testing.T) {
	// Directive appears on the same line as code — should suppress that line.
	content := "query := db.Query(sql) // batou:ignore injection\nnextLine()"
	s := Parse(content)

	if len(s.Directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(s.Directives))
	}
	// Line 1 should be suppressed (directive is on line 1).
	if _, ok := s.lineTargets[1]; !ok {
		t.Error("expected line 1 to be suppressed (same-line directive)")
	}
}

func TestIsSuppressed_SameLineDirective(t *testing.T) {
	content := "db.Query(sql) // batou:ignore BATOU-INJ-001\nnextLine()"
	s := Parse(content)

	f := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 1}
	if !s.IsSuppressed(f) {
		t.Error("finding on line 1 should be suppressed by same-line directive")
	}
}

// =========================================================================
// Directive at end of file (no following code line)
// =========================================================================

func TestParse_DirectiveAtEOF(t *testing.T) {
	content := "code()\n// batou:ignore injection"
	s := Parse(content)

	if len(s.Directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(s.Directives))
	}
	// Line 2 (directive itself) should be suppressed.
	if _, ok := s.lineTargets[2]; !ok {
		t.Error("expected line 2 (directive at EOF) to be suppressed")
	}
	// No next code line — should not crash or suppress line 3.
	if _, ok := s.lineTargets[3]; ok {
		t.Error("nonexistent line 3 should not be suppressed")
	}
}

// =========================================================================
// Nested blocks
// =========================================================================

func TestParse_NestedBlocks(t *testing.T) {
	content := "// batou:ignore-start injection\nline2\n// batou:ignore-start xss\nline4\n// batou:ignore-end\nline6\n// batou:ignore-end\nline8"
	s := Parse(content)

	// Line 4 should be suppressed by both injection and xss.
	targets := s.lineTargets[4]
	hasInj, hasXSS := false, false
	for _, t := range targets {
		if t == "injection" {
			hasInj = true
		}
		if t == "xss" {
			hasXSS = true
		}
	}
	if !hasInj || !hasXSS {
		t.Errorf("expected line 4 to be suppressed by both injection and xss, got targets: %v", targets)
	}

	// Line 6 should still be suppressed by injection (outer block) but not xss (inner ended).
	targets6 := s.lineTargets[6]
	hasInj6 := false
	for _, t := range targets6 {
		if t == "injection" {
			hasInj6 = true
		}
	}
	if !hasInj6 {
		t.Errorf("expected line 6 to be suppressed by outer injection block, got targets: %v", targets6)
	}

	// Line 8 should NOT be suppressed.
	if _, ok := s.lineTargets[8]; ok {
		t.Error("line 8 should not be suppressed (both blocks ended)")
	}
}

// =========================================================================
// Orphan ignore-end (no matching start)
// =========================================================================

func TestParse_OrphanEnd(t *testing.T) {
	// An ignore-end without a matching start should be gracefully ignored.
	content := "line1\n// batou:ignore-end\nline3"
	s := Parse(content)

	// Should have one directive (the end).
	if len(s.Directives) != 1 {
		t.Fatalf("expected 1 directive (orphan end), got %d", len(s.Directives))
	}
	// No lines should be suppressed.
	if len(s.lineTargets) != 0 {
		t.Errorf("orphan end should not suppress any lines, got %d suppressed lines", len(s.lineTargets))
	}
}

// =========================================================================
// Block with wrong category
// =========================================================================

func TestIsSuppressed_BlockWrongCategory(t *testing.T) {
	content := "// batou:ignore-start xss\nline2\n// batou:ignore-end"
	s := Parse(content)

	// XSS finding should be suppressed.
	fXSS := rules.Finding{RuleID: "BATOU-XSS-001", LineNumber: 2}
	if !s.IsSuppressed(fXSS) {
		t.Error("XSS finding should be suppressed inside xss block")
	}

	// Injection finding should NOT be suppressed.
	fINJ := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 2}
	if s.IsSuppressed(fINJ) {
		t.Error("injection finding should NOT be suppressed inside xss-only block")
	}
}

// =========================================================================
// Multiple independent directives in one file
// =========================================================================

func TestParse_MultipleDirectivesInFile(t *testing.T) {
	content := "// batou:ignore injection\nline2\nline3\n// batou:ignore xss\nline5"
	s := Parse(content)

	if len(s.Directives) != 2 {
		t.Fatalf("expected 2 directives, got %d", len(s.Directives))
	}

	// Line 2: suppressed for injection.
	fINJ := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 2}
	if !s.IsSuppressed(fINJ) {
		t.Error("injection finding on line 2 should be suppressed")
	}

	// Line 2: NOT suppressed for xss.
	fXSS2 := rules.Finding{RuleID: "BATOU-XSS-001", LineNumber: 2}
	if s.IsSuppressed(fXSS2) {
		t.Error("xss finding on line 2 should NOT be suppressed (only injection directive)")
	}

	// Line 5: suppressed for xss.
	fXSS5 := rules.Finding{RuleID: "BATOU-XSS-001", LineNumber: 5}
	if !s.IsSuppressed(fXSS5) {
		t.Error("xss finding on line 5 should be suppressed")
	}

	// Line 5: NOT suppressed for injection.
	fINJ5 := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 5}
	if s.IsSuppressed(fINJ5) {
		t.Error("injection finding on line 5 should NOT be suppressed")
	}
}

// =========================================================================
// Partial suppression (two findings on same line, one matches)
// =========================================================================

func TestApply_PartialSuppression(t *testing.T) {
	s := Parse("// batou:ignore injection\nline2")
	findings := []rules.Finding{
		{RuleID: "BATOU-INJ-001", LineNumber: 2},
		{RuleID: "BATOU-XSS-001", LineNumber: 2},
		{RuleID: "BATOU-INJ-005", LineNumber: 2},
	}

	kept, suppressed := Apply(s, findings)

	// INJ-001 and INJ-005 should be suppressed, XSS-001 should remain.
	if len(suppressed) != 2 {
		t.Errorf("expected 2 suppressed findings, got %d", len(suppressed))
	}
	if len(kept) != 1 {
		t.Errorf("expected 1 kept finding, got %d", len(kept))
	}
	if len(kept) > 0 && kept[0].RuleID != "BATOU-XSS-001" {
		t.Errorf("expected XSS finding kept, got %s", kept[0].RuleID)
	}
}

// =========================================================================
// Category matching coverage
// =========================================================================

func TestMatchesTargets_AllCategories(t *testing.T) {
	tests := []struct {
		ruleID   string
		category string
	}{
		{"BATOU-INJ-001", "injection"},
		{"BATOU-XSS-001", "xss"},
		{"BATOU-SEC-001", "secrets"},
		{"BATOU-CRY-001", "crypto"},
		{"BATOU-TRV-001", "traversal"},
		{"BATOU-AUTH-001", "auth"},
		{"BATOU-SSRF-001", "ssrf"},
		{"BATOU-TAINT-001", "taint"},
		{"BATOU-DESER-001", "deserialize"},
		{"BATOU-REDIR-001", "redirect"},
		{"BATOU-NOSQL-001", "injection"},
		{"BATOU-XXE-001", "xxe"},
		{"BATOU-CORS-001", "cors"},
		{"BATOU-LOG-001", "logging"},
		{"BATOU-MEM-001", "memory"},
		{"BATOU-PROTO-001", "prototype"},
		{"BATOU-MASS-001", "massassign"},
		{"BATOU-GQL-001", "graphql"},
		{"BATOU-MISCONF-001", "misconfig"},
		{"BATOU-INTERPROC-SQL", "interprocedural"},
	}

	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			f := rules.Finding{RuleID: tt.ruleID, LineNumber: 1}
			if !matchesTargets(f, []string{tt.category}) {
				t.Errorf("expected %s to match category %q", tt.ruleID, tt.category)
			}
		})
	}
}

func TestMatchesTargets_NoMatchUnrelatedCategory(t *testing.T) {
	f := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 1}
	if matchesTargets(f, []string{"xss"}) {
		t.Error("injection rule should not match xss category")
	}
}

func TestMatchesTargets_GeneralFallback(t *testing.T) {
	f := rules.Finding{RuleID: "BATOU-UNKNOWN-001", LineNumber: 1}
	if !matchesTargets(f, []string{"general"}) {
		t.Error("unknown rule should fall back to 'general' category")
	}
}

package suppress

import (
	"github.com/turenlabs/batou-rules/rules"
	"testing"
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
		{"BATOU-FW-FASTAPI-001", "framework"},
		{"BATOU-FW-DJANGO-001", "framework"},
		{"BATOU-FW-EXPRESS-001", "framework"},
		{"BATOU-JWT-001", "jwt"},
		{"BATOU-SESS-001", "session"},
		{"BATOU-OAUTH-001", "oauth"},
		{"BATOU-RACE-001", "race"},
		{"BATOU-SSTI-001", "ssti"},
		{"BATOU-UPLOAD-001", "upload"},
		{"BATOU-VAL-001", "validation"},
		{"BATOU-HDR-001", "header"},
		{"BATOU-ENC-001", "encoding"},
		{"BATOU-WS-001", "websocket"},
		{"BATOU-MISC-001", "misconfig"},
		{"BATOU-GEN-001", "general"},
		{"BATOU-GO-001", "golang"},
		{"BATOU-PY-001", "python"},
		{"BATOU-PYAST-001", "python"},
		{"BATOU-JSTS-001", "jsts"},
		{"BATOU-JAVA-001", "java"},
		{"BATOU-PHP-001", "php"},
		{"BATOU-RB-001", "ruby"},
		{"BATOU-RS-001", "rust"},
		{"BATOU-CS-001", "csharp"},
		{"BATOU-KT-001", "kotlin"},
		{"BATOU-SWIFT-001", "swift"},
		{"BATOU-LUA-001", "lua"},
		{"BATOU-PL-001", "perl"},
		{"BATOU-GVY-001", "groovy"},
		{"BATOU-ZIG-001", "zig"},
		{"BATOU-CTR-001", "container"},
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

func TestMatchesTargets_TaintSinkSubcategory(t *testing.T) {
	// BATOU-TAINT-sql_query should be suppressible by "sql_query"
	tests := []struct {
		ruleID string
		target string
	}{
		{"BATOU-TAINT-sql_query", "sql_query"},
		{"BATOU-TAINT-file_write", "file_write"},
		{"BATOU-TAINT-url_fetch", "url_fetch"},
		{"BATOU-TAINT-command_exec", "command_exec"},
		{"BATOU-TAINT-html_output", "html_output"},
	}
	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			f := rules.Finding{RuleID: tt.ruleID, LineNumber: 1}
			if !matchesTargets(f, []string{tt.target}) {
				t.Errorf("expected %s to match target %q", tt.ruleID, tt.target)
			}
		})
	}
}

func TestMatchesTargets_TaintCatchAll(t *testing.T) {
	// All BATOU-TAINT-* findings should match the "taint" catch-all
	taintRules := []string{
		"BATOU-TAINT-sql_query",
		"BATOU-TAINT-file_write",
		"BATOU-TAINT-url_fetch",
	}
	for _, ruleID := range taintRules {
		f := rules.Finding{RuleID: ruleID, LineNumber: 1}
		if !matchesTargets(f, []string{"taint"}) {
			t.Errorf("expected %s to match 'taint' catch-all", ruleID)
		}
	}
}

func TestIsSuppressed_LineZeroFinding(t *testing.T) {
	// A finding at line 0 (file-level) should be suppressible by a
	// directive on line 1 of the file.
	s := Parse("# batou:ignore BATOU-SSRF-001 -- false positive\nimport requests")
	f := rules.Finding{RuleID: "BATOU-SSRF-001", LineNumber: 0}
	if !s.IsSuppressed(f) {
		t.Error("line 0 finding should be suppressed by directive on line 1")
	}
}

func TestIsSuppressed_LineZeroNotSuppressedWithoutDirective(t *testing.T) {
	// A finding at line 0 should NOT be suppressed if line 1 has no directive.
	s := Parse("import requests\n# batou:ignore BATOU-SSRF-001\ndo_stuff()")
	f := rules.Finding{RuleID: "BATOU-SSRF-001", LineNumber: 0}
	if s.IsSuppressed(f) {
		t.Error("line 0 finding should not be suppressed when directive is on line 2")
	}
}

func TestIsSuppressed_PythonDecorator(t *testing.T) {
	// Exact scenario from user: suppress directive above @app.post decorator
	code := "# batou:ignore BATOU-FW-FASTAPI-001 -- public meme generator\n@app.post(\"/api/generate\")\nasync def generate_meme():\n    pass"
	s := Parse(code)

	// Finding is on the decorator line (line 2)
	f := rules.Finding{RuleID: "BATOU-FW-FASTAPI-001", LineNumber: 2}
	if !s.IsSuppressed(f) {
		t.Error("expected BATOU-FW-FASTAPI-001 on line 2 to be suppressed by directive on line 1")
		t.Logf("lineTargets: %v", s.lineTargets)
	}
}

func TestIsSuppressed_PythonDecoratorWithBlankLine(t *testing.T) {
	// What if there's a blank line between the directive and the decorator?
	code := "# batou:ignore BATOU-FW-FASTAPI-001 -- public\n\n@app.post(\"/api/generate\")\nasync def generate_meme():\n    pass"
	s := Parse(code)

	// Blank line should be skipped; finding on line 3 (decorator)
	f := rules.Finding{RuleID: "BATOU-FW-FASTAPI-001", LineNumber: 3}
	if !s.IsSuppressed(f) {
		t.Error("expected finding on line 3 to be suppressed (blank line between directive and decorator)")
		t.Logf("lineTargets: %v", s.lineTargets)
	}
}

func TestIsSuppressed_FrameworkRuleCategory(t *testing.T) {
	// Test that BATOU-FW-FASTAPI-001 can be suppressed by category
	code := "# batou:ignore framework\n@app.post(\"/api/generate\")"
	s := Parse(code)
	f := rules.Finding{RuleID: "BATOU-FW-FASTAPI-001", LineNumber: 2}
	if !s.IsSuppressed(f) {
		t.Errorf("expected framework category suppress to work for BATOU-FW-FASTAPI-001")
		t.Logf("categorizeRule result: %q", categorizeRule("BATOU-FW-FASTAPI-001"))
	}
}

// =========================================================================
// Failure mode tests — edge cases and regressions
// =========================================================================

func TestUnsuppressible_SuppressReview(t *testing.T) {
	// BATOU-SUPPRESS-REVIEW must never be suppressible — agents can't suppress
	// the warning that tells them to fix code instead of suppressing.
	code := "// batou:ignore all\n// batou:ignore BATOU-SUPPRESS-REVIEW\ndb.Query(sql)"
	s := Parse(code)
	f := rules.Finding{RuleID: "BATOU-SUPPRESS-REVIEW", LineNumber: 3}
	if s.IsSuppressed(f) {
		t.Fatal("BATOU-SUPPRESS-REVIEW must not be suppressible")
	}
}

func TestUnsuppressible_Timeout(t *testing.T) {
	code := "// batou:ignore all\npackage main"
	s := Parse(code)
	f := rules.Finding{RuleID: "BATOU-TIMEOUT", LineNumber: 2}
	if s.IsSuppressed(f) {
		t.Fatal("BATOU-TIMEOUT must not be suppressible")
	}
}

func TestUnsuppressible_Panic(t *testing.T) {
	code := "// batou:ignore all\npackage main"
	s := Parse(code)
	f := rules.Finding{RuleID: "BATOU-PANIC", LineNumber: 2}
	if s.IsSuppressed(f) {
		t.Fatal("BATOU-PANIC must not be suppressible")
	}
}

func TestUnsuppressible_NormalRulesStillWork(t *testing.T) {
	// Normal rules should still be suppressible
	code := "// batou:ignore BATOU-INJ-001\ndb.Query(sql)"
	s := Parse(code)
	f := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 2}
	if !s.IsSuppressed(f) {
		t.Fatal("normal rules should still be suppressible")
	}
}

func TestBlockSuppress_MissingEnd(t *testing.T) {
	// Missing ignore-end should suppress everything after ignore-start
	// (over-suppress for safety — better than under-suppress)
	code := "// batou:ignore-start injection\ndb.Query(sql)\ndb.Query(sql2)\ndb.Query(sql3)"
	s := Parse(code)
	for _, line := range []int{2, 3, 4} {
		f := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: line}
		if !s.IsSuppressed(f) {
			t.Errorf("line %d should be suppressed (unclosed block covers rest of file)", line)
		}
	}
}

func TestBlockSuppress_EmptyBlock(t *testing.T) {
	// ignore-start immediately followed by ignore-end should suppress nothing
	code := "line1\n// batou:ignore-start injection\n// batou:ignore-end\ndb.Query(sql)"
	s := Parse(code)
	f := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 4}
	if s.IsSuppressed(f) {
		t.Fatal("finding outside empty block should not be suppressed")
	}
}

func TestSuppress_CaseInsensitiveTarget(t *testing.T) {
	// Targets should be case-insensitive
	code := "// batou:ignore INJECTION\ndb.Query(sql)"
	s := Parse(code)
	f := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 2}
	if !s.IsSuppressed(f) {
		t.Fatal("uppercase category target should still match")
	}
}

func TestSuppress_MisspelledRuleID(t *testing.T) {
	// Misspelled rule ID should NOT suppress
	code := "// batou:ignore BATOU-INJ-999\ndb.Query(sql)"
	s := Parse(code)
	f := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 2}
	if s.IsSuppressed(f) {
		t.Fatal("misspelled rule ID should not suppress a different rule")
	}
}

func TestSuppress_DirectiveInStringLiteral(t *testing.T) {
	// A suppress directive inside a string literal is still parsed as a directive
	// because suppress.Parse is regex-based (no AST). This is a known limitation.
	// The test documents the behavior.
	code := "msg := \"// batou:ignore injection\"\ndb.Query(sql)"
	s := Parse(code)
	// The regex parser WILL find this — it's a known false positive in parsing.
	// We document the behavior rather than assert it's filtered.
	t.Logf("directives found in string literal test: %d", len(s.Directives))
}

func TestSuppress_MultipleTargets(t *testing.T) {
	// Multiple targets on one directive should suppress all
	code := "// batou:ignore injection xss -- both categories\ndb.Query(sql)"
	s := Parse(code)
	injF := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 2}
	xssF := rules.Finding{RuleID: "BATOU-XSS-001", LineNumber: 2}
	if !s.IsSuppressed(injF) {
		t.Error("injection should be suppressed by multi-target directive")
	}
	if !s.IsSuppressed(xssF) {
		t.Error("xss should be suppressed by multi-target directive")
	}
}

// =========================================================================
// ParseWithLineMap — mirroring to original line coordinates
//
// Regression: a Python file where joinPythonContinuations collapses a
// multi-line argparse.ArgumentParser(...) call (original lines 2–4) into a
// single preprocessed line. A `# batou:ignore` comment above a taint sink
// further down the file would otherwise miss the sink entirely, because:
//   - suppress.Parse sees the directive at preprocessed line N.
//   - The taint engine reports the sink at original line N+2 (the collapse
//     shifted things by 2).
//   - lineTargets[N+2] is empty, lookup fails, finding is not suppressed.
// ParseWithLineMap mirrors each preprocessed entry across every original line
// in the group, so lookups in either coordinate system succeed.
// =========================================================================

func TestParseWithLineMap_MirrorsToOriginalAfterCollapse(t *testing.T) {
	// Shape: orig lines 1..3 collapse into preprocessed line 1 (argparse-like
	// multi-line ctor). Directive at orig line 4 = preprocessed line 2.
	// Sink at orig line 5 = preprocessed line 3.
	preToOrig := []int{1, 4, 5, 6}
	totalOrigLines := 6
	// Parse runs on preprocessed content, which has 4 physical lines after
	// collapse.
	preprocessed := "p1 joined\n# batou:ignore file_read\nsink()\nafter"

	s := ParseWithLineMap(preprocessed, preToOrig, totalOrigLines)

	// Finding reported in ORIGINAL coords (e.g. from the taint engine).
	taintFinding := rules.Finding{RuleID: "BATOU-TAINT-file_read", LineNumber: 5}
	if !s.IsSuppressed(taintFinding) {
		t.Errorf("taint finding at original line 5 should be suppressed via mirroring; lineTargets=%v", s.lineTargets)
	}

	// Finding reported in PREPROCESSED coords (e.g. from a regex rule) still
	// resolves directly.
	regexFinding := rules.Finding{RuleID: "BATOU-TAINT-file_read", LineNumber: 3}
	if !s.IsSuppressed(regexFinding) {
		t.Error("regex-style finding at preprocessed line 3 should still be suppressed (backwards compat)")
	}

	// A finding BEYOND the mirror range should not be suppressed.
	unrelated := rules.Finding{RuleID: "BATOU-TAINT-file_read", LineNumber: 6}
	if s.IsSuppressed(unrelated) {
		t.Error("finding on line 6 (outside directive scope) should not be suppressed")
	}
}

func TestParseWithLineMap_ExpandsGroupAcrossCollapse(t *testing.T) {
	// Directive above a collapsed group: orig lines 2..4 collapse into
	// preprocessed line 2. A directive at orig line 1 should suppress
	// findings anywhere in the collapsed group (orig lines 2, 3, or 4).
	preToOrig := []int{1, 2, 5}
	totalOrigLines := 5
	preprocessed := "# batou:ignore injection\nsink(joined,content)\nafter"

	s := ParseWithLineMap(preprocessed, preToOrig, totalOrigLines)

	// Any original line within the collapsed group should be suppressed.
	for _, ln := range []int{2, 3, 4} {
		f := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: ln}
		if !s.IsSuppressed(f) {
			t.Errorf("line %d (inside collapsed group) should be suppressed; lineTargets=%v", ln, s.lineTargets)
		}
	}

	// Line 5 (next group) should NOT be suppressed.
	f5 := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 5}
	if s.IsSuppressed(f5) {
		t.Error("line 5 (outside directive scope) should not be suppressed")
	}
}

func TestParseWithLineMap_NilMapIsIdentity(t *testing.T) {
	// Passing nil preToOrig should behave identically to Parse.
	code := "# batou:ignore injection\ndb.Query(sql)"
	s := ParseWithLineMap(code, nil, 0)
	ref := Parse(code)

	if len(s.lineTargets) != len(ref.lineTargets) {
		t.Errorf("expected identical lineTargets; got %v vs %v", s.lineTargets, ref.lineTargets)
	}
	for ln, targets := range ref.lineTargets {
		if got := s.lineTargets[ln]; len(got) != len(targets) {
			t.Errorf("line %d mismatch: got %v, want %v", ln, got, targets)
		}
	}
}

// =========================================================================
// Trailing (inline) directive scope
//
// Regression: a directive that trails a code line should only suppress that
// one line. The old implementation always extended to the next code line,
// which silently suppressed unrelated findings below.
// =========================================================================

func TestTrailingDirective_DoesNotLeakToNextLine(t *testing.T) {
	content := "risky_call()  // batou:ignore injection\nanother_call()"
	s := Parse(content)

	// The directive line itself is suppressed.
	onLine1 := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 1}
	if !s.IsSuppressed(onLine1) {
		t.Error("directive line (trailing form) should be suppressed")
	}

	// The NEXT line must NOT be suppressed — it's unrelated code.
	onLine2 := rules.Finding{RuleID: "BATOU-INJ-002", LineNumber: 2}
	if s.IsSuppressed(onLine2) {
		t.Error("line 2 should NOT be suppressed by a trailing directive on line 1")
	}
}

func TestPureCommentDirective_ExtendsToNextCodeLine(t *testing.T) {
	// Guardrail: pure-comment form must still extend to the next code line.
	content := "// batou:ignore injection\nrisky_call()"
	s := Parse(content)

	onLine2 := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 2}
	if !s.IsSuppressed(onLine2) {
		t.Error("pure-comment directive must still suppress next code line (regression)")
	}
}

func TestParseWithLineMap_LastPreprocessedLineExtendsToEOF(t *testing.T) {
	// The last preprocessed line represents a collapsed group that runs to
	// the end of the file (unclosed paren / trailing backslash). The mirror
	// must extend to totalOrigLines, not just preToOrig[-1].
	preToOrig := []int{1, 3}
	totalOrigLines := 5
	preprocessed := "before\n# batou:ignore injection trailing"

	s := ParseWithLineMap(preprocessed, preToOrig, totalOrigLines)

	// The directive is on preprocessed line 2 which maps to orig lines 3..5.
	// Every original line in that range should carry the directive's targets
	// (so a finding on any of them is suppressed).
	for _, ln := range []int{3, 4, 5} {
		f := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: ln}
		if !s.IsSuppressed(f) {
			t.Errorf("line %d (end-of-file group) should be suppressed; lineTargets=%v", ln, s.lineTargets)
		}
	}
}

// =========================================================================
// ReasonForFinding — exported reason lookup for the audit trail
// =========================================================================

// ReasonForFinding must return the directive's `-- reason` text for a finding
// the directive suppresses, so the scanner can stamp Finding.SuppressReason
// and the findings store / ledger persist the developer's justification.
func TestReasonForFinding_ReturnsDirectiveReason(t *testing.T) {
	s := Parse("# batou:ignore BATOU-INJ-001 -- known FP because X\ncursor.execute(sql)")
	f := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 2}
	reason, ok := s.ReasonForFinding(f)
	if !ok {
		t.Fatal("expected ok=true for a finding covered by the directive")
	}
	if reason != "known FP because X" {
		t.Errorf("reason = %q, want %q", reason, "known FP because X")
	}
}

// A reasonless directive still covers the finding (ok=true) but yields an
// empty reason; an uncovered finding yields ok=false.
func TestReasonForFinding_ReasonlessAndUncovered(t *testing.T) {
	s := Parse("# batou:ignore BATOU-INJ-001\ncursor.execute(sql)")

	covered := rules.Finding{RuleID: "BATOU-INJ-001", LineNumber: 2}
	reason, ok := s.ReasonForFinding(covered)
	if !ok || reason != "" {
		t.Errorf("reasonless directive: got (%q, %v), want (\"\", true)", reason, ok)
	}

	uncovered := rules.Finding{RuleID: "BATOU-XSS-001", LineNumber: 2}
	if reason, ok := s.ReasonForFinding(uncovered); ok {
		t.Errorf("non-matching rule: got (%q, %v), want ok=false", reason, ok)
	}
}

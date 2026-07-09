package phpast

import (
	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
	"testing"
)

func scanPHP(code string) []rules.Finding {
	tree := ast.Parse([]byte(code), rules.LangPHP)
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.php",
		Content:  code,
		Language: rules.LangPHP,
		Tree:     tree,
	}
	a := &PHPASTAnalyzer{}
	return a.Scan(ctx)
}

func findByRule(findings []rules.Finding, ruleID string) *rules.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

func countByRule(findings []rules.Finding, ruleID string) int {
	count := 0
	for _, f := range findings {
		if f.RuleID == ruleID {
			count++
		}
	}
	return count
}

func TestEvalVariable(t *testing.T) {
	code := `<?php
function handler($input) {
    eval($input);
}
?>`
	findings := scanPHP(code)
	f := findByRule(findings, "BATOU-PHPAST-001")
	if f == nil {
		t.Error("expected eval finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestEvalLiteralSafe(t *testing.T) {
	code := `<?php eval("1 + 2"); ?>`
	findings := scanPHP(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-PHPAST-001" {
			t.Errorf("should not flag eval with literal: %s", f.Title)
		}
	}
}

func TestCommandInjection(t *testing.T) {
	code := `<?php
function handler($input) {
    exec($input);
    system($input);
    passthru($input);
}
?>`
	findings := scanPHP(code)
	count := countByRule(findings, "BATOU-PHPAST-002")
	if count != 3 {
		t.Errorf("expected 3 command injection findings, got %d", count)
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestIncludeVariable(t *testing.T) {
	code := `<?php
function handler($path) {
    include($path);
}
?>`
	findings := scanPHP(code)
	f := findByRule(findings, "BATOU-PHPAST-003")
	if f == nil {
		t.Error("expected file inclusion finding for include with variable")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestRequireVariable(t *testing.T) {
	code := `<?php
function handler($path) {
    require($path);
}
?>`
	findings := scanPHP(code)
	f := findByRule(findings, "BATOU-PHPAST-003")
	if f == nil {
		t.Error("expected file inclusion finding for require with variable")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestUnserialize(t *testing.T) {
	code := `<?php
function handler($data) {
    unserialize($data);
}
?>`
	findings := scanPHP(code)
	f := findByRule(findings, "BATOU-PHPAST-004")
	if f == nil {
		t.Error("expected deserialization finding for unserialize")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestPregReplaceE(t *testing.T) {
	code := `<?php
function handler($input, $subject) {
    preg_replace('/pattern/e', $input, $subject);
}
?>`
	findings := scanPHP(code)
	f := findByRule(findings, "BATOU-PHPAST-005")
	if f == nil {
		t.Error("expected preg_replace /e finding")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestPregReplaceNoESafe(t *testing.T) {
	code := `<?php
preg_replace('/pattern/', $replacement, $subject);
?>`
	findings := scanPHP(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-PHPAST-005" {
			t.Errorf("should not flag preg_replace without /e: %s", f.Title)
		}
	}
}

func TestSQLConcatInAssignment(t *testing.T) {
	code := `<?php
function handler($input) {
    $query = "SELECT * FROM users WHERE name = '" . $input . "'";
}
?>`
	findings := scanPHP(code)
	f := findByRule(findings, "BATOU-PHPAST-006")
	if f == nil {
		t.Error("expected SQL injection finding for concat in assignment")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestTwigCreateTemplateSSTI(t *testing.T) {
	code := `<?php
function handler($twig, $input) {
    $template = $twig->createTemplate($input);
    return $template->render([]);
}
?>`
	findings := scanPHP(code)
	f := findByRule(findings, "BATOU-PHPAST-007")
	if f == nil {
		t.Error("expected SSTI finding for Twig createTemplate with variable")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
		return
	}
	if f.CWEID != "CWE-1336" {
		t.Errorf("expected CWE-1336, got %s", f.CWEID)
	}
}

func TestTwigCreateTemplateSecondOrder(t *testing.T) {
	// Template string arrives from a DB row — taint cannot trace it to a
	// request source, but structurally it is still SSTI.
	code := `<?php
function renderStored($twig, $db) {
    $row = $db->query("SELECT body FROM tpls")->fetch();
    $tpl = $row['body'];
    $template = $twig->createTemplate($tpl);
    return $template->render([]);
}
?>`
	findings := scanPHP(code)
	if findByRule(findings, "BATOU-PHPAST-007") == nil {
		t.Error("expected SSTI finding for second-order Twig createTemplate")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestBladeCompileStringSSTI(t *testing.T) {
	code := `<?php
function handler($blade, $snippet) {
    return $blade->compileString($snippet);
}
?>`
	findings := scanPHP(code)
	if findByRule(findings, "BATOU-PHPAST-007") == nil {
		t.Error("expected SSTI finding for Blade compileString with variable")
		for _, f := range findings {
			t.Logf("  %s: %s (line %d)", f.RuleID, f.Title, f.LineNumber)
		}
	}
}

func TestTwigCreateTemplateLiteralSafe(t *testing.T) {
	// A developer-authored literal template string must NOT be flagged.
	code := `<?php
$template = $twig->createTemplate("Hello {{ name }}");
?>`
	findings := scanPHP(code)
	for _, f := range findings {
		if f.RuleID == "BATOU-PHPAST-007" {
			t.Errorf("should not flag createTemplate with literal string: %s", f.Title)
		}
	}
}

func TestNonSSTIMethodCallSafe(t *testing.T) {
	// An unrelated method named like a sink elsewhere must not trip PHPAST-007.
	code := `<?php
$user->createTemplate($input);
$x->render($data);
?>`
	findings := scanPHP(code)
	// createTemplate is the only SSTI method here; render alone is not a
	// compile-string sink in this analyzer. createTemplate on a non-engine
	// receiver still flags (conservative) — assert render() does not.
	for _, f := range findings {
		if f.RuleID == "BATOU-PHPAST-007" && f.LineNumber == 3 {
			t.Errorf("render() should not be flagged as SSTI compile sink: %s", f.Title)
		}
	}
}

func TestNilTree(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.php",
		Content:  "<?php eval($x); ?>",
		Language: rules.LangPHP,
		Tree:     nil,
	}
	a := &PHPASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings with nil tree")
	}
}

func TestWrongLanguage(t *testing.T) {
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.py",
		Content:  "eval(x)",
		Language: rules.LangPython,
	}
	a := &PHPASTAnalyzer{}
	findings := a.Scan(ctx)
	if len(findings) != 0 {
		t.Error("expected no findings for wrong language")
	}
}

func TestLineNumbers(t *testing.T) {
	code := `<?php
// comment
function handler($input) {
    eval($input);
}
?>`
	findings := scanPHP(code)
	f := findByRule(findings, "BATOU-PHPAST-001")
	if f == nil {
		t.Fatal("expected finding")
	}
	if f.LineNumber != 4 {
		t.Errorf("expected line 4, got %d", f.LineNumber)
	}
}

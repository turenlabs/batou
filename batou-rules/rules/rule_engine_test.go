package rules

import (
	"regexp"
	"strings"
	"testing"
)

// --- Severity methods -------------------------------------------------------

func TestSeverity_StringAndIcon(t *testing.T) {
	cases := []struct {
		sev      Severity
		str      string
		icon     string
		shouldBl bool
		shouldWa bool
	}{
		{Info, "INFO", "i", false, false},
		{Low, "LOW", "L", false, false},
		{Medium, "MEDIUM", "M", false, false},
		{High, "HIGH", "H", false, true},
		{Critical, "CRITICAL", "!", true, true},
		{Severity(99), "UNKNOWN", "?", true, true}, // out-of-range >= Critical
	}
	for _, c := range cases {
		if got := c.sev.String(); got != c.str {
			t.Errorf("Severity(%d).String() = %q, want %q", c.sev, got, c.str)
		}
		if got := c.sev.Icon(); got != c.icon {
			t.Errorf("Severity(%d).Icon() = %q, want %q", c.sev, got, c.icon)
		}
		if got := c.sev.ShouldBlock(); got != c.shouldBl {
			t.Errorf("Severity(%d).ShouldBlock() = %v, want %v", c.sev, got, c.shouldBl)
		}
		if got := c.sev.ShouldWarn(); got != c.shouldWa {
			t.Errorf("Severity(%d).ShouldWarn() = %v, want %v", c.sev, got, c.shouldWa)
		}
	}
}

func TestSeverity_ImpactWeight(t *testing.T) {
	cases := []struct {
		sev  Severity
		want float64
	}{
		{Critical, 1.0},
		{High, 0.8},
		{Medium, 0.5},
		{Low, 0.25},
		{Info, 0.1},
		{Severity(-1), 0.1}, // default branch
	}
	for _, c := range cases {
		if got := c.sev.ImpactWeight(); got != c.want {
			t.Errorf("Severity(%d).ImpactWeight() = %v, want %v", c.sev, got, c.want)
		}
	}
}

// --- Finding.ShouldBlock / SyncConfidenceString -----------------------------

func TestFinding_ShouldBlock_RiskThreshold(t *testing.T) {
	cases := []struct {
		risk float64
		want bool
	}{
		{0.0, false},
		{0.69, false},
		{0.70, true}, // exact threshold blocks
		{0.95, true},
		{1.0, true},
	}
	for _, c := range cases {
		f := Finding{RiskScore: c.risk}
		if got := f.ShouldBlock(); got != c.want {
			t.Errorf("Finding{RiskScore:%v}.ShouldBlock() = %v, want %v", c.risk, got, c.want)
		}
	}
}

func TestFinding_SyncConfidenceString(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{0.0, "low"},
		{0.39, "low"},
		{0.40, "medium"}, // medium boundary inclusive
		{0.69, "medium"},
		{0.70, "high"}, // high boundary inclusive
		{1.0, "high"},
	}
	for _, c := range cases {
		f := Finding{ConfidenceScore: c.score}
		f.SyncConfidenceString()
		if f.Confidence != c.want {
			t.Errorf("SyncConfidenceString(score=%v) = %q, want %q", c.score, f.Confidence, c.want)
		}
	}
}

// --- Finding format helpers -------------------------------------------------

func TestFinding_FormatShort(t *testing.T) {
	f := Finding{
		RuleID:     "BATOU-INJ-001",
		Severity:   Critical,
		Title:      "SQL injection",
		FilePath:   "/app/handler.go",
		LineNumber: 42,
	}
	got := f.FormatShort()
	for _, want := range []string{"!", "BATOU-INJ-001", "SQL injection", "/app/handler.go:42"} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatShort() = %q, missing %q", got, want)
		}
	}

	// LineNumber 0 → no ":line" suffix, just the path.
	noLine := Finding{RuleID: "X", Severity: Low, Title: "t", FilePath: "/a/b.go"}
	g2 := noLine.FormatShort()
	if strings.Contains(g2, "/a/b.go:") {
		t.Errorf("FormatShort() should not append line when LineNumber==0: %q", g2)
	}
	if !strings.Contains(g2, "/a/b.go") {
		t.Errorf("FormatShort() missing file path: %q", g2)
	}
}

func TestFinding_FormatDetail(t *testing.T) {
	// Finding with a MatchedText (no taint path) and rich metadata.
	f := Finding{
		RuleID:        "BATOU-INJ-001",
		Severity:      High,
		Title:         "SQL injection",
		FilePath:      "/app/h.go",
		LineNumber:    10,
		Description:   "User input flows to query",
		MatchedText:   "db.Query(userInput)",
		Suggestion:    "Use parameterized queries",
		CWEID:         "CWE-89",
		OWASPCategory: "A03",
		RiskScore:     0.8,
	}
	got := f.FormatDetail()
	for _, want := range []string{
		"HIGH", "BATOU-INJ-001", "SQL injection", "/app/h.go:10",
		"Match: db.Query(userInput)", "User input flows to query",
		"Fix: Use parameterized queries", "CWE: CWE-89", "OWASP: A03", "Risk: 80%",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("FormatDetail() missing %q in:\n%s", want, got)
		}
	}

	// A taint-path finding renders the path instead of the Match line, and
	// when RiskScore==0 but ConfidenceScore>0 it shows Confidence not Risk.
	tf := Finding{
		RuleID:          "BATOU-TAINT-sql_query",
		Severity:        Critical,
		CWEID:           "CWE-89",
		ConfidenceScore: 0.9,
		TaintPath: []TaintStep{
			{File: "h.go", Line: 1, Kind: TaintStepSource, Label: "req.args"},
			{File: "r.go", Line: 3, Kind: TaintStepSink, Label: "execute(q)"},
		},
	}
	g2 := tf.FormatDetail()
	if !strings.Contains(g2, "Data-flow path:") {
		t.Errorf("FormatDetail() should render taint path, got:\n%s", g2)
	}
	if strings.Contains(g2, "Match:") {
		t.Errorf("FormatDetail() should not show Match line when TaintPath present:\n%s", g2)
	}
	if !strings.Contains(g2, "Confidence: 90%") {
		t.Errorf("FormatDetail() should show Confidence when RiskScore==0:\n%s", g2)
	}

	// Long MatchedText is truncated to 120 chars + ellipsis.
	long := Finding{Severity: Low, MatchedText: strings.Repeat("x", 200)}
	gl := long.FormatDetail()
	if !strings.Contains(gl, strings.Repeat("x", 120)+"...") {
		t.Errorf("FormatDetail() did not truncate long MatchedText:\n%s", gl)
	}
}

// --- CategoryForRule --------------------------------------------------------

func TestCategoryForRule(t *testing.T) {
	cases := []struct {
		ruleID string
		want   string
	}{
		// Taint rules: sink name lowercased.
		{"BATOU-TAINT-sql_query", "sql_query"},
		{"BATOU-TAINT-FILE_WRITE", "file_write"},
		// Prefix-map (language/framework) rules.
		{"BATOU-GO-001", "golang"},
		{"BATOU-PY-014", "python"},
		{"BATOU-PYAST-005", "python"},
		{"BATOU-JSTS-030", "jsts"},
		{"BATOU-JAVA-007", "java"},
		{"BATOU-FW-001", "framework"},
		{"BATOU-CTR-001", "container"},
		// Contains-list ordering: longer/more-specific substrings win.
		{"BATOU-OAUTH-001", "oauth"},       // OAUTH before AUTH
		{"BATOU-AUTH-011", "auth"},         // plain AUTH
		{"BATOU-NOSQL-002", "injection"},   // NOSQL before SQL → injection
		{"BATOU-MISCONF-003", "misconfig"}, // MISCONF before MISC
		{"BATOU-INJ-001", "injection"},
		{"BATOU-XSS-029", "xss"},
		{"BATOU-CRY-019", "crypto"},
		{"BATOU-SEC-001", "secrets"},
		{"BATOU-TRV-001", "traversal"},
		{"BATOU-SSRF-001", "ssrf"},
		{"BATOU-INTERPROC-001", "interprocedural"},
		{"BATOU-SESS-011", "session"},
		{"BATOU-JWT-001", "jwt"},
		// Unknown → general.
		{"BATOU-WHATEVER-999", "general"},
		{"totally-unrelated", "general"},
	}
	for _, c := range cases {
		if got := CategoryForRule(c.ruleID); got != c.want {
			t.Errorf("CategoryForRule(%q) = %q, want %q", c.ruleID, got, c.want)
		}
	}
}

func TestCategoryForRule_CaseInsensitive(t *testing.T) {
	// Lowercase rule IDs are upper-cased internally before matching.
	if got := CategoryForRule("batou-inj-001"); got != "injection" {
		t.Errorf("CategoryForRule(lowercase) = %q, want injection", got)
	}
}

// --- Shared helpers ---------------------------------------------------------

func TestIsComment(t *testing.T) {
	yes := []string{"// c", "# c", "* c", "/* c", "<!-- c"}
	no := []string{"code()", "  // indented (caller trims first)", "var x = 1", ""}
	for _, l := range yes {
		if !IsComment(l) {
			t.Errorf("IsComment(%q) = false, want true", l)
		}
	}
	for _, l := range no {
		if IsComment(l) {
			t.Errorf("IsComment(%q) = true, want false", l)
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := Truncate("short", 10); got != "short" {
		t.Errorf("Truncate short = %q", got)
	}
	if got := Truncate("0123456789", 5); got != "01234..." {
		t.Errorf("Truncate long = %q, want 01234...", got)
	}
	// Exactly maxLen → no truncation.
	if got := Truncate("12345", 5); got != "12345" {
		t.Errorf("Truncate exact = %q, want 12345", got)
	}
}

func TestHasHTMLSanitizer(t *testing.T) {
	yes := []string{
		"out = escapeHtml(x)",
		"v := DOMPurify.sanitize(dirty)",
		"echo htmlspecialchars($x);",
		"safe = html.escape(s)",
		"ESAPI.encoder().encodeForHTML(x)",
	}
	no := []string{"out = x + y", "plain text no sanitizer here", ""}
	for _, c := range yes {
		if !HasHTMLSanitizer(c) {
			t.Errorf("HasHTMLSanitizer(%q) = false, want true", c)
		}
	}
	for _, c := range no {
		if HasHTMLSanitizer(c) {
			t.Errorf("HasHTMLSanitizer(%q) = true, want false", c)
		}
	}
}

func TestIsFrontendJS_And_IsServerSideCode(t *testing.T) {
	// Non-JS language: IsFrontendJS always false, IsServerSideCode always true.
	goCtx := &ScanContext{Language: LangGo, Content: "package main"}
	if IsFrontendJS(goCtx) {
		t.Errorf("IsFrontendJS for Go should be false")
	}
	if !IsServerSideCode(goCtx) {
		t.Errorf("IsServerSideCode for Go should be true")
	}

	// Pure browser JS: frontend APIs, no server patterns.
	frontend := &ScanContext{
		Language: LangJavaScript,
		Content:  "document.getElementById('x').innerHTML = data;\nwindow.addEventListener('load', f);",
	}
	if !IsFrontendJS(frontend) {
		t.Errorf("expected IsFrontendJS=true for pure browser JS")
	}
	if IsServerSideCode(frontend) {
		t.Errorf("expected IsServerSideCode=false for pure browser JS")
	}

	// Server JS: express import + req/res handlers → not frontend, is server.
	server := &ScanContext{
		Language: LangTypeScript,
		Content:  "import express from 'express';\napp.get('/x', (req, res) => res.json(req.query));",
	}
	if IsFrontendJS(server) {
		t.Errorf("expected IsFrontendJS=false for server JS")
	}
	if !IsServerSideCode(server) {
		t.Errorf("expected IsServerSideCode=true for server JS")
	}

	// Mixed (browser API AND server import) → IsFrontendJS false (server wins).
	mixed := &ScanContext{
		Language: LangJavaScript,
		Content:  "const fs = require('fs');\ndocument.getElementById('x');",
	}
	if IsFrontendJS(mixed) {
		t.Errorf("expected IsFrontendJS=false when server patterns also present")
	}
}

// --- ScanContext line helpers ----------------------------------------------

func TestScanContext_SplitLines(t *testing.T) {
	// On-demand split when Lines is nil.
	c := &ScanContext{Content: "a\nb\nc"}
	got := c.SplitLines()
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Errorf("SplitLines on-demand = %v", got)
	}
	// Reuses the populated Lines slice (identity, not a re-split).
	pre := []string{"x", "y"}
	c2 := &ScanContext{Content: "ignored\ncontent", Lines: pre}
	got2 := c2.SplitLines()
	if len(got2) != 2 || got2[0] != "x" {
		t.Errorf("SplitLines should reuse populated Lines, got %v", got2)
	}
}

func TestScanContext_LowerLines(t *testing.T) {
	// On-demand lowering when LinesLower is nil.
	c := &ScanContext{Content: "ABC\nDeF"}
	got := c.LowerLines()
	if len(got) != 2 || got[0] != "abc" || got[1] != "def" {
		t.Errorf("LowerLines on-demand = %v", got)
	}
	// Reuses populated LinesLower.
	pre := []string{"pre", "lowered"}
	c2 := &ScanContext{Content: "WHATEVER", LinesLower: pre}
	got2 := c2.LowerLines()
	if len(got2) != 2 || got2[0] != "pre" {
		t.Errorf("LowerLines should reuse populated LinesLower, got %v", got2)
	}
}

// --- Registry ---------------------------------------------------------------

// testRule is a minimal Rule implementation for registry tests.
type testRule struct {
	id    string
	langs []Language
}

func (r *testRule) ID() string                { return r.id }
func (r *testRule) Name() string              { return "test-" + r.id }
func (r *testRule) Description() string       { return "desc" }
func (r *testRule) DefaultSeverity() Severity { return Medium }
func (r *testRule) Languages() []Language     { return r.langs }
func (r *testRule) Scan(ctx *ScanContext) []Finding {
	return []Finding{{RuleID: r.id, FilePath: ctx.FilePath}}
}

func TestRegistry_RegisterAllForLanguage(t *testing.T) {
	before := len(All())

	goRule := &testRule{id: "TEST-REG-GO", langs: []Language{LangGo}}
	anyRule := &testRule{id: "TEST-REG-ANY", langs: []Language{LangAny}}
	Register(goRule)
	Register(anyRule)

	all := All()
	if len(all) != before+2 {
		t.Fatalf("All() len = %d, want %d", len(all), before+2)
	}

	// All() returns a copy: mutating it must not affect the registry.
	all[0] = nil
	if All()[0] == nil {
		t.Errorf("All() must return a defensive copy")
	}

	// ForLanguage(Go) includes both the Go-specific and the LangAny rule.
	goRules := ForLanguage(LangGo)
	if !containsRuleID(goRules, "TEST-REG-GO") || !containsRuleID(goRules, "TEST-REG-ANY") {
		t.Errorf("ForLanguage(Go) missing expected rules: %v", ruleIDs(goRules))
	}
	// ForLanguage(Python) gets the LangAny rule but NOT the Go-specific one.
	pyRules := ForLanguage(LangPython)
	if containsRuleID(pyRules, "TEST-REG-GO") {
		t.Errorf("ForLanguage(Python) must not include a Go-only rule")
	}
	if !containsRuleID(pyRules, "TEST-REG-ANY") {
		t.Errorf("ForLanguage(Python) must include the LangAny rule")
	}

	// The per-language cache is served on a second call (and must be consistent).
	if len(ForLanguage(LangGo)) != len(goRules) {
		t.Errorf("ForLanguage cache returned inconsistent length")
	}

	// Registering a new rule invalidates the cache so it becomes visible.
	Register(&testRule{id: "TEST-REG-GO2", langs: []Language{LangGo}})
	if !containsRuleID(ForLanguage(LangGo), "TEST-REG-GO2") {
		t.Errorf("Register did not invalidate ForLanguage cache")
	}
}

func containsRuleID(rs []Rule, id string) bool {
	for _, r := range rs {
		if r.ID() == id {
			return true
		}
	}
	return false
}

func ruleIDs(rs []Rule) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.ID()
	}
	return out
}

// --- RegexRule (the data-driven rule engine) --------------------------------

func newRegexRule(id string, langs []Language, pats ...string) *RegexRule {
	compiled := make([]*regexp.Regexp, len(pats))
	for i, p := range pats {
		compiled[i] = regexp.MustCompile(p)
	}
	return &RegexRule{
		RuleID:   id,
		RuleName: "name-" + id,
		Desc:     "desc",
		Sev:      High,
		Langs:    langs,
		Patterns: compiled,
		Title:    "title-" + id,
		FindDesc: "finding desc",
		Fix:      "the fix",
		CWE:      "CWE-79",
		OWASP:    "A03",
		Conf:     "medium",
		RuleTags: []string{"tag1"},
	}
}

func TestRegexRule_InterfaceMethods(t *testing.T) {
	r := newRegexRule("BATOU-X-001", []Language{LangGo, LangPython}, `foo`)
	if r.ID() != "BATOU-X-001" {
		t.Errorf("ID = %q", r.ID())
	}
	if r.Name() != "name-BATOU-X-001" {
		t.Errorf("Name = %q", r.Name())
	}
	if r.Description() != "desc" {
		t.Errorf("Description = %q", r.Description())
	}
	if r.DefaultSeverity() != High {
		t.Errorf("DefaultSeverity = %v", r.DefaultSeverity())
	}
	if got := r.Languages(); len(got) != 2 || got[0] != LangGo {
		t.Errorf("Languages = %v", got)
	}
}

func TestRegexRule_Scan_Match(t *testing.T) {
	r := newRegexRule("BATOU-X-002", []Language{LangGo}, `(?i)os\.system\s*\(`)
	ctx := &ScanContext{
		FilePath: "/app/handler.go",
		Content:  "package main\nfunc f() {\n    os.system(cmd)\n}\n",
		Language: LangGo,
	}
	got := r.Scan(ctx)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(got), got)
	}
	f := got[0]
	if f.RuleID != "BATOU-X-002" || f.Severity != High || f.LineNumber != 3 {
		t.Errorf("finding fields wrong: %+v", f)
	}
	if f.FilePath != "/app/handler.go" || f.CWEID != "CWE-79" || f.Title != "title-BATOU-X-002" {
		t.Errorf("finding metadata wrong: %+v", f)
	}
	if f.SeverityLabel != "HIGH" || f.Suggestion != "the fix" || f.Confidence != "medium" {
		t.Errorf("finding label/fix/conf wrong: %+v", f)
	}
	if len(f.Tags) != 1 || f.Tags[0] != "tag1" {
		t.Errorf("finding tags wrong: %+v", f.Tags)
	}
}

func TestRegexRule_Scan_FileLevelPrefilterSkip(t *testing.T) {
	// The required literal "os.system" is absent from the file → anyCandidate
	// returns false and Scan early-exits with no findings (gate, not regex).
	r := newRegexRule("BATOU-X-003", []Language{LangGo}, `(?i)os\.system\s*\(`)
	ctx := &ScanContext{
		FilePath: "/app/clean.go",
		Content:  "package main\nfunc f() { fmt.Println(\"hi\") }\n",
		Language: LangGo,
	}
	if got := r.Scan(ctx); got != nil {
		t.Errorf("expected nil findings on a file lacking the required literal, got %+v", got)
	}
}

func TestRegexRule_Scan_SkipsCommentLines(t *testing.T) {
	// A match that appears only inside a comment line is skipped (IsComment).
	r := newRegexRule("BATOU-X-004", []Language{LangGo}, `(?i)os\.system\s*\(`)
	ctx := &ScanContext{
		FilePath: "/app/c.go",
		// First occurrence is a comment; second is real code.
		Content:  "// os.system(evil) -- documented\n    os.system(real)\n",
		Language: LangGo,
	}
	got := r.Scan(ctx)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 finding (comment skipped), got %d: %+v", len(got), got)
	}
	if got[0].LineNumber != 2 {
		t.Errorf("expected finding on line 2 (the code line), got %d", got[0].LineNumber)
	}
}

func TestRegexRule_Scan_MultiPatternFirstWins(t *testing.T) {
	// Two patterns; a line matching both must emit only one finding (break).
	r := newRegexRule("BATOU-X-005", []Language{LangGo}, `(?i)exec\s*\(`, `(?i)system\s*\(`)
	ctx := &ScanContext{
		FilePath: "/app/m.go",
		Content:  "exec(system(x))\n",
		Language: LangGo,
	}
	got := r.Scan(ctx)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding for a line matching both patterns, got %d", len(got))
	}
}

func TestRegexRule_Scan_UsesPopulatedLowerLines(t *testing.T) {
	// Exercise the LinesLower fast path: scanner pre-populates Lines + LinesLower.
	r := newRegexRule("BATOU-X-006", []Language{LangGo}, `(?i)os\.system\s*\(`)
	lines := []string{"OS.SYSTEM(CMD)"}
	ctx := &ScanContext{
		FilePath:   "/app/u.go",
		Content:    "OS.SYSTEM(CMD)",
		Lines:      lines,
		LinesLower: []string{"os.system(cmd)"},
		Language:   LangGo,
	}
	got := r.Scan(ctx)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding via LinesLower path, got %d", len(got))
	}
}

// --- LineMightMatch (String()-keyed cached gate) ----------------------------

func TestLineMightMatch(t *testing.T) {
	re := regexp.MustCompile(`(?i)os\.system\s*\(`)
	lo := strings.ToLower("    os.system(cmd)")
	if !LineMightMatch(lo, re) {
		t.Errorf("LineMightMatch should pass a line containing the required literal")
	}
	// Second call hits the cache (same regex String()).
	if !LineMightMatch(lo, re) {
		t.Errorf("LineMightMatch (cached) should still pass")
	}
	if LineMightMatch("nothing here", re) {
		t.Errorf("LineMightMatch should skip a line lacking the required literal")
	}
	// An always-run pattern (no usable literal) is never skipped.
	reAny := regexp.MustCompile(`\w+`)
	if !LineMightMatch("", reAny) {
		t.Errorf("LineMightMatch must always pass for an always-run pattern")
	}
}

// --- Selected language-helper functions (clean, deterministic behavior) -----

func TestJavaExtractConcatVar(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{`String q = "SELECT * FROM t WHERE id=" + userId;`, "userId"},
		{`cmd = base + suffix`, "suffix"},  // VAR + VAR fallback, last non-keyword
		{`x = "lit" + new Thing()`, "new"}, // 'new' is a keyword → but reJavaConcatVar captures 'new'; verify keyword filter falls through
		{`no concatenation here`, ""},
	}
	for _, c := range cases {
		got := JavaExtractConcatVar(c.line)
		// For the 'new' case, JavaExtractConcatVar should skip the keyword and
		// find no other variable → "".
		if c.line == `x = "lit" + new Thing()` {
			if got != "" {
				t.Errorf("JavaExtractConcatVar(%q) = %q, want \"\" (keyword filtered)", c.line, got)
			}
			continue
		}
		if got != c.want {
			t.Errorf("JavaExtractConcatVar(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

func TestJavaExtractArgVar(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{`response.getWriter().println(userInput);`, "userInput"},
		{`session.setAttribute("key", tainted);`, "tainted"},
		{`new File(path);`, "path"},
		{`foo.bar("literal only");`, ""},
	}
	for _, c := range cases {
		if got := JavaExtractArgVar(c.line); got != c.want {
			t.Errorf("JavaExtractArgVar(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

func TestJavaGetPropertyDefault(t *testing.T) {
	if got := JavaGetPropertyDefault(`x = props.getProperty("algo", "AES")`); got != "AES" {
		t.Errorf("JavaGetPropertyDefault = %q, want AES", got)
	}
	if got := JavaGetPropertyDefault(`x = props.getProperty("algo")`); got != "" {
		t.Errorf("JavaGetPropertyDefault with no default = %q, want \"\"", got)
	}
}

func TestJavaHasSanitizerOnVar(t *testing.T) {
	lines := []string{
		`String clean = StringEscapeUtils.escapeHtml4(raw);`,
		`out.println(clean);`,
	}
	if !JavaHasSanitizerOnVar(lines, 1, "clean") {
		t.Errorf("expected sanitizer detected on 'clean'")
	}
	if JavaHasSanitizerOnVar(lines, 1, "raw") {
		t.Errorf("did not expect sanitizer on 'raw'")
	}
	if JavaHasSanitizerOnVar(lines, 1, "") {
		t.Errorf("empty varName must return false")
	}
}

func TestJavaLastAssignmentIsSafe_Guards(t *testing.T) {
	lines := []string{`x = "safe literal";`, `use(x);`}
	// Out-of-range / empty inputs return false (guard clauses).
	if JavaLastAssignmentIsSafe(lines, 1, "") {
		t.Errorf("empty varName must be false")
	}
	if JavaLastAssignmentIsSafe(lines, -1, "x") {
		t.Errorf("negative lineIdx must be false")
	}
	if JavaLastAssignmentIsSafe(lines, 99, "x") {
		t.Errorf("out-of-range lineIdx must be false")
	}
}

func TestPyHasURLValidation(t *testing.T) {
	lines := []string{
		`parsed = urlparse(user_url)`,
		`if parsed.netloc not in allowed: abort()`,
		`requests.get(user_url)`,
	}
	if !PyHasURLValidation(lines, 2) {
		t.Errorf("expected URL validation guard detected before sink")
	}
	// No guard within the window.
	noguard := []string{`requests.get(user_url)`}
	if PyHasURLValidation(noguard, 0) {
		t.Errorf("did not expect URL validation guard")
	}
}

func TestPyHasEvalGuard(t *testing.T) {
	lines := []string{
		`if not expr.startswith("allowed"):`,
		`    raise ValueError`,
		`eval(expr)`,
	}
	if !PyHasEvalGuard(lines, 2) {
		t.Errorf("expected eval guard detected")
	}
	noguard := []string{`eval(expr)`}
	if PyHasEvalGuard(noguard, 0) {
		t.Errorf("did not expect eval guard")
	}
}

func TestPyExtractSinkVar(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{`query = f"SELECT * FROM t WHERE id={user_id}"`, "user_id"},
		{`cmd = "ls {}".format(path)`, "path"},
		{`exec(payload)`, "payload"},
		{`x = "no variable interpolation"`, ""},
	}
	for _, c := range cases {
		if got := PyExtractSinkVar(c.line); got != c.want {
			t.Errorf("PyExtractSinkVar(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

func TestPySinkVarIsSafe_Guards(t *testing.T) {
	lines := []string{`query = f"id={user_id}"`}
	// Out-of-range index returns false.
	if PySinkVarIsSafe(lines, -1) {
		t.Errorf("negative index must be false")
	}
	if PySinkVarIsSafe(lines, 5) {
		t.Errorf("out-of-range index must be false")
	}
	// A line with no extractable sink var returns false.
	if PySinkVarIsSafe([]string{`x = 1`}, 0) {
		t.Errorf("line with no sink var must be false")
	}
}

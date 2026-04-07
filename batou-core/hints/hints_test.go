package hints_test

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-core/findings"
	"github.com/turenlabs/batou-core/hints"
	"github.com/turenlabs/batou-core/reporter"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/taint"
)

// ---------------------------------------------------------------------------
// Hints contain CWE references
// ---------------------------------------------------------------------------

func TestHintsContainCWEReferences(t *testing.T) {
	tests := []struct {
		name    string
		flow    taint.TaintFlow
		wantCWE string
	}{
		{
			name: "SQL injection flow includes CWE-89",
			flow: taint.TaintFlow{
				Source: taint.SourceDef{
					Category:    taint.SrcUserInput,
					MethodName:  "FormValue",
					Description: "HTTP form parameter",
				},
				Sink: taint.SinkDef{
					Category:      taint.SnkSQLQuery,
					MethodName:    "Query",
					Severity:      rules.Critical,
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Description:   "SQL query with tainted input",
				},
				SourceLine: 5,
				SinkLine:   10,
				FilePath:   "test.go",
				ScopeName:  "handler",
				Confidence: 1.0,
			},
			wantCWE: "CWE-89",
		},
		{
			name: "Command injection flow includes CWE-78",
			flow: taint.TaintFlow{
				Source: taint.SourceDef{
					Category:    taint.SrcUserInput,
					MethodName:  "FormValue",
					Description: "HTTP form parameter",
				},
				Sink: taint.SinkDef{
					Category:      taint.SnkCommand,
					MethodName:    "Command",
					Severity:      rules.Critical,
					CWEID:         "CWE-78",
					OWASPCategory: "A03:2021-Injection",
					Description:   "OS command execution",
				},
				SourceLine: 3,
				SinkLine:   7,
				FilePath:   "test.go",
				ScopeName:  "handler",
				Confidence: 1.0,
			},
			wantCWE: "CWE-78",
		},
		{
			name: "XSS flow includes CWE-79",
			flow: taint.TaintFlow{
				Source: taint.SourceDef{
					Category:    taint.SrcUserInput,
					MethodName:  "query",
					Description: "Express request query parameters",
				},
				Sink: taint.SinkDef{
					Category:      taint.SnkHTMLOutput,
					MethodName:    "send",
					Severity:      rules.High,
					CWEID:         "CWE-79",
					OWASPCategory: "A03:2021-Injection",
					Description:   "HTML response",
				},
				SourceLine: 2,
				SinkLine:   5,
				FilePath:   "test.js",
				ScopeName:  "handler",
				Confidence: 1.0,
			},
			wantCWE: "CWE-79",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &hints.HintContext{
				FilePath:   tt.flow.FilePath,
				Language:   rules.LangGo,
				TaintFlows: []taint.TaintFlow{tt.flow},
				Findings:   []rules.Finding{tt.flow.ToFinding()},
			}

			hintList := hints.GenerateHints(ctx)
			output := hints.FormatForClaude(ctx, hintList)

			if !strings.Contains(output, tt.wantCWE) {
				t.Errorf("expected hints output to contain %q, got:\n%s", tt.wantCWE, output)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Hints contain fix examples
// ---------------------------------------------------------------------------

func TestHintsContainFixExamples(t *testing.T) {
	tests := []struct {
		name     string
		lang     rules.Language
		sinkCat  taint.SinkCategory
		wantText string // substring expected in the fix example
	}{
		{
			name:     "Go SQL injection fix mentions parameterized queries",
			lang:     rules.LangGo,
			sinkCat:  taint.SnkSQLQuery,
			wantText: "parameterized",
		},
		{
			name:     "Python SQL injection fix mentions parameterized queries",
			lang:     rules.LangPython,
			sinkCat:  taint.SnkSQLQuery,
			wantText: "parameterized",
		},
		{
			name:     "JS SQL injection fix mentions parameterized queries",
			lang:     rules.LangJavaScript,
			sinkCat:  taint.SnkSQLQuery,
			wantText: "parameterized",
		},
		{
			name:     "Go command injection fix mentions explicit command",
			lang:     rules.LangGo,
			sinkCat:  taint.SnkCommand,
			wantText: "explicit command",
		},
		{
			name:     "Go XSS fix mentions EscapeString or textContent",
			lang:     rules.LangGo,
			sinkCat:  taint.SnkHTMLOutput,
			wantText: "EscapeString",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := taint.TaintFlow{
				Source: taint.SourceDef{
					Category:    taint.SrcUserInput,
					MethodName:  "FormValue",
					Description: "HTTP form parameter",
				},
				Sink: taint.SinkDef{
					Category:      tt.sinkCat,
					MethodName:    "sink",
					Severity:      rules.Critical,
					CWEID:         "CWE-89",
					OWASPCategory: "A03:2021-Injection",
					Description:   "dangerous sink",
				},
				SourceLine: 1,
				SinkLine:   5,
				FilePath:   "test.go",
				ScopeName:  "handler",
				Confidence: 1.0,
			}

			ctx := &hints.HintContext{
				FilePath:   "test.go",
				Language:   tt.lang,
				TaintFlows: []taint.TaintFlow{flow},
				Findings:   []rules.Finding{flow.ToFinding()},
			}

			hintList := hints.GenerateHints(ctx)
			output := hints.FormatForClaude(ctx, hintList)

			if !strings.Contains(output, tt.wantText) {
				t.Errorf("expected fix example to contain %q, got:\n%s", tt.wantText, output)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Clean code produces positive hint
// ---------------------------------------------------------------------------

func TestCleanCodeProducesPositiveHint(t *testing.T) {
	ctx := &hints.HintContext{
		FilePath:   "clean.go",
		Language:   rules.LangGo,
		TaintFlows: nil,
		Findings:   nil,
	}

	hintList := hints.GenerateHints(ctx)
	if len(hintList) == 0 {
		t.Fatal("expected at least a positive hint for clean code")
	}

	hasPositive := false
	for _, h := range hintList {
		if h.Category == "positive" {
			hasPositive = true
			break
		}
	}
	if !hasPositive {
		t.Error("expected positive hint category for clean code")
	}

	output := hints.FormatForClaude(ctx, hintList)
	if !strings.Contains(output, "No security issues detected") {
		t.Errorf("expected clean scan message, got:\n%s", output)
	}
}

// ---------------------------------------------------------------------------
// Hint priority ordering
// ---------------------------------------------------------------------------

func TestHintPriorityOrdering(t *testing.T) {
	criticalFlow := taint.TaintFlow{
		Source: taint.SourceDef{Category: taint.SrcUserInput, MethodName: "FormValue", Description: "input"},
		Sink:   taint.SinkDef{Category: taint.SnkSQLQuery, MethodName: "Query", Severity: rules.Critical, Description: "sql"},
		SourceLine: 1, SinkLine: 5, FilePath: "test.go", ScopeName: "h1", Confidence: 1.0,
	}
	mediumFlow := taint.TaintFlow{
		Source: taint.SourceDef{Category: taint.SrcUserInput, MethodName: "FormValue", Description: "input"},
		Sink:   taint.SinkDef{Category: taint.SnkLog, MethodName: "Printf", Severity: rules.Medium, Description: "log"},
		SourceLine: 1, SinkLine: 8, FilePath: "test.go", ScopeName: "h2", Confidence: 1.0,
	}

	ctx := &hints.HintContext{
		FilePath:   "test.go",
		Language:   rules.LangGo,
		TaintFlows: []taint.TaintFlow{mediumFlow, criticalFlow}, // intentionally reversed
		Findings: []rules.Finding{
			mediumFlow.ToFinding(),
			criticalFlow.ToFinding(),
		},
	}

	hintList := hints.GenerateHints(ctx)

	// The first non-positive hint should be the critical one.
	for _, h := range hintList {
		if h.Category == "positive" {
			continue
		}
		if h.Severity != rules.Critical {
			t.Errorf("expected first hint to be Critical, got %s", h.Severity)
		}
		break
	}
}

// ---------------------------------------------------------------------------
// FormatForClaude output structure
// ---------------------------------------------------------------------------

func TestFormatForClaudeStructure(t *testing.T) {
	flow := taint.TaintFlow{
		Source: taint.SourceDef{
			Category:    taint.SrcUserInput,
			MethodName:  "FormValue",
			Description: "HTTP form parameter",
		},
		Sink: taint.SinkDef{
			Category:      taint.SnkSQLQuery,
			MethodName:    "Query",
			Severity:      rules.Critical,
			CWEID:         "CWE-89",
			OWASPCategory: "A03:2021-Injection",
			Description:   "SQL query",
		},
		SourceLine: 2,
		SinkLine:   5,
		FilePath:   "test.go",
		ScopeName:  "handler",
		Confidence: 1.0,
	}

	ctx := &hints.HintContext{
		FilePath:   "test.go",
		Language:   rules.LangGo,
		TaintFlows: []taint.TaintFlow{flow},
		Findings:   []rules.Finding{flow.ToFinding()},
		ScanTimeMs: 42,
	}

	hintList := hints.GenerateHints(ctx)
	output := hints.FormatForClaude(ctx, hintList)

	// Verify structure (compact format).
	if !strings.Contains(output, "=== Batou [test.go]") {
		t.Error("expected Batou header with filepath")
	}
	if !strings.Contains(output, "go | 42ms") {
		t.Error("expected language and scan time in header")
	}
	if !strings.Contains(output, "=== End Batou ===") {
		t.Error("expected End Batou footer")
	}
	if !strings.Contains(output, "1. [") {
		t.Error("expected at least hint #1")
	}
	if !strings.Contains(output, "Fix:") {
		t.Error("expected Fix section")
	}
}

// ---------------------------------------------------------------------------
// Every sink category produces a non-empty fix example
// ---------------------------------------------------------------------------

func TestAllSinkCategoriesProduceFixExamples(t *testing.T) {
	sinkCategories := []struct {
		cat      taint.SinkCategory
		wantText string // a substring we expect in the output
	}{
		{taint.SnkSQLQuery, "parameterized"},
		{taint.SnkCommand, "command"},
		{taint.SnkHTMLOutput, "escap"},         // "escape" or "Escape" or "auto-escapes"
		{taint.SnkFileWrite, "path"},            // "path" appears in all path fix examples
		{taint.SnkRedirect, "allowlist"},        // all redirect fixes mention allowlist
		{taint.SnkEval, "eval"},                 // all eval fixes mention eval
		{taint.SnkURLFetch, "allowlist"},        // SSRF fixes mention allowlist
		{taint.SnkDeserialize, "JSON"},          // deserialization fixes mention JSON
		{taint.SnkLDAP, "LDAP"},                 // LDAP fixes mention LDAP
		{taint.SnkXPath, "XPath"},               // XPath fixes mention XPath
		{taint.SnkHeader, "header"},             // header fixes mention header
		{taint.SnkTemplate, "template"},         // template fixes mention template
		{taint.SnkLog, "log"},                   // log fixes mention log
		{taint.SnkCrypto, "key"},                // crypto fixes mention key/keys
	}

	for _, tt := range sinkCategories {
		t.Run(string(tt.cat), func(t *testing.T) {
			flow := taint.TaintFlow{
				Source: taint.SourceDef{
					Category:    taint.SrcUserInput,
					MethodName:  "input",
					Description: "user input",
				},
				Sink: taint.SinkDef{
					Category:    tt.cat,
					MethodName:  "sink",
					Severity:    rules.High,
					Description: "dangerous " + string(tt.cat),
				},
				SourceLine: 1,
				SinkLine:   5,
				FilePath:   "test.go",
				ScopeName:  "handler",
				Confidence: 1.0,
			}

			ctx := &hints.HintContext{
				FilePath:   "test.go",
				Language:   rules.LangGo,
				TaintFlows: []taint.TaintFlow{flow},
			}

			hintList := hints.GenerateHints(ctx)
			output := hints.FormatForClaude(ctx, hintList)

			if !strings.Contains(strings.ToLower(output), strings.ToLower(tt.wantText)) {
				t.Errorf("sink category %s: expected fix example to contain %q, got:\n%s",
					tt.cat, tt.wantText, output)
			}
			// Every hint should have a Fix section
			if !strings.Contains(output, "Fix:") {
				t.Errorf("sink category %s: expected Fix: section in output", tt.cat)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Language-specific fix suggestions for key categories
// ---------------------------------------------------------------------------

func TestLanguageSpecificFixSuggestions(t *testing.T) {
	tests := []struct {
		name     string
		lang     rules.Language
		sinkCat  taint.SinkCategory
		wantText string
	}{
		// SQL injection - language-specific syntax
		{"Go SQL fix uses ?", rules.LangGo, taint.SnkSQLQuery, "db.Query"},
		{"Python SQL fix uses %s", rules.LangPython, taint.SnkSQLQuery, "cursor.execute"},
		{"Java SQL fix uses PreparedStatement", rules.LangJava, taint.SnkSQLQuery, "PreparedStatement"},
		{"JS SQL fix uses $1 or ?", rules.LangJavaScript, taint.SnkSQLQuery, "parameterized"},
		{"PHP SQL fix uses prepare", rules.LangPHP, taint.SnkSQLQuery, "prepare"},
		{"Ruby SQL fix uses params", rules.LangRuby, taint.SnkSQLQuery, "params"},

		// Command injection - language-specific
		{"Go cmd fix uses exec.Command", rules.LangGo, taint.SnkCommand, "exec.Command"},
		{"Python cmd fix uses subprocess", rules.LangPython, taint.SnkCommand, "subprocess"},
		{"JS cmd fix uses execFile", rules.LangJavaScript, taint.SnkCommand, "execFile"},
		{"Java cmd fix uses ProcessBuilder", rules.LangJava, taint.SnkCommand, "ProcessBuilder"},
		{"PHP cmd fix uses escapeshellarg", rules.LangPHP, taint.SnkCommand, "escapeshellarg"},
		{"Ruby cmd fix uses array form", rules.LangRuby, taint.SnkCommand, "system"},

		// XSS - language-specific
		{"Go XSS fix uses EscapeString", rules.LangGo, taint.SnkHTMLOutput, "EscapeString"},
		{"JS XSS fix uses textContent", rules.LangJavaScript, taint.SnkHTMLOutput, "textContent"},
		{"Python XSS fix uses markupsafe", rules.LangPython, taint.SnkHTMLOutput, "escape"},
		{"Java XSS fix uses escapeHtml", rules.LangJava, taint.SnkHTMLOutput, "escapeHtml"},
		{"PHP XSS fix uses htmlspecialchars", rules.LangPHP, taint.SnkHTMLOutput, "htmlspecialchars"},
		{"Ruby XSS fix uses html_escape", rules.LangRuby, taint.SnkHTMLOutput, "html_escape"},

		// Path traversal - language-specific
		{"Go path fix uses filepath.Clean", rules.LangGo, taint.SnkFileWrite, "filepath.Clean"},
		{"Python path fix uses realpath", rules.LangPython, taint.SnkFileWrite, "realpath"},
		{"JS path fix uses path.resolve", rules.LangJavaScript, taint.SnkFileWrite, "path.resolve"},
		{"Java path fix uses normalize", rules.LangJava, taint.SnkFileWrite, "normalize"},
		{"PHP path fix uses realpath", rules.LangPHP, taint.SnkFileWrite, "realpath"},
		{"Ruby path fix uses realpath", rules.LangRuby, taint.SnkFileWrite, "realpath"},

		// Redirect - language-specific
		{"Go redirect fix uses url.Parse", rules.LangGo, taint.SnkRedirect, "url.Parse"},
		{"Python redirect fix uses urlparse", rules.LangPython, taint.SnkRedirect, "urlparse"},
		{"Java redirect fix uses URI.create", rules.LangJava, taint.SnkRedirect, "URI.create"},

		// Eval - language-specific
		{"Python eval fix uses ast.literal_eval", rules.LangPython, taint.SnkEval, "literal_eval"},
		{"JS eval fix uses JSON.parse", rules.LangJavaScript, taint.SnkEval, "JSON.parse"},
		{"PHP eval fix mentions json_decode", rules.LangPHP, taint.SnkEval, "json_decode"},

		// SSRF - language-specific
		{"Go SSRF fix uses url.Parse", rules.LangGo, taint.SnkURLFetch, "url.Parse"},
		{"Python SSRF fix uses urlparse", rules.LangPython, taint.SnkURLFetch, "urlparse"},
		{"Java SSRF fix uses URI.create", rules.LangJava, taint.SnkURLFetch, "URI.create"},

		// Deserialization - language-specific
		{"Python deser fix uses json.loads", rules.LangPython, taint.SnkDeserialize, "json.loads"},
		{"Java deser fix uses ObjectInputFilter", rules.LangJava, taint.SnkDeserialize, "ObjectInputFilter"},
		{"PHP deser fix uses json_decode", rules.LangPHP, taint.SnkDeserialize, "json_decode"},
		{"Ruby deser fix uses JSON.parse", rules.LangRuby, taint.SnkDeserialize, "JSON.parse"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := taint.TaintFlow{
				Source: taint.SourceDef{
					Category:    taint.SrcUserInput,
					MethodName:  "input",
					Description: "user input",
				},
				Sink: taint.SinkDef{
					Category:    tt.sinkCat,
					MethodName:  "sink",
					Severity:    rules.Critical,
					Description: "dangerous sink",
				},
				SourceLine: 1,
				SinkLine:   5,
				FilePath:   "test.go",
				ScopeName:  "handler",
				Confidence: 1.0,
			}

			ctx := &hints.HintContext{
				FilePath:   "test.go",
				Language:   tt.lang,
				TaintFlows: []taint.TaintFlow{flow},
			}

			hintList := hints.GenerateHints(ctx)
			output := hints.FormatForClaude(ctx, hintList)

			if !strings.Contains(output, tt.wantText) {
				t.Errorf("expected output to contain %q, got:\n%s", tt.wantText, output)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Block messages are clear and actionable
// ---------------------------------------------------------------------------

func TestBlockMessageIsActionable(t *testing.T) {
	result := &reporter.ScanResult{
		FilePath: "/app/handler.go",
		Language: rules.LangGo,
		Findings: []rules.Finding{
			{
				RuleID:          "BATOU-INJ-001",
				Title:           "SQL Injection",
				Severity:        rules.Critical,
				FilePath:        "/app/handler.go",
				LineNumber:      42,
				MatchedText:     "db.Query(\"SELECT * FROM users WHERE id = \" + id)",
				Description:     "SQL query built with string concatenation",
				Suggestion:      "Use parameterized queries: db.Query(\"SELECT * FROM users WHERE id = ?\", id)",
				CWEID:           "CWE-89",
				OWASPCategory:   "A03:2021-Injection",
				ConfidenceScore: 0.8,
				RiskScore:       0.8,
			},
		},
	}

	msg := reporter.FormatBlockMessage(result)

	// Must contain the key elements for Claude to fix the issue
	checks := []struct {
		label string
		want  string
	}{
		{"severity", "CRITICAL"},
		{"rule ID", "BATOU-INJ-001"},
		{"location", "/app/handler.go:42"},
		{"vulnerable code snippet", "db.Query"},
		{"fix suggestion", "parameterized"},
		{"CWE reference", "CWE-89"},
		{"OWASP reference", "A03:2021-Injection"},
		{"action directive", "ACTION"},
	}

	for _, c := range checks {
		if !strings.Contains(msg, c.want) {
			t.Errorf("block message missing %s (%q), got:\n%s", c.label, c.want, msg)
		}
	}
}

// ---------------------------------------------------------------------------
// Impact descriptions cover all major categories
// ---------------------------------------------------------------------------

func TestImpactDescriptionCoverage(t *testing.T) {
	// Generate hints for different sink categories and verify output
	// contains category-relevant keywords (in explanation, fix, or refs).
	categories := []struct {
		sinkCat  taint.SinkCategory
		wantWord string // a word that should appear somewhere in the output
	}{
		{taint.SnkSQLQuery, "query"},
		{taint.SnkCommand, "command"},
		{taint.SnkHTMLOutput, "html"},
		{taint.SnkFileWrite, "file"},
		{taint.SnkEval, "code"},
		{taint.SnkRedirect, "redirect"},
		{taint.SnkURLFetch, "url"},
		{taint.SnkDeserialize, "deserializ"},
		{taint.SnkLog, "log"},
	}

	for _, tt := range categories {
		t.Run(string(tt.sinkCat), func(t *testing.T) {
			flow := taint.TaintFlow{
				Source: taint.SourceDef{
					Category:    taint.SrcUserInput,
					MethodName:  "input",
					Description: "user input",
				},
				Sink: taint.SinkDef{
					Category:    tt.sinkCat,
					MethodName:  "sink",
					Severity:    rules.High,
					Description: "dangerous sink",
				},
				SourceLine: 1,
				SinkLine:   5,
				FilePath:   "test.go",
				ScopeName:  "handler",
				Confidence: 1.0,
			}

			ctx := &hints.HintContext{
				FilePath:   "test.go",
				Language:   rules.LangGo,
				TaintFlows: []taint.TaintFlow{flow},
			}

			hintList := hints.GenerateHints(ctx)
			output := hints.FormatForClaude(ctx, hintList)

			if !strings.Contains(strings.ToLower(output), strings.ToLower(tt.wantWord)) {
				t.Errorf("sink %s: expected output to mention %q, got:\n%s",
					tt.sinkCat, tt.wantWord, output)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Architectural hints fire when patterns repeat
// ---------------------------------------------------------------------------

func TestArchitecturalHintsOnRepeatedPatterns(t *testing.T) {
	// Create 4 findings with the same injection category
	var findings []rules.Finding
	for i := 0; i < 4; i++ {
		findings = append(findings, rules.Finding{
			RuleID:          "BATOU-INJ-001",
			Title:           "SQL Injection",
			Severity:        rules.Critical,
			LineNumber:      i + 1,
			ConfidenceScore: 0.8,
			RiskScore:       0.8,
			Tags:            []string{"taint-analysis"},
		})
	}

	ctx := &hints.HintContext{
		FilePath: "test.go",
		Language: rules.LangGo,
		Findings: findings,
	}

	hintList := hints.GenerateHints(ctx)
	output := hints.FormatForClaude(ctx, hintList)

	if !strings.Contains(output, "architectural") || !strings.Contains(output, "Recurring pattern") {
		t.Errorf("expected architectural hint for repeated injection pattern, got:\n%s", output)
	}
	if !strings.Contains(output, "ORM") || !strings.Contains(output, "query builder") {
		t.Errorf("expected injection-specific architectural advice, got:\n%s", output)
	}
}

// ---------------------------------------------------------------------------
// Default/fallback language still produces useful hints
// ---------------------------------------------------------------------------

func TestDefaultLanguageFallbackProducesHints(t *testing.T) {
	// Use a language that doesn't have specific fix examples (e.g., LangC)
	sinkCategories := []taint.SinkCategory{
		taint.SnkSQLQuery, taint.SnkCommand, taint.SnkHTMLOutput,
		taint.SnkFileWrite, taint.SnkRedirect, taint.SnkEval,
		taint.SnkURLFetch, taint.SnkDeserialize,
	}

	for _, cat := range sinkCategories {
		t.Run(string(cat), func(t *testing.T) {
			flow := taint.TaintFlow{
				Source: taint.SourceDef{
					Category:    taint.SrcUserInput,
					MethodName:  "input",
					Description: "user input",
				},
				Sink: taint.SinkDef{
					Category:    cat,
					MethodName:  "sink",
					Severity:    rules.High,
					Description: "dangerous sink",
				},
				SourceLine: 1,
				SinkLine:   5,
				FilePath:   "test.c",
				ScopeName:  "handler",
				Confidence: 1.0,
			}

			ctx := &hints.HintContext{
				FilePath:   "test.c",
				Language:   rules.LangC,
				TaintFlows: []taint.TaintFlow{flow},
			}

			hintList := hints.GenerateHints(ctx)
			output := hints.FormatForClaude(ctx, hintList)

			// Even for unsupported languages, there must be a fix example
			if !strings.Contains(output, "Fix:") {
				t.Errorf("sink %s with LangC: expected Fix section, got:\n%s", cat, output)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tier-based filtering: regex-only findings are omitted from hints
// ---------------------------------------------------------------------------

func TestRegexOnlyFindingsFiltered(t *testing.T) {
	ctx := &hints.HintContext{
		FilePath: "/app/handler.go",
		Language: rules.LangGo,
		Findings: []rules.Finding{
			{RuleID: "BATOU-INJ-001", Severity: rules.High, ConfidenceScore: 0.4, Title: "SQL Injection", Description: "bad", LineNumber: 10},
			{RuleID: "BATOU-HDR-002", Severity: rules.Medium, ConfidenceScore: 0.4, Title: "Missing header", Description: "bad", LineNumber: 20},
		},
		ScanTimeMs: 10,
	}

	hintList := hints.GenerateHints(ctx)
	output := hints.FormatForClaude(ctx, hintList)

	// Should say "clean" since all findings are regex-only
	if !strings.Contains(output, "Code looks clean") {
		t.Errorf("expected clean code message when only regex findings, got:\n%s", output)
	}
	// Should show the regex summary count
	if !strings.Contains(output, "2 low-fidelity regex patterns omitted") {
		t.Errorf("expected regex summary line, got:\n%s", output)
	}
	// Should NOT contain individual hint blocks
	if strings.Contains(output, "Hint 1") {
		t.Errorf("regex-only findings should not produce individual hints, got:\n%s", output)
	}
}

func TestASTAndTaintFindingsSurvive(t *testing.T) {
	ctx := &hints.HintContext{
		FilePath: "/app/handler.go",
		Language: rules.LangGo,
		Findings: []rules.Finding{
			// Regex-only — should be filtered
			{RuleID: "BATOU-INJ-001", Severity: rules.High, ConfidenceScore: 0.4, Title: "SQL Injection", Description: "bad", LineNumber: 10},
			// AST — should survive
			{RuleID: "BATOU-AST-008", Severity: rules.Medium, ConfidenceScore: 0.7, Title: "Goroutine no context", Description: "bad", LineNumber: 20},
			// Taint — should survive
			{RuleID: "BATOU-TAINT-sqli", Severity: rules.Critical, ConfidenceScore: 0.85, Title: "Taint flow", Description: "bad", Tags: []string{"taint-analysis"}, LineNumber: 30},
			// Interprocedural — should survive
			{RuleID: "BATOU-INTERPROC-XSS", Severity: rules.High, ConfidenceScore: 0.8, Title: "Interproc", Description: "bad", Tags: []string{"interprocedural", "taint-analysis"}, LineNumber: 40},
		},
		ScanTimeMs: 10,
	}

	hintList := hints.GenerateHints(ctx)
	output := hints.FormatForClaude(ctx, hintList)

	// Should have individual hints for AST, taint, interproc
	if !strings.Contains(output, "BATOU-AST-008") {
		t.Error("expected AST finding in output")
	}
	if !strings.Contains(output, "BATOU-TAINT-sqli") {
		t.Error("expected taint finding in output")
	}
	if !strings.Contains(output, "BATOU-INTERPROC-XSS") {
		t.Error("expected interproc finding in output")
	}
	// Regex finding should NOT appear as individual hint
	if strings.Contains(output, "BATOU-INJ-001") {
		t.Error("regex-only finding should not appear in output")
	}
	// Summary should mention 1 regex pattern omitted
	if !strings.Contains(output, "1 low-fidelity regex patterns omitted") {
		t.Errorf("expected regex summary, got:\n%s", output)
	}
}

func TestBlockingRegexFindingSurvives(t *testing.T) {
	ctx := &hints.HintContext{
		FilePath: "/app/handler.go",
		Language: rules.LangGo,
		Findings: []rules.Finding{
			// Regex-only but blocking (Critical + high confidence)
			{RuleID: "BATOU-INJ-001", Severity: rules.Critical, ConfidenceScore: 0.9, RiskScore: 0.9, Title: "SQL Injection", Description: "bad", LineNumber: 10},
			// Regex-only non-blocking
			{RuleID: "BATOU-HDR-002", Severity: rules.Medium, ConfidenceScore: 0.4, RiskScore: 0.2, Title: "Missing header", Description: "bad", LineNumber: 20},
		},
		ScanTimeMs: 10,
	}

	hintList := hints.GenerateHints(ctx)
	output := hints.FormatForClaude(ctx, hintList)

	// Blocking finding should show
	if !strings.Contains(output, "BATOU-INJ-001") {
		t.Error("blocking regex finding should survive tier filter")
	}
	// Non-blocking regex should be in summary
	if !strings.Contains(output, "1 low-fidelity regex patterns omitted") {
		t.Errorf("expected 1 regex pattern in summary, got:\n%s", output)
	}
}

// ---------------------------------------------------------------------------
// Finding lifecycle tags (NEW / seen Nx / fixed)
// ---------------------------------------------------------------------------

func TestInjectLifecycle_NewTag(t *testing.T) {
	f := rules.Finding{
		RuleID:      "BATOU-INJ-001",
		FilePath:    "/app/handler.go",
		LineNumber:  10,
		Title:       "SQL injection",
		Severity:    rules.Critical,
		MatchedText: "exec(cmd)",
	}

	input := "1. [CRIT 95%] BATOU-INJ-001\n   SQL injection\n=== End Batou ===\n"
	deltas := &findings.Deltas{
		New: []rules.Finding{f},
	}

	output := hints.InjectLifecycle(input, deltas, []rules.Finding{f})

	if !strings.Contains(output, "BATOU-INJ-001 (NEW)") {
		t.Errorf("expected (NEW) tag, got:\n%s", output)
	}
}

func TestInjectLifecycle_RecurringTag(t *testing.T) {
	// Use the store to build proper deltas with recurring counts
	dir := t.TempDir()
	store, err := findings.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	f := rules.Finding{
		RuleID:      "BATOU-INJ-001",
		FilePath:    "/app/handler.go",
		LineNumber:  10,
		Title:       "SQL injection",
		Severity:    rules.Critical,
		MatchedText: "exec(cmd)",
	}

	// First scan
	store.ComputeDeltas("/app/handler.go", []rules.Finding{f})
	// Second scan
	store.ComputeDeltas("/app/handler.go", []rules.Finding{f})
	// Third scan — should show "seen 3x"
	deltas := store.ComputeDeltas("/app/handler.go", []rules.Finding{f})

	input := "1. [CRIT 95%] BATOU-INJ-001\n   SQL injection\n=== End Batou ===\n"
	output := hints.InjectLifecycle(input, deltas, []rules.Finding{f})

	if !strings.Contains(output, "seen 3x") {
		t.Errorf("expected (seen 3x) tag, got:\n%s", output)
	}
}

func TestInjectLifecycle_FixedFooter(t *testing.T) {
	dir := t.TempDir()
	store, err := findings.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	f1 := rules.Finding{
		RuleID:      "BATOU-INJ-001",
		FilePath:    "/app/handler.go",
		LineNumber:  10,
		Title:       "SQL injection",
		Severity:    rules.Critical,
		MatchedText: "exec(cmd)",
	}
	f2 := rules.Finding{
		RuleID:      "BATOU-XSS-001",
		FilePath:    "/app/handler.go",
		LineNumber:  20,
		Title:       "XSS",
		Severity:    rules.High,
		MatchedText: "fmt.Fprintf(w, name)",
	}

	// First scan — both findings
	store.ComputeDeltas("/app/handler.go", []rules.Finding{f1, f2})

	// Second scan — f2 removed (fixed)
	deltas := store.ComputeDeltas("/app/handler.go", []rules.Finding{f1})

	input := "1. [CRIT 95%] BATOU-INJ-001\n   SQL injection\n=== End Batou ===\n"
	output := hints.InjectLifecycle(input, deltas, []rules.Finding{f1})

	if !strings.Contains(output, "1 finding fixed since last scan") {
		t.Errorf("expected fixed footer, got:\n%s", output)
	}
}

func TestInjectLifecycle_NilDeltas(t *testing.T) {
	input := "1. [CRIT 95%] BATOU-INJ-001\n   SQL injection\n=== End Batou ===\n"
	output := hints.InjectLifecycle(input, nil, nil)

	if output != input {
		t.Errorf("nil deltas should return input unchanged, got:\n%s", output)
	}
}

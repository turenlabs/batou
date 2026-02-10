package hints_test

import (
	"strings"
	"testing"

	"github.com/turen/gtss/internal/hints"
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
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

	// Verify structure.
	if !strings.Contains(output, "=== GTSS Security Copilot") {
		t.Error("expected GTSS Security Copilot header")
	}
	if !strings.Contains(output, "Language: go") {
		t.Error("expected language in header")
	}
	if !strings.Contains(output, "=== End GTSS ===") {
		t.Error("expected End GTSS footer")
	}
	if !strings.Contains(output, "Hint 1") {
		t.Error("expected at least Hint 1")
	}
	if !strings.Contains(output, "Why:") {
		t.Error("expected 'Why:' explanation section")
	}
}

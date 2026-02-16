package taintrule

import (
	"time"

	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
	"github.com/turenio/gtss/internal/taint/astflow"
	"github.com/turenio/gtss/internal/taint/tsflow"
)

// TaintRule implements rules.Rule using the taint analysis engine.
// It runs source-to-sink dataflow analysis on the scanned code.
type TaintRule struct{}

func init() {
	rules.Register(&TaintRule{})
}

func (t *TaintRule) ID() string              { return "GTSS-TAINT" }
func (t *TaintRule) Name() string            { return "Taint Analysis" }
func (t *TaintRule) Description() string     { return "Source-to-sink dataflow taint tracking" }
func (t *TaintRule) DefaultSeverity() rules.Severity { return rules.Critical }
func (t *TaintRule) Languages() []rules.Language {
	// Return all languages that have catalogs registered
	return []rules.Language{
		rules.LangGo, rules.LangPython, rules.LangJavaScript, rules.LangTypeScript,
		rules.LangJava, rules.LangPHP, rules.LangRuby,
		rules.LangC, rules.LangCPP,
		rules.LangKotlin, rules.LangSwift, rules.LangRust, rules.LangCSharp,
		rules.LangPerl, rules.LangLua, rules.LangGroovy,
	}
}

func (t *TaintRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	start := time.Now()

	// Route to the best taint engine for the language, matching the
	// logic in scanner.go Phase 3.
	var flows []taint.TaintFlow
	if ctx.Language == rules.LangGo {
		flows = astflow.AnalyzeGo(ctx.Content, ctx.FilePath)
	} else if tsflow.Supports(ctx.Language) {
		flows = tsflow.Analyze(ctx.Content, ctx.FilePath, ctx.Language)
	} else {
		flows = taint.Analyze(ctx.Content, ctx.FilePath, ctx.Language)
	}

	// Cache flows on the ScanContext so scanner.go Phase 3 can reuse
	// them for hint generation without re-running taint analysis.
	ctx.TaintFlows = flows

	if len(flows) == 0 {
		return nil
	}

	// Convert flows to findings
	findings := make([]rules.Finding, 0, len(flows))
	for i := range flows {
		finding := flows[i].ToFinding()
		finding.Language = ctx.Language
		finding.FilePath = ctx.FilePath
		findings = append(findings, finding)
	}

	// Also add the formatted taint report as context in the last finding
	elapsed := time.Since(start).Milliseconds()
	report := taint.FormatFlowsReport(flows, ctx.FilePath, ctx.Language, elapsed)
	if len(findings) > 0 && report != "" {
		// Append the visual flow report to the last finding's description
		findings[len(findings)-1].Description += "\n\n" + report
	}

	return findings
}

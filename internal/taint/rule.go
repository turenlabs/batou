package taint

import (
	"time"

	"github.com/turenio/gtss/internal/rules"
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
	}
}

func (t *TaintRule) Scan(ctx *rules.ScanContext) []rules.Finding {
	start := time.Now()

	// Run taint analysis
	flows := Analyze(ctx.Content, ctx.FilePath, ctx.Language)

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
	report := FormatFlowsReport(flows, ctx.FilePath, ctx.Language, elapsed)
	if len(findings) > 0 && report != "" {
		// Append the visual flow report to the last finding's description
		findings[len(findings)-1].Description += "\n\n" + report
	}

	return findings
}

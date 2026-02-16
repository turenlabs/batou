package taintrule

import (
	"time"

	batouast "github.com/turenlabs/batou/internal/ast"
	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"
	"github.com/turenlabs/batou/internal/taint/astflow"
	"github.com/turenlabs/batou/internal/taint/tsflow"
)

// TaintRule implements rules.Rule using the taint analysis engine.
// It runs source-to-sink dataflow analysis on the scanned code.
type TaintRule struct{}

func init() {
	rules.Register(&TaintRule{})
}

func (t *TaintRule) ID() string              { return "BATOU-TAINT" }
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
	// logic in scanner.go Phase 3.  Reuse pre-parsed trees from Layer 2
	// when available to avoid redundant parsing.
	var flows []taint.TaintFlow
	if ctx.Language == rules.LangGo {
		// Reuse cached go/ast parse, or parse once and cache for the
		// call graph builder (Layer 4) to share.
		var goParsed *astflow.GoParseResult
		if cached, ok := ctx.GoASTFile.(*astflow.GoParseResult); ok {
			goParsed = cached
		} else {
			goParsed = astflow.ParseGo(ctx.Content, ctx.FilePath)
			if goParsed != nil {
				ctx.GoASTFile = goParsed
			}
		}
		flows = astflow.AnalyzeGoWithAST(ctx.Content, ctx.FilePath, goParsed)
	} else if tsflow.Supports(ctx.Language) {
		// Reuse tree-sitter tree from Layer 2 (stored in ctx.Tree).
		tree := batouast.TreeFromContext(ctx)
		flows = tsflow.AnalyzeWithTree(ctx.Content, ctx.FilePath, ctx.Language, tree)
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

package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/turenio/gtss/internal/analyzer"
	"github.com/turenio/gtss/internal/ast"
	"github.com/turenio/gtss/internal/fpfilter"
	"github.com/turenio/gtss/internal/graph"
	"github.com/turenio/gtss/internal/hints"
	"github.com/turenio/gtss/internal/hook"
	"github.com/turenio/gtss/internal/reporter"
	"github.com/turenio/gtss/internal/rules"
	"github.com/turenio/gtss/internal/taint"
	"github.com/turenio/gtss/internal/taint/astflow"
	"github.com/turenio/gtss/internal/taint/tsflow"
)

// scanTimeout is the maximum time a scan may take before we return partial results.
const scanTimeout = 10 * time.Second

// Scan performs a complete security scan including:
// - Regex-based rule scanning
// - Taint analysis (via registered TaintRule)
// - Call graph update and interprocedural analysis
// - Smart hints generation
func Scan(input *hook.Input) *reporter.ScanResult {
	start := time.Now()

	filePath := input.ResolvePath()
	lang := analyzer.DetectLanguage(filePath)

	result := &reporter.ScanResult{
		FilePath: filePath,
		Language: lang,
		Event:    input.HookEventName,
	}

	if !analyzer.IsScannable(filePath) {
		result.ScanTimeMs = time.Since(start).Milliseconds()
		return result
	}

	content := resolveContent(input)
	if content == "" {
		result.ScanTimeMs = time.Since(start).Milliseconds()
		return result
	}

	// Normalize CRLF line endings to LF so that regex rules, taint
	// analysis, and line splitting all behave consistently regardless
	// of the line ending style used in the source file.
	content = strings.ReplaceAll(content, "\r\n", "\n")

	// Skip generated / vendored files — they are not authored by the user
	// and produce noise.
	if fpfilter.IsGeneratedFile(filePath, content) || fpfilter.IsVendoredLibrary(filePath) {
		result.ScanTimeMs = time.Since(start).Milliseconds()
		return result
	}

	// Run the scan with a context-based timeout to prevent hanging on
	// malicious/huge input. The goroutine writes to its own coreResult so
	// that on timeout we never read a concurrently-mutated struct (no data
	// race). The context is threaded into scanCore so the goroutine can
	// exit early on cancellation instead of leaking.
	ctx, cancel := context.WithTimeout(context.Background(), scanTimeout)
	defer cancel()

	coreResult := &reporter.ScanResult{
		FilePath: filePath,
		Language: lang,
		Event:    input.HookEventName,
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanCore(ctx, input, content, filePath, lang, start, coreResult)
	}()

	select {
	case <-done:
		return coreResult
	case <-ctx.Done():
		result.ScanTimeMs = time.Since(start).Milliseconds()
		result.Findings = append(result.Findings, rules.Finding{
			RuleID:        "GTSS-TIMEOUT",
			Severity:      rules.Medium,
			SeverityLabel: rules.Medium.String(),
			Title:         "Scan timed out",
			Description:   fmt.Sprintf("Security scan exceeded %s timeout. Partial results may be available. This can happen with very large files.", scanTimeout),
			FilePath:      filePath,
			Confidence:    "low",
			Tags:          []string{"timeout", "performance"},
		})
		return result
	}
}

// scanCore performs the actual scan work. It is run in a goroutine with a
// context-based timeout. The context is checked between phases so the
// goroutine can exit early on cancellation instead of leaking.
func scanCore(ctx context.Context, input *hook.Input, content, filePath string, lang rules.Language, start time.Time, result *reporter.ScanResult) {
	// Pre-process content to join continuation lines for regex matching.
	// Keep the original content for AST parsing and taint analysis (which
	// need accurate line numbers).
	preprocessed := JoinContinuationLines(content, lang)

	// Build scan context — use preprocessed content for regex rules.
	sctx := &rules.ScanContext{
		FilePath: filePath,
		Content:  preprocessed,
		Language: lang,
		IsNew:    input.IsWriteOperation(),
	}
	if input.IsEditOperation() {
		sctx.OldText = input.ToolInput.OldString
		sctx.NewText = input.ToolInput.NewString
	}

	// Parse AST using original content (needs accurate line positions).
	var tree *ast.Tree
	if ast.SupportsLanguage(lang) {
		tree = ast.Parse([]byte(content), lang)
		sctx.Tree = tree
	}

	// Phase 1: Run all registered rules concurrently (regex + taint)
	applicable := rules.ForLanguage(lang)
	result.RulesRun = len(applicable)

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		findings []rules.Finding
	)

	for _, r := range applicable {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(rule rules.Rule) {
			defer wg.Done()
			defer func() {
				if rec := recover(); rec != nil {
					// A rule panicked — don't crash the whole scan.
					mu.Lock()
					findings = append(findings, rules.Finding{
						RuleID:      "GTSS-PANIC",
						Severity:    rules.Medium,
						Title:       fmt.Sprintf("Rule %s panicked: %v", rule.ID(), rec),
						Description: "A scan rule panicked during analysis. This finding is informational and indicates a bug in the rule implementation.",
						FilePath:    filePath,
						Confidence:  "low",
						Tags:        []string{"internal", "panic"},
					})
					mu.Unlock()
				}
			}()
			founds := rule.Scan(sctx)
			if len(founds) > 0 {
				mu.Lock()
				findings = append(findings, founds...)
				mu.Unlock()
			}
		}(r)
	}
	wg.Wait()

	// Exit early if the context was cancelled (timeout).
	if ctx.Err() != nil {
		result.Findings = findings
		result.ScanTimeMs = time.Since(start).Milliseconds()
		return
	}

	// Phase 2: Call graph update and interprocedural analysis
	var callGraph *graph.CallGraph
	var interprocFindings []rules.Finding
	var changedFuncName string

	projectRoot := input.Cwd
	if projectRoot == "" {
		projectRoot, _ = os.Getwd()
	}

	// Load or create call graph (best-effort, don't fail the scan)
	callGraph, _ = graph.LoadGraph(projectRoot, input.SessionID)
	if callGraph != nil {
		// Update graph with the current file
		changedIDs := graph.UpdateFile(callGraph, filePath, content, lang)

		// Track which function was changed (for hints)
		if len(changedIDs) > 0 {
			// Extract just the function name from the ID
			for _, id := range changedIDs {
				// ID format is "filepath:FuncName"
				if idx := lastIndexByte(id, ':'); idx >= 0 {
					changedFuncName = id[idx+1:]
					break
				}
			}
		}

		// Run interprocedural analysis on changed functions
		fileContents := map[string]string{filePath: content}
		interprocFindings = graph.PropagateInterproc(callGraph, changedIDs, fileContents)
		findings = append(findings, interprocFindings...)

		// Save updated graph (best-effort)
		graph.SaveGraph(callGraph)
	}

	// AST-based false positive filtering: suppress findings that fall
	// entirely within comments or string literals in the parsed AST.
	findings = ast.FilterFindings(tree, findings)

	// Deduplicate findings that share the same (line, CWE) — keep the
	// highest-fidelity finding (taint > AST > interprocedural > regex)
	// and merge tags from suppressed duplicates into the winner.
	findings = DeduplicateFindings(findings)

	// Reduce severity for findings in test / fixture files.
	// Test code intentionally contains vulnerable patterns so we downgrade
	// rather than suppress entirely — the hints are still useful.
	if fpfilter.IsTestFile(filePath) {
		for i := range findings {
			if findings[i].Severity > rules.Low {
				findings[i].Severity = rules.Low
			}
			findings[i].Tags = appendUnique(findings[i].Tags, "test-file")
		}
	}

	// Populate severity labels and file paths
	for i := range findings {
		findings[i].SeverityLabel = findings[i].Severity.String()
		if findings[i].Language == "" {
			findings[i].Language = lang
		}
		if findings[i].FilePath == "" {
			findings[i].FilePath = filePath
		}
	}

	result.Findings = findings
	result.ScanTimeMs = time.Since(start).Milliseconds()

	// Exit early if the context was cancelled (timeout).
	if ctx.Err() != nil {
		result.Findings = findings
		result.ScanTimeMs = time.Since(start).Milliseconds()
		return
	}

	// Phase 3: Generate hints (always — even for clean code)
	// Run taint analysis to get raw TaintFlow structs for rich hint output.
	// For Go, use AST-driven analysis which provides more accurate tracking
	// through reassignment, aliasing, and complex expressions.
	var taintFlows []taint.TaintFlow
	if lang == rules.LangGo {
		taintFlows = astflow.AnalyzeGo(content, filePath)
	} else if tsflow.Supports(lang) {
		taintFlows = tsflow.Analyze(content, filePath, lang)
	} else {
		taintFlows = taint.Analyze(content, filePath, lang)
	}

	hintCtx := &hints.HintContext{
		FilePath:    filePath,
		Language:    lang,
		Findings:    findings,
		TaintFlows:  taintFlows,
		CallGraph:   callGraph,
		ChangedFunc: changedFuncName,
		IsNewFile:   input.IsWriteOperation(),
		ScanTimeMs:  result.ScanTimeMs,
	}

	hintList := hints.GenerateHints(hintCtx)
	result.HintsOutput = hints.FormatForClaude(hintCtx, hintList)
}

func resolveContent(input *hook.Input) string {
	if input.IsPreToolUse() {
		return input.ResolveContent()
	}
	filePath := input.ResolvePath()
	if filePath == "" {
		return ""
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return input.ResolveContent()
	}
	return string(data)
}

func lastIndexByte(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// appendUnique appends tag to tags only if it is not already present.
func appendUnique(tags []string, tag string) []string {
	for _, t := range tags {
		if t == tag {
			return tags
		}
	}
	return append(tags, tag)
}

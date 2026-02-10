package scanner

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/turen/gtss/internal/analyzer"
	"github.com/turen/gtss/internal/graph"
	"github.com/turen/gtss/internal/hints"
	"github.com/turen/gtss/internal/hook"
	"github.com/turen/gtss/internal/reporter"
	"github.com/turen/gtss/internal/rules"
	"github.com/turen/gtss/internal/taint"
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

	// Run the scan with a timeout to prevent hanging on malicious/huge input.
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanCore(input, content, filePath, lang, start, result)
	}()

	select {
	case <-done:
		// Normal completion
	case <-time.After(scanTimeout):
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
	}

	return result
}

// scanCore performs the actual scan work. It is run in a goroutine with a timeout.
func scanCore(input *hook.Input, content, filePath string, lang rules.Language, start time.Time, result *reporter.ScanResult) {
	// Build scan context
	ctx := &rules.ScanContext{
		FilePath: filePath,
		Content:  content,
		Language: lang,
		IsNew:    input.IsWriteOperation(),
	}
	if input.IsEditOperation() {
		ctx.OldText = input.ToolInput.OldString
		ctx.NewText = input.ToolInput.NewString
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
		wg.Add(1)
		go func(rule rules.Rule) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					// A rule panicked — don't crash the whole scan.
					mu.Lock()
					findings = append(findings, rules.Finding{
						RuleID:      "GTSS-PANIC",
						Severity:    rules.Medium,
						Title:       fmt.Sprintf("Rule %s panicked: %v", rule.ID(), r),
						Description: "A scan rule panicked during analysis. This finding is informational and indicates a bug in the rule implementation.",
						FilePath:    filePath,
						Confidence:  "low",
						Tags:        []string{"internal", "panic"},
					})
					mu.Unlock()
				}
			}()
			founds := rule.Scan(ctx)
			if len(founds) > 0 {
				mu.Lock()
				findings = append(findings, founds...)
				mu.Unlock()
			}
		}(r)
	}
	wg.Wait()

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

	// Phase 3: Generate hints (always — even for clean code)
	// Run taint analysis to get raw TaintFlow structs for rich hint output.
	taintFlows := taint.Analyze(content, filePath, lang)

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

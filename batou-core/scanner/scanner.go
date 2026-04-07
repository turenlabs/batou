package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/turenlabs/batou-core/analyzer"
	"github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-core/fpfilter"
	"github.com/turenlabs/batou-core/graph"
	"github.com/turenlabs/batou-core/hints"
	"github.com/turenlabs/batou-core/hook"
	"github.com/turenlabs/batou-core/reporter"
	"github.com/turenlabs/batou-rules/rules"
	"github.com/turenlabs/batou-core/suppress"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-core/taint/astflow"
	"github.com/turenlabs/batou-core/taint/tsflow"
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

	if shouldSkipFile(filePath, content) {
		result.ScanTimeMs = time.Since(start).Milliseconds()
		return result
	}

	// Normalize CRLF line endings to LF so that regex rules, taint
	// analysis, and line splitting all behave consistently regardless
	// of the line ending style used in the source file.
	content = strings.ReplaceAll(content, "\r\n", "\n")

	// Detect agent adding new batou:ignore directives. In PreToolUse, compare
	// the new content against the existing file to find freshly introduced
	// suppress comments. Emit a high-visibility hint telling Claude to ask the
	// user before suppressing.
	if input.IsPreToolUse() {
		detectNewSuppressDirectives(input, content, result)
	}

	// Skip generated / vendored files — they are not authored by the user
	// and produce noise. In PreToolUse, only trust the generated marker if
	// it was already in the file on disk (not added by the current edit/write).
	// This prevents an agent from injecting "Code generated - DO NOT EDIT"
	// to bypass scanning entirely.
	isGenerated := fpfilter.IsGeneratedFile(filePath, content)
	if input.IsPreToolUse() && isGenerated {
		// Check if the marker existed before this edit.
		if existing, err := os.ReadFile(filePath); err == nil {
			isGenerated = fpfilter.IsGeneratedFile(filePath, string(existing))
		} else {
			// New file (Write) — don't trust agent-provided generated markers.
			isGenerated = false
		}
	}
	if isGenerated || fpfilter.IsVendoredLibrary(filePath) {
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
		// Mark suppress-only edits so the block decision can let them through.
		// This breaks the chicken-and-egg deadlock where pre-existing blocking
		// findings prevent adding suppress directives to the file.
		if input.IsPreToolUse() && isSuppressOnlyEdit(input) {
			coreResult.SuppressOnlyEdit = true
		}
		return coreResult
	case <-ctx.Done():
		result.ScanTimeMs = time.Since(start).Milliseconds()
		result.Findings = append(result.Findings, rules.Finding{
			RuleID:          "BATOU-TIMEOUT",
			Severity:        rules.Medium,
			SeverityLabel:   rules.Medium.String(),
			Title:           "Scan timed out",
			Description:     fmt.Sprintf("Security scan exceeded %s timeout. Partial results may be available. This can happen with very large files.", scanTimeout),
			FilePath:        filePath,
			Confidence:      "low",
			ConfidenceScore: 0.2,
			Tags:            []string{"timeout", "performance"},
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
						RuleID:          "BATOU-PANIC",
						Severity:        rules.Medium,
						Title:           fmt.Sprintf("Rule %s panicked: %v", rule.ID(), rec),
						Description:     "A scan rule panicked during analysis. This finding is informational and indicates a bug in the rule implementation.",
						FilePath:        filePath,
						Confidence:      "low",
						ConfidenceScore: 0.2,
						Tags:            []string{"internal", "panic"},
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

	// Parse inline suppression directives from the PREPROCESSED content so
	// line numbers match what rules report (rules scan preprocessed content).
	// JoinContinuationLines preserves comment lines, so batou:ignore directives
	// are still present and at the correct preprocessed line numbers.
	suppressions := suppress.Parse(preprocessed)
	suppressedLines := suppressions.SuppressedLines()

	// Compute content hash for taint cache (FNV-1a, fast).
	contentHash := graph.FileContentHash(content)

	// Count taint flows from the TaintRule cache for the taint cache.
	var taintFlowCount int
	if cached, ok := sctx.TaintFlows.([]taint.TaintFlow); ok {
		taintFlowCount = len(cached)
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
		// Update graph with the current file, reusing the go/ast parse
		// from Layer 3 (taint analysis) when available.
		var goParsed *astflow.GoParseResult
		if cached, ok := sctx.GoASTFile.(*astflow.GoParseResult); ok {
			goParsed = cached
		}
		changedIDs := graph.UpdateFileWithAST(callGraph, filePath, content, lang, goParsed)

		// Track which function was changed (for hints)
		if len(changedIDs) > 0 {
			// Extract just the function name from the ID
			for _, id := range changedIDs {
				// ID format is "filepath:FuncName"
				if idx := strings.LastIndexByte(id, ':'); idx >= 0 {
					changedFuncName = id[idx+1:]
					break
				}
			}
		}

		// Extract cached Layer 3 taint flows (if available) to pass to
		// interprocedural analysis for precise signature computation.
		var layer3Flows []taint.TaintFlow
		if cached, ok := sctx.TaintFlows.([]taint.TaintFlow); ok {
			layer3Flows = cached
		}

		// Run interprocedural analysis on changed functions
		fileContents := map[string]string{filePath: content}
		interprocFindings = graph.PropagateInterproc(callGraph, changedIDs, fileContents, layer3Flows, suppressedLines)
		findings = append(findings, interprocFindings...)

		// Note: graph is saved AFTER suppression checks below, along with
		// the taint cache population.
	}

	// AST-based false positive filtering: suppress findings that fall
	// entirely within comments or string literals in the parsed AST.
	findings = ast.FilterFindings(tree, filePath, findings)

	// Assign base confidence scores before dedup so the multi-layer
	// boost in DeduplicateFindings can work with meaningful values.
	for i := range findings {
		AssignBaseConfidenceScore(&findings[i])
	}

	// Suppress regex-only findings for CWEs where taint analysis confirmed
	// safety BEFORE dedup, so removed regex noise doesn't inflate the
	// multi-layer boost. Two modes:
	//   1. Taint found flows in this scan → regex-only findings for same CWEs
	//      are redundant (existing behavior).
	//   2. Taint ran and found 0 flows, AND the file taint cache confirms this
	//      with a matching content hash → "negative confirmation" suppresses
	//      regex findings for all taint-coverable CWEs.
	findings = SuppressRegexWhenTaintClean(findings, callGraph, filePath, contentHash)

	// Deduplicate findings that share the same (line, CWE) — keep the
	// highest-fidelity finding (taint > AST > interprocedural > regex)
	// and merge tags from suppressed duplicates into the winner.
	findings = DeduplicateFindings(findings)

	// JavaScript/TypeScript scanner-level FP suppression: suppress regex+taint
	// findings where safe APIs, sanitizers, or guard patterns neutralize the CWE.
	if lang == rules.LangJavaScript || lang == rules.LangTypeScript {
		findings = jsFilterAllFindings(content, findings)
	}

	// Go scanner-level FP suppression: suppress regex findings where Go safety
	// patterns (filepath.Clean, url.Parse+host check, strconv.Atoi, etc.) are present.
	if lang == rules.LangGo {
		findings = goFilterAllFindings(content, findings)
	}

	// Python scanner-level FP suppression: suppress findings where Python
	// framework patterns (SQLAlchemy ORM, jwt.encode, Pydantic, etc.) are safe.
	if lang == rules.LangPython {
		findings = pyFilterAllFindings(content, findings)
	}

	// Rust scanner-level FP suppression: suppress findings where Rust safety
	// patterns (canonicalize+starts_with, .parse::<T>, typed deser, etc.) are present.
	if lang == rules.LangRust {
		findings = rustFilterAllFindings(content, findings)
	}

	// PHP scanner-level FP suppression: suppress findings where PHP safety
	// patterns (htmlspecialchars, escapeshellarg, prepare, realpath, etc.) are present.
	if lang == rules.LangPHP {
		findings = phpFilterAllFindings(content, findings)
	}

	// Ruby scanner-level FP suppression: suppress findings where Ruby safety
	// patterns (File.basename, expand_path+start_with?, sanitize, YAML.safe_load, etc.) are present.
	if lang == rules.LangRuby {
		findings = rubyFilterAllFindings(content, findings)
	}

	// C# scanner-level FP suppression: suppress findings where C# safety
	// patterns (SqlParameter, HtmlEncode, Path.GetFullPath+StartsWith, etc.) are present.
	if lang == rules.LangCSharp {
		findings = csharpFilterAllFindings(content, findings)
	}

	// Now that suppression checks are done, populate the taint cache for
	// future scans. This must happen AFTER SuppressRegexWhenTaintClean so
	// the current scan doesn't read its own cache entry.
	if callGraph != nil {
		callGraph.SetFileTaintCache(filePath, contentHash, taintFlowCount)
		if err := graph.SaveGraph(callGraph); err != nil {
			fmt.Fprintf(os.Stderr, "Batou: graph save: %v\n", err)
		}
	}

	// Compute initial risk scores so ShouldBlock() works during cap/suppress.
	// Recomputed after edge-case adjustments below.
	for i := range findings {
		ComputeRiskScore(&findings[i])
	}

	// Record whether any finding would block BEFORE suppression. This prevents
	// a bypass where an agent adds batou:ignore directives to cover vulnerable
	// code — the suppress hides findings but PreSuppressBlock ensures the
	// write is still blocked in PreToolUse.
	for _, f := range findings {
		if f.ShouldBlock() {
			result.PreSuppressBlock = true
			break
		}
	}

	// Apply inline suppressions first: respect user's batou:ignore directives
	// before capping, so suppressed findings don't consume cap slots.
	var suppressedFindings []rules.Finding
	findings, suppressedFindings = suppress.Apply(suppressions, findings)

	// Cap findings to keep output actionable: max 3 per rule, 20 per file.
	var cappedCount int
	findings, cappedCount = CapFindings(findings, DefaultPerRuleCap, DefaultPerFileCap)

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

	// Edge-case confidence adjustments, compute final risk score, and sync labels.
	for i := range findings {
		if findings[i].RuleID == "BATOU-TIMEOUT" || findings[i].RuleID == "BATOU-PANIC" {
			findings[i].ConfidenceScore = 0.2
		}
		if fpfilter.IsTestFile(filePath) && findings[i].ConfidenceScore > 0.3 {
			findings[i].ConfidenceScore = 0.3
		}
		ComputeRiskScore(&findings[i])
		findings[i].SyncConfidenceString()
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
	result.SuppressedCount = len(suppressedFindings)
	result.SuppressedFindings = suppressedFindings
	result.ScanTimeMs = time.Since(start).Milliseconds()

	// Exit early if the context was cancelled (timeout).
	if ctx.Err() != nil {
		return
	}

	// Phase 3: Generate hints (always — even for clean code)
	// Retrieve cached TaintFlow results from Phase 1 (stored by TaintRule).
	// Fall back to running taint analysis only if the cache is empty (e.g.
	// the language was not covered by TaintRule).
	var taintFlows []taint.TaintFlow
	if cached, ok := sctx.TaintFlows.([]taint.TaintFlow); ok {
		taintFlows = cached
	} else if lang == rules.LangGo {
		// Reuse cached go/ast parse if available.
		var goParsed *astflow.GoParseResult
		if cached, ok := sctx.GoASTFile.(*astflow.GoParseResult); ok {
			goParsed = cached
		}
		taintFlows = astflow.AnalyzeGoWithAST(content, filePath, goParsed)
	} else if tsflow.Supports(lang) {
		// Reuse tree-sitter tree from Layer 2 if available.
		taintFlows = tsflow.AnalyzeWithTree(content, filePath, lang, tree)
	} else {
		taintFlows = taint.Analyze(content, filePath, lang)
	}

	hintCtx := &hints.HintContext{
		FilePath:           filePath,
		Language:           lang,
		Findings:           findings,
		SuppressedFindings: suppressedFindings,
		TaintFlows:         taintFlows,
		CallGraph:          callGraph,
		ChangedFunc:        changedFuncName,
		IsNewFile:          input.IsWriteOperation(),
		ScanTimeMs:         result.ScanTimeMs,
		CappedCount:        cappedCount,
	}

	hintList := hints.GenerateHints(hintCtx)
	result.HintsOutput = hints.FormatForClaude(hintCtx, hintList)
}

func resolveContent(input *hook.Input) string {
	if input.IsPreToolUse() {
		// For Edit PreToolUse, ResolveContent() returns only NewString
		// (the replacement snippet), not the full file. Read the current
		// file from disk and apply the edit so suppress directives and
		// rules see the complete post-edit content.
		if input.IsEditOperation() {
			filePath := input.ResolvePath()
			if filePath != "" {
				if data, err := os.ReadFile(filePath); err == nil {
					original := string(data)
					old := input.ToolInput.OldString
					new := input.ToolInput.NewString
					if old != "" {
						if input.ToolInput.ReplaceAll {
							return strings.ReplaceAll(original, old, new)
						}
						if idx := strings.Index(original, old); idx >= 0 {
							return original[:idx] + new + original[idx+len(old):]
						}
					}
					return original
				}
			}
		}
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


// isSuppressOnlyEdit returns true if an Edit operation's diff only adds
// batou:ignore directives (and whitespace/comments around them). This detects
// the chicken-and-egg case where an agent can't add suppress directives because
// the pre-existing findings block every edit to the file.
func isSuppressOnlyEdit(input *hook.Input) bool {
	if !input.IsEditOperation() {
		return false
	}
	old := input.ToolInput.OldString
	new := input.ToolInput.NewString
	if old == "" || new == "" || old == new {
		return false
	}

	// The new string must contain at least one batou:ignore directive.
	if !strings.Contains(strings.ToLower(new), "batou:ignore") {
		return false
	}

	// Split both into lines. Every line in new that isn't in old must be
	// a suppress directive (or blank/comment-only whitespace around it).
	oldLines := strings.Split(old, "\n")
	newLines := strings.Split(new, "\n")

	// Build a set of old lines for fast lookup.
	oldSet := make(map[string]int, len(oldLines))
	for _, l := range oldLines {
		oldSet[strings.TrimSpace(l)]++
	}

	// Check each new line: if it wasn't in old, it must be a suppress directive or blank.
	for _, l := range newLines {
		trimmed := strings.TrimSpace(l)
		if count, ok := oldSet[trimmed]; ok && count > 0 {
			oldSet[trimmed]--
			continue
		}
		// New line — must be suppress directive or empty.
		if trimmed == "" {
			continue
		}
		if !isSuppressComment(trimmed) {
			return false
		}
	}
	return true
}

// isSuppressComment returns true if the line is a comment containing batou:ignore.
// Rejects string literals like `secret = "batou:ignore"` that contain the substring
// but aren't actual suppress directives.
func isSuppressComment(trimmed string) bool {
	lower := strings.ToLower(trimmed)
	if !strings.Contains(lower, "batou:ignore") {
		return false
	}
	// Must start with a recognized comment prefix.
	commentPrefixes := []string{"//", "#", "--", "/*", "<!--", "rem ", "'"}
	for _, p := range commentPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// detectNewSuppressDirectives checks if the agent is adding new batou:ignore
// directives. Compares new content against the file on disk. For each new
// directive found, emits a high-visibility hint telling Claude to ask the user.
func detectNewSuppressDirectives(input *hook.Input, newContent string, result *reporter.ScanResult) {
	// Count suppress directives in new content.
	newLines := strings.Split(newContent, "\n")
	var newDirectives []int // 1-indexed line numbers with new directives
	for i, line := range newLines {
		if strings.Contains(strings.ToLower(line), "batou:ignore") {
			newDirectives = append(newDirectives, i+1)
		}
	}
	if len(newDirectives) == 0 {
		return
	}

	// Read existing file to find pre-existing directives.
	existingCount := 0
	filePath := input.ResolvePath()
	if filePath != "" {
		if data, err := os.ReadFile(filePath); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.Contains(strings.ToLower(line), "batou:ignore") {
					existingCount++
				}
			}
		}
	}

	// If new content has more directives than the existing file, the agent
	// is adding suppression. Emit a finding for each new one.
	added := len(newDirectives) - existingCount
	if added <= 0 {
		return
	}

	// Pick the line numbers of the last N directives (the new ones).
	start := len(newDirectives) - added
	for _, lineNum := range newDirectives[start:] {
		result.Findings = append(result.Findings, rules.Finding{
			RuleID:          "BATOU-SUPPRESS-REVIEW",
			Severity:        rules.High,
			SeverityLabel:   rules.High.String(),
			Title:           "Fix the security issue instead of suppressing it",
			Description:     "You are adding a batou:ignore directive instead of fixing the underlying issue. Remove the suppress comment and fix the code. If the finding is about missing auth, add auth. If it's about injection, use parameterized queries. If it's about secrets, use environment variables. Suppression is a last resort — fix the code first.",
			Suggestion:      "Remove the batou:ignore comment and fix the underlying security issue. Write secure code instead of suppressing the warning.",
			FilePath:        filePath,
			LineNumber:      lineNum,
			Confidence:      "high",
			ConfidenceScore: 1.0,
			RiskScore:       0.6, // High enough to show prominently, not enough to block
			Tags:            []string{"suppress-review", "workflow"},
		})
	}
}

// shouldSkipFile returns true for files that should not be scanned because
// they are non-source content (markdown, .claude/ config, empty files, or
// stub __init__.py files).
func shouldSkipFile(filePath, content string) bool {
	// Skip markdown files — documentation, not source code.
	if strings.EqualFold(filepath.Ext(filePath), ".md") {
		return true
	}

	// Skip files inside .claude/ directories (config/metadata).
	for _, part := range strings.Split(filepath.ToSlash(filePath), "/") {
		if part == ".claude" {
			return true
		}
	}

	// Skip empty files (no content or whitespace-only).
	if strings.TrimSpace(content) == "" {
		return true
	}

	// Skip stub __init__.py files (empty or just whitespace).
	if filepath.Base(filePath) == "__init__.py" && strings.TrimSpace(content) == "" {
		return true
	}

	return false
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

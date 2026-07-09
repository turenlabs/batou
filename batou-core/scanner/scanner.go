package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
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
	"github.com/turenlabs/batou-core/suppress"
	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-core/taint/astflow"
	"github.com/turenlabs/batou-core/taint/ssaflow"
	"github.com/turenlabs/batou-core/taint/tsflow"
	"github.com/turenlabs/batou-rules/rules"
)

// ssaflowEnabledForScanner mirrors taintrule.ssaflowEnabled — duplicated here
// to keep scanner.go free of a cross-package dependency on taintrule (which
// already imports scanner indirectly via rules.ScanContext). ssaflow is ON
// by default since PR-KK; users can opt out with BATOU_SSAFLOW=0.
func ssaflowEnabledForScanner() bool {
	v := os.Getenv("BATOU_SSAFLOW")
	if v == "" {
		return true // default ON
	}
	if v == "0" || strings.EqualFold(v, "false") || strings.EqualFold(v, "off") || strings.EqualFold(v, "no") {
		return false
	}
	return true
}

// batouScanWorkers returns how many rule.Scan calls may run concurrently during
// Phase 1. Batou runs in the background as an editor hook, so it must leave the
// developer's machine responsive: the pool is sized to a PROPORTION of the
// machine's cores (half, NumCPU/2), never the full core count, leaving headroom
// for the editor and everything else.
//
//   - Default: runtime.NumCPU() / 2 (2-core box → 1, 8-core box → 4).
//   - Ops override: BATOU_SCAN_WORKERS, parsed with strconv.Atoi, used only when
//     it is > 0 (a bad/empty/zero/negative value falls back to the default).
//   - Floored to at least 1 so we never produce a zero-worker (deadlocking) pool.
//   - Capped at ruleCount so we never spawn more workers than there are rules.
func batouScanWorkers(ruleCount int) int {
	n := runtime.NumCPU() / 2
	if v := os.Getenv("BATOU_SCAN_WORKERS"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
			n = parsed
		}
	}
	if n < 1 {
		n = 1
	}
	if ruleCount > 0 && n > ruleCount {
		n = ruleCount
	}
	return n
}

// scanTimeout is the default maximum time a scan may take before we return
// partial results. Overridable via BATOU_SCAN_TIMEOUT (any time.ParseDuration
// value, e.g. "30s"); see effectiveScanTimeout. Production leaves it unset, so
// the cap stays 10s.
const scanTimeout = 10 * time.Second

// effectiveScanTimeout returns the scan deadline. It is scanTimeout (10s) unless
// BATOU_SCAN_TIMEOUT is set to a valid, positive time.ParseDuration value.
//
// The override exists for the -race CI large-file perf gate
// (TestLargeFileScansWithoutTimeout): the 10s cap is a WALL-CLOCK limit, and the
// race detector inflates wall-clock ~10x, so under -race a legitimately large
// (non-quadratic) file can exceed 10s purely from instrumentation overhead and
// trip the timeout sentinel — a false regression signal. That test sets a
// race-appropriate budget so the assertion still catches a genuine algorithmic
// blowup (which dwarfs any budget) without flaking on the detector's overhead.
// Production never sets the env var, so the 10s cap is unchanged.
func effectiveScanTimeout() time.Duration {
	if v := os.Getenv("BATOU_SCAN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return scanTimeout
}

// timeoutHarvestGrace is how long Scan waits, after the scan deadline fires,
// for the worker goroutine to observe cancellation and RETURN — at which point
// its partial findings are safe to surface (done closed = no concurrent write).
// Bounds the worst-case Scan latency to scanTimeout+grace on a wedged file.
const timeoutHarvestGrace = 2 * time.Second

// hookCrossFileEnabled gates the write-time cross-file lane: adopting a
// scan-built project graph in hook mode, incrementally re-resolving the
// edited file's cross-file edges, and walking its one-hop cross-file
// pairs. ON by default; set BATOU_HOOK_CROSSFILE=0 to fall back to the
// legacy session-keyed hook graph behavior.
func hookCrossFileEnabled() bool {
	v := os.Getenv("BATOU_HOOK_CROSSFILE")
	if v == "" {
		return true // default ON
	}
	if v == "0" || strings.EqualFold(v, "false") || strings.EqualFold(v, "off") || strings.EqualFold(v, "no") {
		return false
	}
	return true
}

// hookCrossFileTwoHop gates the second-hop deepening of the write-time
// cross-file lane: after the one-hop walk's bounded re-lift, the edited
// file's direct cross-file callees (B) inherit their own cross-file
// callees' (C) sinks in-memory so an A->B->C flow connects at write
// time (LiftSecondHopSinksForFile). It is a strict subset of the
// cross-file lane, so it is OFF whenever BATOU_HOOK_CROSSFILE is off.
// Independently controllable via BATOU_HOOK_CROSSFILE_HOPS: "1" (or
// off/false/no/0) restricts the lane to one hop; any other value (incl.
// unset) enables two hops. Default ON — the second hop is bounded
// (maxSecondHopCallees) and measured to add only sub-millisecond
// latency on aggregator-shaped graphs.
func hookCrossFileTwoHop() bool {
	if !hookCrossFileEnabled() {
		return false
	}
	v := os.Getenv("BATOU_HOOK_CROSSFILE_HOPS")
	if v == "" {
		return true // default ON (two hops)
	}
	if v == "1" || v == "0" || strings.EqualFold(v, "false") || strings.EqualFold(v, "off") || strings.EqualFold(v, "no") {
		return false
	}
	return true
}

// Call-graph persistence overrides. Defaults preserve the original hook-mode
// behavior exactly (load/save .batou/callgraph.json relative to the project
// root). The `batou scan` subcommand sets these to honor its --callgraph PATH
// and --no-callgraph flags; everywhere else they remain at their zero values
// so the byte-for-byte hook output is unchanged.
//
// These are package-level rather than per-call to avoid widening Scan's
// signature (which would ripple through the testutil callers and the hook
// entry point). `batou scan` configures them once before its worker pool
// starts, then leaves them set for the lifetime of the process — there is
// no second consumer that needs different settings concurrently.
var (
	// CallgraphPathOverride, when non-empty, replaces the default
	// .batou/callgraph.json location for both load and save. Ignored when
	// CallgraphPersistDisabled is true.
	CallgraphPathOverride string
	// CallgraphPersistDisabled, when true, skips persistent call-graph
	// load and save entirely. The graph is still built in-memory for
	// interprocedural analysis during the scan; only persistence is bypassed.
	CallgraphPersistDisabled bool
	// SharedCallGraph, when non-nil, makes every scanner.Scan use the
	// same in-memory CallGraph instead of loading/saving the persisted
	// file. Set by dirscan before launching its worker pool to avoid
	// the per-file load-modify-save race that lost ~15–30% of cross-
	// file edges run-to-run. The graph's Mu field MUST be acquired
	// around mutations and iterations while in shared mode.
	SharedCallGraph *graph.CallGraph

	// cwdCacheOnce + cwdCache memoize os.Getwd() across the lifetime of
	// the process. os.Getwd is a syscall on macOS/Linux that costs a few
	// microseconds; doing it once per file is fine for hook mode but
	// burns several seconds during a `batou scan` on large repos (4.6s
	// of 80s on coder env-OFF before this cache).
	cwdCacheOnce sync.Once
	cwdCache     string
)

// lowerLines splits content on "\n" and lowercases each line, once per file.
// The result feeds ScanContext.LinesLower so the fold-aware line pre-gate
// across the ~140 line-scanning rules reuses one lowering pass instead of
// lowercasing each line once per (?i) pattern.
func lowerLines(content string) []string {
	lines := strings.Split(content, "\n")
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = strings.ToLower(l)
	}
	return out
}

// cachedCwd returns the process working directory, memoised on first
// call. Used by scanCore so dirscan workers don't redo the syscall
// thousands of times. Returns "" if os.Getwd ever fails (callers
// already handle that case from the original os.Getwd call).
func cachedCwd() string {
	cwdCacheOnce.Do(func() {
		cwd, err := os.Getwd()
		if err == nil {
			cwdCache = cwd
		}
	})
	return cwdCache
}

// sortFindingsCanonical orders findings by a stable total key so that the
// order the per-rule goroutines happened to finish in cannot affect which
// findings survive dedup/cap or the order they are emitted. Sorting by line
// first means the per-rule/per-file caps keep the earliest occurrences.
func sortFindingsCanonical(fs []rules.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := &fs[i], &fs[j]
		if a.LineNumber != b.LineNumber {
			return a.LineNumber < b.LineNumber
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.CWEID != b.CWEID {
			return a.CWEID < b.CWEID
		}
		if a.MatchedText != b.MatchedText {
			return a.MatchedText < b.MatchedText
		}
		return a.Title < b.Title
	})
}

// loadCallGraph reads the call graph honoring the package-level overrides.
// Defaults to graph.LoadGraph(projectRoot, sessionID) so hook mode is
// unchanged when no override is set.
//
// When SharedCallGraph is non-nil (the dirscan worker-pool case),
// every scan reuses the same in-memory graph; we don't re-read it
// from disk per file. This eliminates the per-file load/modify/save
// race that lost cross-file edges.
// In hook mode (no SharedCallGraph) with the cross-file lane enabled,
// the load goes through graph.LoadGraphForHook, which ADOPTS a persisted
// scan-built project graph across sessions (instead of discarding it on
// SessionID mismatch) so the hook can see scan-built cross-file edges
// and taint signatures. Graphs without scan-built cross-file state keep
// the original session-reset semantics.
func loadCallGraph(projectRoot, sessionID string) (*graph.CallGraph, error) {
	if SharedCallGraph != nil {
		return SharedCallGraph, nil
	}
	if CallgraphPersistDisabled {
		// Persistence is off, but interprocedural analysis still needs a
		// graph instance to update. Return an empty one bound to the
		// project root; saveCallGraph below will no-op.
		return graph.NewCallGraph(projectRoot, sessionID), nil
	}
	if CallgraphPathOverride != "" {
		if hookCrossFileEnabled() {
			return graph.LoadGraphForHookAt(CallgraphPathOverride, projectRoot, sessionID)
		}
		return graph.LoadGraphAt(CallgraphPathOverride, projectRoot, sessionID)
	}
	if hookCrossFileEnabled() {
		return graph.LoadGraphForHook(projectRoot, sessionID)
	}
	return graph.LoadGraph(projectRoot, sessionID)
}

// saveCallGraph writes the call graph honoring the package-level overrides.
// Defaults to graph.SaveGraph(cg) so hook mode is unchanged when no override
// is set.
//
// When SharedCallGraph is set, per-scan saves are no-ops: dirscan
// persists the graph once at finalize after the worker pool drains.
func saveCallGraph(cg *graph.CallGraph) error {
	if SharedCallGraph != nil {
		return nil
	}
	if CallgraphPersistDisabled {
		return nil
	}
	if cg != nil && cg.SkipPersist {
		// LoadGraphForHook declined to adopt an oversized scan-built
		// graph; saving this fresh session graph would clobber the
		// scan-built cross-file state on disk, so skip persistence.
		return nil
	}
	if CallgraphPathOverride != "" {
		return graph.SaveGraphAt(cg, CallgraphPathOverride)
	}
	return graph.SaveGraph(cg)
}

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
	timeout := effectiveScanTimeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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
		timeoutFinding := rules.Finding{
			RuleID:          "BATOU-TIMEOUT",
			Severity:        rules.Medium,
			SeverityLabel:   rules.Medium.String(),
			Title:           "Scan timed out",
			Description:     fmt.Sprintf("Security scan exceeded %s timeout. Partial results may be available. This can happen with very large files.", timeout),
			FilePath:        filePath,
			Confidence:      "low",
			ConfidenceScore: 0.2,
			Tags:            []string{"timeout", "performance"},
		}
		// Best-effort HARVEST instead of dropping everything: scanCore checks
		// ctx between phases, so after the deadline it usually returns within a
		// moment. Wait a bounded grace for `done` to close — that means the
		// worker has fully RETURNED, so coreResult is no longer being mutated
		// (no data race) and the findings it accumulated before the deadline
		// can be surfaced (the description already promises "partial results").
		// Only a genuinely wedged worker (tight regex backtrack / CGo parse that
		// never observes cancellation) misses the grace and falls back to the
		// empty result — the prior always-drop behaviour.
		select {
		case <-done:
			coreResult.ScanTimeMs = time.Since(start).Milliseconds()
			coreResult.Findings = append(coreResult.Findings, timeoutFinding)
			return coreResult
		case <-time.After(timeoutHarvestGrace):
			result.ScanTimeMs = time.Since(start).Milliseconds()
			result.Findings = append(result.Findings, timeoutFinding)
			return result
		}
	}
}

// scanCore performs the actual scan work. It is run in a goroutine with a
// context-based timeout. The context is checked between phases so the
// goroutine can exit early on cancellation instead of leaking.
func scanCore(ctx context.Context, input *hook.Input, content, filePath string, lang rules.Language, start time.Time, result *reporter.ScanResult) {
	// Pre-process content to join continuation lines for regex matching.
	// Keep the original content for AST parsing and taint analysis (which
	// need accurate line numbers). preToOrig maps each preprocessed line back
	// to the original line where its group began, so suppress directives
	// resolve against both coordinate systems.
	preprocessed, preToOrig := JoinContinuationLinesWithMap(content, lang)
	totalOrigLines := strings.Count(content, "\n") + 1

	// Build scan context — use preprocessed content for regex rules.
	// OriginalContent preserves the un-preprocessed source so AST analyzers
	// can align their AST line numbers (which come from the original) with
	// line-by-line helpers like rules.PySinkVarIsSafe.
	sctx := &rules.ScanContext{
		FilePath: filePath,
		Content:  preprocessed,
		// Split into lines once here so the line-oriented regex rules reuse it
		// instead of each re-splitting the whole file (the top heap allocator).
		Lines: strings.Split(preprocessed, "\n"),
		// Lowercase each line once here so the fold-aware OR-set pre-gate
		// (Prefilter.MightMatch / rules.LineMightMatch) lowercases each line
		// ONCE per file instead of once per (?i) regex pattern across the ~140
		// line-scanning rules — the lever that turns the per-line regex tier
		// from O(rules×lines) ToLower calls into O(lines).
		LinesLower: lowerLines(preprocessed),
		// Lowercase the whole file once here so hand-written rules' per-file
		// early-exit guards — re.MatchString(ctx.Content) over the entire file,
		// the dominant remaining (?i) regex cost after the per-line gate — reuse
		// one lowering pass via the fold-aware file pre-gate (rules.GMatchFile)
		// instead of running the backtracking (?i) engine on every file.
		ContentLower:    strings.ToLower(preprocessed),
		OriginalContent: content,
		Language:        lang,
		IsNew:           input.IsWriteOperation(),
	}
	if input.IsEditOperation() {
		sctx.OldText = input.ToolInput.OldString
		sctx.NewText = input.ToolInput.NewString
	}

	// Parse AST using original content (needs accurate line positions).
	// A nil tree silently downgrades the file to regex-only taint — emit a
	// one-line WARN so users can audit timeouts/parse failures.
	var tree *ast.Tree
	if ast.SupportsLanguage(lang) {
		// ParseFile routes .tsx through the JSX-aware tsx grammar; for all
		// other files it is identical to Parse. Feeding the JSX-aware tree
		// into sctx.Tree means tsflow (Layer 3) reuses it too.
		tree = ast.ParseFile([]byte(content), lang, filePath)
		sctx.Tree = tree
		if tree == nil {
			fmt.Fprintf(os.Stderr,
				"Batou WARN: tree-sitter parse returned nil for %s (%s); falling back to regex-only taint\n",
				filePath, lang,
			)
		}
	}

	// Phase 1: Run all registered rules concurrently (regex + taint)
	applicable := rules.ForLanguage(lang)
	result.RulesRun = len(applicable)

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		findings []rules.Finding
	)

	// Bounded worker pool. Batou runs in the background as an editor hook, so we
	// deliberately cap concurrency at a PROPORTION of the machine's cores
	// (batouScanWorkers) rather than fanning out one goroutine per rule and
	// grabbing every core — that would make the developer's machine unresponsive.
	// N long-lived workers drain a channel of rules; AT MOST N rule.Scan calls
	// run concurrently.
	workers := batouScanWorkers(len(applicable))
	ruleCh := make(chan rules.Rule)

	// scanOne runs a single rule under its OWN recover so a panicking rule yields
	// a BATOU-PANIC finding without killing the worker (which would silently lose
	// every other rule that worker still has to process).
	scanOne := func(rule rules.Rule) {
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
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rule := range ruleCh {
				scanOne(rule)
			}
		}()
	}

	// Feed rules to the workers, stopping early once the context is cancelled
	// (timeout). The send selects on ctx.Done() so a cancel can never deadlock
	// the feeder against a full channel, and ruleCh is ALWAYS closed so every
	// worker drains its remaining rules and exits.
	for _, r := range applicable {
		if ctx.Err() != nil {
			break
		}
		select {
		case ruleCh <- r:
		case <-ctx.Done():
		}
	}
	close(ruleCh)
	wg.Wait()

	// Exit early if the context was cancelled (timeout).
	if ctx.Err() != nil {
		result.Findings = findings
		result.ScanTimeMs = time.Since(start).Milliseconds()
		return
	}

	// Parse inline suppression directives from the PREPROCESSED content so
	// line numbers match what regex rules report (rules scan preprocessed
	// content). JoinContinuationLines preserves comment lines, so batou:ignore
	// directives are still present at the correct preprocessed line numbers.
	//
	// ParseWithLineMap additionally mirrors each preprocessed entry back to
	// every original line in the group it represents. This is required because
	// AST and taint findings report ORIGINAL line numbers, not preprocessed —
	// without the mirror, a directive above a collapsed multi-line block
	// (e.g. Python argparse.ArgumentParser(...) spanning 3 lines) would fail
	// to suppress taint flows whose sinks live below the collapse.
	suppressions := suppress.ParseWithLineMap(preprocessed, preToOrig, totalOrigLines)
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
		// cachedCwd memoises os.Getwd across the scan. Hook mode hits this
		// path once; dirscan workers hit it thousands of times and the
		// syscall was costing 5%+ of total scan CPU before the cache.
		projectRoot = cachedCwd()
	}

	// Load or create call graph (best-effort, don't fail the scan).
	// loadCallGraph honors the package-level CallgraphPathOverride /
	// CallgraphPersistDisabled options (defaults preserve the hook-mode
	// .batou/callgraph.json behavior).
	callGraph, _ = loadCallGraph(projectRoot, input.SessionID)

	// graphPath is the path the call graph keys this file by. Identical to
	// filePath except in the hook cross-file lane, where a scan-built graph
	// may know the file under a ProjectRoot-relative spelling (scans run
	// from the repo root record CWD-relative paths) — updating under the
	// graph's own spelling replaces the scan's nodes instead of creating a
	// duplicate node set for the same file.
	graphPath := filePath

	if callGraph != nil {
		// In SharedCallGraph mode (dirscan worker pool) the graph is
		// concurrently mutated; serialize the update + interproc walk
		// behind the graph's mutex so map writes/reads stay safe. In
		// the hook-mode single-file path the mutex is uncontended and
		// adds negligible overhead.
		callGraph.Mu.Lock()

		// Write-time cross-file lane: active only in hook mode (never in
		// the dirscan worker pool) when the loaded graph carries scan-built
		// cross-file state. Captures the file's inbound cross-file callers
		// BEFORE UpdateFileWithAST strips the back-edges, so the bounded
		// re-resolve below can restore edges INTO this file as well as out.
		crossFileLane := SharedCallGraph == nil && !CallgraphPersistDisabled &&
			hookCrossFileEnabled() && callGraph.HasCrossFileState()
		var inboundCallerIDs []string
		if crossFileLane {
			graphPath = graph.CanonicalGraphPath(callGraph, filePath)
			inboundCallerIDs = graph.CallersOfFileFromOtherFiles(callGraph, graphPath)
		}

		// Update graph with the current file, reusing the go/ast parse
		// from Layer 3 (taint analysis) when available.
		var goParsed *astflow.GoParseResult
		if cached, ok := sctx.GoASTFile.(*astflow.GoParseResult); ok {
			goParsed = cached
		}
		// Pass the tree-sitter tree parsed in Layer 2 (sctx.Tree) so the graph
		// builders for non-Go languages reuse it instead of re-parsing the file.
		changedIDs := graph.UpdateFileWithAST(callGraph, graphPath, content, lang, goParsed, tree)

		// Restore this file's cross-file edges (one hop, both directions)
		// against the scan-built PackageIndex. Graceful no-op when the
		// graph has no cross-file state.
		if crossFileLane {
			graph.ResolveCrossFileEdgesForFile(callGraph, projectRoot, graphPath, []byte(content), inboundCallerIDs)
		}

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

		// Build typed Go info from the cached go/ast parse so interprocedural
		// analysis can populate typed Params/Returns and apply call-site type
		// confirmation. Non-Go scans or files that failed to parse pass nil.
		var typed *graph.GoTypeInfo
		if lang == rules.LangGo && goParsed != nil && goParsed.File != nil {
			// Pass the fset so closure literals (FuncLit) get indexed under
			// their canonical "<Outer>.closure@<line>:<col>" name; without it,
			// populateTypedParams can't derive typed Params for closure
			// FuncNodes the call graph builder now emits.
			typed = graph.BuildGoTypeInfoWithFset(goParsed.File, goParsed.Fset)
		}

		// Run interprocedural analysis on changed functions. With the
		// cross-file lane active, the restored inbound edges let this
		// walk reach callers in OTHER files (their content is loaded
		// from disk by loadCallerFile).
		fileContents := map[string]string{graphPath: content}
		interprocFindings = graph.PropagateInterprocTyped(callGraph, changedIDs, fileContents, layer3Flows, suppressedLines, typed)

		// Cross-file lane, caller direction: walk THIS file's outbound
		// cross-file callees (one hop) against their scan-built taint
		// signatures, surfacing flows like "this handler passes request
		// input to another file's SQL sink". PropagateInterproc above
		// covers the callee direction; the pair sets are disjoint.
		if crossFileLane {
			// Second-hop deepening (bounded): re-lift the edited file's
			// direct cross-file callees' downstream sinks in-memory so an
			// edited-file -> B -> C(sink) chain connects at write time even
			// when B's persisted signature lacks the lift. The walk below
			// then renders the full chain via the lifted SinkRef's
			// OriginFile/OriginLine. Gated independently behind
			// BATOU_HOOK_CROSSFILE_HOPS; subset of the cross-file lane.
			if hookCrossFileTwoHop() {
				graph.LiftSecondHopSinksForFile(callGraph, graphPath, fileContents)
			}
			interprocFindings = append(interprocFindings,
				graph.WalkCrossFileTaintFlowsForCaller(callGraph, graphPath, fileContents)...)
		}
		callGraph.Mu.Unlock()

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
	// SuppressRegexWhenTaintClean reads callGraph.FileTaintCaches;
	// lock for the read so it can't race the per-scanner mutations.
	//
	// taintRan: the taint tier actually executed on this file in this scan
	// (the BATOU-TAINT rule was applicable for this language) AND the scan was
	// not degraded by a per-rule timeout/panic. When true, the absence of a
	// taint finding for a coverable CWE is authoritative within this scan, so
	// the regex-only match for that CWE is suppressed without needing a
	// persisted cache entry. The degraded guard prevents suppressing real
	// coverage on a file where taint did not finish.
	// Within-scan negative confirmation is only safe for languages whose taint
	// engine has mature-enough source/sink RECALL that "taint produced no flow"
	// reliably means "no real dataflow vuln" — otherwise suppressing the regex
	// layer drops genuine detections the taint engine misses (a taint FN). It
	// is validated to HOLD recall on Java (servlet/JDBC source+sink coverage is
	// mature: OWASP-Java TPR held ~91% with FPR→0). It is deliberately NOT
	// enabled for languages where the taint engine still misses real flows that
	// regex catches (e.g. Python xss/trustbound, JS/Ruby cases drop to ~0 TPR
	// under blanket suppression). Extend this set ONLY after per-language
	// validation that recall does not regress. Other languages keep the
	// cache-based negative-confirmation path (a prior identical-content scan).
	taintRan := withinScanTaintAuthoritative[lang]
	if taintRan {
		hasTaintRule := false
		for _, r := range applicable {
			if r.ID() == "BATOU-TAINT" {
				hasTaintRule = true
				break
			}
		}
		taintRan = hasTaintRule
	}
	if taintRan {
		for i := range findings {
			if findings[i].RuleID == "BATOU-TIMEOUT" || findings[i].RuleID == "BATOU-PANIC" {
				taintRan = false
				break
			}
		}
	}
	if callGraph != nil {
		callGraph.Mu.Lock()
	}
	findings = SuppressRegexWhenTaintClean(findings, callGraph, graphPath, contentHash, taintRan)
	if callGraph != nil {
		callGraph.Mu.Unlock()
	}

	// Normalize FilePath before dedup: many regex rules emit findings without
	// setting FilePath, while taint/AST/interproc findings carry one.
	// DeduplicateFindings keys on (FilePath, line, CWE), so an empty path
	// would otherwise split same-file groups and resurrect duplicates.
	// Interprocedural findings whose FilePath points at a caller in a
	// different file keep their own path — that distinction is the point of
	// the file-aware key. The post-dedup backfill below stays for findings
	// appended later (e.g. suppression adjudication).
	for i := range findings {
		if findings[i].FilePath == "" {
			findings[i].FilePath = filePath
		}
	}

	// Sort findings into a canonical order so everything downstream is
	// deterministic regardless of the order the per-rule goroutines finished in
	// and the order interproc/AST findings were appended: DeduplicateFindings
	// keeps the first finding per (line, CWE) group and CapFindings keeps the
	// first N per rule/file, so a stable input order is what makes which
	// findings survive — and the emitted JSONL — reproducible run to run.
	// Placed here (after rule + interproc + taint findings are all collected,
	// before dedup) so no later append can reintroduce order nondeterminism.
	sortFindingsCanonical(findings)

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
		callGraph.Mu.Lock()
		callGraph.SetFileTaintCache(graphPath, contentHash, taintFlowCount)
		callGraph.Mu.Unlock()
		// saveCallGraph honors the package-level CallgraphPathOverride /
		// CallgraphPersistDisabled options. In SharedCallGraph mode it
		// is a no-op — dirscan persists the graph once at finalize.
		if err := saveCallGraph(callGraph); err != nil {
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
	//
	// IMPORTANT: evaluate the block decision against the POST-CAP confidence, so
	// the structural/style/interproc caps (applied to the live findings further
	// below) are honoured here too. Without this, a finding the caps demote to a
	// hint (e.g. an AST-structural Critical capped to 0.65) would still latch
	// PreSuppressBlock at its pre-cap 0.70 RiskScore and hard-block the write in
	// the hook — silently defeating every confidence cap. The caps only lower
	// confidence and are idempotent, so applying them to a copy here is safe and
	// keeps this loop PRE-suppression (the anti-bypass property): a genuinely
	// blocking finding still latches even if a later batou:ignore hides it.
	for _, f := range findings {
		fc := f
		CapInterprocConfidenceForTestPaths(&fc)
		CapLowValueHeuristicConfidence(&fc)
		// External-origin block invariant: a finding is block-eligible only if a
		// taint/interproc flow from a GENUINE external source confirms it. This
		// MUST run in the PreSuppressBlock latch too — otherwise a finding the
		// gate demotes to a hint would still latch PreSuppressBlock at its pre-cap
		// 0.70 RiskScore and hard-block the write in the hook, silently defeating
		// the gate (the same anti-bypass property documented above for the other
		// caps). hasExternalOrigin reads only post-dedup-stable fields, is
		// idempotent, and only lowers confidence, so applying it to this copy is
		// safe and keeps the loop PRE-suppression.
		CapNonExternalOriginConfidence(&fc)
		ComputeRiskScore(&fc)
		if fc.ShouldBlock() {
			result.PreSuppressBlock = true
			break
		}
	}

	// Apply inline suppressions first: respect user's batou:ignore directives
	// before capping, so suppressed findings don't consume cap slots.
	var suppressedFindings []rules.Finding
	findings, suppressedFindings = suppress.Apply(suppressions, findings)

	// Stamp each suppressed finding with the directive's stated `-- reason` so
	// the audit trail (findings store, ledger) records the developer's actual
	// justification instead of a generic "batou:ignore" marker. Reasonless
	// directives leave SuppressReason empty.
	for i := range suppressedFindings {
		if reason, ok := suppressions.ReasonForFinding(suppressedFindings[i]); ok && reason != "" {
			suppressedFindings[i].SuppressReason = reason
		}
	}

	// Write-time adjudication: for each suppressed taint/dataflow finding whose
	// batou:ignore reason makes an affirmative safety claim ("parameterized",
	// "sanitized", "not user input"), machine-check the claim against the
	// suppressed finding's OWN flow. When the flow contradicts the stated
	// rationale, emit BATOU-SUPPRESS-UNJUSTIFIED (the original stays suppressed;
	// this flags the suppression itself). Deterministic, no model calls.
	if adj := suppress.Adjudicate(suppressions, suppressedFindings); len(adj) > 0 {
		findings = append(findings, suppress.AdjudicationFindings(adj)...)
	}

	// Cap findings to keep output actionable: max 3 per rule, 20 per file.
	var cappedCount int
	findings, cappedCount = CapFindings(findings, DefaultPerRuleCap, DefaultPerFileCap)

	// Reduce severity for findings in test / fixture files.
	// Test code intentionally contains vulnerable patterns so we downgrade
	// rather than suppress entirely — the hints are still useful.
	isTest := fpfilter.IsTestFile(filePath)
	isInfra := !isTest && fpfilter.IsInfraFile(filePath)
	if isTest || isInfra {
		tag := "test-file"
		if isInfra {
			tag = "infra-file"
		}
		for i := range findings {
			if findings[i].Severity > rules.Low {
				findings[i].Severity = rules.Low
			}
			findings[i].Tags = appendUnique(findings[i].Tags, tag)
		}
	}

	// Edge-case confidence adjustments, compute final risk score, and sync labels.
	for i := range findings {
		if findings[i].RuleID == "BATOU-TIMEOUT" || findings[i].RuleID == "BATOU-PANIC" {
			findings[i].ConfidenceScore = 0.2
		}
		if (isTest || isInfra) && findings[i].ConfidenceScore > 0.3 {
			findings[i].ConfidenceScore = 0.3
		}
		// Cross-file BATOU-INTERPROC findings produced by per-file
		// PropagateInterproc may have a caller-file (FilePath) that
		// differs from the scanned file (e.g. when the call graph
		// resolves to a cross-file edge). Apply the test/infra cap
		// based on the finding's own FilePath so noise on test-
		// shaped paths never reaches the 0.7 block threshold.
		CapInterprocConfidenceForTestPaths(&findings[i])
		// Demote low-value style/heuristic findings (Go goroutine/defer/weak-
		// crypto-import lints, CWE-117 log injection) to hint tier so a single
		// style nit never blocks a write or dominates a real-repo headline.
		// This only lowers confidence — findings still emit, so recall measured
		// at minConf=0 is unchanged.
		CapLowValueHeuristicConfidence(&findings[i])
		// External-origin block invariant (A NO-FLOW→NO-BLOCK / B WEAK-SOURCE→
		// NO-BLOCK): cap any finding NOT confirmed by a taint/interproc flow from
		// a genuine external source below the 0.70 block threshold. Applied
		// post-dedup so a genuinely reachable instance — which wins dedup at the
		// taint tier with a real external SourceCategory — keeps blocking, while a
		// bare structural smell (null taint) or an ambient/param-name-fabricated
		// flow stays a hint. Case (A) subsumes the former per-rule AST-structural
		// denylist (CapASTStructuralConfidence) into one invariant: every
		// pure-AST-structural Critical has a null taint path, so it has no
		// confirming external-origin flow and is capped here. Emission is
		// unchanged, so recall at minConf=0 (OWASP / CVE benches) is identical.
		// Runs last among the caps so its ceiling is authoritative for
		// block-eligibility.
		CapNonExternalOriginConfidence(&findings[i])
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
		// PR-V: env-gated SSA engine. Merge flows so hint generation and
		// downstream dedup see both engines' results. Cheap no-op when the
		// gate is off (skips parser + type-check + SSA build entirely).
		if ssaflowEnabledForScanner() {
			if ssaFlows := ssaflow.AnalyzeGo(content, filePath); len(ssaFlows) > 0 {
				taintFlows = append(taintFlows, ssaFlows...)
			}
		}
	} else if tsflow.Supports(lang) && ast.SupportsLanguage(lang) {
		// Reuse tree-sitter tree from Layer 2 if available.
		taintFlows = tsflow.AnalyzeWithTree(content, filePath, lang, tree)
	} else {
		// No tree-sitter grammar for this lang (e.g. Zig) — regex fallback.
		taintFlows = taint.Analyze(content, filePath, lang)
	}

	hintCtx := &hints.HintContext{
		FilePath:           filePath,
		Language:           lang,
		Findings:           findings,
		SuppressedFindings: suppressedFindings,
		Suppressions:       suppressions,
		TaintFlows:         taintFlows,
		CallGraph:          callGraph,
		ChangedFunc:        changedFuncName,
		IsNewFile:          input.IsWriteOperation(),
		ScanTimeMs:         result.ScanTimeMs,
		CappedCount:        cappedCount,
	}

	// hints.GenerateHints reads callGraph.Nodes via GetTransitiveCallers;
	// lock the graph for the read so it can't race a concurrent
	// scanner.Scan in another goroutine (SharedCallGraph mode).
	if callGraph != nil {
		callGraph.Mu.Lock()
	}
	hintList := hints.GenerateHints(hintCtx)
	if callGraph != nil {
		callGraph.Mu.Unlock()
	}
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
		if isSuppressComment(trimmed) {
			continue
		}
		// Trailing-comment form: `existing code ... // batou:ignore ...`.
		// Strip the trailing comment and check if the residue matches an
		// existing line. This covers the case where an agent moves a
		// pure-comment directive inline to the sink line — a semantically
		// equivalent edit that earlier versions rejected.
		if residue, ok := stripTrailingSuppress(trimmed); ok {
			if count, ok := oldSet[residue]; ok && count > 0 {
				oldSet[residue]--
				continue
			}
		}
		return false
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

// stripTrailingSuppress removes a trailing `<comment-prefix> batou:ignore ...`
// segment from a line and returns the code portion. It returns ok=false when
// the line has no trailing suppress comment. Comment prefixes considered are
// the same set used by isSuppressComment — // and # cover Go/Python/Ruby/etc.
func stripTrailingSuppress(line string) (string, bool) {
	lower := strings.ToLower(line)
	ignoreIdx := strings.Index(lower, "batou:ignore")
	if ignoreIdx <= 0 {
		return "", false
	}
	// Walk back to find the comment marker that opens the trailing comment.
	prefix := line[:ignoreIdx]
	for _, marker := range []string{"//", "#", "--", "/*", "<!--"} {
		if idx := strings.LastIndex(prefix, marker); idx >= 0 {
			residue := strings.TrimRight(line[:idx], " \t")
			if residue == "" {
				// The whole line is a pure-comment directive — not trailing.
				return "", false
			}
			return residue, true
		}
	}
	return "", false
}

// detectNewSuppressDirectives checks if the agent is adding new batou:ignore
// directives. For directives that lack an explanatory reason (the `-- …`
// suffix), it injects a BATOU-SUPPRESS-REVIEW finding so the agent is
// nudged to document WHY the finding is a false positive. A directive with
// a non-empty reason is treated as a self-correction the agent already
// thought through — no review finding fires.
func detectNewSuppressDirectives(input *hook.Input, newContent string, result *reporter.ScanResult) {
	newLines := strings.Split(newContent, "\n")

	// Collect all directive line numbers in new content.
	var newDirectives []int
	for i, line := range newLines {
		if strings.Contains(strings.ToLower(line), "batou:ignore") {
			newDirectives = append(newDirectives, i+1)
		}
	}
	if len(newDirectives) == 0 {
		return
	}

	// Read existing file to find pre-existing directives (so we only flag
	// directives the agent is ADDING, not ones already in the file).
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

	added := len(newDirectives) - existingCount
	if added <= 0 {
		return
	}

	// Flag only the newly-added directives that LACK a `-- reason` suffix.
	// An agent that wrote a specific reason has already self-corrected:
	// either they identified a genuine false positive or they documented
	// intent. Either way, don't lecture them.
	start := len(newDirectives) - added
	for _, lineNum := range newDirectives[start:] {
		line := newLines[lineNum-1]
		if directiveHasReason(line) {
			continue
		}
		result.Findings = append(result.Findings, rules.Finding{
			RuleID:          "BATOU-SUPPRESS-REVIEW",
			Severity:        rules.Medium,
			SeverityLabel:   rules.Medium.String(),
			Title:           "Document why this suppression is a false positive",
			Description:     "A batou:ignore directive was added without a reason. If this finding is genuinely a false positive, add `-- <reason>` explaining why (e.g. `# batou:ignore file_read -- local CLI utility; user-supplied path is intentional`). If the finding is real, remove the directive and fix the underlying issue. No need to ask for permission — decide and document.",
			Suggestion:      "Append `-- <specific reason>` to the directive, or remove it and fix the code.",
			FilePath:        filePath,
			LineNumber:      lineNum,
			Confidence:      "high",
			ConfidenceScore: 1.0,
			RiskScore:       0.3, // informational; well below the 0.7 block threshold
			Tags:            []string{"suppress-review", "workflow"},
		})
	}
}

// directiveHasReason reports whether a batou:ignore directive line carries a
// non-empty reason after the `--` separator. Example: both
//
//	# batou:ignore file_read -- local CLI utility
//	// batou:ignore-start injection -- pre-validated by middleware
//
// return true. A bare `# batou:ignore file_read` returns false.
func directiveHasReason(line string) bool {
	lower := strings.ToLower(line)
	idx := strings.Index(lower, "batou:ignore")
	if idx < 0 {
		return false
	}
	rest := line[idx+len("batou:ignore"):]
	dashIdx := strings.Index(rest, "--")
	if dashIdx < 0 {
		return false
	}
	reason := strings.TrimSpace(rest[dashIdx+2:])
	return reason != ""
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

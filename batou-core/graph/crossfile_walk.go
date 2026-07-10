// Cross-file interprocedural walk.
//
// PropagateInterproc (the per-file interproc engine) walks CalledBy
// edges to find callers and run AnalyzeCallerImpact on each. Per-file
// scans call it BEFORE the cross-file resolution pass populates the
// CalledBy edges that span files, so a first-time full scan never sees
// cross-file interproc flows. WalkCrossFileTaintFlows runs after the
// cross-file resolution finishes and re-walks every cross-file edge
// against AnalyzeCallerImpact to surface those findings.
//
// This is a "fix forward" pass: it doesn't re-emit same-file findings
// (those came from PropagateInterproc during the per-file scan), only
// cross-file ones.
package graph

import (
	"sort"

	"github.com/turenlabs/batou-rules/rules"
)

// crossFileSinkKey is the dedup key used by WalkCrossFileTaintFlows to
// collapse middleware-chain explosion. When N middleware layers each
// forward the same source-typed param to the same eventual sink, the
// per-pair walker emits N otherwise-distinct findings: each pair has a
// different caller, but they all point at the same vulnerable call
// site. The leaf-sink position (deepSinkFile, deepSinkLine) is recorded
// as the last TaintStep of each finding (Kind == TaintStepSink) so
// extraction is straightforward.
//
// The key includes the SOURCE position (file+line) AND category, plus
// the rule ID, so genuinely-distinct flows targeting the same physical
// sink stay separate findings. PR-NN's original key used sourceCategory
// alone, which collapsed sibling handlers (each with a distinct
// *http.Request source) that all forwarded to the same downstream
// sink. PR-OO widened the key to fix that recall regression — the
// dedup now only fires when the SAME source reaches the SAME sink via
// multiple call paths (the original middleware-chain pathology).
type crossFileSinkKey struct {
	deepSinkFile   string
	deepSinkLine   int
	ruleID         string // e.g. BATOU-INTERPROC-LOG_OUTPUT
	sourceFile     string
	sourceLine     int
	sourceCategory string
}

// WalkCrossFileTaintFlows iterates every cross-file caller→callee edge
// in the call graph and runs AnalyzeCallerImpact on each. Returns the
// findings the cross-file walk discovered; same-file findings are NOT
// produced here (they came from the per-file interproc layer).
//
// fileContents is an optional map of file_path → content; when the
// caller's file isn't in the map the walker reads it from disk via the
// same loadCallerFile helper PropagateInterproc uses. Pass an empty map
// to force all reads from disk (the common case at dirscan finalize
// time — by then the per-file goroutines have released their content).
//
// Findings are returned in deterministic file/line order so JSONL
// output is reproducible across runs.
func WalkCrossFileTaintFlows(cg *CallGraph, fileContents map[string]string) []rules.Finding {
	return WalkCrossFileTaintFlowsWithStats(cg, fileContents, nil)
}

// CrossFileWalkStats is a counter struct populated by
// WalkCrossFileTaintFlowsWithStats for diagnostics.
type CrossFileWalkStats struct {
	Pairs             int // cross-file caller-callee pairs considered
	CalleeHasSink     int // callees whose taint_sig has a SinkCall
	CalleeTaintedRet  int // callees whose taint_sig has a tainted return
	ContentLoadFailed int // pairs skipped because caller file couldn't be loaded
}

func WalkCrossFileTaintFlowsWithStats(cg *CallGraph, fileContents map[string]string, stats *CrossFileWalkStats) []rules.Finding {
	if cg == nil {
		return nil
	}
	if fileContents == nil {
		fileContents = map[string]string{}
	}

	// Sorted node-ID iteration so the emitted findings slice is in a
	// reproducible order across runs (Go map iteration is randomised).
	ids := make([]string, 0, len(cg.Nodes))
	for id := range cg.Nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var findings []rules.Finding
	// Module-wide dedup keyed by the LEAF sink + source category.
	// Middleware-chain pathologies (N layers each forwarding the same
	// param to the same downstream sink) produce N distinct (caller,
	// callee) pairs but a single vulnerable call site. The first
	// finding for any unique key wins; subsequent ones are dropped. See
	// crossFileSinkKey docstring for the rationale.
	seen := make(map[crossFileSinkKey]bool)
	caches := newCrossFileCallIdxCaches()
	for _, id := range ids {
		callee := cg.Nodes[id]
		if callee == nil {
			continue
		}
		if len(callee.CalledBy) == 0 {
			continue
		}
		ensureCalleeSignatures(cg, callee)

		// Fast-skip: callees with neither sinks nor tainted-return
		// signatures cannot produce findings — AnalyzeCallerImpact and
		// AnalyzeCallerImpactPython both short-circuit on this condition.
		// Hoisting the check out of the inner loop saves per-caller
		// loadCallerFile reads + stats updates for leaves that can't
		// produce findings. Mirrors the analogous Go quick-skip PR-MM
		// landed for the same-file PropagateInterproc path.
		// TaintedReturnPaths (JS/TS field-sensitive returns, PR3) is an
		// independent producer signal: a callee returning an object literal
		// with a tainted FIELD (`return {user:{id:req.query.id}}`) has no
		// whole-return taint but can still drive a Path B field-composition
		// finding, so it must not be fast-skipped.
		if len(callee.TaintSig.SinkCalls) == 0 && len(callee.TaintSig.TaintedReturns) == 0 && len(callee.TaintSig.TaintedReturnPaths) == 0 {
			if stats != nil {
				stats.Pairs += len(callee.CalledBy)
			}
			continue
		}
		for _, callerID := range callee.CalledBy {
			caller := cg.GetNode(callerID)
			if caller == nil {
				continue
			}
			if caller.FilePath == callee.FilePath {
				continue
			}
			if stats != nil {
				stats.Pairs++
				if len(callee.TaintSig.SinkCalls) > 0 {
					stats.CalleeHasSink++
				}
				if len(callee.TaintSig.TaintedReturns) > 0 {
					stats.CalleeTaintedRet++
				}
			}

			callerContent, ok := loadCallerFile(cg, caller.FilePath, fileContents)
			if !ok {
				if stats != nil {
					stats.ContentLoadFailed++
				}
				continue
			}

			impact := analyzeCrossFilePair(cg, caller, callee, callerContent, caches)
			for _, f := range impact {
				key := crossFileSinkKeyForFinding(f)
				// When the key is "empty" (no sink step on the path,
				// e.g. for Path-B tainted-return findings whose sink
				// row is the caller's own sink line not a separate
				// step) skip dedup — every finding stays. We don't
				// want a missing leaf-sink to silently collapse
				// unrelated findings.
				if key.deepSinkFile != "" {
					if seen[key] {
						continue
					}
					seen[key] = true
				}
				findings = append(findings, f)
			}
		}
	}
	return findings
}

// crossFileCallIdxCaches bundles the per-pass tree-sitter parse caches
// used by the per-language caller-impact analyzers. The walker touches
// the same caller file once per callee that lives across the boundary;
// without a cache, each analyzer reparses the caller's full source for
// every callee. One instance lives for the duration of a single walk
// (full-graph or file-scoped), mirroring the original per-pass locals.
type crossFileCallIdxCaches struct {
	py     *pythonCallIndexCache
	js     *javascriptCallIndexCache
	ruby   *rubyCallIndexCache
	lua    *luaCallIndexCache
	kotlin *kotlinCallIndexCache
	groovy *groovyCallIndexCache
	perl   *perlCallIndexCache
	shell  *shellCallIndexCache
	cpp    *cppCallIndexCache
	swift  *swiftCallIndexCache
	rust   *rustCallIndexCache
	csharp *csharpCallIndexCache
	php    *phpCallIndexCache
	// generic is the sanitizer-facts memo for the default (Go/Java)
	// analyzer route, which has no per-language call-index cache of its
	// own to carry one. Same pass-scoped lifetime as the caches above.
	generic *sanitizerFactsMemo
}

func newCrossFileCallIdxCaches() *crossFileCallIdxCaches {
	return &crossFileCallIdxCaches{
		generic: newSanitizerFactsMemo(),
		py:     newPythonCallIndexCache(),
		js:     newJavaScriptCallIndexCache(),
		ruby:   newRubyCallIndexCache(),
		lua:    newLuaCallIndexCache(),
		kotlin: newKotlinCallIndexCache(),
		groovy: newGroovyCallIndexCache(),
		perl:   newPerlCallIndexCache(),
		shell:  newShellCallIndexCache(),
		cpp:    newCPPCallIndexCache(),
		swift:  newSwiftCallIndexCache(),
		rust:   newRustCallIndexCache(),
		csharp: newCSharpCallIndexCache(),
		php:    newPHPCallIndexCache(),
	}
}

// ensureCalleeSignatures lazily populates a callee's SinkCalls /
// TaintedReturns for languages whose per-file walker doesn't regex-scan
// them (everything except Go). Idempotent — each ensure* helper
// publishes once and re-checks. Hoisted out of the walk loops so both
// the full-graph walk and the file-scoped hook walk share the exact
// same population semantics.
func ensureCalleeSignatures(cg *CallGraph, callee *FuncNode) {
	// Lazy-populate Python callee sinks once per callee. AnalyzeCaller-
	// ImpactPython does this per (caller, callee) pair via ensure-
	// PythonCalleeSinks, but that helper is idempotent — hoisting it
	// here keeps the lazy semantics (tests that skip Propagate-
	// SignaturesAcrossCallgraph still get the population) while
	// letting the fast-skip in the walk cover Python leaves too.
	if callee.Language == rules.LangPython {
		ensurePythonCalleeSinks(cg, callee)
	}
	// JS/TS callees arrive without SinkCalls or TaintedReturns
	// populated for the same reason Python / Lua do (the per-file
	// walker is regex-Go-specific). Lazy-populate both once per
	// callee so the fast-skip covers JS/TS leaves too — without the
	// tainted-return seeding, the canonical `return req.query.x`
	// getter idiom never clears the gate.
	if callee.Language == rules.LangJavaScript || callee.Language == rules.LangTypeScript {
		ensureJavaScriptCalleeSinks(cg, callee)
		ensureJavaScriptCalleeReturns(cg, callee)
	}
	// Ruby callees: same situation — the per-file walker doesn't
	// regex-scan Ruby sinks. Lazy-populate so the fast-skip covers
	// Ruby leaves.
	if callee.Language == rules.LangRuby {
		ensureRubyCalleeSinks(cg, callee)
	}
	// Lua callees: same situation — the per-file walker doesn't
	// regex-scan Lua sinks or tainted returns. Lazy-populate so the
	// fast-skip covers Lua leaves (PR-Glua).
	if callee.Language == rules.LangLua {
		ensureLuaCalleeSinks(cg, callee)
		ensureLuaCalleeReturns(cg, callee)
	}
	if callee.Language == rules.LangKotlin {
		ensureKotlinCalleeSinks(cg, callee)
		ensureKotlinCalleeReturns(cg, callee)
	}
	if callee.Language == rules.LangGroovy {
		ensureGroovyCalleeSinks(cg, callee)
		ensureGroovyCalleeReturns(cg, callee)
	}
	if callee.Language == rules.LangPerl {
		ensurePerlCalleeSinks(cg, callee)
		ensurePerlCalleeReturns(cg, callee)
	}
	if callee.Language == rules.LangShell {
		ensureShellCalleeSinks(cg, callee)
		ensureShellCalleeReturns(cg, callee)
	}
	if isCPPFamily(callee.Language) {
		ensureCPPCalleeSinks(cg, callee)
		ensureCPPCalleeReturns(cg, callee)
	}
	if callee.Language == rules.LangSwift {
		ensureSwiftCalleeSinks(cg, callee)
		ensureSwiftCalleeReturns(cg, callee)
	}
	if callee.Language == rules.LangRust {
		ensureRustCalleeSinks(cg, callee)
		ensureRustCalleeReturns(cg, callee)
	}
	if callee.Language == rules.LangCSharp {
		ensureCSharpCalleeSinks(cg, callee)
		ensureCSharpCalleeReturns(cg, callee)
	}
	// PHP callees: the per-file walker doesn't regex-scan PHP sinks or
	// tainted returns either. Lazy-populate so the fast-skip covers PHP
	// leaves (PR-Gphp).
	if callee.Language == rules.LangPHP {
		ensurePHPCalleeSinks(cg, callee)
		ensurePHPCalleeReturns(cg, callee)
	}
}

// analyzeCrossFilePair routes a single (caller, callee) pair to the
// per-language caller-impact analyzer. AnalyzeCallerImpact is Go-
// specific (Go regex sink list, Go arg parsing); Python goes through
// AnalyzeCallerImpactPython which uses tree-sitter + the Python taint
// catalog; JS/TS through AnalyzeCallerImpactJavaScript; etc. Languages
// without their own walker fall back to the Go path (no findings
// expected).
func analyzeCrossFilePair(cg *CallGraph, caller, callee *FuncNode, callerContent string, caches *crossFileCallIdxCaches) []rules.Finding {
	switch callee.Language {
	case rules.LangPython:
		return analyzeCallerImpactPythonCached(cg, caller, callee, callerContent, caches.py)
	case rules.LangJavaScript, rules.LangTypeScript:
		return analyzeCallerImpactJavaScriptCached(cg, caller, callee, callerContent, caches.js)
	case rules.LangRuby:
		return analyzeCallerImpactRubyCached(cg, caller, callee, callerContent, caches.ruby)
	case rules.LangLua:
		return analyzeCallerImpactLuaCached(cg, caller, callee, callerContent, caches.lua)
	case rules.LangKotlin:
		return analyzeCallerImpactKotlinCached(cg, caller, callee, callerContent, caches.kotlin)
	case rules.LangGroovy:
		return analyzeCallerImpactGroovyCached(cg, caller, callee, callerContent, caches.groovy)
	case rules.LangPerl:
		return analyzeCallerImpactPerlCached(cg, caller, callee, callerContent, caches.perl)
	case rules.LangShell:
		return analyzeCallerImpactShellCached(cg, caller, callee, callerContent, caches.shell)
	case rules.LangC, rules.LangCPP:
		return analyzeCallerImpactCPPCached(cg, caller, callee, callerContent, caches.cpp)
	case rules.LangSwift:
		return analyzeCallerImpactSwiftCached(cg, caller, callee, callerContent, caches.swift)
	case rules.LangRust:
		return analyzeCallerImpactRustCached(cg, caller, callee, callerContent, caches.rust)
	case rules.LangCSharp:
		return analyzeCallerImpactCSharpCached(cg, caller, callee, callerContent, caches.csharp)
	case rules.LangPHP:
		return analyzeCallerImpactPHPCached(cg, caller, callee, callerContent, caches.php)
	default:
		return analyzeCallerImpactWithSanMemo(cg, caller, callee, callerContent, caches.generic)
	}
}

// maxHookCrossFilePairs bounds how many cross-file (caller, callee)
// pairs the file-scoped hook walk analyzes per invocation. A file with
// more outbound cross-file callees than this keeps only the first N in
// sorted order; the next full `batou scan` covers everything. Keeps the
// added write-time latency bounded on files that call into hundreds of
// modules.
const maxHookCrossFilePairs = 200

// WalkCrossFileTaintFlowsForCaller is the write-time-hook-scoped variant
// of WalkCrossFileTaintFlows: it analyzes ONLY the cross-file pairs whose
// CALLER is defined in callerFile, walking that file's outbound Calls
// edges one hop. The callee side comes from the persisted scan-built
// graph (TaintSig.SinkCalls / TaintedReturns, including sinks lifted by
// PropagateSignaturesAcrossCallgraph — so multi-hop chains through
// unchanged intermediates still surface).
//
// The complementary direction — the edited file as CALLEE — is covered
// by PropagateInterproc, which walks the changed functions' CalledBy
// edges (cross-file ones restored by ResolveCrossFileEdgesForFile) and
// loads caller files from disk. The two emit disjoint pair sets, so no
// dedup is needed between them.
//
// fileContents should carry the edited file's in-memory content so the
// caller side is analyzed against what is being WRITTEN, not what's on
// disk. Findings are returned in deterministic order (sorted caller
// node IDs, sorted callee IDs).
func WalkCrossFileTaintFlowsForCaller(cg *CallGraph, callerFile string, fileContents map[string]string) []rules.Finding {
	if cg == nil || callerFile == "" {
		return nil
	}
	if fileContents == nil {
		fileContents = map[string]string{}
	}
	callers := cg.NodesInFile(callerFile)
	if len(callers) == 0 {
		return nil
	}
	sort.Slice(callers, func(i, j int) bool { return callers[i].ID < callers[j].ID })

	caches := newCrossFileCallIdxCaches()
	seen := make(map[crossFileSinkKey]bool)
	var findings []rules.Finding
	pairs := 0
	for _, caller := range callers {
		calleeIDs := append([]string(nil), caller.Calls...)
		sort.Strings(calleeIDs)
		for _, calleeID := range calleeIDs {
			callee := cg.GetNode(calleeID)
			if callee == nil || callee.FilePath == callerFile {
				continue
			}
			if pairs >= maxHookCrossFilePairs {
				capHits.pairs.Add(1) // diagnostics only: remaining cross-file pairs were not walked
				return findings
			}
			pairs++
			ensureCalleeSignatures(cg, callee)
			if len(callee.TaintSig.SinkCalls) == 0 && len(callee.TaintSig.TaintedReturns) == 0 && len(callee.TaintSig.TaintedReturnPaths) == 0 {
				continue
			}
			callerContent, ok := loadCallerFile(cg, caller.FilePath, fileContents)
			if !ok {
				continue
			}
			impact := analyzeCrossFilePair(cg, caller, callee, callerContent, caches)
			for _, f := range impact {
				key := crossFileSinkKeyForFinding(f)
				if key.deepSinkFile != "" {
					if seen[key] {
						continue
					}
					seen[key] = true
				}
				findings = append(findings, f)
			}
		}
	}
	return findings
}

// crossFileSinkKeyForFinding extracts the dedup key from a finding's
// TaintPath. The leaf-sink step is the last step with Kind ==
// TaintStepSink; its File + Line are the position of the actual
// dangerous call. The source step is the first step with Kind ==
// TaintStepSource (or the very first step if no explicit source marker
// is present); its File + Line identify where the tainted value enters
// the chain. Returns the zero value when no sink step is present;
// callers treat that as "don't dedup" so unusual finding shapes don't
// get silently collapsed.
func crossFileSinkKeyForFinding(f rules.Finding) crossFileSinkKey {
	key := crossFileSinkKey{}
	hasSink := false
	for i := len(f.TaintPath) - 1; i >= 0; i-- {
		st := f.TaintPath[i]
		if st.Kind == rules.TaintStepSink {
			key.deepSinkFile = st.File
			key.deepSinkLine = st.Line
			hasSink = true
			break
		}
	}
	if !hasSink {
		return crossFileSinkKey{}
	}
	// Source step: prefer an explicit TaintStepSource; fall back to the
	// first step when no explicit source marker is present (some flow
	// builders don't tag the leading step).
	for _, st := range f.TaintPath {
		if st.Kind == rules.TaintStepSource {
			key.sourceFile = st.File
			key.sourceLine = st.Line
			break
		}
	}
	if key.sourceFile == "" && len(f.TaintPath) > 0 {
		key.sourceFile = f.TaintPath[0].File
		key.sourceLine = f.TaintPath[0].Line
	}
	key.ruleID = f.RuleID
	key.sourceCategory = f.SourceCategory
	return key
}

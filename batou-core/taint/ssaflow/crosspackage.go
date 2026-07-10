package ssaflow

// Cross-package SSA taint analysis.
//
// PR-AA introduced per-function summaries and a fixed-point driver that
// propagated taint across same-package call edges. That is sufficient for
// single-file or single-package scans but misses what is, in real Go
// repositories, the most common shape of taint: a handler in package
// `app/http` calls into `app/store`, which calls into `app/db`, which
// builds the SQL. Without cross-package summaries the per-file engine
// only catches the deepest sink (inside `app/db`) and misses the call
// chain that connects user input to that sink.
//
// This file extends the SSA engine to build summaries for every package
// in the file's Go module (via packages.Load + ssautil.Packages), so the
// same fixed-point can resolve a callee's summary even when the callee
// is in a different package — provided that package is in the SAME
// MODULE. Stdlib and third-party packages are still opaque: their
// summaries are absent and the engine falls back to the per-call sink
// catalog, matching the pre-PR behaviour.
//
// Scope and explicit non-goals (see crossfunction.go for the rationale
// behind the SSA engine's general scope limits, all of which still hold
// here):
//   - Module-local only. A repository with multiple go.mod files
//     (multi-module workspace, vendor/ tree) is treated as multiple
//     independent modules; cross-module taint is out of scope.
//   - Same-build-tag set: packages.Load uses the ambient GOOS / GOARCH /
//     build tags. Files behind non-matching tags are not analyzed.
//   - Best-effort load: if packages.Load fails (no go.mod, broken
//     imports, vendor mismatch, etc.) we silently fall back to the
//     existing single-file build.
//   - Returns flows scoped to the file the caller asked about. The
//     module-wide summary table is computed once and cached, but only
//     functions defined in the requested file produce TaintFlow records
//     — keeping the scanner's per-file emission contract intact.
//
// Performance: the module load is the dominant cost. A first scan of a
// medium-sized module (~50 packages, ~5kLOC) takes ~1.5s vs ~10ms for
// a single-file SSA build; subsequent scans of files in the same module
// reuse the cached program and pay only the per-file emission cost. The
// cache is keyed by module root and never invalidated within a single
// process invocation — appropriate because the scanner is short-lived
// (a Claude Code hook spans one tool call).
//
// Concurrency: the cache uses sync.Mutex for entry creation. SSA
// construction itself is internally concurrent (ssautil.Packages calls
// Program.Build which fans out across packages). Emission walks each
// function's blocks serially but is safe to invoke concurrently across
// files in different modules (different cache entries). Same-module
// concurrent calls serialize on the cache mutex during the first load,
// then proceed in parallel.

import (
	"bufio"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// maxModuleSummaryIterations bounds the cross-package fixed-point. We
// allow more iterations than the per-package driver in crossfunction.go
// (maxSummaryIterations=10) because real cross-package chains can be
// deeper — a handler → service → repository → db layering is common,
// and each layer may itself fan out to several callees that all need to
// stabilize before the chain finalises. Real modules converge in well
// under 15 iterations; the cap is a defensive guard.
const maxModuleSummaryIterations = 15

// maxModuleSizeForSSA caps how many .go files a single module load will
// attempt to bring into the SSA build. Beyond this we skip the module
// load to protect the hook's latency budget — the existing single-file
// SSA build still runs, and the scanner falls back to astflow + regex
// for cross-file inference. Chosen empirically: 2500 files comfortably
// covers most application repos but rejects monorepos where SSA build
// time would dominate the hook budget. The constant is intentionally
// not configurable in this PR.
const maxModuleSizeForSSA = 2500

// moduleAnalysis is the per-module cached artifact produced by the
// cross-package builder. We hold onto:
//   - prog: the SSA program (kept alive so *ssa.Function pointers in
//     summaries remain valid for as long as the cache entry lives).
//   - summaries: module-wide funcSummary table keyed by *ssa.Function.
//     Same map type as crossfunction.go's per-package map; the only
//     change is that keys now span packages.
//   - fileToPkg: maps absolute file paths to the *ssa.Package that owns
//     them, so callers can ask "which ssa.Package corresponds to my
//     scanned file?" without walking every package's Syntax tree.
//   - fset: shared FileSet used by every parsed file in the module; we
//     emit FlowStep line numbers against it.
//   - matcher: catalog matcher reused across all per-file emissions in
//     this module so the (sink-name → index) tables aren't rebuilt for
//     every scan.
//   - loadErr: non-nil when packages.Load failed; cached so a broken
//     module doesn't get retried on every file.
type moduleAnalysis struct {
	prog      *ssa.Program
	summaries map[*ssa.Function]*funcSummary
	// methodSet marks the named-type methods in the summary table. They
	// are summarised (so method callees resolve) but excluded from the
	// index-based per-file emission scopes — emitting from a method's
	// source-typed receiver as a whole-receiver root surfaces field-blind
	// cross-function FPs. The receiver-rooted lane consumes their summaries
	// field-sensitively instead. See analyzeFileWithModule.
	methodSet  map[*ssa.Function]bool
	fileToPkg  map[string]*ssa.Package
	fset       *token.FileSet
	matcher    *catalogMatcher
	modulePath string
	loadErr    error
}

// moduleCache holds module-level analyses for the lifetime of the
// process. Keys are module roots (the directory containing go.mod).
//
// We never expire entries: the scanner is short-lived (one hook
// invocation per Claude Code tool call) and modules don't change shape
// during a run. A long-lived host process would need TTL or content
// hashing, but that's not the scanner's deployment model.
//
// The slots map holds a single moduleSlot per module root. Each slot
// owns a sync.Once that serialises buildModuleAnalysis across workers
// for the same module — without it, every dirscan worker (15 by default
// on a modern Mac) would concurrently call packages.Load on the same
// module on first access, each doing a full type-check of every
// transitive dep. That's the actual cause of the env-ON hang the
// problem statement describes — not lock contention but N concurrent
// 60s+ packages.Load calls competing for CPU and RAM.
var (
	moduleSlotsMu sync.Mutex
	moduleSlots   = make(map[string]*moduleSlot)
)

// moduleSlot serialises the first-time build of a module analysis.
// All callers for the same module share the same slot; the first one
// runs the build inside once.Do, the rest block on it and then read
// the cached entry.
type moduleSlot struct {
	once  sync.Once
	entry *moduleAnalysis
}

// getModuleAnalysis returns the cached module analysis for the module
// containing filePath, building it on first request. Returns (nil, true)
// when filePath is not inside a Go module, when the module is too large
// to analyze, or when packages.Load failed — all of which are
// non-failures: the caller falls back to single-file SSA.
//
// The second return is `shouldFallback`: true means "do not attempt
// cross-package analysis for this file; use the single-file path".
func getModuleAnalysis(filePath string) (*moduleAnalysis, bool) {
	root, modulePath := findModuleRoot(filePath)
	if root == "" {
		return nil, true
	}

	// One slot per module root — concurrent callers for the same root
	// all share the same sync.Once via this slot.
	moduleSlotsMu.Lock()
	slot, ok := moduleSlots[root]
	if !ok {
		slot = &moduleSlot{}
		moduleSlots[root] = slot
	}
	moduleSlotsMu.Unlock()

	// once.Do serialises the actual packages.Load — the first caller
	// runs the build; concurrent callers block here until it finishes,
	// then read slot.entry. No more N-way races on the same module.
	slot.once.Do(func() {
		slot.entry = buildModuleAnalysis(root, modulePath)
	})

	entry := slot.entry
	if entry == nil || entry.loadErr != nil {
		return nil, true
	}
	return entry, false
}

// buildModuleAnalysis is the worker that loads the module, builds SSA
// for every package, and runs the module-wide fixed-point summary pass.
// Returns nil on any unrecoverable load failure (caller falls back).
func buildModuleAnalysis(moduleRoot, modulePath string) *moduleAnalysis {
	// Defensive: never let a malformed module crash the scanner.
	defer func() { _ = recover() }()

	cat := taint.GetCatalog(rules.LangGo)
	if cat == nil {
		return &moduleAnalysis{loadErr: errCatalogMissing}
	}

	// Quick size check: if the module is enormous, refuse to load it
	// and let the per-file SSA pass continue. We count .go files
	// directly rather than calling packages.Load with NeedFiles first
	// because counting is far cheaper than a full load.
	if countGoFilesUnder(moduleRoot, maxModuleSizeForSSA+1) > maxModuleSizeForSSA {
		return &moduleAnalysis{loadErr: errModuleTooLarge}
	}

	cfg := &packages.Config{
		// LoadAllSyntax: full type-checked syntax for every package
		// the query matches, INCLUDING transitive in-project deps so
		// that callee summaries are computable for every same-module
		// callee. We also add NeedDeps to surface stdlib *types.Package
		// pointers (needed by our catalog matcher's package-name check).
		Mode:  packages.LoadAllSyntax | packages.NeedDeps,
		Dir:   moduleRoot,
		Tests: false,
	}

	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return &moduleAnalysis{loadErr: err}
	}
	if len(pkgs) == 0 {
		return &moduleAnalysis{loadErr: errNoPackages}
	}

	// Build SSA for every loaded package. ssautil.Packages tolerates
	// individual package errors — those packages produce nil entries
	// in the returned slice and we skip them when iterating.
	prog, ssaPkgs := ssautil.Packages(pkgs, ssa.SanityCheckFunctions)
	if prog == nil {
		return &moduleAnalysis{loadErr: errSSABuildFailed}
	}
	prog.Build()

	// Index loaded files → owning ssa.Package. We use the absolute
	// path so callers can map their scan target to a package without
	// having to re-resolve relative paths.
	fileToPkg := make(map[string]*ssa.Package)
	for i, p := range pkgs {
		if p == nil || i >= len(ssaPkgs) || ssaPkgs[i] == nil {
			continue
		}
		files := p.CompiledGoFiles
		if len(files) == 0 {
			files = p.GoFiles
		}
		for _, f := range files {
			abs, err := filepath.Abs(f)
			if err != nil {
				abs = f
			}
			fileToPkg[abs] = ssaPkgs[i]
		}
	}

	matcher := newCatalogMatcher(cat.Sinks(), cat.Sanitizers())

	// Collect every analyzable function across the module (filtered to
	// packages owned by ssaPkgs — i.e. in-project plus stdlib bodies
	// that ssautil chose to materialise; stdlib functions are NOT in
	// scope for summarization so we restrict to ssaPkgs membership
	// later via the `fn.Pkg != nil` check during emission).
	funcs := collectModuleFunctions(ssaPkgs)

	// Pre-populate the summary table with empty summaries so the
	// fixed-point driver can look up callee summaries by pointer
	// without nil-checks for known functions.
	summaries := make(map[*ssa.Function]*funcSummary, len(funcs))
	for _, fn := range funcs {
		summaries[fn] = newSummary(fn)
	}

	// Module-wide fixed-point pass. Same monotonic-lattice argument
	// as crossfunction.go applies: each iteration can only ADD facts
	// to a summary; convergence is guaranteed even without the cap.
	// The cap exists to bound worst-case latency on pathological
	// inputs.
	fset := prog.Fset
	for iter := 0; iter < maxModuleSummaryIterations; iter++ {
		changed := false
		for _, fn := range funcs {
			prev := summaries[fn]
			next := computeSummary(fn, summaries, matcher, fset)
			if !prev.equal(next) {
				summaries[fn] = next
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	return &moduleAnalysis{
		prog:       prog,
		summaries:  summaries,
		methodSet:  moduleMethods(ssaPkgs),
		fileToPkg:  fileToPkg,
		fset:       fset,
		matcher:    matcher,
		modulePath: modulePath,
	}
}

// collectModuleFunctions returns every ssa.Function across the supplied
// packages — including AnonFuncs — matching the iteration shape used by
// crossfunction.collectFunctions but spanning packages.
//
// Functions with no Blocks (declared without a body, e.g. assembly stubs
// or extern decls) are filtered. Synthetic init wrappers are kept (they
// carry no params so produce empty summaries cheaply).
func collectModuleFunctions(ssaPkgs []*ssa.Package) []*ssa.Function {
	var out []*ssa.Function
	var visit func(fn *ssa.Function)
	visit = func(fn *ssa.Function) {
		if fn == nil || fn.Blocks == nil {
			return
		}
		out = append(out, fn)
		for _, anon := range fn.AnonFuncs {
			visit(anon)
		}
	}
	for _, p := range ssaPkgs {
		if p == nil {
			continue
		}
		for _, member := range p.Members {
			if fn, ok := member.(*ssa.Function); ok {
				visit(fn)
			}
		}
		// Materialise named-type methods (see packageMethods) so method
		// callees are summarised in the module pass too. They are tagged
		// in moduleMethodSet (caller-side) so the index-based emitter can
		// skip them as emission scopes; the receiver-rooted lane consumes
		// their summaries instead.
		for _, m := range packageMethods(p) {
			visit(m)
		}
	}
	return out
}

// moduleMethods returns just the named-type methods across ssaPkgs (a subset
// of collectModuleFunctions), so the module emitter can identify which
// collected functions are methods and exclude them from the index-based
// emission lane. Returned as a set for O(1) membership checks.
func moduleMethods(ssaPkgs []*ssa.Package) map[*ssa.Function]bool {
	set := make(map[*ssa.Function]bool)
	for _, p := range ssaPkgs {
		if p == nil {
			continue
		}
		for _, m := range packageMethods(p) {
			set[m] = true
		}
	}
	return set
}

// analyzeFileWithModule produces TaintFlows for the functions declared in
// filePath using the module-wide summary table. Functions in OTHER files
// of the module still participate in the summary table (so cross-package
// callees can be resolved) but only flows scoped to the requested file
// are returned — this preserves the per-file emission contract the
// scanner relies on.
//
// Returns nil when filePath is not part of the loaded module (e.g. the
// file is outside ./... or its build tags excluded it). The caller falls
// back to the single-file SSA pass in that case.
func analyzeFileWithModule(mod *moduleAnalysis, content, filePath string) []taint.TaintFlow {
	if mod == nil {
		return nil
	}
	abs, err := filepath.Abs(filePath)
	if err != nil {
		abs = filePath
	}
	pkg := mod.fileToPkg[abs]
	if pkg == nil {
		// The file isn't tracked by the loaded module — most often
		// because the scanner is asked about a synthetic in-memory
		// path (e.g. tests pass "/app/handler.go"). Caller falls back
		// to single-file SSA.
		return nil
	}

	// Identify which ssa.Functions in the module were compiled from
	// this exact file. We use the FileSet's Position to map each
	// function's start position back to a filename. SSA-synthesised
	// functions (wrappers, init) have NoPos and are skipped naturally.
	wantFile := abs
	var fileFuncs []*ssa.Function
	for fn := range mod.summaries {
		if fn.Pkg != pkg {
			continue
		}
		// Methods are summarised (callee lookups) but are NOT emission
		// scopes — keep the index-based per-file lanes (analyzeFunction +
		// emitCrossPackageFlows) operating only on top-level functions, the
		// exact set they ran on before methods were summarised. The
		// receiver-rooted lane (below) handles method-mediated flows
		// field-sensitively. See moduleAnalysis.methodSet.
		if mod.methodSet[fn] {
			continue
		}
		pos := fn.Pos()
		if !pos.IsValid() {
			continue
		}
		name := mod.fset.Position(pos).Filename
		if name == "" {
			continue
		}
		// packages.Load resolves filenames via filepath.Abs already,
		// but be defensive and compare the basename if absolute paths
		// don't line up (CGo + Windows path normalisation differ).
		if name == wantFile || filepath.Base(name) == filepath.Base(wantFile) {
			fileFuncs = append(fileFuncs, fn)
		}
	}
	if len(fileFuncs) == 0 {
		return nil
	}

	// Intra-procedural pass — emit flows for every typed-source param
	// reaching a sink inside the same function. Same code path as
	// AnalyzeGo's per-file driver; we just restrict to functions in
	// this file.
	var flows []taint.TaintFlow
	for _, fn := range fileFuncs {
		flows = append(flows, analyzeFunction(fn, mod.fset, filePath, mod.matcher)...)
	}

	// Cross-function pass — module-wide summary table, so this now
	// resolves both same-package AND cross-package callees that live
	// within the loaded module. Shared seenDeep across every fn in
	// fileFuncs so middleware-chain emissions collapse to one finding
	// per leaf sink (see crossSinkKey docstring in crossfunction.go).
	seenDeep := make(map[crossSinkKey]bool)
	for _, fn := range fileFuncs {
		flows = append(flows, emitCrossPackageFlows(fn, mod.summaries, mod.matcher, mod.fset, filePath, seenDeep)...)
		// Receiver-rooted (construction-site) lane — see receiver_rooted.go.
		// The callee method's summary is module-wide so a construction site
		// here can match a method whose body lives in another file/package.
		flows = append(flows, emitReceiverRootedFlows(fn, mod.summaries, mod.matcher, mod.fset, filePath, seenDeep)...)
	}
	return flows
}

// emitCrossPackageFlows is the cross-package analogue of
// emitCrossFunctionFlows. The body is identical EXCEPT for the
// same-package gate, which is removed: any statically resolvable
// callee with a non-nil summary entry is fair game. Callees that
// are in third-party / stdlib packages have no summary (we never
// created one for them) and therefore fall through without emitting
// a flow — preserving the catalog-based handling for opaque
// packages.
//
// Kept as a separate function rather than parameterising
// emitCrossFunctionFlows to avoid touching same-package behaviour
// while PR-DD (pointer-arg taint) is in flight: that PR is iterating
// on emitCrossFunctionFlows directly, and a shared rewrite would
// likely cause merge conflicts.
func emitCrossPackageFlows(
	fn *ssa.Function,
	summaries map[*ssa.Function]*funcSummary,
	matcher *catalogMatcher,
	fset *token.FileSet,
	filePath string,
	seenDeep map[crossSinkKey]bool,
) []taint.TaintFlow {
	if fn == nil || fn.Blocks == nil {
		return nil
	}
	paramSources := make(map[ssa.Value]*taint.SourceDef, len(fn.Params))
	for _, p := range fn.Params {
		if src := paramSource(p); src != nil {
			paramSources[p] = src
		}
	}
	if len(paramSources) == 0 {
		return nil
	}

	scopeName := fn.Name()
	if recv := fn.Signature.Recv(); recv != nil {
		scopeName = receiverTypeString(recv.Type()) + "." + scopeName
	}

	var flows []taint.TaintFlow
	seen := make(map[crossFlowKey]bool)

	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}
			callee := call.Common().StaticCallee()
			if callee == nil {
				continue
			}
			// NOTE: no same-package gate here — cross-package callees
			// are exactly the new case this PR enables. A callee with
			// no summary in the table (stdlib / third-party) drops
			// through to the `sum == nil` guard below, matching the
			// pre-PR behaviour for those callees.
			sum := summaries[callee]
			if sum == nil || len(sum.paramSinks) == 0 {
				continue
			}
			args := call.Common().Args
			offset := 0
			if !call.Common().IsInvoke() && call.Common().Signature() != nil &&
				call.Common().Signature().Recv() != nil {
				offset = 1
			}
			for paramIdx, recs := range sum.paramSinks {
				// context.Context plumbing: see context_filter.go. The
				// cross-package emitter mirrors crossfunction.go's gate
				// for the same reason — flows through a ctx param are
				// almost always control-flow metadata, not data flow.
				if calleeParamIsContext(callee, paramIdx) {
					continue
				}
				argPos := paramIdx + offset
				if argPos < 0 || argPos >= len(args) {
					continue
				}
				arg := args[argPos]
				visited := make(map[ssa.Value]bool)
				reached, path := reachesAnyParamSource(arg, paramSources, visited, 0, matcher, recs[0].sink, summaries)
				if reached == nil {
					continue
				}
				src := paramSources[reached]
				// Source position: where the tainted param enters the
				// caller. Included in the leaf-sink dedup key so two
				// distinct handlers each forwarding a same-category
				// source into the same downstream sink stay separate
				// findings (see crossSinkKey doc).
				sourceLine := positionLineOrZero(fset, reached.Pos())
				for _, rec := range recs {
					key := crossFlowKey{
						callerFn: fn,
						calleeFn: callee,
						sinkID:   rec.sink.ID,
						paramIdx: paramIdx,
					}
					if seen[key] {
						continue
					}
					seen[key] = true
					// Module-wide dedup on the leaf sink + SOURCE:
					// collapses middleware-chain pathologies where every
					// layer emits a distinct (callerFn, calleeFn) tuple
					// for the same eventual sink AND same source.
					// Different sources (distinct file+line) stay
					// separate. See crossSinkKey doc.
					if rec.deepSinkFile != "" && seenDeep != nil {
						deepKey := newCrossSinkKey(rec, *src, filePath, sourceLine)
						if seenDeep[deepKey] {
							continue
						}
						seenDeep[deepKey] = true
					}
					flow := buildCrossFlow(fn, call, callee, *src, rec, reached, path, fset, filePath, scopeName)
					flows = append(flows, flow)
				}
			}
		}
	}
	return flows
}

// findModuleRoot walks up from filePath looking for a go.mod file and
// returns the directory containing it plus the declared module path.
// Mirrors graph/resolver_golang.go's ProjectRoot but takes a file path
// instead of a directory; we duplicate the small amount of logic rather
// than introducing a graph→taint import cycle.
//
// Returns ("", "") when no go.mod is found OR when filePath doesn't
// correspond to an actual on-disk file. The on-disk check matters in
// hook / ScanContent / TaintRule paths where the scanner is fed
// in-memory content with a path like "test.go": without the guard, the
// walk would climb to the *test process's* working directory and try
// to module-wide-load whatever ambient go.mod happens to be above it
// (e.g. the batou-core module under test), blowing the 10-second
// per-rule timeout under -race. Intra-procedural SSA on the in-memory
// content still runs via the AnalyzeGo fallback path.
func findModuleRoot(filePath string) (root, modulePath string) {
	if filePath == "" {
		return "", ""
	}
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return "", ""
	}
	info, err := os.Stat(absPath)
	if err != nil {
		// File isn't on disk (in-memory hook content). Skip module
		// discovery; AnalyzeGo's intra-procedural pass handles the
		// content directly.
		return "", ""
	}
	dir := absPath
	if !info.IsDir() {
		dir = filepath.Dir(dir)
	}
	for {
		candidate := filepath.Join(dir, "go.mod")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return dir, readGoModPath(candidate)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", ""
		}
		dir = parent
	}
}

// readGoModPath returns the module path declared in a go.mod file. A
// minimal parser — sufficient for our needs and avoids depending on the
// (internal) modfile parser. Same shape as graph/resolver_golang.go's
// readGoModModulePath; duplicated to avoid the import cycle.
func readGoModPath(modPath string) string {
	f, err := os.Open(modPath)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	const maxLines = 64
	for i := 0; i < maxLines && scanner.Scan(); i++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if !strings.HasPrefix(line, "module") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "module"))
		rest = strings.TrimPrefix(rest, "(")
		rest = strings.TrimSpace(rest)
		rest = strings.Trim(rest, `"`)
		if idx := strings.Index(rest, "//"); idx >= 0 {
			rest = strings.TrimSpace(rest[:idx])
		}
		return rest
	}
	return ""
}

// countGoFilesUnder counts .go files under root, bailing out once the
// running total exceeds limit. Returns at most limit+1. Vendor
// directories are skipped (we don't analyze them — third-party code
// stays opaque), as are dot-prefixed directories (.git, .claude, etc.).
func countGoFilesUnder(root string, limit int) int {
	count := 0
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // ignore unreadable subtrees
		}
		if d.IsDir() {
			base := d.Name()
			if base == "vendor" || base == "testdata" {
				return filepath.SkipDir
			}
			if strings.HasPrefix(base, ".") && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(d.Name(), ".go") && !strings.HasSuffix(d.Name(), "_test.go") {
			count++
			if count > limit {
				return filepath.SkipAll
			}
		}
		return nil
	})
	return count
}

// errModuleSentinels are used to differentiate cached "tried and failed"
// states from "never tried" in the moduleCache. They're plain error
// values — never surfaced to the user; only used internally so the
// cache can short-circuit re-attempts in the same process.
var (
	errCatalogMissing = sentinelErr("ssaflow: Go taint catalog not registered")
	errNoPackages     = sentinelErr("ssaflow: packages.Load returned no packages")
	errModuleTooLarge = sentinelErr("ssaflow: module exceeds maxModuleSizeForSSA")
	errSSABuildFailed = sentinelErr("ssaflow: ssautil.Packages returned nil program")
)

// sentinelErr is a tiny error type kept private to ssaflow. We avoid
// using errors.New / fmt.Errorf here so the cached error values are
// pointer-comparable for easy testing.
type sentinelErr string

func (e sentinelErr) Error() string { return string(e) }

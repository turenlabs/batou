// Package ssaflow implements SSA-based intra-procedural taint analysis for
// Go source code.
//
// Unlike astflow (which walks go/ast and tracks variables by name), ssaflow
// builds the SSA intermediate representation and walks def-use chains. This
// gives precise, name-independent dataflow within a single function body.
//
// Scope of this engine (intentionally small):
//   - Intra-procedural only — taint is NOT propagated across function calls.
//     If a sink call's argument is itself the return value of a same-package
//     function that consumes a tainted param, ssaflow will only report flows
//     INSIDE that callee, not at the original caller site. Cross-function
//     propagation is a planned follow-up.
//   - Direct calls only — interface dispatch and dynamic call sites are not
//     resolved. ssa.Call.Common().StaticCallee() must return a concrete func.
//   - Closures are analyzed as independent functions (the body of the closure
//     gets its own ssa.Function with captured free variables surfaced as
//     parameters or referenced as ssa.FreeVar; this engine treats them only
//     as separate functions, ignoring captured taint).
//   - No generic instantiation handling beyond Go SSA's default.
//
// Sources, sinks, and sanitizers are read from the existing Go taint catalog
// (taint/languages/go_*.go) so this engine is consistent with astflow and
// tsflow. The package is registered nowhere by default — it must be invoked
// explicitly by callers (currently the TaintRule, gated by BATOU_SSAFLOW=1).
package ssaflow

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
	"golang.org/x/tools/go/ssa"
)

// confidenceSSAIntraProc is the confidence emitted for every flow this engine
// produces. Higher than astflow's intra-procedural 0.85 because SSA gives us
// real def-use chains rather than name-based heuristics — when this engine
// reports a flow, there is an actual operand path from the source value to
// the sink-call's dangerous arg through SSA instructions.
const confidenceSSAIntraProc = 0.9

// maxDefUseDepth caps how many backward def-use hops we follow per sink-arg
// reachability search. Keeps single-function analysis bounded for pathological
// inputs (deeply nested phi/binop chains) without hurting recall on real code.
const maxDefUseDepth = 64

// AnalyzeGo is the public entry point. It parses content as a single Go file,
// builds SSA for the file's package, and emits TaintFlow records for any
// source param → sink call reachable via intra-procedural SSA def-use chains.
//
// On any failure (parse error, type-check bailout, SSA build error) the
// function returns nil — ssaflow never panics and never reports half-baked
// flows. The caller is expected to also run astflow (the regex/AST engine
// remains the source of truth); ssaflow is purely additive.
//
// PR-CC: When filePath is inside a Go module, AnalyzeGo first attempts a
// module-wide SSA build (via packages.Load) and runs cross-package summary
// propagation. If the module load succeeds and the file is part of the
// loaded packages, the cross-package emission path supersedes the
// single-file path entirely — the module build already covers the file's
// intra-procedural flows and adds the cross-package surface on top. If
// the module load is unsuccessful (no go.mod, oversized module, packages
// failed to type-check), we silently fall back to the legacy single-file
// build below; the env-OFF behaviour and the no-module case are preserved.
func AnalyzeGo(content string, filePath string) []taint.TaintFlow {
	if mod, fallback := getModuleAnalysis(filePath); !fallback && mod != nil {
		if flows := analyzeFileWithModule(mod, content, filePath); flows != nil {
			return flows
		}
		// fall through: module loaded but file not part of it (e.g.
		// synthetic in-memory path used by tests) — try single-file.
	}

	cat := taint.GetCatalog(rules.LangGo)
	if cat == nil {
		return nil
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, content, parser.ParseComments|parser.AllErrors)
	if err != nil || file == nil {
		return nil
	}

	ssaPkg, _, ok := buildSSA(fset, file)
	if !ok || ssaPkg == nil {
		return nil
	}

	matcher := newCatalogMatcherWithSources(cat.Sinks(), cat.Sanitizers(), cat.Sources())

	var flows []taint.TaintFlow
	for _, member := range ssaPkg.Members {
		fn, isFn := member.(*ssa.Function)
		if !isFn {
			continue
		}
		flows = append(flows, analyzeFunction(fn, fset, filePath, matcher)...)
		// Also analyze any anonymous functions (closures) nested inside.
		for _, anon := range fn.AnonFuncs {
			flows = append(flows, analyzeFunction(anon, fset, filePath, matcher)...)
		}
	}

	// Cross-function pass: build per-function summaries (which params
	// flow to which sinks, which params taint the return value) and
	// iterate to a fixed point, then emit a TaintFlow at each caller
	// site where a source-typed parameter is propagated into a callee
	// whose summary records a reachable sink. Same-package only; static
	// call targets only — see crossfunction.go for the scope-limits
	// rationale. Both passes' outputs are concatenated; the scanner's
	// downstream dedup (group by line/CWE) collapses overlapping
	// intra- and cross-function detections into a single boosted
	// finding rather than emitting duplicates.
	flows = append(flows, analyzePackageCrossFunction(ssaPkg, fset, filePath, matcher)...)

	return flows
}

// buildSSA constructs an SSA package for a single file. The type-checker is
// configured to tolerate import / type errors (Error handler set, stub
// importer fallback) so that missing third-party packages do not block the
// build. When SSA construction cannot proceed at all, ok is false.
//
// Unlike ssautil.BuildPackage we do NOT abort when types.Checker.Files
// returns a non-nil error: even when the package contains references to
// unresolved third-party symbols (gin.Context, fiber.Ctx, …) the checker
// still annotates the parts it CAN resolve, and the SSA builder can
// still emit useful intra-procedural code for those parts. Bailing on
// any type error would hide bind/parser flows in files that import any
// missing dependency — the common case in code we scan from a hook.
//
// ssaPkg.Build() may panic when an unresolved third-party symbol is
// dereferenced (e.g. a method call on a stub type with no methods). We
// recover and report ok=false in that case — better to silently lose
// SSA recall on this file than to crash the scanner.
func buildSSA(fset *token.FileSet, file *ast.File) (ret *ssa.Package, retInfo *types.Info, ok bool) {
	pkgPath := "ssaflow.local/_"
	if file.Name != nil && file.Name.Name != "" {
		pkgPath = "ssaflow.local/" + file.Name.Name
	}
	pkg := types.NewPackage(pkgPath, file.Name.Name)

	conf := &types.Config{
		// Swallow type errors so that a single bad import or undefined
		// reference does not poison the whole SSA build.
		Error:    func(error) {},
		Importer: newFallbackImporter(),
	}

	info := &types.Info{
		Types:        make(map[ast.Expr]types.TypeAndValue),
		Defs:         make(map[*ast.Ident]types.Object),
		Uses:         make(map[*ast.Ident]types.Object),
		Implicits:    make(map[ast.Node]types.Object),
		Instances:    make(map[*ast.Ident]types.Instance),
		Scopes:       make(map[ast.Node]*types.Scope),
		Selections:   make(map[*ast.SelectorExpr]*types.Selection),
		FileVersions: make(map[*ast.File]string),
	}
	// Run the type-checker. Errors are reported to conf.Error (a no-op)
	// and the returned err is suppressed — partial type info is enough
	// for SSA to emit code for the well-typed parts of the file.
	defer func() {
		if r := recover(); r != nil {
			ret, retInfo, ok = nil, nil, false
		}
	}()
	_ = types.NewChecker(conf, fset, pkg, info).Files([]*ast.File{file})

	prog := ssa.NewProgram(fset, ssa.SanityCheckFunctions)
	created := make(map[*types.Package]bool)
	var createAll func(pkgs []*types.Package)
	createAll = func(pkgs []*types.Package) {
		for _, p := range pkgs {
			if !created[p] {
				created[p] = true
				prog.CreatePackage(p, nil, nil, true)
				createAll(p.Imports())
			}
		}
	}
	createAll(pkg.Imports())

	ssaPkg := prog.CreatePackage(pkg, []*ast.File{file}, info, false)
	if ssaPkg == nil {
		return nil, nil, false
	}
	ssaPkg.Build()
	return ssaPkg, info, true
}

// fallbackImporter wraps importer.Default() and returns a stub *types.Package
// when the underlying importer cannot resolve a path. This means
// type-checking always succeeds at the import layer; later references to
// symbols inside an unresolved package become typed as the empty pkg and
// the type-checker reports them via Error (which we swallow).
type fallbackImporter struct {
	primary types.Importer
	cache   map[string]*types.Package
}

func newFallbackImporter() *fallbackImporter {
	return &fallbackImporter{
		primary: importer.Default(),
		cache:   make(map[string]*types.Package),
	}
}

func (f *fallbackImporter) Import(path string) (*types.Package, error) {
	if p, ok := f.cache[path]; ok {
		return p, nil
	}
	if f.primary != nil {
		if p, err := f.primary.Import(path); err == nil && p != nil {
			f.cache[path] = p
			return p, nil
		}
	}
	stub := types.NewPackage(path, defaultAliasForPath(path))
	stub.MarkComplete()
	f.cache[path] = stub
	return stub, nil
}

// defaultAliasForPath mirrors astflow's helper so we render stub packages
// with the conventional alias (e.g. "github.com/gin-gonic/gin" → "gin").
func defaultAliasForPath(path string) string {
	if path == "" {
		return ""
	}
	last := path
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			last = path[i+1:]
			break
		}
	}
	return last
}

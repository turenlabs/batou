// Per-language adapter: Go (go/types-based).
//
// This is an alternate Go resolver gated behind the BATOU_GOTYPES_RESOLVER
// environment variable. When the variable is set (any non-empty value),
// resolve.go's Go-specific path delegates to this resolver for module-
// scoped bulk resolution; the default (env unset) keeps the legacy name-
// matching resolver in resolver_golang.go.
//
// The legacy resolver scans imports with parser.ImportsOnly and matches
// "alias.Method" → "<importPath>.<Method>" by string slicing. That works
// well when imports use their default name and callees are top-level
// functions, but it falls over on:
//
//   - Aliased imports ("h \"net/http\"" → "h.Request" should resolve to
//     "*net/http.Request", but the string-slicer can only produce
//     "h.Request").
//   - Dot imports (no alias at all).
//   - Interface method calls (the receiver is a variable, not a package
//     alias, so the legacy resolver bails out entirely).
//   - Embedded promoted methods (the receiver is one type, but the
//     method body lives on the embedded type).
//   - Generics (the receiver carries a type parameter that erases at
//     the syntactic level).
//   - Method values ("f := obj.Method; f()" splits the call site from
//     the receiver lookup).
//
// This resolver replaces the string-slicing with `go/types`. It loads
// the module's packages via golang.org/x/tools/go/packages, then for
// every call expression in every function body it asks the type
// checker which package/function the call actually resolves to. For
// interface dispatch, it consults typeutil.NewMethodSetCache to find
// every concrete implementation and emits an edge per implementation.
//
// COST: packages.Load is expensive (parses + type-checks the whole
// module). Cache per module within a single ResolveCrossFileEdges call.
// This resolver is intended for `batou scan` mode only — the hook
// PreTool path is too latency-sensitive. resolve.go's Go branch checks
// the env var; if absent, it stays on the legacy path.
package graph

import (
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/turenlabs/batou-rules/rules"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/types/typeutil"
)

// EnvGoTypesResolver is the environment variable that gates the
// go/types resolver. Default ON since PR-KK; users can opt out with
// BATOU_GOTYPES_RESOLVER=0 (or "false" / "off"). Legacy opt-in
// spellings ("1", "true", "on") still enable the resolver as a no-op
// for back-compat with scripts that set them explicitly.
const EnvGoTypesResolver = "BATOU_GOTYPES_RESOLVER"

// GoTypesResolverEnabled reports whether the resolver should run.
// Centralised so resolve.go's branching and the resolver's own
// short-circuits agree.
func GoTypesResolverEnabled() bool {
	v := os.Getenv(EnvGoTypesResolver)
	if v == "" {
		return true // default ON
	}
	if v == "0" || strings.EqualFold(v, "false") || strings.EqualFold(v, "off") || strings.EqualFold(v, "no") {
		return false
	}
	return true
}

// goTypesResolver implements LanguageResolver. It mirrors the legacy
// goResolver for ProjectRoot / ExtractScope (re-using the same go.mod
// reader and import parser) so behavior is identical for callers that
// only need scope extraction. ResolveCall on this type is a no-op:
// the env-gated path in resolve.go calls ResolveModule for bulk
// resolution, which is where the go/types machinery lives.
type goTypesResolver struct {
	// legacy is the original resolver; we delegate ProjectRoot and
	// ExtractScope to it so we don't duplicate the go.mod / import
	// parser. The new logic only matters for call resolution.
	legacy goResolver
}

// Language reports that this resolver handles Go.
func (r *goTypesResolver) Language() rules.Language { return r.legacy.Language() }

// ProjectRoot delegates to the legacy resolver — go.mod discovery is
// identical regardless of which call resolver is active.
func (r *goTypesResolver) ProjectRoot(scanDir string) (string, string, bool) {
	return r.legacy.ProjectRoot(scanDir)
}

// ExtractScope delegates to the legacy resolver — import parsing is
// identical regardless of which call resolver is active. The bulk
// ResolveModule path doesn't actually consult the scope (go/types
// already knows every file's imports), but resolve.go still populates
// CallGraph.FileScopes from this and downstream consumers may inspect
// the scope.
func (r *goTypesResolver) ExtractScope(filePath string, content []byte) (FileScope, error) {
	return r.legacy.ExtractScope(filePath, content)
}

// ResolveCall is a no-op for the go/types resolver — the env-gated
// path in resolve.go invokes ResolveModule instead, which resolves
// every call in the module in one bulk pass with cached package data.
// We still implement the method so the type satisfies
// LanguageResolver: tests or future consumers that call ResolveCall
// directly fall back to the legacy resolver.
func (r *goTypesResolver) ResolveCall(callee string, scope FileScope, modulePath string, idx *PackageIndex) ResolveResult {
	return r.legacy.ResolveCall(callee, scope, modulePath, idx)
}

// --- Bulk module resolution -------------------------------------------------

// moduleLoadResult caches the type-checked packages for one module so
// repeated ResolveModule calls within a single ResolveCrossFileEdges
// invocation don't reload. Keyed by moduleRoot (the directory holding
// go.mod).
type moduleLoadResult struct {
	pkgs    []*packages.Package
	loadErr error
	// fileToPkg maps absolute file path → owning package. Used by the
	// resolution loop to find a node's owning *types.Package.
	fileToPkg map[string]*packages.Package
	// inProjectPaths is the set of in-project import paths (those under
	// modulePath). Cached so we don't re-prefix on every call.
	inProjectPaths map[string]bool
	// msetCache lazily builds method sets for interface lookups.
	msetCache *typeutil.MethodSetCache
	// concreteImpls caches interface-type → concrete implementing
	// type-names (qualified by package path). Populated on demand.
	concreteImpls map[string][]string
	// Mu protects concreteImpls (msetCache is safe for concurrent use).
	mu sync.Mutex
}

// moduleCache is keyed by moduleRoot. resolve.go is single-threaded
// over the resolver for a given graph, but typeutil.MethodSetCache is
// concurrent-safe and we hold no per-call lock, so this is fine.
type moduleCache struct {
	mu      sync.Mutex
	entries map[string]*moduleLoadResult
}

func newModuleCache() *moduleCache {
	return &moduleCache{entries: make(map[string]*moduleLoadResult)}
}

// resolveModuleStats summarises what ResolveModule did. It mirrors the
// shape of the per-call counters in ResolveCrossFileEdges so resolve.go
// can fold these into ResolveStats.
type resolveModuleStats struct {
	CrossFileEdges int
	ExternEdges    int
	Unresolved     int
}

// ResolveModule resolves every call expression for every node belonging
// to the given module in a single pass.
//
// Returns counts of (cross-file edges added, extern edges added,
// unresolved-calls recorded) for stats accumulation by the caller.
func (r *goTypesResolver) ResolveModule(
	cg *CallGraph,
	scanDir string,
	modulePath, moduleRoot string,
	nodes []*FuncNode,
	cache *moduleCache,
) resolveModuleStats {
	var stats resolveModuleStats
	if cg == nil || moduleRoot == "" || len(nodes) == 0 {
		return stats
	}

	result := cache.load(moduleRoot, scanDir)
	if result == nil || result.loadErr != nil || !hasUsableTypeInfo(result) {
		// packages.Load failed or produced no type-checked packages
		// (broken module, no Go files, missing deps). Fall back to the
		// legacy resolver for these nodes so we don't silently drop
		// edges.
		return r.fallback(cg, scanDir, modulePath, nodes, &stats)
	}

	// Resolve calls for each node. We walk the node's owning package's
	// syntax tree to find its function declaration, then walk that
	// declaration's body for call expressions. types.Info on the
	// owning package tells us what each call resolves to.
	for _, node := range nodes {
		r.resolveNode(cg, modulePath, node, result, &stats)
	}
	return stats
}

// fallback resolves nodes via the legacy ResolveCall path. Used when
// packages.Load couldn't produce usable type info.
func (r *goTypesResolver) fallback(
	cg *CallGraph,
	scanDir string,
	modulePath string,
	nodes []*FuncNode,
	stats *resolveModuleStats,
) resolveModuleStats {
	for _, node := range nodes {
		if len(node.RawCalls) == 0 {
			continue
		}
		scope := cg.FileScopes[node.FilePath]
		for _, raw := range node.RawCalls {
			res := r.legacy.ResolveCall(raw, scope, modulePath, cg.PackageIndex)
			switch {
			case res.TargetID != "" && res.TargetID != node.ID:
				if !containsStr(node.Calls, res.TargetID) {
					cg.AddEdge(node.ID, res.TargetID)
					stats.CrossFileEdges++
				}
			case res.Extern != "":
				if !containsStr(node.ExternCalls, res.Extern) {
					node.ExternCalls = append(node.ExternCalls, res.Extern)
					stats.ExternEdges++
				}
			}
		}
	}
	_ = scanDir // legacy.ResolveCall doesn't need it
	return *stats
}

// resolveNode walks one node's function body, asks types.Info what each
// call expression refers to, and emits in-project / extern edges.
func (r *goTypesResolver) resolveNode(
	cg *CallGraph,
	modulePath string,
	node *FuncNode,
	mod *moduleLoadResult,
	stats *resolveModuleStats,
) {
	pkg := mod.fileToPkg[node.FilePath]
	if pkg == nil || pkg.TypesInfo == nil {
		return
	}
	fn := findFuncDeclForNode(pkg, node)
	if fn == nil || fn.Body == nil {
		return
	}

	// Reset extern/unresolved for idempotency (mirrors resolve.go).
	node.ExternCalls = nil
	node.UnresolvedCalls = nil

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		r.resolveCallExpr(cg, modulePath, node, call, pkg, mod, stats)
		return true
	})
}

// resolveCallExpr handles a single *ast.CallExpr. It tries (in order):
//
//  1. Direct function reference: types.Info.Uses gives us a
//     *types.Func, whose Pkg() and Name() are the canonical answer.
//  2. Method call on a concrete type: same — types.Info.Uses on the
//     selector's Sel ident yields a *types.Func with Recv().Type().
//  3. Method call on an interface: types.Info.Uses gives an interface
//     method; we look up every concrete implementation via the
//     module's method-set cache and emit one edge per implementer.
//  4. Anything else (function values, closures): record as unresolved.
func (r *goTypesResolver) resolveCallExpr(
	cg *CallGraph,
	modulePath string,
	node *FuncNode,
	call *ast.CallExpr,
	pkg *packages.Package,
	mod *moduleLoadResult,
	stats *resolveModuleStats,
) {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		// Direct call: Func() — either local or dot-imported.
		obj := pkg.TypesInfo.Uses[fun]
		if obj == nil {
			obj = pkg.TypesInfo.Defs[fun]
		}
		if obj == nil {
			return
		}
		r.emitForObject(cg, modulePath, node, obj, mod, stats)
	case *ast.SelectorExpr:
		// Selector: pkg.Func(), recv.Method(), or interface.Method().
		obj := pkg.TypesInfo.Uses[fun.Sel]
		if obj == nil {
			return
		}
		fnObj, isFn := obj.(*types.Func)
		if !isFn {
			// Not a function (e.g. struct field used as value, then
			// called) — record as unresolved using the syntactic form.
			r.recordUnresolved(node, callExprName(fun), stats)
			return
		}
		// Interface-method dispatch: when the receiver is an interface
		// type, fan out to all concrete implementers.
		if recv := fnObj.Type().(*types.Signature).Recv(); recv != nil {
			recvType := recv.Type()
			// Pointer receivers carry through, but the interface check
			// looks at the element type.
			if ptr, ok := recvType.(*types.Pointer); ok {
				recvType = ptr.Elem()
			}
			if iface, ok := recvType.Underlying().(*types.Interface); ok {
				r.emitForInterfaceCall(cg, modulePath, node, iface, fnObj.Name(), mod, stats)
				return
			}
		}
		r.emitForObject(cg, modulePath, node, fnObj, mod, stats)
	default:
		// Function literals, type assertions, method values bound to a
		// var. We can't resolve these without dataflow.
		r.recordUnresolved(node, callExprName(call.Fun), stats)
	}
}

// emitForObject handles a non-interface function/method target. The
// object's package decides in-project vs extern; the result is added to
// node's edges.
func (r *goTypesResolver) emitForObject(
	cg *CallGraph,
	modulePath string,
	node *FuncNode,
	obj types.Object,
	mod *moduleLoadResult,
	stats *resolveModuleStats,
) {
	fnObj, ok := obj.(*types.Func)
	if !ok {
		// Could be a *types.Var holding a function value; we'd need
		// dataflow to resolve. Skip silently.
		return
	}
	targetPkg := ""
	if fnObj.Pkg() != nil {
		targetPkg = fnObj.Pkg().Path()
	}
	if targetPkg == "" {
		// Universe scope (panic, len, make, ...) or builtin —
		// uninteresting for call graphs.
		return
	}

	// Compute the qualified name. For methods we use
	// "<canonical-recv-type>.<method>"; for free functions just the
	// function name. This matches what builder.go writes into
	// FuncNode.Name (e.g. "Service.Login").
	qualName := fnObj.Name()
	if sig, ok := fnObj.Type().(*types.Signature); ok && sig.Recv() != nil {
		recvName := canonicalReceiverName(sig.Recv().Type())
		if recvName != "" {
			qualName = recvName + "." + fnObj.Name()
		}
	}

	if mod.inProjectPaths[targetPkg] {
		// In-project: look up the candidate nodes in the package index.
		candidates := cg.PackageIndex.Lookup(targetPkg)
		for _, candID := range candidates {
			colon := strings.LastIndexByte(candID, ':')
			if colon < 0 {
				continue
			}
			fnPart := candID[colon+1:]
			if fnPart == qualName || fnPart == fnObj.Name() ||
				strings.HasSuffix(fnPart, "."+fnObj.Name()) {
				if candID == node.ID {
					continue
				}
				if !containsStr(node.Calls, candID) {
					cg.AddEdge(node.ID, candID)
					stats.CrossFileEdges++
				}
				return
			}
		}
		// In-project but unindexed: fall through silently. Older code
		// emits nothing in this case too.
		return
	}

	// External — record on the node. Use the canonical extern form
	// "<importPath>.<funcName>" (same as the legacy resolver) so
	// downstream consumers see a consistent shape.
	extern := targetPkg + "." + fnObj.Name()
	if !containsStr(node.ExternCalls, extern) {
		node.ExternCalls = append(node.ExternCalls, extern)
		stats.ExternEdges++
	}
}

// emitForInterfaceCall fans out an interface-method call to every
// concrete implementation in the loaded module. One edge per
// implementer.
func (r *goTypesResolver) emitForInterfaceCall(
	cg *CallGraph,
	modulePath string,
	node *FuncNode,
	iface *types.Interface,
	methodName string,
	mod *moduleLoadResult,
	stats *resolveModuleStats,
) {
	implementers := mod.findImplementers(iface)
	if len(implementers) == 0 {
		return
	}
	for _, impl := range implementers {
		// impl is "<importPath>.<TypeName>". Look it up in the index.
		dot := strings.LastIndexByte(impl, '.')
		if dot <= 0 {
			continue
		}
		implPkg := impl[:dot]
		implType := impl[dot+1:]
		qualName := implType + "." + methodName
		if mod.inProjectPaths[implPkg] {
			candidates := cg.PackageIndex.Lookup(implPkg)
			for _, candID := range candidates {
				colon := strings.LastIndexByte(candID, ':')
				if colon < 0 {
					continue
				}
				fnPart := candID[colon+1:]
				if fnPart == qualName ||
					strings.HasSuffix(fnPart, "."+methodName) && strings.HasPrefix(fnPart, implType+".") {
					if candID == node.ID {
						continue
					}
					if !containsStr(node.Calls, candID) {
						cg.AddEdge(node.ID, candID)
						stats.CrossFileEdges++
					}
				}
			}
		}
	}
	_ = modulePath
}

// recordUnresolved appends raw to node.UnresolvedCalls (deduped).
func (r *goTypesResolver) recordUnresolved(node *FuncNode, raw string, stats *resolveModuleStats) {
	if raw == "" {
		return
	}
	if !containsStr(node.UnresolvedCalls, raw) {
		node.UnresolvedCalls = append(node.UnresolvedCalls, raw)
		stats.Unresolved++
	}
}

// --- module cache implementation -------------------------------------------

// load returns the cached load result for moduleRoot, loading lazily on
// first request.
func (c *moduleCache) load(moduleRoot, scanDir string) *moduleLoadResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r, ok := c.entries[moduleRoot]; ok {
		return r
	}
	r := loadModulePackages(moduleRoot, scanDir)
	c.entries[moduleRoot] = r
	return r
}

// loadModulePackages runs packages.Load with the modes we need and
// indexes files → owning packages plus in-project import paths.
func loadModulePackages(moduleRoot, scanDir string) *moduleLoadResult {
	out := &moduleLoadResult{
		fileToPkg:      make(map[string]*packages.Package),
		inProjectPaths: make(map[string]bool),
		msetCache:      new(typeutil.MethodSetCache),
		concreteImpls:  make(map[string][]string),
	}

	// Load every package under the module. "./..." relative to the
	// module root is the conventional pattern.
	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedCompiledGoFiles |
			packages.NeedImports |
			packages.NeedTypes |
			packages.NeedTypesInfo |
			packages.NeedTypesSizes |
			packages.NeedSyntax |
			packages.NeedDeps,
		Dir:   moduleRoot,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		out.loadErr = err
		return out
	}
	// We keep partial results even if some packages have errors —
	// individual call sites in well-typed packages are still useful.
	out.pkgs = pkgs

	// Read the module path from go.mod so we can classify each pkg as
	// in-project vs extern.
	modulePath := readGoModModulePath(filepath.Join(moduleRoot, "go.mod"))

	for _, p := range pkgs {
		if p == nil {
			continue
		}
		if isInProject(p.PkgPath, modulePath) {
			out.inProjectPaths[p.PkgPath] = true
		}
		// Index every file owned by the package. CompiledGoFiles is the
		// authoritative list (CGo-expanded files included); fall back to
		// GoFiles if CompiledGoFiles is empty (older toolchains).
		files := p.CompiledGoFiles
		if len(files) == 0 {
			files = p.GoFiles
		}
		for _, f := range files {
			abs, err := filepath.Abs(f)
			if err != nil {
				abs = f
			}
			out.fileToPkg[abs] = p
		}
	}

	// Also walk transitive deps so in-project sub-packages discovered
	// via NeedDeps get tagged. (packages.Load only returns the queried
	// roots in pkgs; deps live on each pkg.Imports.)
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		if isInProject(p.PkgPath, modulePath) {
			out.inProjectPaths[p.PkgPath] = true
		}
	})

	return out
}

// hasUsableTypeInfo reports whether result has at least one package
// with non-nil TypesInfo. packages.Load can return a stub package
// (no syntax, no type info) when run in a directory with no go.mod
// — we treat that as "no usable load" and fall back to the legacy
// name-matcher.
func hasUsableTypeInfo(result *moduleLoadResult) bool {
	if result == nil {
		return false
	}
	for _, p := range result.pkgs {
		if p == nil {
			continue
		}
		if p.TypesInfo != nil && len(p.Syntax) > 0 {
			return true
		}
	}
	return false
}

// findImplementers returns "<importPath>.<TypeName>" for every concrete
// in-project type that implements iface's method set. Cached per
// interface-string-key.
func (m *moduleLoadResult) findImplementers(iface *types.Interface) []string {
	if iface == nil || iface.NumMethods() == 0 {
		return nil
	}
	key := iface.String()
	m.mu.Lock()
	if cached, ok := m.concreteImpls[key]; ok {
		m.mu.Unlock()
		return cached
	}
	m.mu.Unlock()

	var found []string
	for _, p := range m.pkgs {
		if p == nil || p.Types == nil {
			continue
		}
		scope := p.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			tn, ok := obj.(*types.TypeName)
			if !ok {
				continue
			}
			t := tn.Type()
			if t == nil {
				continue
			}
			// Skip aliases and interfaces; we only want concrete impls.
			if _, isIface := t.Underlying().(*types.Interface); isIface {
				continue
			}
			// Check both value-receiver and pointer-receiver method sets;
			// a method declared on *T is part of *T's set, not T's.
			if types.AssignableTo(t, iface) {
				found = append(found, p.PkgPath+"."+name)
				continue
			}
			ptr := types.NewPointer(t)
			if types.AssignableTo(ptr, iface) {
				found = append(found, p.PkgPath+"."+name)
			}
		}
	}

	m.mu.Lock()
	m.concreteImpls[key] = found
	m.mu.Unlock()
	return found
}

// --- helpers ---------------------------------------------------------------

// findFuncDeclForNode walks a package's syntax trees looking for the
// FuncDecl whose qualified name (ReceiverType.Method or Func) matches
// node.Name. Returns nil if the node's function declaration isn't in
// pkg (e.g. body-less declaration, generated by a tool, …).
func findFuncDeclForNode(pkg *packages.Package, node *FuncNode) *ast.FuncDecl {
	if pkg == nil {
		return nil
	}
	for _, file := range pkg.Syntax {
		// Only walk the file the node lives in. Compare absolute paths.
		pos := pkg.Fset.Position(file.Pos())
		if pos.Filename == "" {
			continue
		}
		// Match either the absolute path stored on the node or a path
		// suffix (resolve.go's nodes use the dirscan-relative form).
		if !sameFile(pos.Filename, node.FilePath) {
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil {
				continue
			}
			declName := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				if recvType := exprTypeName(fn.Recv.List[0].Type); recvType != "" {
					declName = recvType + "." + fn.Name.Name
				}
			}
			if declName == node.Name {
				return fn
			}
		}
	}
	return nil
}

// sameFile reports whether a and b refer to the same file on disk.
// Handles the common case where one path is absolute and the other is
// relative-to-CWD (dirscan emits CWD-relative paths).
func sameFile(a, b string) bool {
	if a == b {
		return true
	}
	if filepath.Base(a) != filepath.Base(b) {
		return false
	}
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA == nil && errB == nil && absA == absB {
		return true
	}
	// Fall back to suffix match (handles symlinked module dirs).
	return strings.HasSuffix(absA, b) || strings.HasSuffix(absB, a)
}

// canonicalReceiverName returns the bare type name for a method
// receiver type (e.g. "*foo/bar.Server" → "Server"). Used to assemble
// the "Receiver.Method" form that matches FuncNode.Name strings.
func canonicalReceiverName(t types.Type) string {
	// Strip pointers.
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	// Named types give us the type-name directly.
	if named, ok := t.(*types.Named); ok {
		if named.Obj() != nil {
			return named.Obj().Name()
		}
	}
	// Generic instantiation: *types.Named already returns the generic
	// name from Obj(); the type-arg list is on TypeArgs() which we
	// ignore for matching.
	return ""
}

// callExprName lives in builder.go — shared across the graph package.

// isInProject reports whether pkgPath is under modulePath. modulePath
// must be non-empty; empty modulePath returns false (we can't classify
// in-project without it).
func isInProject(pkgPath, modulePath string) bool {
	if modulePath == "" || pkgPath == "" {
		return false
	}
	return pkgPath == modulePath || strings.HasPrefix(pkgPath, modulePath+"/")
}

// goTypesResolverSingleton is created lazily and held for the lifetime
// of the process. It carries no module state — that lives on the
// per-call moduleCache built by resolve.go.
var (
	goTypesResolverOnce sync.Once
	goTypesResolverInst *goTypesResolver
)

func getGoTypesResolver() *goTypesResolver {
	goTypesResolverOnce.Do(func() {
		goTypesResolverInst = &goTypesResolver{}
	})
	return goTypesResolverInst
}

// Ensure unused imports / vars stay compilable while iterating on this
// file. _ = token.NoPos pins the import.
var _ = token.NoPos

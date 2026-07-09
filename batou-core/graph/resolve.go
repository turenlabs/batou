// Cross-file resolution pass.
//
// Runs after the per-file AST extraction phase. For each language with
// a registered LanguageResolver, this pass:
//
//  1. Locates the project's module manifest (go.mod / package.json /
//     pyproject.toml / …) via resolver.ProjectRoot and stashes the
//     module path on CallGraph.ModulePaths[lang].
//  2. For every file with nodes in the graph, parses the file's
//     imports into a FileScope and stashes it on CallGraph.FileScopes.
//  3. Builds CallGraph.PackageIndex by classifying each node into its
//     file's package, then mapping that to the in-project import path.
//  4. Walks every node's RawCalls and resolves each one. Calls that
//     resolve to an in-project node become edges (Calls/CalledBy).
//     Calls that resolve to an external package go on ExternCalls.
//     Calls the resolver can't pin down stay in UnresolvedCalls.
//
// The pass is idempotent: running it twice produces the same result.
// It is safe to call after every full scan or as part of a finalize
// step in the dirscan orchestrator.
package graph

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// ResolveCrossFileEdges runs the cross-file resolution pass on cg.
//
// scanDir is the directory the scan was rooted at (the value
// dirscan passes as its target); resolvers use it to locate the
// project's manifest by walking up from there. fileContents is an
// optional map of file_path → content for the files in this scan.
// When a file's content is in the map, the resolver uses it directly;
// otherwise the pass reads from disk. Hook-mode (single-file) scans
// should pass the content of just the changed file. Full scans
// should pass all scanned files.
//
// Returns a summary of what changed (counts of resolved/extern/
// unresolved edges) so callers can log a one-line metric.
type ResolveStats struct {
	FilesScoped    int
	NodesResolved  int
	CrossFileEdges int
	ExternEdges    int
	Unresolved     int
}

func ResolveCrossFileEdges(cg *CallGraph, scanDir string, fileContents map[string][]byte) ResolveStats {
	if cg == nil {
		return ResolveStats{}
	}

	// Step 1: For each language present in the graph, locate the
	// outer-most manifest and record its module path. ModulePaths /
	// ModuleRoots is the global per-language fallback used when a
	// file isn't in FileModules.
	langs := languagesInGraph(cg)
	if cg.ModulePaths == nil {
		cg.ModulePaths = make(map[rules.Language]string)
	}
	if cg.ModuleRoots == nil {
		cg.ModuleRoots = make(map[rules.Language]string)
	}
	for _, lang := range langs {
		r := GetResolver(lang)
		if r == nil {
			continue
		}
		manifest, mod, ok := r.ProjectRoot(scanDir)
		if !ok {
			continue
		}
		cg.ModulePaths[lang] = mod
		cg.ModuleRoots[lang] = filepath.Dir(manifest)
	}

	// Step 1b: For each file in the graph, walk up from the file's
	// own directory to find the *nearest* manifest. This gives correct
	// in-project classification on multi-module repos (Vault declares
	// 16+ go.mod files; coder/gitea declare 1). Cache per directory so
	// the lookup is O(directories), not O(files).
	if cg.FileModules == nil {
		cg.FileModules = make(map[string]FileModule)
	}
	dirCache := make(map[string]FileModule)
	for _, n := range cg.Nodes {
		if _, already := cg.FileModules[n.FilePath]; already {
			continue
		}
		r := GetResolver(n.Language)
		if r == nil {
			continue
		}
		// absoluteFileDir already returns the file's containing
		// directory; the nearest go.mod is in that directory or one
		// of its ancestors, so we walk up from there. (Earlier
		// versions of this code wrapped the call in filepath.Dir(...),
		// climbing one level too high — which on Vault meant a sub-
		// module file in vault/api/auth/approle/ resolved to the
		// vault/api/ manifest instead of its own.)
		dir := absoluteFileDir(n.FilePath, scanDir)
		if fm, hit := dirCache[dir]; hit {
			cg.FileModules[n.FilePath] = fm
			continue
		}
		manifest, mod, ok := r.ProjectRoot(dir)
		if !ok {
			dirCache[dir] = FileModule{}
			continue
		}
		fm := FileModule{ModulePath: mod, ModuleRoot: filepath.Dir(manifest)}
		dirCache[dir] = fm
		cg.FileModules[n.FilePath] = fm
	}

	// Step 2: Extract scopes for every file that has nodes.
	if cg.FileScopes == nil {
		cg.FileScopes = make(map[string]FileScope)
	}
	files := filesInGraph(cg)
	for _, filePath := range files {
		// Determine language from any node in the file.
		nodes := cg.NodesInFile(filePath)
		if len(nodes) == 0 {
			continue
		}
		lang := nodes[0].Language
		r := GetResolver(lang)
		if r == nil {
			continue
		}
		content := fetchContent(filePath, scanDir, fileContents)
		if content == nil {
			continue
		}
		scope, _ := r.ExtractScope(filePath, content)
		// For languages whose module path is fully derived from the
		// filesystem layout (Python), recompute scope.Package using the
		// per-file ModuleRoot known to the framework. This keeps the
		// dotted-module keys in the file's scope aligned with the keys
		// PackageIndex uses (importPathForNode does the same path
		// arithmetic). Stash ModuleRoot in Aux too in case the
		// resolver wants it during ResolveCall.
		if lang == rules.LangPython {
			if scope.Aux == nil {
				scope.Aux = map[string]string{}
			}
			_, root := moduleForFile(cg, filePath, rules.LangPython)
			scope.Aux["module_root"] = root
			scope.Package = pythonModuleKey(filePath, root, scanDir)
			// Re-extract imports against the corrected package so
			// relative imports (from . import X) resolve to the
			// real-world dotted parent (e.g. "myapp.sub").
			if content := fetchContent(filePath, scanDir, fileContents); content != nil {
				rebuildPythonScopeRelative(&scope, content)
			}
		}
		cg.FileScopes[filePath] = scope
	}

	// Step 2a: Many real Python packages have a re-export-only
	// __init__.py with zero function definitions (e.g. flask's
	// src/flask/__init__.py wires up Flask, Blueprint, request, etc.
	// from sub-modules). The builder doesn't emit a node for those, so
	// the step-2 loop above never visits them and we'd miss every
	// re-export. Discover __init__.py files in the ancestor chain of
	// every Python file with a node and extract their scopes too.
	extractPythonInitScopes(cg, scanDir, fileContents)

	// Step 2b: Build the Python re-export index from every __init__.py
	// FileScope we just extracted. A package's __init__.py exposes its
	// imports as attributes of the package itself: `from pkg.sub import
	// handler` in pkg/__init__.py means `pkg.handler` is the same symbol
	// as `pkg.sub.handler`. We capture that mapping once, here, so
	// resolvePythonFullName can follow `from pkg import handler` from
	// app.py through pkg/__init__.py to pkg/sub.py.
	//
	// Single-hop only: chains like __init__.py → __init__.py → leaf are
	// NOT followed in this pass (documented as future work). Wildcard
	// (`from x import *`) re-exports are not expanded either — the star
	// list lands in scope.StarImports but no name resolution happens
	// against it.
	pyReExports := collectPythonReExports(cg.FileScopes)

	// Step 2c (JS/TS): Barrel files (`index.js` with only
	// `export {x} from './impl'`) define no functions, so the step-2 loop
	// over filesInGraph never visits them and their re-export tables are
	// lost. Discover barrel files referenced by JS/TS import targets that
	// aren't yet scoped and extract their scopes too — the JS analog of
	// extractPythonInitScopes.
	extractJSBarrelScopes(cg, scanDir, fileContents)

	// Step 2d (JS/TS): Build the barrel re-export index from every JS/TS
	// FileScope's recorded re-exports. `export {handler} from './impl'` in
	// index.js means importing `handler` from './index' is the same symbol
	// as './impl'.handler. Single-hop only (barrel → leaf), mirroring the
	// Python re-export semantics.
	jsReExports := collectJSReExports(cg.FileScopes)

	// Step 3: Build PackageIndex by mapping each node's file to its
	// in-project import path. For Go, the import path is the
	// modulePath joined with the file's directory relative to the
	// manifest's directory. For other languages, the resolver's
	// ExtractScope populates FileScope.Package which we key on.
	//
	// Iterate node IDs in sorted order so PackageIndex.PackageToNodes
	// slices end up deterministic across runs.
	cg.PackageIndex = NewPackageIndex()
	cg.PackageIndex.PythonReExports = pyReExports
	cg.PackageIndex.JSReExports = jsReExports
	// Java interface→impl index (Spring @Autowired dispatch). Built from
	// every Java FileScope's captured `implements` metadata; consulted by
	// javaResolver.ResolveCall. nil when there are no Java implements
	// clauses, so the interface-dispatch path is skipped on non-Spring
	// projects with no cost.
	cg.PackageIndex.javaImpls = buildJavaImplIndex(cg.FileScopes)
	// Shell source-graph (`source FILE` / `. FILE` edges). Built from every
	// Shell FileScope's StarImports (the resolved sourced-file paths captured
	// by shellResolver.ExtractScope); consulted by shellResolver.ResolveCall
	// to resolve a bare function call only to a transitively-sourced file. nil
	// when there are no Shell files, so the source-graph path is skipped at no
	// cost on non-Shell projects.
	cg.PackageIndex.shellSources = buildShellSourceGraph(cg.FileScopes)
	nodeIDs := make([]string, 0, len(cg.Nodes))
	for id := range cg.Nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)
	for _, id := range nodeIDs {
		node := cg.Nodes[id]
		pkg := importPathForNode(cg, node, scanDir)
		if pkg == "" {
			continue
		}
		cg.PackageIndex.Add(pkg, node.ID)
	}

	// Step 4: Resolve every node's RawCalls. Same sorted order so the
	// AddEdge calls produce stable Calls / CalledBy slices.
	stats := ResolveStats{FilesScoped: len(cg.FileScopes)}

	// Step 4a (env-gated): If BATOU_GOTYPES_RESOLVER is set, hand every
	// Go node off to the go/types-based bulk resolver, which loads each
	// module's packages once and resolves all calls in one pass. Skip
	// those nodes in the per-call loop below (the bulk pass already
	// counted them). Non-Go nodes still use the per-call loop. When the
	// env var is unset, this whole block is skipped and behaviour is
	// byte-for-byte identical to the legacy path.
	goTypesHandled := make(map[string]bool)
	if GoTypesResolverEnabled() {
		modCache := newModuleCache()
		// Group Go nodes by their owning module (multi-module repos:
		// Vault has 16+ go.mod files, each module gets its own
		// packages.Load + cache entry).
		byModule := make(map[string][]*FuncNode)
		for _, id := range nodeIDs {
			node := cg.Nodes[id]
			if node.Language != rules.LangGo {
				continue
			}
			_, root := moduleForFile(cg, node.FilePath, rules.LangGo)
			if root == "" {
				continue
			}
			byModule[root] = append(byModule[root], node)
			goTypesHandled[id] = true
		}
		gtr := getGoTypesResolver()
		// Sort module roots for stable iteration order across runs.
		modRoots := make([]string, 0, len(byModule))
		for k := range byModule {
			modRoots = append(modRoots, k)
		}
		sort.Strings(modRoots)
		for _, root := range modRoots {
			modulePath := ""
			// All nodes under this root share the same module path; grab
			// it from the first node's FileModules entry (or the global
			// fallback).
			if nodes := byModule[root]; len(nodes) > 0 {
				modulePath, _ = moduleForFile(cg, nodes[0].FilePath, rules.LangGo)
			}
			nodes := byModule[root]
			// Count NodesResolved before delegating — the bulk pass
			// won't touch nodes with no RawCalls, and the per-call loop
			// only increments on RawCalls anyway, so be consistent.
			for _, n := range nodes {
				if len(n.RawCalls) > 0 {
					stats.NodesResolved++
				}
			}
			res := gtr.ResolveModule(cg, scanDir, modulePath, root, nodes, modCache)
			stats.CrossFileEdges += res.CrossFileEdges
			stats.ExternEdges += res.ExternEdges
			stats.Unresolved += res.Unresolved
		}
	}

	for _, id := range nodeIDs {
		if goTypesHandled[id] {
			continue
		}
		resolveNodeRawCalls(cg, cg.Nodes[id], &stats)
	}

	// Step 5: cross-language HTTP service-boundary edges. Link
	// outbound request sites (FuncNode.OutboundRequests) to the in-repo
	// route handler (FuncNode.RoutePath) serving the same path, in another
	// file/language. This adds Calls/CalledBy edges so the dependency is
	// visible to downstream consumers; the synthesised findings are
	// produced separately by CrossLangServiceBoundaryFindings at emit
	// time. We count the new edges into CrossFileEdges so the resolve
	// metric reflects them. The pass is idempotent (AddEdge dedups).
	before := countEdges(cg)
	_ = linkServiceBoundaryEdges(cg)
	stats.CrossFileEdges += countEdges(cg) - before

	return stats
}

// resolveNodeRawCalls re-resolves a single node's RawCalls against the
// graph's PackageIndex / FileScopes, adding cross-file edges and
// recording extern / unresolved calls. This is the per-node body of
// ResolveCrossFileEdges' step 4, factored out so the incremental
// hook-lane pass (ResolveCrossFileEdgesForFile) can reuse it for a
// bounded node set. Idempotent: AddEdge dedups both directions and
// ExternCalls / UnresolvedCalls are reset before re-resolving.
func resolveNodeRawCalls(cg *CallGraph, node *FuncNode, stats *ResolveStats) {
	if node == nil || len(node.RawCalls) == 0 {
		return
	}
	stats.NodesResolved++

	r := GetResolver(node.Language)
	if r == nil {
		return
	}
	scope := cg.FileScopes[node.FilePath]
	// Use the file's own module path (multi-module repos), not the
	// global ModulePaths[lang] — otherwise sub-module calls get
	// mis-classified as external. moduleForFile falls back to the
	// global value when the file isn't in FileModules.
	modulePath, _ := moduleForFile(cg, node.FilePath, node.Language)

	// Reset extern/unresolved before re-resolving so the pass is
	// idempotent. Same-file edges in Calls/CalledBy stay — they
	// were resolved during per-file extraction and don't need
	// re-checking here.
	node.ExternCalls = nil
	node.UnresolvedCalls = nil

	for _, raw := range node.RawCalls {
		res := r.ResolveCall(raw, scope, modulePath, cg.PackageIndex)
		switch {
		case res.TargetID != "" && res.TargetID != node.ID:
			// Always call AddEdge (it is idempotent on BOTH directions)
			// rather than gating on node.Calls membership. On a warm
			// rescan the caller's Calls slice can survive on a
			// content-hash-reused node while the callee's CalledBy
			// back-edge was stripped by RemoveFile when the callee's
			// file was rebuilt — leaving an asymmetric edge. Gating on
			// node.Calls would then skip AddEdge and never restore the
			// callee.CalledBy, so the cross-file taint walk (which
			// iterates callees by CalledBy) drops the flow
			// non-deterministically depending on worker scan order.
			// AddEdge dedups each side independently, so re-issuing it
			// repairs the back-edge without duplicating the forward one.
			hadEdge := containsStr(node.Calls, res.TargetID)
			cg.AddEdge(node.ID, res.TargetID)
			if !hadEdge {
				stats.CrossFileEdges++
			}
		case res.Extern != "":
			if !containsStr(node.ExternCalls, res.Extern) {
				node.ExternCalls = append(node.ExternCalls, res.Extern)
				stats.ExternEdges++
			}
		default:
			// Bare identifiers (no dot) are intra-package calls
			// already resolved by the same-file pass during AST
			// extraction. Recording them as "unresolved" creates
			// false noise — skip.
			if !strings.Contains(raw, ".") {
				continue
			}
			// Likewise skip dotted calls whose receiver is a local
			// variable rather than an import alias. If the prefix
			// before the first dot is NOT in scope.Imports, this is
			// almost certainly a method call on a typed value (e.g.
			// `db.Query(...)` where db is a *sql.DB local). We
			// can't resolve those without type inference; leave
			// them out of unresolved_calls to keep the noise floor
			// low. Adapters with method-dispatch support (Java, C#)
			// will handle these via their own ResolveCall.
			dot := strings.Index(raw, ".")
			if dot > 0 {
				alias := raw[:dot]
				if _, isImport := scope.Imports[alias]; !isImport {
					continue
				}
			}
			if !containsStr(node.UnresolvedCalls, raw) {
				node.UnresolvedCalls = append(node.UnresolvedCalls, raw)
				stats.Unresolved++
			}
		}
	}
}

// countEdges returns the total number of directed Calls edges in cg.
// Used to measure how many new edges a pass added.
func countEdges(cg *CallGraph) int {
	n := 0
	for _, node := range cg.Nodes {
		if node != nil {
			n += len(node.Calls)
		}
	}
	return n
}

// CrossLangServiceBoundaryFindings runs the cross-language path-literal
// matcher and returns the synthesised cross-language taint findings. It is
// idempotent: re-running re-adds the same (deduped) edges and re-derives
// the same findings from the persisted RoutePath / OutboundRequests node
// metadata. Call this AFTER ResolveCrossFileEdges so handler sinks have
// been populated and edges resolved.
func CrossLangServiceBoundaryFindings(cg *CallGraph) []rules.Finding {
	return linkServiceBoundaryEdges(cg)
}

// languagesInGraph returns the unique set of languages whose nodes
// exist in cg.
func languagesInGraph(cg *CallGraph) []rules.Language {
	seen := make(map[rules.Language]bool)
	var out []rules.Language
	for _, n := range cg.Nodes {
		if n.Language == "" {
			continue
		}
		if !seen[n.Language] {
			seen[n.Language] = true
			out = append(out, n.Language)
		}
	}
	return out
}

// filesInGraph returns the unique set of file paths represented in cg.
func filesInGraph(cg *CallGraph) []string {
	seen := make(map[string]bool)
	var out []string
	for _, n := range cg.Nodes {
		if !seen[n.FilePath] {
			seen[n.FilePath] = true
			out = append(out, n.FilePath)
		}
	}
	return out
}

// fetchContent returns the content of filePath. It first checks the
// caller-supplied map (which avoids a disk read during the scan), then
// falls back to reading from disk relative to scanDir or as an
// absolute path. Returns nil if neither lookup succeeds.
func fetchContent(filePath, scanDir string, fileContents map[string][]byte) []byte {
	if c, ok := fileContents[filePath]; ok {
		return c
	}
	// Try as written (might be absolute or relative-to-cwd).
	if b, err := os.ReadFile(filePath); err == nil {
		return b
	}
	// Try relative to scanDir.
	if scanDir != "" {
		if b, err := os.ReadFile(filepath.Join(scanDir, filePath)); err == nil {
			return b
		}
	}
	return nil
}

// importPathForNode returns the in-project import path of node's file.
// Implementation is language-specific:
//
//	Go:     <modulePath>/<file's directory relative to manifest dir>
//	Python: <modulePath>.<filesystem path relative to module root,
//	        with slashes → dots and ".py"/"__init__" suffixes stripped>
//
// Looks up the file's per-file module via cg.FileModules first (for
// multi-module repos), falling back to the global ModulePaths[lang]
// when no per-file entry exists. Other languages will get their own
// branches as the adapters land. Returns "" when the node lies
// outside any known module.
func importPathForNode(cg *CallGraph, node *FuncNode, scanDir string) string {
	switch node.Language {
	case rules.LangGo:
		modulePath, moduleRoot := moduleForFile(cg, node.FilePath, rules.LangGo)
		if modulePath == "" {
			return ""
		}
		fileDir := filepath.Dir(node.FilePath)
		rel := relativeDir(fileDir, moduleRoot, scanDir)
		if rel == "" || rel == "." {
			return modulePath
		}
		return modulePath + "/" + filepath.ToSlash(rel)
	case rules.LangPython:
		_, moduleRoot := moduleForFile(cg, node.FilePath, rules.LangPython)
		// Python doesn't strictly require a manifest-declared module
		// path — pure-package repos work fine with just a module root
		// (the package directory above __init__.py). When neither is
		// known, fall back to deriving the dotted path from the file
		// path alone — this still gives consistent keys across nodes
		// in the same module so PackageIndex lookups line up.
		return pythonModuleKey(node.FilePath, moduleRoot, scanDir)
	case rules.LangJavaScript, rules.LangTypeScript:
		// JS/TS doesn't have a global namespace — every file is its own
		// "module". The resolver keys imports on absolute file paths
		// (see resolveJSSpecifier), so PackageIndex uses the same form:
		// each node's package == its file's absolute path.
		if filepath.IsAbs(node.FilePath) {
			return node.FilePath
		}
		if abs, err := filepath.Abs(node.FilePath); err == nil {
			return abs
		}
		return node.FilePath
	case rules.LangJava:
		// Java has a dotted package namespace, but multiple classes
		// can share a package across files. The resolver keys imports
		// on the absolute path of the .java file declaring the imported
		// class (resolveJavaImportToFile), so PackageIndex uses the
		// same form: each node's package == its file's absolute path.
		// Mirrors the JS/TS branch above.
		if filepath.IsAbs(node.FilePath) {
			return node.FilePath
		}
		if abs, err := filepath.Abs(node.FilePath); err == nil {
			return abs
		}
		return node.FilePath
	case rules.LangRuby:
		// Ruby has no formal namespace-to-file mapping. The resolver
		// keys imports on the absolute path of the .rb file the
		// require / require_relative / autoload lands on (see
		// resolveRubyRelative / resolveRubyLibrarySpecifier), so
		// PackageIndex uses the same form. Mirrors the JS/TS / Java
		// "every file is its own namespace" branches.
		if filepath.IsAbs(node.FilePath) {
			return node.FilePath
		}
		if abs, err := filepath.Abs(node.FilePath); err == nil {
			return abs
		}
		return node.FilePath
	case rules.LangPHP:
		// PHP has a backslash-qualified namespace (App\Foo) but the
		// resolver keys imports on the absolute path of the .php file
		// declaring the imported class (phpResolveFQNToFile), so
		// PackageIndex uses the same form: each node's package == its
		// file's absolute path. Mirrors the JS/TS and Java branches.
		if filepath.IsAbs(node.FilePath) {
			return node.FilePath
		}
		if abs, err := filepath.Abs(node.FilePath); err == nil {
			return abs
		}
		return node.FilePath
	case rules.LangLua:
		// Lua has no file-path-to-namespace mapping — modules are values
		// returned by a chunk and bound via `require`. The resolver keys
		// imports on the absolute path of the .lua file the require lands
		// on (see resolveLuaModuleSpecifier), so PackageIndex uses the
		// same form: each node's package == its file's absolute path.
		// Mirrors the JS/TS, Java, Ruby, and PHP branches.
		if filepath.IsAbs(node.FilePath) {
			return node.FilePath
		}
		if abs, err := filepath.Abs(node.FilePath); err == nil {
			return abs
		}
		return node.FilePath
	case rules.LangKotlin:
		// Kotlin has a dotted `package`, but a package spans many files and
		// there is no enforced file=directory layout (the C# situation, not
		// Java's), so the resolver keys nodes on the absolute path of the
		// .kt file (each node's fully-qualified name carries the package;
		// resolver_kotlin.go matches same-package calls by node-name
		// prefix). PackageIndex uses the same form: each node's package ==
		// its file's absolute path. Mirrors the C# / Java branches.
		if filepath.IsAbs(node.FilePath) {
			return node.FilePath
		}
		if abs, err := filepath.Abs(node.FilePath); err == nil {
			return abs
		}
		return node.FilePath
	case rules.LangGroovy:
		// Groovy is a JVM language with a file-level `package a.b.c` (and,
		// like C#, no enforced file=directory layout — many files can share a
		// package), so the resolver keys nodes on the absolute path of the
		// .groovy file. Each node's fully-qualified name carries the package
		// prefix (the builder emits "app.A.getName"); resolver_groovy.go
		// matches same-package calls by node-name prefix. PackageIndex uses
		// the same form: each node's package == its file's absolute path.
		// Mirrors the C# / Java branches. (This REPLACES the earlier
		// single-bucket "groovy::module" model whose bare-suffix matching
		// cross-wired same-named methods in different packages.)
		if filepath.IsAbs(node.FilePath) {
			return node.FilePath
		}
		if abs, err := filepath.Abs(node.FilePath); err == nil {
			return abs
		}
		return node.FilePath
	case rules.LangPerl:
		// Perl packages map to files (`Foo::Bar` → `Foo/Bar.pm`), but the
		// resolver keys nodes on the absolute path of the .pm/.pl file (a
		// `use`/`require` binds packageName → that absolute path; see
		// resolver_perl.go). PackageIndex uses the same form: each node's
		// package == its file's absolute path. Mirrors the Lua / Rust / C++
		// / C# / Java / JS/TS / Ruby / PHP branches.
		if filepath.IsAbs(node.FilePath) {
			return node.FilePath
		}
		if abs, err := filepath.Abs(node.FilePath); err == nil {
			return abs
		}
		return node.FilePath
	case rules.LangShell:
		// Shell functions are bare top-level names (like Swift), BUT unlike
		// Swift a function is only visible cross-file when its defining file
		// is reached via `source FILE` / `. FILE` — sourcing injects the
		// target's functions into the sourcer's namespace. So we do NOT use a
		// single shared bucket (that would over-resolve a function from ANY
		// file in the scan dir, the diagnosed FP class). Instead each Shell
		// node keys under its own absolute file path and the resolver
		// (resolver_shell.go) walks the source-graph from the caller's file,
		// resolving a bare call only to a function defined in a transitively-
		// sourced file. Mirrors the C# / Lua path-keyed branches.
		if filepath.IsAbs(node.FilePath) {
			return node.FilePath
		}
		if abs, err := filepath.Abs(node.FilePath); err == nil {
			return abs
		}
		return node.FilePath
	case rules.LangC, rules.LangCPP:
		// C/C++ have no module system — cross-translation-unit visibility is
		// established by the preprocessor's `#include`. The resolver keys
		// nodes on the absolute path of the .cpp/.h file they're defined in
		// and resolves an `#include "x.h"` to that header's sibling .cpp
		// implementation file (resolver_cpp.go). PackageIndex uses the same
		// form: each node's package == its file's absolute path. Mirrors the
		// Rust / C# / Java / JS/TS / Ruby / PHP / Lua branches.
		if filepath.IsAbs(node.FilePath) {
			return node.FilePath
		}
		if abs, err := filepath.Abs(node.FilePath); err == nil {
			return abs
		}
		return node.FilePath
	case rules.LangSwift:
		// Swift has no file-path-to-namespace mapping — within one module
		// every top-level func and method is visible across all files by
		// bare name (`import X` is module-level only, never per-symbol). The
		// resolver keys ALL Swift nodes under one shared bucket and resolves
		// a call by its bare suffix (see resolver_swift.go), so PackageIndex
		// must use the same constant key. Returning "" here would make
		// resolve.go skip every Swift node from the index. v1 treats the
		// whole scan dir as one module (correct for single-target apps).
		return swiftModuleBucket
	case rules.LangRust:
		// Rust modules are file-based (mod/use), but the resolver keys
		// imports on the absolute path of the .rs file a mod declaration
		// maps to (see rustResolveModFile), so PackageIndex uses the same
		// form: each node's package == its file's absolute path. Mirrors
		// the Lua / JS/TS / Java / Ruby / PHP / C# branches.
		if filepath.IsAbs(node.FilePath) {
			return node.FilePath
		}
		if abs, err := filepath.Abs(node.FilePath); err == nil {
			return abs
		}
		return node.FilePath
	case rules.LangCSharp:
		// C# has a dotted namespace, but a `namespace` can span many files
		// and there is no enforced file=directory layout, so the resolver
		// keys nodes on the absolute path of the .cs file (each node's
		// fully-qualified name carries the namespace; resolver_csharp.go
		// matches same-namespace calls by node-name prefix). PackageIndex
		// uses the same form: each node's package == its file's absolute
		// path. Mirrors the Java / JS/TS / Ruby / PHP / Lua branches.
		if filepath.IsAbs(node.FilePath) {
			return node.FilePath
		}
		if abs, err := filepath.Abs(node.FilePath); err == nil {
			return abs
		}
		return node.FilePath
	}
	return ""
}

// pythonModuleKey returns the dotted Python module path for a file
// relative to moduleRoot. moduleRoot is the parent directory of the
// project's package root (so a file at moduleRoot/myapp/sub/x.py keys
// to "myapp.sub.x"). When moduleRoot is empty we fall back to a CWD-
// relative dotted path.
func pythonModuleKey(filePath, moduleRoot, _scanDir string) string {
	abs := filePath
	if !filepath.IsAbs(abs) {
		if cwd, err := os.Getwd(); err == nil {
			abs = filepath.Join(cwd, strings.TrimPrefix(abs, "./"))
		}
	}
	rel := abs
	if moduleRoot != "" {
		// moduleRoot from the resolver is the directory containing the
		// manifest. For pyproject.toml at /proj/pyproject.toml, that's
		// /proj, and files live at /proj/myapp/x.py → "myapp.x".
		if r, err := filepath.Rel(moduleRoot, abs); err == nil && !strings.HasPrefix(r, "..") {
			rel = r
		}
	}
	rel = filepath.ToSlash(rel)
	rel = strings.TrimSuffix(rel, ".py")
	rel = strings.TrimSuffix(rel, "/__init__")
	rel = strings.TrimPrefix(rel, "./")
	rel = strings.TrimPrefix(rel, "/")
	parts := strings.Split(rel, "/")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	module := strings.Join(out, ".")
	// pythonModuleKey returns the full dotted path INCLUDING the
	// final file component. PackageIndex is keyed by *module*, so for
	// "myapp/handlers/login.py" we want "myapp.handlers.login" as the
	// key — that's what `from myapp.handlers.login import foo`
	// resolves to. (Other files in the same dir live under
	// "myapp.handlers.<other>" and get their own key.)
	return module
}

// moduleForFile returns (modulePath, moduleRoot) for filePath: the
// per-file entry if known, else the global per-language fallback.
func moduleForFile(cg *CallGraph, filePath string, lang rules.Language) (string, string) {
	if fm, ok := cg.FileModules[filePath]; ok && fm.ModulePath != "" {
		return fm.ModulePath, fm.ModuleRoot
	}
	return cg.ModulePaths[lang], cg.ModuleRoots[lang]
}

// absoluteFileDir returns an absolute path to the directory of
// filePath, treating filePath as relative-to-cwd when it isn't
// already absolute. scanDir is unused for the path-relative case
// (dirscan emits CWD-relative paths) but kept for symmetry with
// relativeDir.
func absoluteFileDir(filePath, _scanDir string) string {
	dir := filepath.Dir(filePath)
	if filepath.IsAbs(dir) {
		return dir
	}
	cwd, err := os.Getwd()
	if err != nil {
		return dir
	}
	dir = strings.TrimPrefix(dir, "./")
	return filepath.Join(cwd, dir)
}

// extractPythonInitScopes finds every __init__.py file in a directory
// that contains (directly or transitively) a Python file with at least
// one node in cg, and extracts a FileScope for it. The dispatcher's
// main scope-extraction loop (step 2) only visits files that have at
// least one FuncNode, which means re-export-only __init__.py files
// (Flask's src/flask/__init__.py is the canonical example: 40+ lines
// of `from .submod import X as X`, zero function defs) are skipped and
// their re-export tables are lost.
//
// This helper closes that gap: we walk each Python file's ancestor
// directories up to the per-file ModuleRoot, collecting __init__.py
// siblings, then extract a scope for each one (with the same Python
// post-processing the main loop applies: rebuilding imports against
// the corrected Package, stashing module_root on Aux).
//
// __init__.py files that ALREADY have a scope from step 2 are left
// alone; we never overwrite. This keeps the pass idempotent.
func extractPythonInitScopes(cg *CallGraph, scanDir string, fileContents map[string][]byte) {
	if cg == nil || cg.FileScopes == nil {
		return
	}
	r := GetResolver(rules.LangPython)
	if r == nil {
		return
	}
	// De-dupe candidates by absolute path so we don't re-parse the
	// same __init__.py multiple times when several files share a
	// package directory.
	seen := make(map[string]bool)
	for _, n := range cg.Nodes {
		if n.Language != rules.LangPython {
			continue
		}
		_, moduleRoot := moduleForFile(cg, n.FilePath, rules.LangPython)
		dir := absoluteFileDir(n.FilePath, scanDir)
		// Walk up the ancestor chain to (and including) moduleRoot,
		// stopping if we leave it. When moduleRoot is empty (scripts-
		// only repos), walk up only one level — there's no package
		// chain to follow.
		for {
			initPath := filepath.Join(dir, "__init__.py")
			if seen[initPath] {
				// Already processed (or scheduled); ascend.
			} else {
				seen[initPath] = true
				if _, already := cg.FileScopes[initPath]; !already {
					if info, err := os.Stat(initPath); err == nil && !info.IsDir() {
						content := fetchContent(initPath, scanDir, fileContents)
						if content != nil {
							scope, _ := r.ExtractScope(initPath, content)
							if scope.Aux == nil {
								scope.Aux = map[string]string{}
							}
							scope.Aux["module_root"] = moduleRoot
							scope.Package = pythonModuleKey(initPath, moduleRoot, scanDir)
							rebuildPythonScopeRelative(&scope, content)
							cg.FileScopes[initPath] = scope
						}
					}
				}
			}
			// Ascend one level. Stop when we leave moduleRoot or hit
			// the filesystem root.
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			if moduleRoot != "" {
				rel, err := filepath.Rel(moduleRoot, parent)
				if err != nil || strings.HasPrefix(rel, "..") {
					break
				}
			}
			dir = parent
			if moduleRoot == "" {
				// No package chain to follow; one level is enough to
				// catch the immediate __init__.py sibling above.
				break
			}
		}
	}
}

// collectPythonReExports walks scopes and returns a re-export index
// keyed by package dotted name. For each __init__.py FileScope the
// imports map IS the re-export table — anything brought into the
// package's namespace via `from X import Y` becomes accessible as
// `<package>.Y`. We use scope.Package as the key (the dispatcher
// already rewrites it to the canonical dotted form, e.g. "pkg" for
// pkg/__init__.py).
//
// Returns an empty (non-nil) map when there are no __init__.py files.
//
// Single-hop semantics: we don't resolve re-export chains here. If
// pkg/__init__.py re-exports from pkg.mid.__init__.py which re-exports
// from pkg.mid.leaf, looking up `pkg.X` yields `pkg.mid.X` (not
// `pkg.mid.leaf.X`). resolvePythonFullName retries the lookup once but
// stops there to avoid the bookkeeping needed to detect cycles.
func collectPythonReExports(scopes map[string]FileScope) map[string]map[string]string {
	out := make(map[string]map[string]string)
	for path, scope := range scopes {
		if filepath.Base(path) != "__init__.py" {
			continue
		}
		if scope.Package == "" || len(scope.Imports) == 0 {
			continue
		}
		// Take a copy so callers can't mutate the FileScope through
		// the re-export index.
		entries := make(map[string]string, len(scope.Imports))
		for local, full := range scope.Imports {
			entries[local] = full
		}
		out[scope.Package] = entries
	}
	return out
}

// extractJSBarrelScopes discovers JS/TS barrel files — files referenced
// as import targets that have no FuncNodes (so the step-2 loop skipped
// them) — and extracts their scopes so their re-export tables surface.
// The JS analog of extractPythonInitScopes: instead of walking __init__.py
// ancestor chains, we follow each JS/TS file's resolved import targets
// (FileScope.Imports values are absolute file paths) to any on-disk file
// not yet scoped, and scope it. One level only — a barrel that re-exports
// from another barrel is single-hop and the deeper barrel is reached when
// the leaf import resolves to it directly.
//
// Files already scoped from step 2 are left untouched, keeping the pass
// idempotent.
func extractJSBarrelScopes(cg *CallGraph, scanDir string, fileContents map[string][]byte) {
	if cg == nil || cg.FileScopes == nil {
		return
	}
	r := GetResolver(rules.LangJavaScript)
	if r == nil {
		return
	}
	// Collect candidate barrel paths: every import target of a JS/TS
	// scope that isn't already a scoped file. Snapshot first so we don't
	// mutate FileScopes while ranging it.
	candidates := make(map[string]bool)
	for path, scope := range cg.FileScopes {
		node := firstNodeInFile(cg, path)
		if node == nil {
			continue
		}
		if node.Language != rules.LangJavaScript && node.Language != rules.LangTypeScript {
			continue
		}
		for _, target := range scope.Imports {
			if target == "" {
				continue
			}
			if _, scoped := cg.FileScopes[target]; scoped {
				continue
			}
			candidates[target] = true
		}
	}
	for target := range candidates {
		if _, scoped := cg.FileScopes[target]; scoped {
			continue
		}
		if info, err := os.Stat(target); err != nil || info.IsDir() {
			continue
		}
		content := fetchContent(target, scanDir, fileContents)
		if content == nil {
			continue
		}
		scope, err := r.ExtractScope(target, content)
		if err != nil {
			continue
		}
		cg.FileScopes[target] = scope
	}
}

// firstNodeInFile returns any FuncNode declared in filePath, or nil when
// the file has no nodes (e.g. a re-export-only barrel).
func firstNodeInFile(cg *CallGraph, filePath string) *FuncNode {
	nodes := cg.NodesInFile(filePath)
	if len(nodes) == 0 {
		return nil
	}
	return nodes[0]
}

// collectJSReExports builds the barrel re-export index from JS/TS
// FileScopes. Each scope's Aux entries prefixed jsReExportAuxPrefix encode
// "<leafFile>\x00<leafName>"; we decode them into the per-barrel map keyed
// by the barrel file's absolute path (FileScope.Package, which the JS
// resolver sets to the file's own absolute path). Returns an empty
// (non-nil) map when there are no re-exports.
//
// Single-hop only: a barrel re-exporting from another barrel is not
// flattened here — the leaf entry points at the intermediate file, and
// ResolveCall follows exactly one hop.
func collectJSReExports(scopes map[string]FileScope) map[string]map[string]jsReExport {
	out := make(map[string]map[string]jsReExport)
	for _, scope := range scopes {
		if scope.Package == "" || len(scope.Aux) == 0 {
			continue
		}
		var entries map[string]jsReExport
		for k, v := range scope.Aux {
			if !strings.HasPrefix(k, jsReExportAuxPrefix) {
				continue
			}
			exposed := k[len(jsReExportAuxPrefix):]
			sep := strings.IndexByte(v, '\x00')
			if sep < 0 {
				continue
			}
			leafFile := v[:sep]
			leafName := v[sep+1:]
			if leafFile == "" || exposed == "" {
				continue
			}
			if entries == nil {
				entries = make(map[string]jsReExport)
			}
			entries[exposed] = jsReExport{LeafFile: leafFile, LeafName: leafName}
		}
		if entries != nil {
			out[scope.Package] = entries
		}
	}
	return out
}

// relativeDir returns fileDir expressed relative to moduleRoot.
//
// fileDir comes from FuncNode.FilePath which is emitted by dirscan as
// a path RELATIVE TO CWD (the user's working directory when they ran
// `batou scan`). moduleRoot is the absolute directory containing the
// project manifest (go.mod / package.json / …).
//
// We resolve fileDir to an absolute path by joining with CWD if it's
// not already absolute. scanDir is unused — the dirscan paths are
// CWD-relative regardless of where scanDir points; joining scanDir in
// would double-count when fileDir already includes scanDir's basename
// as its first path segment (e.g. `gitea/cmd/x.go` when scanning
// `./gitea`).
//
// Returns "" when the file is outside the module root.
func relativeDir(fileDir, moduleRoot, _scanDir string) string {
	if moduleRoot == "" {
		return ""
	}
	abs := fileDir
	if !filepath.IsAbs(abs) {
		abs = strings.TrimPrefix(abs, "./")
		cwd, err := os.Getwd()
		if err == nil {
			abs = filepath.Join(cwd, abs)
		}
	}
	rel, err := filepath.Rel(moduleRoot, abs)
	if err != nil {
		return ""
	}
	if strings.HasPrefix(rel, "..") {
		return "" // outside the module root
	}
	return rel
}

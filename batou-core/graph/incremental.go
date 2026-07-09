// Incremental (single-file) cross-file resolution for the write-time hook lane.
//
// `batou scan` builds the full cross-file picture in its finalize pass
// (ResolveCrossFileEdges + PropagateSignaturesAcrossCallgraph +
// WalkCrossFileTaintFlows) and persists it to .batou/callgraph.json. The
// hook lane historically never saw any of that: each hook session started
// with an empty session-keyed graph, the builders emit same-file edges
// only, and a hook save could clobber the scan-built state.
//
// This file provides the bounded, per-file complement used by the hook:
//
//   - CallersOfFileFromOtherFiles: snapshot the inbound cross-file callers
//     of a file BEFORE UpdateFile* strips its nodes (RemoveFile cleans the
//     back-edges in both directions), so they can be re-resolved after.
//   - ResolveCrossFileEdgesForFile: re-extract the edited file's scope,
//     refresh its PackageIndex entries, and re-resolve RawCalls for the
//     file's own nodes plus the captured inbound callers — one hop, no
//     project-wide iteration.
//   - CanonicalGraphPath: map the hook's (absolute) file path onto the path
//     form the scan-built graph keys the file by (scans run from the repo
//     root often record CWD-relative paths).
//
// All entry points no-op when the graph carries no cross-file state
// (HasCrossFileState == false), so hook behavior on graphs the scan never
// touched is unchanged.
package graph

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/turenlabs/batou-rules/rules"
)

// maxIncrementalCallers bounds how many inbound cross-file callers the
// hook lane re-resolves after a file update. Files called from more
// places than this keep only the first N (sorted by node ID) — the next
// full `batou scan` heals the rest. Keeps hook latency bounded on
// hub files (utility modules called from hundreds of places).
const maxIncrementalCallers = 64

// CallersOfFileFromOtherFiles returns the sorted, deduplicated IDs of
// nodes in OTHER files that call into any node defined in filePath.
// Capped at maxIncrementalCallers. Call this BEFORE UpdateFileWithAST:
// RemoveFile strips the file's nodes and cleans the callers' Calls
// edges, so the information is gone afterward.
func CallersOfFileFromOtherFiles(cg *CallGraph, filePath string) []string {
	if cg == nil {
		return nil
	}
	seen := make(map[string]bool)
	for _, node := range cg.Nodes {
		if node == nil || node.FilePath != filePath {
			continue
		}
		for _, callerID := range node.CalledBy {
			caller := cg.Nodes[callerID]
			if caller == nil || caller.FilePath == filePath {
				continue
			}
			seen[callerID] = true
		}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	if len(out) > maxIncrementalCallers {
		capHits.callers.Add(1) // diagnostics only: inbound callers beyond the cap were dropped
		out = out[:maxIncrementalCallers]
	}
	return out
}

// CanonicalGraphPath returns the path form the graph knows filePath by.
// Hook events carry absolute paths; a graph built by `batou scan .`
// records CWD-relative paths. When the graph has no entry under the
// absolute form but does under the ProjectRoot-relative form, the
// relative form is returned so the hook's update replaces the scan's
// nodes (preserving content-hash signature reuse) instead of creating a
// duplicate node set under a second spelling of the same file.
func CanonicalGraphPath(cg *CallGraph, filePath string) string {
	if cg == nil || filePath == "" {
		return filePath
	}
	if graphKnowsFile(cg, filePath) {
		return filePath
	}
	if cg.ProjectRoot == "" || !filepath.IsAbs(filePath) {
		return filePath
	}
	rel, err := filepath.Rel(cg.ProjectRoot, filePath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filePath
	}
	for _, cand := range []string{rel, "./" + rel} {
		if graphKnowsFile(cg, cand) {
			return cand
		}
	}
	return filePath
}

// graphKnowsFile reports whether the graph has any node or file scope
// recorded under exactly this path string.
func graphKnowsFile(cg *CallGraph, path string) bool {
	if _, ok := cg.FileScopes[path]; ok {
		return true
	}
	for _, n := range cg.Nodes {
		if n != nil && n.FilePath == path {
			return true
		}
	}
	return false
}

// ResolveCrossFileEdgesForFile is the bounded, single-file version of
// ResolveCrossFileEdges used by the write-time hook lane after
// UpdateFileWithAST rebuilt filePath's nodes. It:
//
//  1. Ensures module metadata (global + per-file) exists for the file's
//     language, discovering manifests only when the persisted graph
//     doesn't already carry them.
//  2. Re-extracts the file's FileScope from the in-memory content (the
//     content just changed — the persisted scope is stale).
//  3. Refreshes the PackageIndex entries owned by this file: stale node
//     IDs (functions removed/renamed by the edit) are dropped, current
//     nodes are (re-)indexed.
//  4. Re-resolves RawCalls for this file's nodes (restoring the file's
//     outbound cross-file edges) and for alsoResolve (the inbound callers
//     captured by CallersOfFileFromOtherFiles, restoring edges INTO this
//     file). One hop in each direction — no transitive fan-out.
//
// scanDir is the project root the hook is running in (hook.Input.Cwd).
// No-ops when the graph has no scan-built cross-file state, so a
// hook-only session graph never pays this cost (and never gains
// half-built cross-file structures).
//
// Skipped relative to the full pass (documented bounds, healed by the
// next `batou scan`): Python __init__/JS barrel re-export DISCOVERY (the
// persisted re-export tables are still used), cross-language service-
// boundary linking, the env-gated go/types bulk resolver, and global
// signature re-propagation (persisted lifted sinks on other files'
// nodes are still honored).
func ResolveCrossFileEdgesForFile(cg *CallGraph, scanDir, filePath string, content []byte, alsoResolve []string) ResolveStats {
	stats := ResolveStats{}
	if cg == nil || !cg.HasCrossFileState() {
		return stats
	}
	if cg.ModulePaths == nil {
		cg.ModulePaths = make(map[rules.Language]string)
	}
	if cg.ModuleRoots == nil {
		cg.ModuleRoots = make(map[rules.Language]string)
	}
	if cg.FileModules == nil {
		cg.FileModules = make(map[string]FileModule)
	}
	if cg.FileScopes == nil {
		cg.FileScopes = make(map[string]FileScope)
	}

	nodes := cg.NodesInFile(filePath)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	if len(nodes) > 0 {
		lang := nodes[0].Language
		if r := GetResolver(lang); r != nil {
			// Global per-language module fallback (mirrors step 1 of the
			// full pass) — only when the persisted graph doesn't have it.
			if _, ok := cg.ModulePaths[lang]; !ok {
				if manifest, mod, found := r.ProjectRoot(scanDir); found {
					cg.ModulePaths[lang] = mod
					cg.ModuleRoots[lang] = filepath.Dir(manifest)
				}
			}
			// Per-file nearest-manifest module (mirrors step 1b).
			if _, ok := cg.FileModules[filePath]; !ok {
				dir := absoluteFileDir(filePath, scanDir)
				if manifest, mod, found := r.ProjectRoot(dir); found {
					cg.FileModules[filePath] = FileModule{ModulePath: mod, ModuleRoot: filepath.Dir(manifest)}
				}
			}
			// Re-extract this file's scope from the just-written content
			// (mirrors step 2, including the Python package-key fixup).
			scope, _ := r.ExtractScope(filePath, content)
			if lang == rules.LangPython {
				if scope.Aux == nil {
					scope.Aux = map[string]string{}
				}
				_, root := moduleForFile(cg, filePath, rules.LangPython)
				scope.Aux["module_root"] = root
				scope.Package = pythonModuleKey(filePath, root, scanDir)
				rebuildPythonScopeRelative(&scope, content)
			}
			cg.FileScopes[filePath] = scope
		}
		stats.FilesScoped = 1

		reindexFileNodes(cg, filePath, scanDir, nodes)
	}

	// The Java interface→impl index and the Shell source-graph are not
	// serialized (rebuilt by every full scan). Rebuild them from the
	// persisted FileScopes so method-dispatch / sourced-function
	// resolution keeps working in the hook lane. Pure functions of
	// FileScopes; cheap relative to a parse.
	if cg.PackageIndex.javaImpls == nil {
		cg.PackageIndex.javaImpls = buildJavaImplIndex(cg.FileScopes)
	}
	if cg.PackageIndex.shellSources == nil {
		cg.PackageIndex.shellSources = buildShellSourceGraph(cg.FileScopes)
	}

	// Re-resolve this file's own nodes (outbound edges)...
	for _, node := range nodes {
		resolveNodeRawCalls(cg, node, &stats)
	}
	// ...and the captured inbound callers (edges INTO this file). Their
	// scopes are normally persisted from the scan; extract from disk as
	// a fallback so a caller scanned before scopes were persisted still
	// resolves.
	for _, callerID := range alsoResolve {
		caller := cg.Nodes[callerID]
		if caller == nil || caller.FilePath == filePath {
			continue
		}
		ensureFileScopeFromDisk(cg, caller.FilePath, scanDir)
		resolveNodeRawCalls(cg, caller, &stats)
	}
	return stats
}

// reindexFileNodes refreshes the PackageIndex entries owned by filePath:
// stale IDs (nodes that no longer exist after the edit) are removed,
// current nodes are added under their import path. Nodes already indexed
// under the right package are left untouched, so repeated hook scans
// don't duplicate index entries.
func reindexFileNodes(cg *CallGraph, filePath, scanDir string, nodes []*FuncNode) {
	pi := cg.PackageIndex
	if pi == nil {
		return
	}
	if pi.PackageToNodes == nil {
		pi.PackageToNodes = make(map[string][]string)
	}
	if pi.NodeToPackage == nil {
		pi.NodeToPackage = make(map[string]string)
	}
	// Drop stale entries: IDs keyed under this file whose node is gone.
	// FuncIDs are "<filePath>:<FuncName>", so the prefix match scopes the
	// sweep to this file.
	prefix := filePath + ":"
	for id, pkg := range pi.NodeToPackage {
		if !strings.HasPrefix(id, prefix) {
			continue
		}
		if cg.Nodes[id] != nil {
			continue
		}
		pi.PackageToNodes[pkg] = removeStr(pi.PackageToNodes[pkg], id)
		if len(pi.PackageToNodes[pkg]) == 0 {
			delete(pi.PackageToNodes, pkg)
		}
		delete(pi.NodeToPackage, id)
	}
	// (Re-)index current nodes.
	for _, node := range nodes {
		pkg := importPathForNode(cg, node, scanDir)
		if pkg == "" {
			continue
		}
		if old, ok := pi.NodeToPackage[node.ID]; ok {
			if old == pkg {
				continue // already indexed correctly
			}
			pi.PackageToNodes[old] = removeStr(pi.PackageToNodes[old], node.ID)
			if len(pi.PackageToNodes[old]) == 0 {
				delete(pi.PackageToNodes, old)
			}
			delete(pi.NodeToPackage, node.ID)
		}
		pi.Add(pkg, node.ID)
	}
}

// ensureFileScopeFromDisk extracts and caches a FileScope for filePath
// when the graph doesn't already have one. Reads from disk with the
// same size cap the interproc caller-loader uses (maxCallerFileSize,
// overridable via BATOU_HOOK_CALLER_MAX_MB).
func ensureFileScopeFromDisk(cg *CallGraph, filePath, scanDir string) {
	if _, ok := cg.FileScopes[filePath]; ok {
		return
	}
	nodes := cg.NodesInFile(filePath)
	if len(nodes) == 0 {
		return
	}
	r := GetResolver(nodes[0].Language)
	if r == nil {
		return
	}
	info, err := os.Stat(filePath)
	if err != nil || info.IsDir() || info.Size() > maxCallerFileSize() {
		return
	}
	content := fetchContent(filePath, scanDir, nil)
	if content == nil {
		return
	}
	scope, err := r.ExtractScope(filePath, content)
	if err != nil {
		return
	}
	cg.FileScopes[filePath] = scope
}

// Package graph: cross-file resolution framework.
//
// This file declares the LanguageResolver interface and the supporting
// data structures used by the cross-file resolution pass. Each language
// adapter implements LanguageResolver and registers itself via
// RegisterResolver at init time. The CallGraph builder consults the
// registry after the per-file AST extraction phase to rewrite call
// edges that target functions in other files within the same project.
//
// The framework is intentionally language-agnostic: it knows nothing
// about Go modules, Python packages, Cargo manifests, etc. All such
// knowledge lives in per-language adapter files (resolver_golang.go,
// resolver_python.go, …). The contract a resolver must satisfy is
// captured by the LanguageResolver interface below.
package graph

import (
	"strings"
	"sync"

	"github.com/turenlabs/batou-rules/rules"
)

// FileScope captures the import-and-package context of a single source
// file as seen from outside the file's body. A resolver populates it
// once per file; the framework reuses it for every call expression
// inside that file.
type FileScope struct {
	// FilePath is the path the scope was extracted from (used for
	// keying caches and disambiguating same-name packages).
	FilePath string

	// Package is the declared package or module name as it appears in
	// the file (Go: `package foo`; Python: derived from the directory
	// containing __init__.py; Java: `package com.foo.bar`).
	Package string

	// Imports maps the alias visible in this file's body to a fully
	// qualified import path:
	//
	//   Go:     "auth" → "code.gitea.io/gitea/services/auth"
	//   Python: "lib"  → "myapp.lib.helpers"
	//   Java:   "Bar"  → "com.foo.bar.Bar"
	//
	// Unaliased imports use the path's last component as the alias.
	// Dot/star imports go in StarImports below.
	Imports map[string]string

	// StarImports lists import paths that introduce names into the
	// current file's body without qualification (Python `from foo
	// import *`, Go `import . "foo"`, Java `import com.foo.*`). A
	// resolver should consult these for unqualified call sites.
	StarImports []string

	// Aux is a per-language scratchpad. Adapters may stash language-
	// specific context here (tsconfig#paths aliases, PSR-4 prefixes,
	// receiver-type bindings, …). The framework does not interpret it.
	Aux map[string]string
}

// PackageIndex maps a normalized in-project package path to the set of
// FuncNode IDs that declare functions or methods in that package. It
// is populated by the cross-file pass before edge rewriting begins,
// then consulted by LanguageResolver.ResolveCall.
//
// "Normalized" means the form a resolver chooses to represent its
// language's package shape — for Go that's typically the import path
// (`code.gitea.io/gitea/services/auth`); for Python it's the dotted
// module path (`myapp.lib.helpers`); for Java it's `com.foo.bar`. The
// framework does not interpret the keys.
type PackageIndex struct {
	// PackageToNodes maps package key → list of node IDs declared
	// inside that package.
	PackageToNodes map[string][]string `json:"package_to_nodes,omitempty"`

	// NodeToPackage is the reverse mapping. Populated when the resolver
	// classifies each node so reverse-lookups (which package owns X?)
	// are O(1) without re-deriving it.
	NodeToPackage map[string]string `json:"node_to_package,omitempty"`

	// PythonReExports records the re-export tables of each Python
	// package's __init__.py. Outer key is the package's dotted name
	// (e.g. "pkg" for pkg/__init__.py); inner map is localName →
	// fully-qualified symbol it re-exports (e.g. "handler" →
	// "pkg.sub.handler" from `from pkg.sub import handler`). Empty for
	// non-Python projects. Populated by the cross-file dispatcher after
	// FileScopes are extracted; consulted by resolvePythonFullName to
	// follow `from pkg import X` through the __init__.py to its real
	// definition module.
	//
	// Single-hop only: chains (__init__.py → __init__.py → leaf) are
	// not followed in this pass — documented as future work.
	PythonReExports map[string]map[string]string `json:"python_re_exports,omitempty"`

	// JSReExports records JS/TS barrel re-export tables. Outer key is the
	// barrel file's absolute path (e.g. .../index.js); inner map is the
	// name the barrel EXPOSES → the leaf symbol it forwards to. For
	// `export {runShell} from './impl'` in index.js, JSReExports[index.js]
	// ["runShell"] = {LeafFile: .../impl.js, LeafName: "runShell"}. The
	// wildcard forms `export * from './x'` and `module.exports =
	// require('./x')` record LeafName "*" so the leaf file is searched
	// directly. Empty for non-JS projects. Populated by the cross-file
	// dispatcher after FileScopes are extracted; consulted by
	// jsResolver.ResolveCall to follow one re-export hop through a barrel
	// to the real definition file. Single-hop only — chains
	// (barrel → barrel → leaf) are not followed, matching PythonReExports.
	JSReExports map[string]map[string]jsReExport `json:"js_re_exports,omitempty"`

	// javaImpls is the project-wide Java interface→impl index used by the
	// Java resolver's @Autowired/@Resource interface-dispatch path. It is
	// built during the cross-file resolution pass (resolve.go) from every
	// Java FileScope's `implements` metadata and consulted by
	// javaResolver.ResolveCall. Unexported and not serialised — it is
	// rebuilt on every full scan alongside the rest of the index, so a
	// loaded graph never relies on it being present.
	javaImpls *ImplIndex

	// shellSources is the project-wide Shell source-graph: absolute caller-
	// file path → the absolute paths it pulls in via `source FILE` / `. FILE`
	// (the targets stashed in each Shell FileScope's StarImports by
	// shellResolver.ExtractScope). It is built during the cross-file
	// resolution pass (resolve.go) and consulted by shellResolver.ResolveCall
	// to resolve a bare function call ONLY to a function defined in a
	// transitively-sourced file — the precision that keeps Shell from over-
	// resolving a same-named function in an unrelated file. Unexported and
	// not serialised; rebuilt on every full scan. nil on non-Shell projects.
	shellSources map[string][]string
}

// jsReExport is one barrel re-export target: the leaf file that actually
// defines the symbol and the leaf's own export name. LeafName "*"
// (jsReExportWildcard) marks a wildcard re-export where only the leaf
// FILE is known (`export * from`, `module.exports = require(...)`).
type jsReExport struct {
	LeafFile string `json:"leaf_file"`
	LeafName string `json:"leaf_name"`
}

// NewPackageIndex returns an empty index ready to be populated.
func NewPackageIndex() *PackageIndex {
	return &PackageIndex{
		PackageToNodes:  make(map[string][]string),
		NodeToPackage:   make(map[string]string),
		PythonReExports: make(map[string]map[string]string),
	}
}

// Add records that nodeID lives in pkg.
func (p *PackageIndex) Add(pkg, nodeID string) {
	if pkg == "" || nodeID == "" {
		return
	}
	p.PackageToNodes[pkg] = append(p.PackageToNodes[pkg], nodeID)
	p.NodeToPackage[nodeID] = pkg
}

// Lookup returns the node IDs declared in pkg. Returns nil if the
// package has no nodes (unknown / out-of-project).
func (p *PackageIndex) Lookup(pkg string) []string {
	return p.PackageToNodes[pkg]
}

// PackageForFile returns the package key under which filePath's nodes are
// indexed, or "" when no node from that file is in the index. Node IDs are
// "<filePath>:<funcName>" (see FuncID), so any node whose ID is prefixed
// "<filePath>:" tells us the file's package via NodeToPackage. Used by the
// Go resolver to find a bare same-package call's owning package without
// re-deriving the import path. O(nodes-in-index) worst case, but returns on
// the first match.
func (p *PackageIndex) PackageForFile(filePath string) string {
	if p == nil || filePath == "" {
		return ""
	}
	prefix := filePath + ":"
	for id, pkg := range p.NodeToPackage {
		if strings.HasPrefix(id, prefix) {
			return pkg
		}
	}
	return ""
}

// ResolveResult is what a LanguageResolver returns when it tries to
// resolve a single call expression.
type ResolveResult struct {
	// TargetID is the FuncNode ID that the call resolves to, when the
	// callee lives inside the current project. Empty when the resolver
	// can't pin it down.
	TargetID string

	// Extern is set when the call resolves to a known external
	// package (e.g. "net/http.Get", "json.dumps"). The framework
	// stores these on FuncNode.ExternCalls so downstream consumers can
	// answer "what does this function depend on externally?".
	Extern string

	// Confidence is a 0..1 rating of how sure the resolver is. The
	// framework writes high-confidence edges into Calls/CalledBy and
	// records lower-confidence ones as candidate edges so the interproc
	// engine can decide whether to walk them. Zero means "no opinion"
	// and the framework uses the resolver's default.
	Confidence float64
}

// LanguageResolver is the per-language contract. Each language adapter
// implements this interface and registers itself via RegisterResolver
// at init time. The framework calls the methods in this order:
//
//  1. ProjectRoot once per scan (or once per detected manifest)
//  2. ExtractScope once per file
//  3. ResolveCall many times per file (once per call expression)
//
// Resolvers must be goroutine-safe — the framework may call them
// concurrently across files.
type LanguageResolver interface {
	// Language returns the language this resolver handles. Used for
	// dispatch by the registry.
	Language() rules.Language

	// ProjectRoot walks up from scanDir looking for the language's
	// project manifest (go.mod, package.json, pyproject.toml, …) and
	// returns:
	//
	//   manifestPath:  absolute path of the manifest, "" if none found
	//   modulePath:    the module / package import-path prefix declared
	//                  in the manifest (e.g. "code.gitea.io/gitea" for
	//                  Go, "myapp" for Python). May be empty even when
	//                  manifestPath is set (manifest without an
	//                  explicit module declaration).
	//   ok:            whether a manifest was located
	//
	// The framework calls this once and stashes the result on the
	// CallGraph for use by ExtractScope / ResolveCall.
	ProjectRoot(scanDir string) (manifestPath, modulePath string, ok bool)

	// ExtractScope parses a file's imports and package declaration
	// and returns the FileScope used to resolve calls inside that
	// file's body. The framework caches the returned scope per
	// (filePath, contentHash) so subsequent scans of unchanged files
	// reuse it.
	ExtractScope(filePath string, content []byte) (FileScope, error)

	// ResolveCall tries to resolve a single call-expression callee
	// against the scope and the project's package index. The
	// callee string is whatever the per-language extractor stored
	// in FuncNode.Calls (typically a bare name like "Login" or a
	// qualified form like "auth.Login"). modulePath is the value
	// from ProjectRoot; resolvers use it to detect whether an import
	// target is in-project.
	ResolveCall(callee string, scope FileScope, modulePath string, idx *PackageIndex) ResolveResult
}

// --- Registry ---------------------------------------------------------------

var (
	resolverMu sync.RWMutex
	resolvers  = make(map[rules.Language]LanguageResolver)
)

// RegisterResolver makes r available to the framework for the language
// returned by r.Language(). Called from per-adapter init() functions.
// Re-registering a language overrides the previous resolver (lets tests
// install fakes).
func RegisterResolver(r LanguageResolver) {
	if r == nil {
		return
	}
	resolverMu.Lock()
	defer resolverMu.Unlock()
	resolvers[r.Language()] = r
}

// GetResolver returns the registered resolver for lang, or nil if no
// adapter has registered for it. Callers must tolerate nil — the
// framework treats nil as "no cross-file resolution for this language",
// preserving the pre-framework AST-local-edges-only behavior.
func GetResolver(lang rules.Language) LanguageResolver {
	resolverMu.RLock()
	defer resolverMu.RUnlock()
	return resolvers[lang]
}

// RegisteredLanguages returns the set of languages with adapters
// installed. Used by tests and diagnostics.
func RegisteredLanguages() []rules.Language {
	resolverMu.RLock()
	defer resolverMu.RUnlock()
	out := make([]rules.Language, 0, len(resolvers))
	for l := range resolvers {
		out = append(out, l)
	}
	return out
}

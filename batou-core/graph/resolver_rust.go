// Per-language adapter: Rust (PR-Grust).
//
// Implements LanguageResolver for cross-file Rust call resolution. A Rust
// crate is a single compilation unit whose module tree is built from
// `mod` declarations and brought into scope by `use`. Both are compile-
// time, file-based constructs, so — like the Lua / JS / Ruby resolvers —
// PackageIndex is keyed on absolute file paths and each `mod`/`use`
// records an alias → absolute target-path binding.
//
// Module / import resolution:
//
//   - `mod a;` (mod_item, `;`-terminated) maps child module `a` to a file
//     relative to the declaring file's directory D: `D/a.rs` then
//     `D/a/mod.rs`. D is `src/` when declared in `main.rs`/`lib.rs`,
//     `src/foo/` when declared in `src/foo.rs` or `src/foo/mod.rs`. This
//     is the dominant 2-file pattern.
//   - `use a::get_name;` (use_declaration → scoped_identifier) brings
//     `get_name` into scope UNQUALIFIED, so the call site is a BARE
//     `get_name(...)` — NOT `a.get_name()`. THIS IS THE KEY DIFFERENCE
//     FROM LUA, where calls are written `alias.method`. ExtractScope
//     records imports["get_name"] = the absolute file the leading
//     mod-path segment `a` resolves to.
//   - Qualified `a::other(...)` (call_expression → scoped_identifier with
//     path `a`, name `other`) is resolved via imports["a"] = abs(a.rs).
//   - `crate::` anchors at the crate root dir (src/); `self::` the current
//     dir; `super::` the parent dir (best-effort).
//
// Out of scope for this initial implementation (documented cuts):
//   - `pub use` re-exports, glob `use a::*`, multi-level `super::`.
//   - External-crate trait/generic dispatch (routed to Extern).
//   - Inline `mod a { ... }` bodies (those are same-file — already covered
//     by the builder's same-file edges).
//   - Workspace multi-crate path dependencies.
//
// Everything here is gated to rules.LangRust: the resolver registers only
// for LangRust and the dispatcher (resolve.go) calls GetResolver(lang),
// so no other language's resolution is affected.
package graph

import (
	"os"
	"path/filepath"
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// rustResolver implements LanguageResolver for Rust.
type rustResolver struct{}

func init() {
	RegisterResolver(&rustResolver{})
}

// Language reports that this resolver handles Rust.
func (r *rustResolver) Language() rules.Language { return rules.LangRust }

// rustManifestFilenames identify a Rust crate's module root.
var rustManifestFilenames = []string{
	"Cargo.toml",
}

// rustManifestDirs are directory names that, when present, indicate a
// crate root even without a manifest file (the conventional `src/` tree).
var rustManifestDirs = []string{
	"src",
}

// rustExternPrefixes lists well-known crate / stdlib roots the resolver
// treats as out-of-source — never searched on disk. A bare `mod`/`use`
// path leading with one of these is routed to Extern.
var rustExternPrefixes = []string{
	"std",
	"core",
	"alloc",
	"axum",
	"actix_web",
	"tokio",
	"serde",
	"serde_json",
	"reqwest",
	"sqlx",
	"diesel",
}

// ProjectRoot walks up from scanDir looking for a Rust crate marker.
// modulePath is always empty for Rust — there is no path-prefix namespace.
func (r *rustResolver) ProjectRoot(scanDir string) (manifestPath, modulePath string, ok bool) {
	dir := scanDir
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", "", false
	}
	cur := abs
	for {
		for _, manifest := range rustManifestFilenames {
			candidate := filepath.Join(cur, manifest)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, "", true
			}
		}
		for _, sub := range rustManifestDirs {
			if info, err := os.Stat(filepath.Join(cur, sub)); err == nil && info.IsDir() {
				return filepath.Join(cur, "__manifest__"), "", true
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	// No marker found — anchor at scanDir so the framework still has a
	// non-empty manifest path (mirrors the Lua last-resort).
	return abs, "", true
}

// findRustModuleRoot walks up from a file's directory looking for the same
// markers as ProjectRoot and returns the crate root directory, or "".
func findRustModuleRoot(fileAbs string) string {
	cur := filepath.Dir(fileAbs)
	for {
		for _, manifest := range rustManifestFilenames {
			candidate := filepath.Join(cur, manifest)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return cur
			}
		}
		for _, sub := range rustManifestDirs {
			if info, err := os.Stat(filepath.Join(cur, sub)); err == nil && info.IsDir() {
				return cur
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return ""
}

// ExtractScope parses a Rust file's `mod` / `use` bindings into a
// FileScope.
//
// Imports map shape:
//   - imports[childModule] = absolute path of the `.rs` file the `mod`
//     declaration maps to (so a later qualified `a::other(...)` resolves
//     via imports["a"]).
//   - imports[importedSymbol] = absolute path the leading mod-path segment
//     of a `use a::importedSymbol;` resolves to (so a later BARE
//     `importedSymbol(...)` resolves — the use-flattening case).
//   - Externs record imports[alias] = bare specifier.
//
// scope.Package is the file's own absolute path — PackageIndex keys nodes
// by absolute file path, mirroring the Lua / JS model.
func (r *rustResolver) ExtractScope(filePath string, content []byte) (FileScope, error) {
	fs := FileScope{
		FilePath: filePath,
		Imports:  map[string]string{},
		Aux:      map[string]string{},
	}
	abs := filePath
	if !filepath.IsAbs(abs) {
		if a, err := filepath.Abs(filePath); err == nil {
			abs = a
		}
	}
	fs.FilePath = abs
	fs.Package = abs

	moduleRoot := findRustModuleRoot(abs)
	if moduleRoot != "" {
		fs.Aux["module_root"] = moduleRoot
	}

	tree := tsast.Parse(content, rules.LangRust)
	if tree == nil || tree.Root() == nil {
		return fs, nil
	}
	root := tree.Root()
	// First pass: record `mod a;` declarations so the `a` alias maps to its
	// file. Done first so a `use a::x;` appearing before/after the `mod a;`
	// can chain through the recorded module path.
	for _, stmt := range root.NamedChildren() {
		if stmt.Type() != "mod_item" {
			continue
		}
		// Skip inline `mod a { ... }` bodies (same-file, already covered).
		if stmt.ChildByFieldName("body") != nil {
			continue
		}
		nameNode := stmt.ChildByFieldName("name")
		if nameNode == nil {
			continue
		}
		modName := strings.TrimSpace(nameNode.Text())
		if modName == "" {
			continue
		}
		if target := rustResolveModFile(modName, abs); target != "" {
			fs.Imports[modName] = target
		}
	}
	// Second pass: record `use a::sym;` flattened bindings.
	for _, stmt := range root.NamedChildren() {
		if stmt.Type() != "use_declaration" {
			continue
		}
		collectRustUseBinding(stmt, abs, fs.Imports)
	}
	return fs, nil
}

// collectRustUseBinding inspects a `use_declaration` node and records the
// flattened binding imports[lastSegment] = absolute file the leading
// mod-path segment resolves to. Handles the single-symbol
// `use a::get_name;` shape (use_declaration → scoped_identifier). Use
// lists (`use a::{x, y}`) and globs (`use a::*`) are deferred.
func collectRustUseBinding(n *tsast.Node, fileAbs string, imports map[string]string) {
	arg := n.ChildByFieldName("argument")
	if arg == nil {
		// Some grammar variants don't field the argument — take the first
		// scoped_identifier child.
		for _, c := range n.NamedChildren() {
			if c.Type() == "scoped_identifier" {
				arg = c
				break
			}
		}
	}
	if arg == nil || arg.Type() != "scoped_identifier" {
		return
	}
	nameNode := arg.ChildByFieldName("name")
	pathNode := arg.ChildByFieldName("path")
	if nameNode == nil || pathNode == nil {
		return
	}
	symbol := strings.TrimSpace(nameNode.Text())
	lead := rustLeadingPathIdent(pathNode)
	if symbol == "" || lead == "" {
		return
	}
	// Resolve the leading mod-path segment to a file. Prefer an already-
	// recorded `mod lead;` binding; otherwise try to locate lead.rs on disk
	// relative to the importing file.
	target := imports[lead]
	if target == "" {
		if isRustExternSpecifier(lead) {
			return
		}
		target = rustResolveModFile(lead, fileAbs)
	}
	if target == "" || !filepath.IsAbs(target) {
		return
	}
	// Bind the FLATTENED symbol to the target file so a bare call
	// `get_name(...)` resolves cross-file. Don't clobber a same-named
	// `mod` binding.
	if _, exists := imports[symbol]; !exists {
		imports[symbol] = target
	}
}

// rustResolveModFile resolves a child module name declared via `mod name;`
// in the file fileAbs to an absolute `.rs` path. Tries, relative to the
// declaring file's directory D: `D/name.rs` then `D/name/mod.rs`. When the
// declaring file is `main.rs`/`lib.rs`/`mod.rs`, sibling files in the same
// directory are the module files; when it's `src/foo.rs`, the submodules
// live under `src/foo/`. Both reduce to "search D and D-as-module-dir".
func rustResolveModFile(modName, fileAbs string) string {
	modName = strings.TrimSpace(modName)
	if modName == "" {
		return ""
	}
	dir := filepath.Dir(fileAbs)
	base := strings.TrimSuffix(filepath.Base(fileAbs), ".rs")

	var roots []string
	// Sibling search root: the declaring file's directory.
	roots = append(roots, dir)
	// When the declaring file is itself a non-root module file (`foo.rs`,
	// not main/lib/mod), its submodules conventionally live in a `foo/`
	// subdirectory.
	if base != "main" && base != "lib" && base != "mod" {
		roots = append(roots, filepath.Join(dir, base))
	}
	for _, root := range roots {
		for _, cand := range []string{
			filepath.Join(root, modName+".rs"),
			filepath.Join(root, modName, "mod.rs"),
		} {
			if info, err := os.Stat(cand); err == nil && !info.IsDir() {
				if abs, err := filepath.Abs(cand); err == nil {
					return abs
				}
				return cand
			}
		}
	}
	return ""
}

// isRustExternSpecifier reports whether spec matches a known crate / stdlib
// root prefix. Strict match: exact or `<prefix>::<rest>`.
func isRustExternSpecifier(spec string) bool {
	s := strings.TrimSpace(spec)
	if s == "" {
		return false
	}
	for _, p := range rustExternPrefixes {
		if s == p || strings.HasPrefix(s, p+"::") || strings.HasPrefix(s, p+".") {
			return true
		}
	}
	return false
}

// ResolveCall resolves a Rust call expression to a FuncNode ID, an extern
// symbol, or "no opinion".
//
// callee is one of:
//
//	"get_name"   — BARE name (the dominant Rust case via use-flattening).
//	             When `get_name` is a `use a::get_name;` import alias we
//	             look it up in the bound target file's nodes. THE PRIMARY
//	             branch for Rust — inverse of Lua, where qualified is
//	             primary.
//
//	"a.other"    — qualified call `a::other(...)`. `a` may be a `mod a;`
//	             alias bound to a file; we look up `other` in that file.
func (r *rustResolver) ResolveCall(callee string, scope FileScope, modulePath string, idx *PackageIndex) ResolveResult {
	if callee == "" {
		return ResolveResult{}
	}
	dot := strings.Index(callee, ".")

	if dot < 0 {
		// BARE call — the use-flattened shape `use a::get_name; get_name()`.
		if target, ok := scope.Imports[callee]; ok && filepath.IsAbs(target) {
			if id, hit := resolveRustNodeID(target, callee, idx); hit {
				return ResolveResult{TargetID: id, Confidence: 0.75}
			}
		}
		return ResolveResult{}
	}

	alias := callee[:dot]
	rest := callee[dot+1:]
	if alias == "" || rest == "" {
		return ResolveResult{}
	}

	target, ok := scope.Imports[alias]
	if !ok {
		return ResolveResult{}
	}
	if !filepath.IsAbs(target) {
		// Extern (unresolved crate specifier).
		return ResolveResult{Extern: target + "::" + rest, Confidence: 0.8}
	}
	if id, hit := resolveRustNodeID(target, rest, idx); hit {
		return ResolveResult{TargetID: id, Confidence: 0.85}
	}
	// File is in-project but no matching function — "no opinion" so the
	// dispatcher's UnresolvedCalls filter handles it.
	return ResolveResult{}
}

// resolveRustNodeID looks up a function named `method` inside the file
// `filePath` via the PackageIndex (keyed by absolute file path for Rust).
// impl methods are emitted bare (`run`) while free functions are also bare
// (`get_name`), so we match on the trailing method name: a node named
// "method" or "Type.method" both satisfy.
func resolveRustNodeID(filePath, method string, idx *PackageIndex) (string, bool) {
	if idx == nil || filePath == "" || method == "" {
		return "", false
	}
	cands := idx.Lookup(filePath)
	wantSuffix := method
	if i := strings.LastIndex(method, "."); i >= 0 {
		wantSuffix = method[i+1:]
	}
	// First pass: exact name match (full dotted name or bare basename) —
	// a free function `helper` must win over an impl method
	// `Type.helper` that merely suffix-matches (mirrors the Java / PHP
	// exact-first two-pass).
	for _, candID := range cands {
		colon := strings.LastIndexByte(candID, ':')
		if colon < 0 {
			continue
		}
		fnPart := candID[colon+1:]
		if fnPart == method || fnPart == wantSuffix {
			return candID, true
		}
	}
	// Second pass: any node whose name ends with ".<basename>".
	for _, candID := range cands {
		colon := strings.LastIndexByte(candID, ':')
		if colon < 0 {
			continue
		}
		if strings.HasSuffix(candID[colon+1:], "."+wantSuffix) {
			return candID, true
		}
	}
	return "", false
}

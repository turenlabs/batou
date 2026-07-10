// Per-language adapter: Perl (PR-Gperl).
//
// Implements LanguageResolver for cross-file Perl call resolution. A Perl
// program is a set of files that pull in named packages via `use Foo;` /
// `require Foo;` / `require Foo::Bar;`. Each package lives in a file whose
// path mirrors the `::`-separated name (`Foo::Bar` → `Foo/Bar.pm`),
// searched relative to the importing file's directory, the project root,
// and conventional `lib/` layouts. Like the Lua / Rust resolvers,
// PackageIndex is keyed on absolute file paths and each `use`/`require`
// records a packageName → absolute target-path binding.
//
// Module / import resolution:
//
//   - `use Foo;` / `use Foo::Bar;` (use_statement → `module` package node)
//     binds packageName `Foo` / `Foo::Bar` to the resolved `.pm` file.
//   - `require Foo::Bar;` (require_expression → bareword) binds the same
//     way for the bareword form. The string form `require "Foo/Bar.pm";`
//     is resolved directly to that relative path.
//   - Calls are written FULLY QUALIFIED `Foo::bar(...)` (the dominant Perl
//     cross-package form). The builder normalises these to `Foo.bar`, and
//     ResolveCall splits on the LAST `.` so `Foo.bar` → package `Foo`,
//     method `bar`, then looks up `bar` (or `Foo.bar`) in the bound file.
//   - Pragmas (`use strict;`, `use warnings;`, ...) and well-known CPAN /
//     core modules are treated as extern — never searched on disk.
//
// Out of scope for this initial implementation (documented cuts):
//   - Exporter-imported bare calls (`use Foo qw(bar); bar();`) — the call
//     site loses the package qualifier, so only same-file / fully-qualified
//     cross-file calls resolve. (Mirrors the Lua require-alias cut.)
//   - `parent`/`base` inheritance and method resolution order.
//   - `@INC` rewrites, `lib->import`, and FindBin-relative loads.
//   - Multiple packages declared in a single file map to that one file;
//     resolution is by file, not by the inner package boundary.
//
// Everything here is gated to rules.LangPerl: the resolver registers only
// for LangPerl and the dispatcher (resolve.go) calls GetResolver(lang), so
// no other language's resolution is affected.
package graph

import (
	"os"
	"path/filepath"
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// perlResolver implements LanguageResolver for Perl.
type perlResolver struct{}

func init() {
	RegisterResolver(&perlResolver{})
}

// Language reports that this resolver handles Perl.
func (r *perlResolver) Language() rules.Language { return rules.LangPerl }

// perlManifestFilenames identify a Perl distribution's root.
var perlManifestFilenames = []string{
	"cpanfile",
	"Makefile.PL",
	"Build.PL",
	"dist.ini",
	"META.json",
	"META.yml",
}

// perlManifestDirs are directory names that, when present, indicate a
// project root even without a manifest file (the conventional `lib/` tree).
var perlManifestDirs = []string{
	"lib",
	"blib",
}

// perlExternPrefixes lists pragmas and well-known CPAN / core module roots
// the resolver treats as out-of-source — never searched on disk. A
// `use`/`require` whose package leads with one of these is routed to
// extern.
var perlExternPrefixes = []string{
	// Pragmas
	"strict", "warnings", "utf8", "feature", "lib", "parent", "base",
	"constant", "vars", "overload", "autodie", "Moose", "Moo", "Mouse",
	// Core / ubiquitous CPAN
	"CGI", "DBI", "JSON", "YAML", "Carp", "Data", "File", "List",
	"Scalar", "Try", "Plack", "Dancer", "Dancer2", "Mojolicious", "Mojo",
	"Catalyst", "POSIX", "Time", "HTTP", "LWP", "URI", "Encode", "Digest",
	"Crypt", "Storable", "Exporter", "Test", "Getopt", "IO", "Net",
	"Template", "DateTime", "Path", "Cwd", "Hash", "Params", "Type",
	"HTML", "XML", "Email", "Redis", "Cache", "Sereal", "CBOR", "Paws",
}

// ProjectRoot walks up from scanDir looking for a Perl distribution marker.
// modulePath is always empty for Perl — there is no path-prefix namespace.
func (r *perlResolver) ProjectRoot(scanDir string) (manifestPath, modulePath string, ok bool) {
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
		for _, manifest := range perlManifestFilenames {
			candidate := filepath.Join(cur, manifest)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, "", true
			}
		}
		for _, sub := range perlManifestDirs {
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
	// non-empty manifest path (mirrors the Lua / Rust last-resort).
	return abs, "", true
}

// findPerlModuleRoot walks up from a file's directory looking for the same
// markers as ProjectRoot and returns the project root directory, or "".
func findPerlModuleRoot(fileAbs string) string {
	cur := filepath.Dir(fileAbs)
	for {
		for _, manifest := range perlManifestFilenames {
			candidate := filepath.Join(cur, manifest)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return cur
			}
		}
		for _, sub := range perlManifestDirs {
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

// ExtractScope parses a Perl file's `use` / `require` bindings into a
// FileScope.
//
// Imports map shape: packageName → absolute file path of the `.pm` file the
// package maps to (when resolvable on disk), or packageName → bare
// specifier for externs. PackageIndex keys nodes by absolute file path,
// mirroring the Lua / Rust model, so scope.Package is the file's own
// absolute path.
func (r *perlResolver) ExtractScope(filePath string, content []byte) (FileScope, error) {
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

	moduleRoot := findPerlModuleRoot(abs)
	if moduleRoot != "" {
		fs.Aux["module_root"] = moduleRoot
	}

	tree := tsast.Parse(content, rules.LangPerl)
	if tree == nil || tree.Root() == nil {
		return fs, nil
	}
	// Walk the whole tree (use/require can appear inside blocks / BEGIN).
	var visit func(n *tsast.Node)
	visit = func(n *tsast.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "use_statement":
			if mod := n.ChildByFieldName("module"); mod != nil {
				bindPerlModule(strings.TrimSpace(mod.Text()), abs, moduleRoot, fs.Imports)
			}
		case "require_expression":
			collectPerlRequire(n, abs, moduleRoot, fs.Imports)
		}
		for _, c := range n.NamedChildren() {
			visit(c)
		}
	}
	visit(tree.Root())
	return fs, nil
}

// collectPerlRequire inspects a `require_expression` node and records the
// package binding. Handles both the bareword form (`require Foo::Bar;`) and
// the string form (`require "Foo/Bar.pm";`).
func collectPerlRequire(n *tsast.Node, fileAbs, moduleRoot string, imports map[string]string) {
	for _, c := range n.NamedChildren() {
		switch c.Type() {
		case "bareword", "package":
			bindPerlModule(strings.TrimSpace(c.Text()), fileAbs, moduleRoot, imports)
			return
		case "interpolated_string_literal", "string_literal":
			spec := perlStripStringLiteral(c)
			if spec == "" {
				return
			}
			// `require "Foo/Bar.pm";` — convert the path back to a package
			// name for the imports key and resolve the relative path.
			pkg := perlPathToPackage(spec)
			if target := resolvePerlRelPath(spec, fileAbs, moduleRoot); target != "" {
				if pkg != "" {
					imports[pkg] = target
				}
				return
			}
			if pkg != "" {
				imports[pkg] = spec
			}
			return
		}
	}
}

// bindPerlModule records imports[packageName] = <target>, resolving the
// package to an absolute path when possible and falling back to
// extern / bare name.
func bindPerlModule(pkgName, fileAbs, moduleRoot string, imports map[string]string) {
	pkgName = strings.TrimSpace(pkgName)
	if pkgName == "" {
		return
	}
	if isPerlExternSpecifier(pkgName) {
		imports[pkgName] = pkgName
		return
	}
	if target := resolvePerlModuleSpecifier(pkgName, fileAbs, moduleRoot); target != "" {
		imports[pkgName] = target
		return
	}
	// Unresolved — record the bare name so ResolveCall routes it to extern.
	imports[pkgName] = pkgName
}

// resolvePerlModuleSpecifier resolves a `::`-separated package name to an
// absolute `.pm` path. `Foo::Bar` → `Foo/Bar.pm`. Search roots are the
// importing file's directory, the module root, and `lib/` under the module
// root (the conventional CPAN layout).
func resolvePerlModuleSpecifier(pkgName, fileAbs, moduleRoot string) string {
	rel := filepath.FromSlash(strings.ReplaceAll(strings.TrimSpace(pkgName), "::", "/")) + ".pm"
	if rel == ".pm" {
		return ""
	}
	var roots []string
	if d := filepath.Dir(fileAbs); d != "" {
		roots = append(roots, d)
	}
	if moduleRoot != "" {
		roots = append(roots,
			moduleRoot,
			filepath.Join(moduleRoot, "lib"),
			filepath.Join(moduleRoot, "blib", "lib"),
		)
	}
	for _, root := range roots {
		cand := filepath.Join(root, rel)
		if info, err := os.Stat(cand); err == nil && !info.IsDir() {
			if abs, err := filepath.Abs(cand); err == nil {
				return abs
			}
			return cand
		}
	}
	return ""
}

// resolvePerlRelPath resolves a string-form require path (`Foo/Bar.pm`) to
// an absolute file under the same search roots as
// resolvePerlModuleSpecifier.
func resolvePerlRelPath(spec, fileAbs, moduleRoot string) string {
	rel := filepath.FromSlash(strings.TrimSpace(spec))
	if rel == "" {
		return ""
	}
	if !strings.HasSuffix(rel, ".pm") && !strings.HasSuffix(rel, ".pl") {
		return ""
	}
	var roots []string
	if d := filepath.Dir(fileAbs); d != "" {
		roots = append(roots, d)
	}
	if moduleRoot != "" {
		roots = append(roots,
			moduleRoot,
			filepath.Join(moduleRoot, "lib"),
			filepath.Join(moduleRoot, "blib", "lib"),
		)
	}
	for _, root := range roots {
		cand := filepath.Join(root, rel)
		if info, err := os.Stat(cand); err == nil && !info.IsDir() {
			if abs, err := filepath.Abs(cand); err == nil {
				return abs
			}
			return cand
		}
	}
	return ""
}

// perlPathToPackage converts a require-string path (`Foo/Bar.pm`) into a
// `::`-separated package name (`Foo::Bar`).
func perlPathToPackage(spec string) string {
	s := strings.TrimSpace(spec)
	s = strings.TrimSuffix(s, ".pm")
	s = strings.TrimSuffix(s, ".pl")
	s = strings.TrimPrefix(s, "./")
	s = filepath.ToSlash(s)
	if s == "" {
		return ""
	}
	return strings.ReplaceAll(s, "/", "::")
}

// perlStripStringLiteral returns the inner text of a Perl string node with
// surrounding quotes removed.
func perlStripStringLiteral(n *tsast.Node) string {
	for _, c := range n.NamedChildren() {
		if c.Type() == "string_content" {
			return strings.TrimSpace(c.Text())
		}
	}
	s := strings.TrimSpace(n.Text())
	s = strings.Trim(s, `"'`)
	return s
}

// isPerlExternSpecifier reports whether a package name matches a known
// pragma / CPAN / core root prefix. Strict match: exact or `<prefix>::<rest>`.
func isPerlExternSpecifier(pkgName string) bool {
	s := strings.TrimSpace(pkgName)
	if s == "" {
		return false
	}
	for _, p := range perlExternPrefixes {
		if s == p || strings.HasPrefix(s, p+"::") {
			return true
		}
	}
	return false
}

// ResolveCall resolves a Perl call expression to a FuncNode ID, an extern
// symbol, or "no opinion".
//
// callee is one of:
//
//	"bar"        — bare name. The same-file pass already handles same-
//	               package subs; cross-file we only act when a package named
//	               `bar` was bound (rare). Exporter-imported bare calls are
//	               out of scope (documented cut).
//
//	"Foo.bar"    — qualified call `Foo::bar(...)` (the dominant Perl cross-
//	               package form, normalised by the builder). `Foo` is looked
//	               up in the `use`/`require` imports; `bar` (or `Foo.bar`)
//	               is then resolved in the bound file's nodes.
func (r *perlResolver) ResolveCall(callee string, scope FileScope, modulePath string, idx *PackageIndex) ResolveResult {
	if callee == "" {
		return ResolveResult{}
	}
	dot := strings.LastIndex(callee, ".")

	if dot < 0 {
		if target, ok := scope.Imports[callee]; ok && filepath.IsAbs(target) {
			if id, hit := resolvePerlNodeID(target, callee, idx); hit {
				return ResolveResult{TargetID: id, Confidence: 0.7}
			}
		}
		return ResolveResult{}
	}

	pkg := callee[:dot]
	method := callee[dot+1:]
	if pkg == "" || method == "" {
		return ResolveResult{}
	}

	target, ok := scope.Imports[pkg]
	if !ok {
		// The call package prefix may carry a `.`-joined sub-namespace from
		// the builder's normalisation (`A::B.sub` → pkg "A::B"); try the
		// raw `::` form too.
		target, ok = scope.Imports[strings.ReplaceAll(pkg, ".", "::")]
	}
	if !ok {
		return ResolveResult{}
	}
	if !filepath.IsAbs(target) {
		// Extern (unresolved pragma / CPAN module).
		return ResolveResult{Extern: target + "::" + method, Confidence: 0.8}
	}
	if id, hit := resolvePerlNodeID(target, method, idx); hit {
		return ResolveResult{TargetID: id, Confidence: 0.85}
	}
	// File is in-project but no matching sub — "no opinion" so the
	// dispatcher's UnresolvedCalls filter handles it.
	return ResolveResult{}
}

// resolvePerlNodeID looks up a sub named `method` inside the file
// `filePath` via the PackageIndex (keyed by absolute file path for Perl).
// Subs are emitted either bare (`bar`, top-level / main package) or
// package-qualified (`Foo.bar`), so we match on the trailing method name: a
// node named "bar" or "Foo.bar" both satisfy a `Foo::bar` call.
func resolvePerlNodeID(filePath, method string, idx *PackageIndex) (string, bool) {
	if idx == nil || filePath == "" || method == "" {
		return "", false
	}
	cands := idx.Lookup(filePath)
	wantSuffix := method
	if i := strings.LastIndex(method, "."); i >= 0 {
		wantSuffix = method[i+1:]
	}
	// First pass: exact name match (full dotted name or bare basename) —
	// a bare top-level sub `helper` must win over a package-qualified
	// `Foo.helper` that merely suffix-matches (mirrors the Java / PHP
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

// Per-language adapter: Kotlin.
//
// Implements LanguageResolver for cross-file Kotlin call resolution. Kotlin
// resolution is namespace-qualified, like Java / C#: every file declares a
// `package a.b.c` header, and within one Gradle module same-package symbols
// (top-level `fun`s and members of same-package types) are visible without
// a per-symbol import. This resolver mirrors resolver_csharp.go — the
// closest precise template — rather than Java's on-disk
// `<pkgDir>/Type.kt` probe, because Kotlin (like C#) does NOT enforce a
// file=directory=package layout:
//
//   - A class / top-level `fun` in `package com.foo` can live in any .kt
//     file anywhere; multiple top-level declarations and several classes
//     routinely share one file, and one package spans many files. A disk
//     probe keyed on the package path would miss the common case.
//
// So, exactly like C#, PackageIndex is keyed on each .kt file's ABSOLUTE
// path (importPathForNode returns node.FilePath), the builder threads the
// file's `package` declaration into every node's dotted name
// ("com.foo.Helper.getName", "com.foo.getName"), and same-package
// resolution scans the project-wide node index for nodes whose name is
// prefixed by the caller's package.
//
// Resolution ranking:
//
//  1. SAME-PACKAGE bare call — `getName(req)` where getName is a top-level
//     `fun` declared in a sibling .kt file of the SAME package. Kotlin
//     makes same-package top-level functions visible without an import, so
//     we scan the index for a node named "<pkg>.getName" (the v1 milestone
//     shape: two `package app` files calling each other).
//  2. SAME-PACKAGE qualified call — `Helper.getName()` where Helper is a
//     same-package type, no import required. Node "<pkg>.Helper.getName".
//  3. EXPLICIT `import a.b.Helper` then `Helper.getName()` — ExtractScope
//     records the import; ResolveCall resolves the type's method in the
//     imported package.
//  4. STAR `import a.b.*` then `Helper.getName()` — scan the starred
//     package for the type.
//  5. EXTERN — kotlin.* / kotlinx.* / java.* / javax.* / io.ktor.* etc.
//     and known stdlib receiver roots (Runtime, System, ProcessBuilder)
//     route to ExternCalls.
//
// Known limitations (documented follow-ups, mirroring the C# / Java cuts):
//   - multi-Gradle-module target boundaries (the whole scan dir is one
//     module — same-package across modules still resolves, which is sound
//     for app-sized single-target scans).
//   - receiver type inference for `localVar.method()` — resolved only when
//     the receiver names a same-package / imported TYPE, never a local
//     value, so a `req.queryParameter(...)` source accessor is NOT
//     mis-resolved to an in-project method.
//   - extension-function receiver binding.
//   - multi-hop relay (A→B→C) — 1-hop only.
//
// Everything here is gated to rules.LangKotlin: the resolver registers only
// for LangKotlin and the dispatcher (resolve.go) calls GetResolver(lang),
// so no other language's resolution is affected.
package graph

import (
	"os"
	"path/filepath"
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// kotlinResolver implements LanguageResolver for Kotlin.
type kotlinResolver struct{}

func init() {
	RegisterResolver(&kotlinResolver{})
}

// Language reports that this resolver handles Kotlin.
func (r *kotlinResolver) Language() rules.Language { return rules.LangKotlin }

// kotlinManifestFilenames identify a Kotlin / Gradle / Maven module root.
var kotlinManifestFilenames = []string{
	"build.gradle.kts",
	"build.gradle",
	"settings.gradle.kts",
	"settings.gradle",
	"pom.xml",
}

// kotlinExternPrefixes lists package-name prefixes treated as out-of-source
// (Kotlin stdlib + JVM stdlib + the dominant framework roots). Calls into
// these resolve to ExternCalls rather than in-project edges. Mirrors
// csharpExternPrefixes / javaExternPrefixes — intentionally short; adding a
// prefix removes cross-file resolution for it.
var kotlinExternPrefixes = []string{
	"kotlin.",
	"kotlinx.",
	"java.",
	"javax.",
	"jakarta.",
	"io.ktor.",
	"org.springframework.",
	"org.junit.",
	"org.jetbrains.",
	"com.google.",
	"com.fasterxml.",
	"retrofit2.",
	"okhttp3.",
	"android.",
	"androidx.",
}

// kotlinExternReceivers lists single-segment receiver names that are
// well-known JVM/Kotlin stdlib roots whose `.method()` is always extern
// (`Runtime.getRuntime()`, `System.getenv()`, `ProcessBuilder(...)`, ...).
// Conservative — only the unambiguous stdlib roots; in-source types must
// NOT appear here (they'd lose cross-file resolution).
var kotlinExternReceivers = map[string]bool{
	"Runtime": true, "System": true, "ProcessBuilder": true,
	"Math": true, "Thread": true, "Class": true,
	"Files": true, "Paths": true, "Regex": true,
}

// ProjectRoot walks up from scanDir looking for a Kotlin / Gradle / Maven
// manifest. modulePath is always empty for Kotlin — packages don't carry a
// global path-prefix the way Go modules do; each file owns its `package`
// declaration directly (mirrors the C# resolver).
func (r *kotlinResolver) ProjectRoot(scanDir string) (manifestPath, modulePath string, ok bool) {
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
		for _, manifest := range kotlinManifestFilenames {
			candidate := filepath.Join(cur, manifest)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, "", true
			}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	// No manifest found — anchor at scanDir so the framework still has a
	// non-empty manifest path (mirrors the C# / Java last-resort).
	return abs, "", true
}

// ExtractScope parses a Kotlin file's `package` declaration and `import`
// directives into a FileScope.
//
//   - scope.Package is the file's dotted package ("com.foo.bar"), or "" for
//     a file with no `package` header (the v1 milestone uses `package app`;
//     a header-less file threads an empty package, like a C# file with no
//     namespace). PackageIndex keys nodes by absolute file path, so the
//     package lives in the node name, not the index key.
//   - Imports binds the short type name of each `import a.b.C` (and
//     `import a.b.C as D`) to its FQN.
//   - StarImports holds each `import a.b.*` package.
//
// scope.FilePath is the file's absolute path — PackageIndex keys nodes by
// absolute file path for Kotlin (importPathForNode returns node.FilePath).
func (r *kotlinResolver) ExtractScope(filePath string, content []byte) (FileScope, error) {
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

	tree := tsast.Parse(content, rules.LangKotlin)
	if tree == nil || tree.Root() == nil {
		return fs, nil
	}
	root := tree.Root()
	for i := 0; i < root.ChildCount(); i++ {
		n := root.Child(i)
		switch n.Type() {
		case "package_header":
			if pkg := kotlinPackageName(n); pkg != "" {
				fs.Package = pkg
			}
		case "import_list":
			for _, imp := range n.NamedChildren() {
				if imp.Type() == "import_header" {
					collectKotlinImportEntry(imp, fs.Imports, &fs.StarImports)
				}
			}
		}
	}
	return fs, nil
}

// collectKotlinImportEntry parses one `import a.b.C` / `import a.b.*` /
// `import a.b.C as D` directive and updates imports / stars.
func collectKotlinImportEntry(n *tsast.Node, imports map[string]string, stars *[]string) {
	text := strings.TrimSpace(n.Text())
	if text == "" {
		return
	}
	text = strings.TrimPrefix(text, "import")
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	// Alias form: `import a.b.C as D`.
	alias := ""
	if idx := strings.Index(text, " as "); idx >= 0 {
		alias = strings.TrimSpace(text[idx+4:])
		text = strings.TrimSpace(text[:idx])
	}
	if strings.HasSuffix(text, ".*") {
		pkg := strings.TrimSuffix(text, ".*")
		pkg = strings.TrimSpace(pkg)
		if pkg != "" {
			*stars = append(*stars, pkg)
		}
		return
	}
	fqn := text
	short := fqn
	if dot := strings.LastIndexByte(fqn, '.'); dot >= 0 {
		short = fqn[dot+1:]
	}
	if alias != "" {
		short = alias
	}
	if short == "" {
		return
	}
	imports[short] = fqn
}

// kotlinPackageName returns the dotted name from a `package com.foo.bar`
// header (the `identifier` child's text).
func kotlinPackageName(n *tsast.Node) string {
	for _, c := range n.NamedChildren() {
		if c.Type() == "identifier" {
			return strings.TrimSpace(c.Text())
		}
	}
	return ""
}

// ResolveCall resolves a Kotlin call expression to a FuncNode ID, an extern
// symbol, or "no opinion".
//
// callee is one of:
//
//	"getName"    — bare name. A same-package top-level `fun` (the v1
//	               milestone path) or a same-class self call (handled by the
//	               same-file pass). Resolved against same-package nodes only.
//	"Recv.bar"   — qualified call. `Recv` may be an import alias / type, a
//	               same-package type, a starred-import type, or an extern
//	               stdlib root. A local-value receiver (`req.queryParameter`)
//	               is NOT resolved (no type inference) so request-source
//	               accessors are never mis-bound to an in-project method.
func (r *kotlinResolver) ResolveCall(callee string, scope FileScope, modulePath string, idx *PackageIndex) ResolveResult {
	if callee == "" || idx == nil {
		return ResolveResult{}
	}

	dot := strings.Index(callee, ".")
	if dot < 0 {
		// Bare name. Unlike C#, Kotlin top-level `fun`s are callable bare
		// across files within the same package, so resolve a same-package
		// node named "<pkg>.callee". This is the v1 milestone path.
		if id, hit := r.resolveSamePackageBare(callee, scope, idx); hit {
			return ResolveResult{TargetID: id, Confidence: 0.85}
		}
		return ResolveResult{}
	}

	// Collapse a fully-qualified receiver to its last two dotted segments
	// ("com.foo.Helper.getName" → class "Helper", method "getName").
	className, method := kotlinSplitClassMethod(callee)
	if className == "" || method == "" {
		return ResolveResult{}
	}

	// Imported alias / type: `import a.b.Helper` then `Helper.method()`.
	if fqn, ok := scope.Imports[className]; ok {
		if isKotlinExternFQN(fqn) {
			return ResolveResult{Extern: fqn + "." + method, Confidence: 0.85}
		}
		impPkg, _ := kotlinSplitPackageType(fqn)
		if id, hit := resolveKotlinNodeInPackages(className, method, []string{impPkg}, idx); hit {
			return ResolveResult{TargetID: id, Confidence: 0.85}
		}
		return ResolveResult{}
	}

	// Extern receiver (`Runtime.getRuntime`, `System.getenv`, ...) — route
	// to extern when the receiver is a known JVM/Kotlin stdlib root.
	if isKotlinExternReceiver(className) {
		return ResolveResult{Extern: callee, Confidence: 0.8}
	}

	// Same-package qualified: `Helper.getName()` where Helper lives in the
	// caller's own package, no import required.
	if id, hit := r.resolveSamePackageQualified(className, method, scope, idx); hit {
		return ResolveResult{TargetID: id, Confidence: 0.85}
	}

	// Starred imports: scan each `import a.b.*` package for the type.
	if len(scope.StarImports) > 0 {
		if id, hit := resolveKotlinNodeInPackages(className, method, scope.StarImports, idx); hit {
			return ResolveResult{TargetID: id, Confidence: 0.8}
		}
	}

	// Unknown receiver — a local variable / runtime value, out of scope
	// without type inference. Return "no opinion" so the framework drops it.
	// CRITICAL: we deliberately do NOT fall back to a bare-suffix lookup of
	// the method name across the whole module here (the held bug). Doing so
	// over-resolved `req.queryParameter(...)` / `ConnectionOptions.parse`
	// onto unrelated in-project methods, attaching phantom sinks. A method
	// on a local value resolves only when its receiver names a known type.
	return ResolveResult{}
}

// resolveSamePackageBare resolves a bare call `getName()` to a same-package
// top-level function node named "<pkg>.getName". For a header-less file
// (scope.Package == "") it matches a bare node named exactly "getName".
func (r *kotlinResolver) resolveSamePackageBare(name string, scope FileScope, idx *PackageIndex) (string, bool) {
	if name == "" {
		return "", false
	}
	var want string
	if scope.Package == "" {
		// Header-less file: match a bare top-level node "name" exactly.
		want = name
	} else {
		want = scope.Package + "." + name
	}
	for _, nodes := range idx.PackageToNodes {
		for _, candID := range nodes {
			if kotlinStripOverloadSuffix(kotlinNodeFuncName(candID)) == want {
				return candID, true
			}
		}
	}
	return "", false
}

// resolveSamePackageQualified handles `Helper.getName()` where Helper is a
// type declared in the caller's own package, reached without an explicit
// import. Scans the project-wide node index for "<pkg>.Helper.getName"
// (exact) or a node under <pkg> whose tail is "Helper.getName".
func (r *kotlinResolver) resolveSamePackageQualified(className, method string, scope FileScope, idx *PackageIndex) (string, bool) {
	if scope.Package == "" {
		// Header-less file: match a bare node "Helper.getName" exactly.
		return resolveKotlinNodeInPackages(className, method, []string{""}, idx)
	}
	return resolveKotlinNodeInPackages(className, method, []string{scope.Package}, idx)
}

// resolveKotlinNodeInPackages scans the project-wide node index for a node
// whose fully-qualified name resolves "<className>.<method>" within one of
// `packages`. Kotlin nodes carry the full dotted name (the builder emits
// "com.foo.Helper.getName"), so the package is a PREFIX of the node name
// rather than a separate index key. We match against
// "<package>.<className>.<method>" (exact) and, as a fallback,
// "<className>.<method>" as a suffix of any node declared under the
// package. A package of "" matches a bare node "<className>.<method>".
//
// The PackageIndex for Kotlin is keyed by absolute file path
// (importPathForNode returns node.FilePath), so there is no package→files
// key; we iterate every indexed node once. O(total nodes) per call, bounded
// by the per-pass call-index cache and the per-rule timeout (same as the C#
// resolver).
func resolveKotlinNodeInPackages(className, method string, packages []string, idx *PackageIndex) (string, bool) {
	if idx == nil || method == "" || len(packages) == 0 {
		return "", false
	}
	want := className + "." + method
	// First pass: exact "<package>.<className>.<method>" full match.
	for _, pkg := range packages {
		var fullWant string
		if pkg == "" {
			fullWant = want
		} else {
			fullWant = pkg + "." + want
		}
		for _, nodes := range idx.PackageToNodes {
			for _, candID := range nodes {
				if kotlinStripOverloadSuffix(kotlinNodeFuncName(candID)) == fullWant {
					return candID, true
				}
			}
		}
	}
	// Second pass: a node declared under one of the packages (its name
	// starts with "<package>.") whose tail is "<className>.<method>" — for
	// nested types / multi-segment packages where the full prefix differs.
	for _, pkg := range packages {
		if pkg == "" {
			continue
		}
		pkgPrefix := pkg + "."
		for _, nodes := range idx.PackageToNodes {
			for _, candID := range nodes {
				fnPart := kotlinStripOverloadSuffix(kotlinNodeFuncName(candID))
				if !strings.HasPrefix(fnPart, pkgPrefix) {
					continue
				}
				if fnPart == pkg+"."+want || strings.HasSuffix(fnPart, "."+want) {
					return candID, true
				}
			}
		}
	}
	return "", false
}

// kotlinNodeFuncName returns the function-name portion of a node ID
// ("<absFilePath>:<pkg.Type.method>" → "pkg.Type.method"). FuncID joins the
// file path and name with the LAST ':' (paths may contain a drive-letter
// colon on Windows, but the func name never contains ':').
func kotlinNodeFuncName(nodeID string) string {
	colon := strings.LastIndexByte(nodeID, ':')
	if colon < 0 {
		return nodeID
	}
	return nodeID[colon+1:]
}

// kotlinStripOverloadSuffix removes a builder-appended overload
// disambiguator ("...method#2@45" → "...method"). registerKotlinFunc adds
// "#<arity>@<line>" to the second and later overloads sharing a qualified
// name so each owns a distinct node; the resolver matches on the clean name
// so both overloads remain resolvable by "Type.method" / ".method".
func kotlinStripOverloadSuffix(name string) string {
	if h := strings.IndexByte(name, '#'); h >= 0 {
		return name[:h]
	}
	return name
}

// kotlinSplitClassMethod collapses a (possibly fully-qualified) callee into
// (className, method): the LAST dotted segment is the method, the
// second-to-last is the class. "Helper.getName" → ("Helper","getName");
// "com.foo.Helper.getName" → ("Helper","getName").
func kotlinSplitClassMethod(callee string) (string, string) {
	last := strings.LastIndexByte(callee, '.')
	if last < 0 {
		return "", ""
	}
	method := callee[last+1:]
	head := callee[:last]
	className := head
	if prev := strings.LastIndexByte(head, '.'); prev >= 0 {
		className = head[prev+1:]
	}
	return strings.TrimSpace(className), strings.TrimSpace(method)
}

// kotlinSplitPackageType splits a type FQN ("a.b.Type") into its package
// ("a.b") and short type name ("Type"). When there is no dot the whole
// string is the type and the package is "".
func kotlinSplitPackageType(fqn string) (string, string) {
	fqn = strings.TrimSpace(fqn)
	if dot := strings.LastIndexByte(fqn, '.'); dot >= 0 {
		return fqn[:dot], fqn[dot+1:]
	}
	return "", fqn
}

// isKotlinExternFQN reports whether fqn names a type in a stdlib / known-
// framework root package. Prefix-based.
func isKotlinExternFQN(fqn string) bool {
	for _, p := range kotlinExternPrefixes {
		if strings.HasPrefix(fqn, p) {
			return true
		}
	}
	return false
}

// isKotlinExternReceiver reports whether a single-segment receiver name is
// a well-known JVM/Kotlin stdlib root type whose `.method()` is always
// extern (`Runtime`, `System`, `ProcessBuilder`, ...).
func isKotlinExternReceiver(receiver string) bool {
	return kotlinExternReceivers[receiver]
}

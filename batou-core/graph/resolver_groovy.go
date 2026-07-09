// Per-language adapter: Groovy (PR-Ggroovy).
//
// Implements LanguageResolver for cross-file Groovy call resolution. Groovy
// runs on the JVM and, like Java / C#, every file declares a `package
// a.b.c` and same-package types are visible to each other WITHOUT an
// explicit import. The canonical cross-file shape — the milestone — is a
// SCRIPT in `package app` calling a method declared on a class in another
// file of the SAME package:
//
//	A.groovy  package app; class A { String getName(req) {...} }
//	B.groovy  package app; def a = new A(); def n = a.getName(req); "cmd $n".execute()
//
// This resolver is the NAMESPACE-QUALIFIED analog of resolver_csharp.go (the
// canonical precise template). It REPLACES the earlier bare-suffix
// single-bucket model, which over-matched on real Grails code: a
// `boltSession.run()` in a Neo4j entity package was cross-wired to an
// unrelated CLI `static void run(String[] args)` in a different package
// purely because both nodes ended in `.run`. Package-qualified resolution
// eliminates that cross-package method-name collision class.
//
// Resolution model (mirrors C#):
//
//   - PackageIndex is keyed on the ABSOLUTE FILE PATH of each .groovy file
//     (importPathForNode returns node.FilePath). Each FuncNode's name
//     carries the full dotted package+class prefix that the builder emits
//     ("app.A.getName", "app.<groovyScriptMain>"), so the package is a
//     PREFIX of the node name rather than a separate index key.
//   - ExtractScope records the file's `package a.b.c` declaration as
//     scope.Package and each `import x.y.Z` into StarImports (the import's
//     package) so an imported-class call can be resolved in the imported
//     package too.
//   - ResolveCall takes a qualified `Recv.method` call and resolves it to a
//     node named "<callerPackage>.<Class>.<method>" (same-package, no
//     import — the v1 milestone) or "<importedPackage>.<Class>.<method>"
//     (explicit import). `Recv` is the receiver-variable's CLASS name when
//     it can be inferred from a same-line `new Recv(...)`; otherwise the
//     receiver token is tried directly as the class name (covers static
//     `Helper.foo()` and the common `def a = new A(); a.getName()` idiom
//     where the variable name differs from the class — see groovy class
//     inference below).
//
// Out of scope for v1 (documented cuts, mirroring the C# / Java cuts):
//   - import-aliased static resolution (`import static com.x.Y.z`).
//   - Multi-module Gradle subproject boundaries (the whole scan dir is one
//     project; same-package resolution spans all files regardless).
//   - Dynamic / metaprogramming dispatch (methodMissing, GString-built
//     method names).
//   - DI / interface dispatch through a field whose declared type is a
//     service interface (the Java resolveInterfaceFieldCall analog).
//   - multi-hop relay (A→B→C) — 1-hop only.
//
// Everything here is gated to rules.LangGroovy: the resolver registers only
// for LangGroovy and the dispatcher (resolve.go) calls GetResolver(lang),
// so no other language's resolution is affected.
package graph

import (
	"os"
	"path/filepath"
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// groovyResolver implements LanguageResolver for Groovy.
type groovyResolver struct{}

func init() {
	RegisterResolver(&groovyResolver{})
}

// Language reports that this resolver handles Groovy.
func (r *groovyResolver) Language() rules.Language { return rules.LangGroovy }

// groovyManifestFilenames identify a Groovy / Gradle / Grails project root.
var groovyManifestFilenames = []string{
	"build.gradle",
	"build.gradle.kts",
	"settings.gradle",
	"settings.gradle.kts",
	"Jenkinsfile",
	"application.yml",
	"grails-app",
}

// groovyExternPrefixes lists package prefixes the resolver treats as
// out-of-source (JDK + dominant JVM framework / library roots). Calls into
// these resolve to ExternCalls rather than in-project edges. Mirrors
// csharpExternPrefixes / javaExternPrefixes — intentionally short; adding a
// prefix removes cross-file resolution for it. These also guard the
// single-segment receiver check so a `String.format(...)` / `System.getenv`
// receiver isn't mistaken for an in-project class.
var groovyExternPrefixes = []string{
	"java.",
	"javax.",
	"jakarta.",
	"groovy.",
	"org.codehaus.groovy.",
	"org.springframework.",
	"org.grails.",
	"grails.",
	"org.apache.",
	"com.google.",
	"io.micronaut.",
	"io.vertx.",
	"ratpack.",
	"hudson.",
	"jenkins.",
	"org.hibernate.",
	"org.neo4j.",
	"reactor.",
	"okhttp3.",
	"retrofit2.",
}

// ProjectRoot walks up from scanDir looking for a Groovy/Gradle/Grails
// build marker. The module path is always empty for Groovy — like C# /
// Java, packages don't carry a global path-prefix the way Go modules do;
// each file owns its `package` declaration directly.
func (r *groovyResolver) ProjectRoot(scanDir string) (manifestPath, modulePath string, ok bool) {
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
		for _, manifest := range groovyManifestFilenames {
			candidate := filepath.Join(cur, manifest)
			if _, err := os.Stat(candidate); err == nil {
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

// ExtractScope parses a Groovy file's `package` declaration and `import`
// statements into a FileScope.
//
//   - scope.Package is the file's `package a.b.c` declaration (empty for a
//     package-less script). Same-package resolution matches a node whose
//     name starts with this prefix.
//   - StarImports holds the PACKAGE of each `import a.b.C` / `import a.b.*`
//     so an imported-class call can be resolved in the imported package.
//
// scope.FilePath is the file's absolute path — PackageIndex keys nodes by
// absolute file path for Groovy (importPathForNode returns node.FilePath),
// mirroring C# / Java.
func (r *groovyResolver) ExtractScope(filePath string, content []byte) (FileScope, error) {
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

	tree := tsast.Parse(content, rules.LangGroovy)
	if tree == nil || tree.Root() == nil {
		return fs, nil
	}
	collectGroovyScope(tree.Root(), &fs)
	return fs, nil
}

// collectGroovyScope walks the source_file recording the `package`
// declaration as fs.Package and each import's package into StarImports.
func collectGroovyScope(root *tsast.Node, fs *FileScope) {
	if root == nil {
		return
	}
	for _, child := range root.NamedChildren() {
		switch child.Type() {
		case "groovy_package":
			if fs.Package == "" {
				fs.Package = groovyPackageName(root)
			}
		case "groovy_import", "import_declaration", "import":
			if pkg := groovyImportPackage(child); pkg != "" {
				fs.StarImports = appendUnique(fs.StarImports, pkg)
			}
		}
	}
}

// groovyImportPackage returns the PACKAGE portion of an import statement —
// `import a.b.C` → "a.b", `import a.b.*` → "a.b", `import static a.b.C.m` →
// "a.b". Returns "" when the import targets a known extern root (so an
// `import org.springframework.X` doesn't widen same-app resolution into the
// framework). The package is the dotted prefix minus the trailing
// Class / `*` / static-member segment.
func groovyImportPackage(imp *tsast.Node) string {
	text := strings.TrimSpace(imp.Text())
	if text == "" {
		return ""
	}
	text = strings.TrimSuffix(text, ";")
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, "import")
	text = strings.TrimSpace(text)
	text = strings.TrimPrefix(text, "static")
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	// `import a.b.* as Foo` / `import a.b.C as Foo` — drop the alias tail.
	if i := strings.Index(text, " as "); i >= 0 {
		text = strings.TrimSpace(text[:i])
	}
	if isGroovyExternFQN(text) {
		return ""
	}
	text = strings.TrimSuffix(text, ".*")
	// The package is everything before the final dotted segment (the class /
	// static member). `a.b.C` → "a.b"; a single bare segment has no package.
	if dot := strings.LastIndexByte(text, '.'); dot >= 0 {
		return strings.TrimSpace(text[:dot])
	}
	return ""
}

// ResolveCall resolves one Groovy call expression to a FuncNode ID, an
// extern symbol, or "no opinion".
//
// callee is one of:
//
//	"foo"        — bare name. A same-class / same-script self call (handled
//	               by the same-file pass). Cross-file bare calls are
//	               out of scope without type inference; return "no opinion".
//
//	"Recv.bar"   — qualified call. `Recv` may be:
//	                 - a class name reached statically (`Helper.foo()`), or a
//	                   `new Recv(...)` instance whose variable was named the
//	                   same — resolved in the caller's own package (the
//	                   milestone) or an imported package.
//	                 - an extern receiver (`System`, `String`, ...) — routed
//	                   to ExternCalls.
//	                 - a local variable / field whose class differs from the
//	                   variable name — resolved via the builder's same-file
//	                   instance inference where possible, else "no opinion".
func (r *groovyResolver) ResolveCall(callee string, scope FileScope, modulePath string, idx *PackageIndex) ResolveResult {
	if callee == "" || idx == nil {
		return ResolveResult{}
	}
	dot := strings.LastIndexByte(callee, '.')
	if dot < 0 {
		// Bare name — same-scope self calls are handled by the same-file
		// pass; cross-file bare calls need type inference (out of scope).
		return ResolveResult{}
	}

	className, method := groovySplitClassMethod(callee)
	if method == "" {
		return ResolveResult{}
	}

	// Extern receiver (`System.getenv`, `String.format`, ...) — route to
	// extern when the receiver is a known JDK / framework root segment.
	if className != "" && isGroovyExternReceiver(className) {
		return ResolveResult{Extern: className + "." + method, Confidence: 0.8}
	}

	// Candidate packages, most-specific first: the caller's own package
	// (same-package, no import — the v1 milestone), then each imported
	// package.
	var packages []string
	if scope.Package != "" {
		packages = append(packages, scope.Package)
	}
	packages = append(packages, scope.StarImports...)

	// Package-less scripts (no `package` declaration): fall back to the
	// empty-package bucket so two package-less files in the same scan dir
	// still resolve against each other (the bare-name node form "A.getName").
	if len(packages) == 0 {
		packages = append(packages, "")
	}

	// Tier 1: className-qualified (precise). Resolves static `Helper.foo()`
	// and any `recv.foo()` whose receiver-variable name happens to equal the
	// class name.
	if id, hit := resolveGroovyNodeInPackages(className, method, packages, idx); hit {
		return ResolveResult{TargetID: id, Confidence: 0.85}
	}

	// Tier 2: className-less but STRICTLY PACKAGE-ANCHORED. Groovy's common
	// idiom is `def a = new A(); a.getName(...)` where the receiver VARIABLE
	// name (`a`) differs from the class (`A`); the resolver can't see the
	// caller body to infer the instance class, so we fall back to a
	// ".<method>" suffix match — but ONLY among nodes whose owning file
	// declares one of the caller's packages. This is the FP-eliminating
	// guard: a `boltSession.run()` in package `app.neo4j` can only resolve to
	// a `run` declared in `app.neo4j` (or an imported package), NEVER to an
	// unrelated CLI `run` in `app.cli` — the exact cross-package collision the
	// bare-suffix model produced. We do NOT take this tier for the empty
	// (package-less) bucket, where a bare ".<method>" suffix would collide
	// globally just like the old model.
	if id, hit := resolveGroovyMethodInPackages(method, packages, idx); hit {
		return ResolveResult{TargetID: id, Confidence: 0.8}
	}
	return ResolveResult{}
}

// resolveGroovyNodeInPackages scans the project-wide node index for a node
// whose fully-qualified name resolves "<className>.<method>" within one of
// `packages`. Groovy nodes carry the full dotted name (the builder emits
// "app.A.getName"), so the package is a PREFIX of the node name rather than
// a separate index key — mirroring resolveCSharpNodeInNamespaces.
//
// The PackageIndex for Groovy is keyed by absolute file path
// (importPathForNode returns node.FilePath), so there is no package→files
// key; we iterate every indexed node once. This is O(total nodes) per call,
// bounded by the per-pass call-index cache and the per-rule timeout.
//
// Match precedence (className must be non-empty):
//  1. EXACT "<package>.<className>.<method>" — strongest, the precise class
//     in the precise package. For the empty (package-less) bucket the want
//     is the bare "<className>.<method>".
//  2. SUFFIX: a node declared under "<package>." whose name ends with
//     ".<className>.<method>" (nested classes) — still package-anchored, so
//     a same-named method in a DIFFERENT package can never match.
func resolveGroovyNodeInPackages(className, method string, packages []string, idx *PackageIndex) (string, bool) {
	if idx == nil || method == "" || className == "" || len(packages) == 0 {
		return "", false
	}
	want := className + "." + method

	// Pass 1: exact "<package>.<className>.<method>" full match.
	for _, pkg := range packages {
		fullWant := groovyJoinPkg(pkg, want)
		for _, nodes := range idx.PackageToNodes {
			for _, candID := range nodes {
				if groovyNodeFuncName(candID) == fullWant {
					return candID, true
				}
			}
		}
	}

	// Pass 2: a node declared under one of the packages whose tail is
	// ".<className>.<method>" (nested-class / multi-segment package).
	// Strictly package-anchored for real packages: the node name must START
	// with "<package>." so a same-named method in another package can never
	// match. The empty bucket matches only package-less ("bare") nodes.
	for _, pkg := range packages {
		if pkg == "" {
			for _, nodes := range idx.PackageToNodes {
				for _, candID := range nodes {
					fnPart := groovyNodeFuncName(candID)
					if !groovyNodeIsBarePackage(fnPart) {
						continue
					}
					if fnPart == want || strings.HasSuffix(fnPart, "."+want) {
						return candID, true
					}
				}
			}
			continue
		}
		nsPrefix := pkg + "."
		for _, nodes := range idx.PackageToNodes {
			for _, candID := range nodes {
				fnPart := groovyNodeFuncName(candID)
				if !strings.HasPrefix(fnPart, nsPrefix) {
					continue
				}
				if strings.HasSuffix(fnPart, "."+want) {
					return candID, true
				}
			}
		}
	}
	return "", false
}

// resolveGroovyMethodInPackages is the className-LESS, strictly
// PACKAGE-ANCHORED fallback for the `def a = new A(); a.getName()` instance
// idiom (receiver variable name ≠ class name). It matches a node ending in
// ".<method>" but ONLY among nodes whose owning file declares one of the
// caller's packages — so a method-name collision in a DIFFERENT package can
// never resolve. This is the FP-eliminating guard that replaces the old
// global bare-suffix match. The empty (package-less) bucket is intentionally
// NOT served here: a bare ".<method>" match with no package anchor would
// reintroduce the global collision, so package-less instance calls stay
// unresolved (a documented v1 cut).
func resolveGroovyMethodInPackages(method string, packages []string, idx *PackageIndex) (string, bool) {
	if idx == nil || method == "" || len(packages) == 0 {
		return "", false
	}
	suffix := "." + method
	for _, pkg := range packages {
		if pkg == "" {
			continue
		}
		nsPrefix := pkg + "."
		for _, nodes := range idx.PackageToNodes {
			for _, candID := range nodes {
				fnPart := groovyNodeFuncName(candID)
				if !strings.HasPrefix(fnPart, nsPrefix) {
					continue
				}
				// Never resolve to the script-main sentinel.
				if strings.HasSuffix(fnPart, "."+groovyScriptMainName) {
					continue
				}
				if strings.HasSuffix(fnPart, suffix) {
					return candID, true
				}
			}
		}
	}
	return "", false
}

// groovyNodeIsBarePackage reports whether a node name has NO package prefix —
// i.e. it came from a package-less file. Package names are lower-case by
// convention while class names start upper-case, so "A.getName" (bare) is
// distinguished from "app.A.getName" (packaged) by the leading segment's
// case. The script-main sentinel ("<groovyScriptMain>") is never a target.
func groovyNodeIsBarePackage(fnPart string) bool {
	if fnPart == "" || strings.HasPrefix(fnPart, "<") {
		return false
	}
	first := fnPart
	if dot := strings.IndexByte(fnPart, '.'); dot >= 0 {
		first = fnPart[:dot]
	}
	if first == "" {
		return false
	}
	r := first[0]
	return r >= 'A' && r <= 'Z'
}

// groovyJoinPkg joins a package prefix and a class.method tail with a dot,
// or returns the tail unchanged when the package is empty.
func groovyJoinPkg(pkg, tail string) string {
	if pkg == "" {
		return tail
	}
	return pkg + "." + tail
}

// groovyNodeFuncName returns the function-name portion of a node ID
// ("<absFilePath>:<pkg.Class.Method>" → "pkg.Class.Method"). FuncID joins
// the file path and name with the LAST ':' (paths may contain a drive-letter
// colon on Windows, but the func name never contains ':').
func groovyNodeFuncName(nodeID string) string {
	colon := strings.LastIndexByte(nodeID, ':')
	if colon < 0 {
		return nodeID
	}
	return nodeID[colon+1:]
}

// groovySplitClassMethod collapses a (possibly fully-qualified) qualified
// callee into (className, method): the LAST dotted segment is the method,
// the second-to-last is the receiver/class. "a.getName" → ("a","getName");
// "app.Helper.getName" → ("Helper","getName"). The className may be a
// variable name rather than a class — same-package suffix resolution treats
// it as the class name when it matches, and falls back to a className-less
// ".<method>" suffix probe (package-anchored) when it doesn't.
func groovySplitClassMethod(callee string) (string, string) {
	last := strings.LastIndexByte(callee, '.')
	if last < 0 {
		return "", ""
	}
	method := strings.TrimSpace(callee[last+1:])
	head := callee[:last]
	className := head
	if prev := strings.LastIndexByte(head, '.'); prev >= 0 {
		className = head[prev+1:]
	}
	return strings.TrimSpace(className), method
}

// isGroovyExternFQN reports whether fqn names a type in a JDK / known-
// framework root package. Prefix-based; we don't enumerate every type.
func isGroovyExternFQN(fqn string) bool {
	for _, p := range groovyExternPrefixes {
		if strings.HasPrefix(fqn, p) {
			return true
		}
	}
	return false
}

// isGroovyExternReceiver reports whether a single-segment receiver name is
// the leading segment of a known extern root, OR a JDK type accessed by its
// short name (`System`, `String`, `Runtime`, `Math`, ...). Conservative:
// only well-known statically-accessed JDK types and the extern-root leading
// segments count, so an in-project class named `App` isn't shadowed.
func isGroovyExternReceiver(receiver string) bool {
	switch receiver {
	case "System", "String", "Runtime", "Math", "Integer", "Long", "Double",
		"Boolean", "Thread", "Class", "Object", "Arrays", "Collections",
		"Optional", "Files", "Paths", "Pattern", "URLEncoder", "URLDecoder":
		return true
	}
	for _, p := range groovyExternPrefixes {
		root := p
		if dot := strings.IndexByte(p, '.'); dot >= 0 {
			root = p[:dot]
		}
		if receiver == root {
			return true
		}
	}
	return false
}

// appendUnique appends s to xs when not already present.
func appendUnique(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

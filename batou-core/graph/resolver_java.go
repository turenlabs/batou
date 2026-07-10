// Per-language adapter: Java.
//
// Implements LanguageResolver for cross-file Java call resolution. This
// is the Java analog of resolver_python.go and resolver_javascript.go;
// like JS/TS, Java has no global namespace shared across the project —
// every class belongs to a `package` declared at the top of its file —
// so PackageIndex is keyed on absolute file paths (mirroring the JS
// approach). Each call site's "alias" (typically a class name brought
// into scope by an `import`) maps to the absolute path of the .java file
// declaring that class.
//
// Scope of this initial implementation:
//
//   - Maven / Gradle source layout: walks up looking for pom.xml,
//     build.gradle, build.gradle.kts, or build.gradle.* under a
//     `src/main/java/` directory. When `src/main/java/` exists, that
//     directory becomes the module root (the on-disk anchor for the
//     package tree). Otherwise the manifest's own directory is used —
//     useful for ad-hoc projects with .java files alongside a build
//     script but no formal layout.
//
//   - `import com.foo.bar.Baz;` resolves to
//     <moduleRoot>/com/foo/bar/Baz.java when the file exists on disk.
//     Star imports (`import com.foo.bar.*;`) record the package
//     directory; ResolveCall doesn't enumerate it but PR-Hjava can.
//     Static imports (`import static …`) are out of scope — they
//     import members, not types, and would need member-level
//     resolution to wire correctly.
//
//   - Same-package access without an explicit import: when ResolveCall
//     sees a bare class name `Foo` and the importing file declares
//     `package com.foo.bar;`, we look for `<moduleRoot>/com/foo/bar/Foo.java`
//     before falling through.
//
//   - Standard-library packages (`java.*`, `javax.*`) and the most
//     common framework root namespaces (`org.springframework.*`,
//     `jakarta.*`) are treated as externs — they're not in-source and
//     trying to resolve them via a classpath walk is out of scope. The
//     resolver returns an empty ResolveResult for those, letting the
//     dispatcher drop them quietly.
//
// Known limitations (documented as follow-ups):
//
//   - Static imports — the importer's body has bare-name calls
//     (`assertTrue(...)`) that mean a static method on the imported
//     class. We'd need to remember the class name behind the bare
//     alias; deferred to PR-BBjava.
//   - Maven / Gradle dependency resolution — third-party libraries on
//     the classpath aren't enumerated.
//   - Multi-module Gradle / Maven repos — every module under a
//     monorepo gets its own ProjectRoot via the dispatcher's per-file
//     module detection (resolve.go); within a module our resolver
//     handles the in-source 80% case. Cross-module symbol resolution
//     (one module's class importing another module's class) works as
//     long as the imported class file lives somewhere under the SAME
//     module root we anchor at — see findJavaModuleRoot.
//   - Inner classes — `import com.foo.Outer;` only records `Outer →
//     <…>/Outer.java`. References to `Outer.Inner` resolve through
//     the same file because the JS-style file-keyed index already
//     contains every method of every class declared in that file
//     (the builder names them `Outer.Inner.method`). What we don't
//     handle is `import com.foo.Outer.Inner;` — fewer than 1% of
//     imports use that form in practice.
package graph

import (
	"os"
	"path/filepath"
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// javaResolver implements LanguageResolver for Java.
type javaResolver struct{}

func init() {
	RegisterResolver(&javaResolver{})
}

// Language reports that this resolver handles Java.
func (j *javaResolver) Language() rules.Language { return rules.LangJava }

// javaSrcMainJava is the Maven / Gradle convention for where the
// importable package tree begins. When this subdirectory exists under a
// project manifest, it becomes the module root (so a class declared
// `package com.foo.bar;` lives at `<modRoot>/com/foo/bar/Foo.java`).
const javaSrcMainJava = "src/main/java"

// javaManifestFilenames is the precedence-ordered list of build manifests
// that mark a Java module root. Lower-index entries win when multiple
// are present in the same directory.
var javaManifestFilenames = []string{
	"pom.xml",
	"build.gradle",
	"build.gradle.kts",
	"settings.gradle",
	"settings.gradle.kts",
}

// javaExternPrefixes lists package-name prefixes that the resolver
// treats as out-of-source (standard library + the dominant Java
// framework roots). Calls into these resolve to ExternCalls rather than
// in-project edges. The list is intentionally short — adding a prefix
// here removes cross-file resolution for it, so we only include
// namespaces we know aren't shipped in-source by application repos.
var javaExternPrefixes = []string{
	"java.",
	"javax.",
	"jakarta.",
	"org.springframework.",
	"org.junit.",
	"org.apache.",
	"com.google.",
	"com.fasterxml.",
	"io.netty.",
	"io.micronaut.",
	"io.quarkus.",
	"reactor.",
	"kotlin.",
}

// ProjectRoot walks up from scanDir looking for a Java project manifest.
//
// The returned manifestPath points at the manifest file (or, if we
// detected the src/main/java/ layout under it, at a synthetic path
// inside that layout so filepath.Dir(manifestPath) gives the module
// root used as the anchor for the package tree). modulePath is always
// empty for Java because Java packages don't have a global prefix the
// way Go modules do — every class file owns its package declaration
// directly.
func (j *javaResolver) ProjectRoot(scanDir string) (manifestPath, modulePath string, ok bool) {
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
		for _, manifest := range javaManifestFilenames {
			candidate := filepath.Join(cur, manifest)
			info, err := os.Stat(candidate)
			if err != nil || info.IsDir() {
				continue
			}
			// Prefer src/main/java/ as the module root when the
			// layout exists; the package tree begins there. Return a
			// synthetic manifest path inside src/main/java/ so the
			// dispatcher's filepath.Dir(manifest) lands on the right
			// anchor.
			srcMain := filepath.Join(cur, javaSrcMainJava)
			if info, err := os.Stat(srcMain); err == nil && info.IsDir() {
				return filepath.Join(srcMain, "__manifest__"), "", true
			}
			return candidate, "", true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	// No manifest found anywhere on the path up to /. Last-resort: try
	// finding a src/main/java ancestor anywhere above scanDir (some
	// monorepo subprojects ship the layout without a per-module
	// manifest at every level).
	cur = abs
	for {
		srcMain := filepath.Join(cur, javaSrcMainJava)
		if info, err := os.Stat(srcMain); err == nil && info.IsDir() {
			return filepath.Join(srcMain, "__manifest__"), "", true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	// Nothing matched. Return the scanDir as a synthetic manifest so
	// cross-file resolution can still anchor — same fallback shape as
	// the JS resolver's script-only-repo case.
	return abs, "", true
}

// findJavaModuleRoot walks up from a file's directory looking for the
// same manifest signals as ProjectRoot, but returns the path of the
// directory the package tree is anchored to. This is the per-file
// ModuleRoot the dispatcher would compute, but we re-derive it here
// because ExtractScope is called without the broader CallGraph state.
//
// Precedence:
//  1. A manifest dir containing src/main/java/ → that subdirectory.
//  2. A manifest dir without src/main/java/ → the manifest dir itself.
//  3. No manifest found → "" (the resolver will skip import-to-file
//     resolution; same-package access still works via filesystem
//     adjacency in resolveSamePackage).
func findJavaModuleRoot(fileAbs string) string {
	cur := filepath.Dir(fileAbs)
	for {
		for _, manifest := range javaManifestFilenames {
			candidate := filepath.Join(cur, manifest)
			info, err := os.Stat(candidate)
			if err != nil || info.IsDir() {
				continue
			}
			srcMain := filepath.Join(cur, javaSrcMainJava)
			if info, err := os.Stat(srcMain); err == nil && info.IsDir() {
				return srcMain
			}
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	// Last-resort: walk up looking for a src/main/java ancestor.
	cur = filepath.Dir(fileAbs)
	for {
		srcMain := filepath.Join(cur, javaSrcMainJava)
		if info, err := os.Stat(srcMain); err == nil && info.IsDir() {
			return srcMain
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return ""
}

// ExtractScope parses a Java file's package declaration and imports
// into a FileScope. The Imports map binds:
//
//   - For non-star imports: the short class name → absolute file path
//     of the .java file declaring that class (when resolvable on
//     disk). Unresolved imports still record the alias as the FQN
//     itself so ResolveCall can fall through to the extern path.
//   - For star imports: nothing in Imports (Java doesn't bind names
//     until use). Star packages go into StarImports for downstream
//     consumers (PR-Hjava can probe individual files there).
//
// scope.Package is the dotted package name declared at the top of the
// file (`package com.foo.bar` → "com.foo.bar"). scope.Aux carries
// "module_root" so ResolveCall can re-derive same-package neighbours
// without re-walking the filesystem.
func (j *javaResolver) ExtractScope(filePath string, content []byte) (FileScope, error) {
	fs := FileScope{
		FilePath: filePath,
		Imports:  map[string]string{},
		Aux:      map[string]string{},
	}
	// Resolve filePath to an absolute path; FileModule/ModuleRoot
	// detection always works with absolute paths.
	abs := filePath
	if !filepath.IsAbs(abs) {
		if a, err := filepath.Abs(filePath); err == nil {
			abs = a
		}
	}
	fs.FilePath = abs

	moduleRoot := findJavaModuleRoot(abs)
	if moduleRoot != "" {
		fs.Aux["module_root"] = moduleRoot
	}

	tree := tsast.Parse(content, rules.LangJava)
	if tree == nil || tree.Root() == nil {
		// Tree-sitter parse failure — record only the filesystem-derived
		// fields (Package stays empty); ResolveCall will degrade.
		return fs, nil
	}
	root := tree.Root()
	for i := 0; i < root.ChildCount(); i++ {
		n := root.Child(i)
		switch n.Type() {
		case "package_declaration":
			fs.Package = extractJavaPackageName(n)
		case "import_declaration":
			collectJavaImportEntry(n, moduleRoot, fs.Imports, &fs.StarImports)
		}
	}
	// Capture the field-type / implements / @Mapper / bean-stereotype
	// metadata interface dispatch needs (PR-CATjava-interproc). Reuses the
	// tree already parsed above — no extra I/O. Stored under prefixed keys
	// in the same Aux map (see java_mybatis.go).
	collectJavaClassMetadata(root, fs.Aux)
	return fs, nil
}

// extractJavaPackageName returns the dotted name from a
// `package com.foo.bar;` declaration.
func extractJavaPackageName(n *tsast.Node) string {
	for _, c := range n.NamedChildren() {
		switch c.Type() {
		case "scoped_identifier", "identifier":
			return strings.TrimSpace(c.Text())
		}
	}
	return ""
}

// collectJavaImportEntry parses one `import com.foo.bar.Baz;` (or its
// `import com.foo.bar.*;` / `import static …` variants) and updates
// imports / stars accordingly.
//
// imports binds the short class name to the absolute path of the .java
// file declaring it, when that file resolves on disk under moduleRoot.
// When the file doesn't resolve, we still bind the alias to the
// fully-qualified name itself so ResolveCall can route the call to the
// extern path (preserving the dependency surface). For star imports we
// don't bind any name; the package directory goes to stars.
func collectJavaImportEntry(n *tsast.Node, moduleRoot string, imports map[string]string, stars *[]string) {
	text := strings.TrimSpace(n.Text())
	if text == "" {
		return
	}
	// Strip leading "import" and trailing ";", normalise whitespace.
	text = strings.TrimPrefix(text, "import")
	text = strings.TrimSpace(text)
	text = strings.TrimSuffix(text, ";")
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	isStatic := strings.HasPrefix(text, "static ")
	if isStatic {
		// Static imports are out of scope for this PR — they import
		// members, not types. Documented in the package docstring.
		return
	}
	if strings.HasSuffix(text, ".*") {
		// Star import: record the package directory under moduleRoot.
		pkg := strings.TrimSuffix(text, ".*")
		pkg = strings.TrimSpace(pkg)
		if pkg == "" {
			return
		}
		if isJavaExternFQN(pkg + ".") {
			// External standard-library or framework package — don't
			// record the directory (we have no on-disk file for it).
			return
		}
		if moduleRoot == "" {
			return
		}
		dir := filepath.Join(moduleRoot, filepath.FromSlash(strings.ReplaceAll(pkg, ".", "/")))
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			*stars = append(*stars, dir)
		}
		return
	}
	// Plain import: bind short name → resolved path (or FQN fallback).
	fqn := text
	short := fqn
	if dot := strings.LastIndexByte(fqn, '.'); dot >= 0 {
		short = fqn[dot+1:]
	}
	if short == "" {
		return
	}
	if isJavaExternFQN(fqn) {
		// External standard-library / framework class — record the FQN
		// so ResolveCall can route as extern.
		imports[short] = fqn
		return
	}
	if path := resolveJavaImportToFile(fqn, moduleRoot); path != "" {
		imports[short] = path
		return
	}
	// In-source import we couldn't pin to a file on disk (file may
	// not exist in this scan's view). Record the FQN; the call will
	// land in the extern path, which is benign for the in-source
	// case (resolve.go re-checks via PackageIndex first).
	imports[short] = fqn
}

// resolveJavaImportToFile turns `com.foo.bar.Baz` into
// `<moduleRoot>/com/foo/bar/Baz.java` when the file exists on disk.
// Returns "" when moduleRoot is empty or the file doesn't exist.
func resolveJavaImportToFile(fqn, moduleRoot string) string {
	if moduleRoot == "" || fqn == "" {
		return ""
	}
	relPath := filepath.FromSlash(strings.ReplaceAll(fqn, ".", "/")) + ".java"
	candidate := filepath.Join(moduleRoot, relPath)
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		abs, err := filepath.Abs(candidate)
		if err != nil {
			return candidate
		}
		return abs
	}
	return ""
}

// isJavaExternFQN reports whether fqn names a class in one of the
// standard-library or known-framework root namespaces. The check is
// prefix-based; we don't enumerate every class.
func isJavaExternFQN(fqn string) bool {
	for _, p := range javaExternPrefixes {
		if strings.HasPrefix(fqn, p) {
			return true
		}
	}
	return false
}

// ResolveCall resolves one Java call expression to a FuncNode ID, an
// extern symbol, or "no opinion".
//
// callee is one of:
//
//	"foo"        — bare name. Could be a same-class self call (handled
//	               by the same-file pass), a same-package class with a
//	               static method, or an instance-method call on a field.
//	               For the same-package case we probe the filesystem
//	               for `<pkgDir>/<Cap-foo>.java`; otherwise return
//	               "no opinion".
//
//	"Alias.bar"  — qualified call. `Alias` may be:
//	                 - an import alias (`import com.foo.X` → "X.bar"
//	                   resolves to the imported file's "X.bar").
//	                 - a same-package class name (no import needed —
//	                   probe the package directory).
//	                 - a local variable / field / `this` — out of scope
//	                   without type inference; return "no opinion".
func (j *javaResolver) ResolveCall(callee string, scope FileScope, modulePath string, idx *PackageIndex) ResolveResult {
	if callee == "" {
		return ResolveResult{}
	}
	dot := strings.Index(callee, ".")

	// Bare name: try same-package, then bail out.
	if dot < 0 {
		if id, hit := j.resolveSamePackage(callee, scope, idx); hit {
			return ResolveResult{TargetID: id, Confidence: 0.85}
		}
		return ResolveResult{}
	}

	alias := callee[:dot]
	rest := callee[dot+1:]
	if alias == "" || rest == "" {
		return ResolveResult{}
	}

	// Imported alias.
	if target, ok := scope.Imports[alias]; ok {
		// Two shapes: an absolute file path (we resolved to a file on
		// disk) or a fully-qualified name (extern / unresolved-source).
		if filepath.IsAbs(target) {
			if id, hit := resolveJavaNodeID(target, alias, rest, idx); hit {
				return ResolveResult{TargetID: id, Confidence: 0.85}
			}
			// Imported file exists but no matching method — return "no
			// opinion" rather than extern so the dispatcher's
			// UnresolvedCalls filter handles it (the file IS in-project).
			return ResolveResult{}
		}
		// Extern or unresolved source. Route to extern with the FQN.
		return ResolveResult{Extern: target + "." + rest, Confidence: 0.85}
	}

	// Same-package qualified call: `Foo.bar()` where Foo is in this
	// file's package but wasn't explicitly imported.
	if id, hit := j.resolveSamePackageQualified(alias, rest, scope, idx); hit {
		return ResolveResult{TargetID: id, Confidence: 0.85}
	}

	// Spring/MyBatis interface dispatch: `field.method()` where `field`
	// is an @Autowired/@Resource/@Inject field whose declared type is a
	// service or mapper interface. This is the branch the base resolver
	// used to drop (controller → service-interface → mapper). Try to
	// resolve the field's interface type to a concrete @Service impl
	// method, or — for a @Mapper interface, whose impl is generated by
	// MyBatis at runtime — to the mapper interface method node itself.
	if res, hit := j.resolveInterfaceFieldCall(alias, rest, scope, idx); hit {
		return res
	}

	// Unknown receiver. Could be `this.method`, a local variable — out of
	// scope without type inference. Return "no opinion" so the framework
	// drops it.
	return ResolveResult{}
}

// resolveInterfaceFieldCall handles `field.method(...)` where `field` is a
// dependency-injected interface field (captured in ExtractScope into
// scope.Aux under javaAuxFieldPrefix). It returns:
//
//   - For a @Mapper interface field: an edge to the mapper interface's own
//     `<Iface>.<method>` node (the impl is MyBatis-generated; the
//     interface method node carries the @Select ${} sink). Confidence 0.8.
//   - For a @Service-style interface field with a single resolvable impl:
//     an edge to `<Impl>.<method>` in the impl's file. Confidence 0.7
//     (interface dispatch is heuristic). Multi-impl / ambiguous cases are
//     left unresolved (hit=false) per the single-impl-only v1 policy.
//
// Returns hit=false when `field` is not a known DI interface field or the
// type can't be pinned to an in-project file.
func (j *javaResolver) resolveInterfaceFieldCall(field, method string, scope FileScope, idx *PackageIndex) (ResolveResult, bool) {
	if scope.Aux == nil {
		return ResolveResult{}, false
	}
	ifaceShort := scope.Aux[javaAuxFieldPrefix+field]
	if ifaceShort == "" {
		return ResolveResult{}, false
	}

	// Resolve the interface short name to the .java file declaring it,
	// via the same import / same-package machinery used for class names.
	ifaceFile := j.resolveJavaTypeFile(ifaceShort, scope)

	// When the interface file resolves to a method node, decide between
	// the concrete impl and the interface node itself:
	//
	//   - Prefer a concrete @Service impl method when the ImplIndex has a
	//     unique one (`FooServiceImpl implements FooService`); the impl is
	//     where the body — and any onward mapper call — lives.
	//   - Otherwise fall back to the interface method node. For a @Mapper
	//     interface this IS the correct sink target (MyBatis generates the
	//     impl at runtime; the interface method carries the @Select ${}
	//     sink). For a service interface with no in-source impl it keeps
	//     default-method flows connected.
	if ifaceFile != "" {
		if id, hit := resolveJavaNodeID(ifaceFile, ifaceShort, method, idx); hit {
			if impl, ok := j.resolveImplMethod(ifaceShort, method, idx); ok {
				return impl, true
			}
			return ResolveResult{TargetID: id, Confidence: 0.8}, true
		}
	}

	// Interface file not resolvable to a node directly (e.g. the interface
	// declares the method but has no node, or the type lives in another
	// module). Still try the impl index — the impl class may be in scope
	// even when the interface file isn't.
	if impl, ok := j.resolveImplMethod(ifaceShort, method, idx); ok {
		return impl, true
	}
	return ResolveResult{}, false
}

// resolveImplMethod consults the project-wide ImplIndex (built in
// resolve.go and stashed on the PackageIndex) for the single best impl
// class of ifaceShort, then looks up `<Impl>.<method>` in that impl's
// file. Returns hit=false when there is no unique impl or the method
// isn't found.
func (j *javaResolver) resolveImplMethod(ifaceShort, method string, idx *PackageIndex) (ResolveResult, bool) {
	if idx == nil || idx.javaImpls == nil {
		return ResolveResult{}, false
	}
	rec, ok := idx.javaImpls.lookup(ifaceShort)
	if !ok {
		return ResolveResult{}, false
	}
	implClass := javaShortName(rec.className)
	if id, hit := resolveJavaNodeID(rec.filePath, implClass, method, idx); hit {
		return ResolveResult{TargetID: id, Confidence: 0.7}, true
	}
	return ResolveResult{}, false
}

// resolveJavaTypeFile resolves a short type name to the absolute path of
// the .java file declaring it: first via an explicit import alias, then
// via the same-package directory probe. Returns "" when neither resolves
// to an in-project file (extern imports are skipped — they're not files).
func (j *javaResolver) resolveJavaTypeFile(short string, scope FileScope) string {
	if target, ok := scope.Imports[short]; ok {
		if filepath.IsAbs(target) {
			return target
		}
		// Extern / unresolved FQN — not an in-source file.
		return ""
	}
	// Same package: probe `<pkgDir>/<short>.java`.
	moduleRoot := scope.Aux["module_root"]
	if moduleRoot == "" || scope.Package == "" {
		return ""
	}
	pkgDir := filepath.Join(moduleRoot, filepath.FromSlash(strings.ReplaceAll(scope.Package, ".", "/")))
	candidate := filepath.Join(pkgDir, short+".java")
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		if abs, err := filepath.Abs(candidate); err == nil {
			return abs
		}
		return candidate
	}
	return ""
}

// resolveSamePackage looks for a same-package neighbour class declaring
// a static method with the given bare name. Java rarely uses bare-name
// calls across files (most cross-file invocations are qualified), so
// this is intentionally narrow: we only probe the obvious capitalised
// neighbour file. Lower-cost than walking the entire package dir.
func (j *javaResolver) resolveSamePackage(name string, scope FileScope, idx *PackageIndex) (string, bool) {
	moduleRoot := scope.Aux["module_root"]
	if moduleRoot == "" || scope.Package == "" {
		return "", false
	}
	// In Java, bare-name calls are almost always same-class methods;
	// the same-file pass already handled those. We only act here when
	// the bare name happens to match a same-package class with a method
	// of the same name — a niche shape but cheap to check.
	pkgDir := filepath.Join(moduleRoot, filepath.FromSlash(strings.ReplaceAll(scope.Package, ".", "/")))
	candidate := filepath.Join(pkgDir, name+".java")
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		abs, err := filepath.Abs(candidate)
		if err != nil {
			abs = candidate
		}
		// Look for "<Class>.<name>" in the index for that file.
		if id, hit := resolveJavaNodeID(abs, name, name, idx); hit {
			return id, true
		}
	}
	return "", false
}

// resolveSamePackageQualified handles `Foo.bar()` where Foo is a class
// in the same package as the importing file but wasn't explicitly
// imported. Java allows this within a package; we probe
// `<pkgDir>/Foo.java`.
func (j *javaResolver) resolveSamePackageQualified(className, method string, scope FileScope, idx *PackageIndex) (string, bool) {
	moduleRoot := scope.Aux["module_root"]
	if moduleRoot == "" || scope.Package == "" {
		return "", false
	}
	pkgDir := filepath.Join(moduleRoot, filepath.FromSlash(strings.ReplaceAll(scope.Package, ".", "/")))
	candidate := filepath.Join(pkgDir, className+".java")
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		abs, err := filepath.Abs(candidate)
		if err != nil {
			abs = candidate
		}
		return resolveJavaNodeID(abs, className, method, idx)
	}
	return "", false
}

// resolveJavaNodeID looks up a method named `method` inside the file
// `filePath` via the PackageIndex (which is keyed by absolute file path
// for Java, same as JS/TS). className is used to bias the suffix match:
// for "Foo.bar" we prefer a node named "Foo.bar" over a same-name
// method on a different class in the same file.
//
// Match precedence:
//  1. Exact `<className>.<method>` — for qualified calls.
//  2. Suffix `.<method>` — for bare-name calls and qualified calls
//     when the leading class is the file's outermost type.
func resolveJavaNodeID(filePath, className, method string, idx *PackageIndex) (string, bool) {
	if idx == nil || filePath == "" || method == "" {
		return "", false
	}
	cands := idx.Lookup(filePath)
	want := className + "." + method
	// First pass: exact "<className>.<method>" match.
	for _, candID := range cands {
		colon := strings.LastIndexByte(candID, ':')
		if colon < 0 {
			continue
		}
		fnPart := candID[colon+1:]
		if fnPart == want || strings.HasSuffix(fnPart, "."+want) {
			return candID, true
		}
	}
	// Second pass: any node whose name ends with ".<method>".
	for _, candID := range cands {
		colon := strings.LastIndexByte(candID, ':')
		if colon < 0 {
			continue
		}
		fnPart := candID[colon+1:]
		if fnPart == method || strings.HasSuffix(fnPart, "."+method) {
			return candID, true
		}
	}
	return "", false
}

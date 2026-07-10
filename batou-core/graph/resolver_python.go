// Per-language adapter: Python.
//
// Implements the LanguageResolver interface for Python source code:
//
//   - ProjectRoot walks up from scanDir looking for a Python project
//     manifest. The first match in precedence order wins:
//     1. pyproject.toml
//     2. setup.py
//     3. setup.cfg
//     4. the highest ancestor still containing __init__.py (i.e. the
//     package root — the parent of the topmost __init__.py-bearing
//     directory). This handles repos that ship a pure package
//     without a setup file.
//     5. the first ancestor containing *.py files (last-resort). In
//     this no-manifest case ProjectRoot returns a SYNTHETIC FILE path
//     inside that directory (dir/<sentinel>) so consumers' uniform
//     filepath.Dir(manifest) derivation anchors ModuleRoot at the
//     directory itself rather than its parent — this is what makes
//     sibling-file cross-file resolution work without a manifest (see
//     pythonSyntheticRootSentinel and the Pass-3 comment below).
//     The "module path" Python returns is the package-namespace prefix
//     declared in the manifest when one exists (pyproject.toml's
//     [project].name, setup.py's name=... arg, setup.cfg's [metadata]
//     name). When no manifest declares it we use the package root's
//     directory basename — for `myapp/__init__.py` that's "myapp".
//
//     SRC-LAYOUT: when the manifest declares package `flask` but the
//     importable code actually lives at `<manifestDir>/src/flask/`
//     (the modern "src layout" convention used by Flask, Werkzeug,
//     Pallets projects, …), ProjectRoot returns the __init__.py
//     inside `src/<name>` as the manifest path so filepath.Dir(manifest)
//     gives `<manifestDir>/src` as ModuleRoot. Without this, every
//     file's dotted path is keyed as `src.flask.X` instead of
//     `flask.X` and `from flask import Y` never finds anything in
//     PackageIndex.
//
//   - ExtractScope parses a file's imports with tree-sitter and builds
//     a local-name → fully-qualified-name index. Handles:
//     import X              → "X" → "X"
//     import X.Y            → "X" → "X.Y" (Python binds the leftmost)
//     import X as Z         → "Z" → "X"
//     import X.Y as Z       → "Z" → "X.Y"
//     from X import Y       → "Y" → "X.Y"
//     from X import Y as Z  → "Z" → "X.Y"
//     from . import X       → "X" → "<this.pkg>.X"
//     from ..X import Y     → "Y" → "<parent.pkg>.X.Y"
//     The file's own dotted module path is also populated on
//     FileScope.Package so ResolveCall can interpret unqualified calls.
//     Aux["module_root"] carries the project's package-root directory so
//     ResolveCall can re-derive the project prefix when the resolver is
//     reused across scans.
//
//     RE-EXPORT FOLLOWING:
//     __init__.py re-exports are followed one hop. When pkg/__init__.py
//     contains `from pkg.sub import handler`, calls of the form
//     `from pkg import handler; handler()` resolve to
//     pkg/sub.py:handler rather than pkg/__init__.py:handler. See
//     resolvePythonFullName / followPythonReExport for the lookup
//     path. The package's re-export table is built by the cross-file
//     dispatcher (resolve.go::collectPythonReExports) and stored on
//     PackageIndex.PythonReExports.
//
//     LIMITATIONS (documented as future work):
//
//   - `from x import *` is not expanded; the star list lands in
//     FileScope.StarImports but no name resolution happens against it.
//
//   - Dynamic imports (importlib.import_module, __import__) are not
//     resolved.
//
//   - Re-export chains (__init__.py → __init__.py → leaf) are only
//     followed for one hop. The intermediate __init__.py's
//     re-export is read; transitive resolution stops at the next
//     level. Multi-hop chains and __all__-enforced visibility are
//     left for a follow-up PR.
//
//   - ResolveCall maps a call expression's textual name to a FuncNode ID.
//     For "foo" (bare name) we look up the local-name index. For
//     "pkg.bar" we resolve "pkg" through the index and look up "bar" in
//     the resulting module. If the resolved module is in-project (its
//     dotted path is == or starts with modulePath + ".") we search the
//     PackageIndex; otherwise it is an extern.
package graph

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// pythonResolver implements LanguageResolver for Python.
type pythonResolver struct{}

func init() {
	RegisterResolver(&pythonResolver{})
}

// Language reports that this resolver handles Python.
func (p *pythonResolver) Language() rules.Language { return rules.LangPython }

// pyprojectNameRe matches the `name = "value"` line under [project] in
// pyproject.toml (PEP 621). Tolerates whitespace and either quoting.
var pyprojectNameRe = regexp.MustCompile(`(?m)^\s*name\s*=\s*['"]([^'"]+)['"]`)

// setupcfgNameRe matches the `name = value` line under [metadata] in
// setup.cfg. Unquoted; case-insensitive on the key as setuptools accepts.
var setupcfgNameRe = regexp.MustCompile(`(?mi)^\s*name\s*=\s*([A-Za-z0-9_.\-]+)\s*$`)

// setupPyNameRe matches `name='value'` or `name="value"` inside
// setup(...) calls. Tolerates whitespace around the equals.
var setupPyNameRe = regexp.MustCompile(`name\s*=\s*['"]([^'"]+)['"]`)

// ProjectRoot walks up from scanDir looking for a Python project
// manifest. See package docstring for the precedence order.
func (p *pythonResolver) ProjectRoot(scanDir string) (manifestPath, modulePath string, ok bool) {
	dir := scanDir
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", "", false
	}

	// Pass 1: walk upward looking for an explicit manifest. The first
	// one found wins — pyproject.toml is most authoritative, then
	// setup.py, then setup.cfg.
	cur := abs
	for {
		for _, manifest := range []string{"pyproject.toml", "setup.py", "setup.cfg"} {
			candidate := filepath.Join(cur, manifest)
			info, err := os.Stat(candidate)
			if err != nil || info.IsDir() {
				continue
			}
			name := readPythonProjectName(candidate)
			// Even with an empty name the manifest itself anchors the
			// project root; fall back to the manifest dir's basename.
			if name == "" {
				name = filepath.Base(cur)
			}
			normalized := normalizePyModuleName(name)
			// Src-layout detection: when the manifest declares
			// `Flask` but the importable package actually lives at
			// `<cur>/src/flask/__init__.py`, the dispatcher needs to
			// anchor ModuleRoot at `<cur>/src` rather than `<cur>`.
			// Otherwise file paths get keyed as `src.flask.X` and
			// every `from flask import X` lookup misses. Return a
			// synthetic manifest path inside `<cur>/src/` so
			// filepath.Dir(manifest) gives the right ModuleRoot.
			//
			// Distribution names are case-insensitive and accept
			// hyphen/underscore variants (PEP 503 normalization);
			// the on-disk directory uses the canonical lowercase
			// importable form. Try the normalized name as-is first,
			// then the lowercase variant.
			if srcInit, dirName, ok := findSrcLayoutInit(cur, normalized); ok {
				return srcInit, dirName, true
			}
			return candidate, normalized, true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}

	// Pass 2: no explicit manifest. Look for an __init__.py chain — the
	// topmost __init__.py-bearing ancestor of scanDir's directory marks
	// the package root. Module path == package root directory name.
	if root := findPackageRoot(abs); root != "" {
		// Treat the __init__.py at the package root as the "manifest"
		// for ModuleRoot bookkeeping; ModuleRoot becomes the parent
		// directory (so files in <parent>/<pkg>/<sub>/x.py resolve to
		// <pkg>.<sub>.x — see filePathToModule).
		manifest := filepath.Join(root, "__init__.py")
		modName := filepath.Base(root)
		return manifest, normalizePyModuleName(modName), true
	}

	// Pass 3: last-resort — the first ancestor that contains at least
	// one *.py file. This catches scripts-only repos with no manifest
	// and no __init__.py (very common for small CLIs, sibling-module
	// layouts, and benchmarks).
	//
	// We return a SYNTHETIC FILE path inside `cur` (cur/<sentinel>) rather
	// than `cur` itself, because every ProjectRoot consumer derives the
	// ModuleRoot via filepath.Dir(manifest) — for Pass 1/2 the manifest is
	// a real file, so that yields the containing dir, but returning the
	// bare directory `cur` here made filepath.Dir(cur) climb one level
	// ABOVE the scanned tree. That off-by-one anchored ModuleRoot at the
	// parent of the sibling files, so a file at <cur>/db.py was keyed in
	// PackageIndex as "<cur-basename>.db" while `from db import x` in a
	// sibling resolved to the absolute module "db.x" — the keys never
	// matched and EVERY cross-file edge was silently dropped (source in
	// file A -> sink in file B yielded 0 flows with no signal). Anchoring
	// filepath.Dir back to `cur` keys sibling modules as their bare
	// basename ("db", "app", …) — exactly what an absolute `from db import
	// x` / `import db` resolves to — so sibling-file resolution works
	// WITHOUT a manifest. (Mirrors findSrcLayoutInit's "return one level
	// deeper than the intended ModuleRoot" convention.) The module path
	// stays empty because we cannot derive a namespace prefix without a
	// marker. Behaviour with a manifest present is unchanged — Pass 1 /
	// Pass 2 return before reaching here.
	cur = abs
	for {
		if anyPythonFile(cur) {
			return filepath.Join(cur, pythonSyntheticRootSentinel), "", true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", "", false
		}
		cur = parent
	}
}

// pythonSyntheticRootSentinel is the basename of the synthetic manifest
// path Pass 3 of ProjectRoot returns for a no-manifest Python tree. It is
// never read from disk — consumers only ever take filepath.Dir() of the
// returned manifest path to derive the ModuleRoot, so the file need not
// exist. The leading dunder keeps it from colliding with any real module
// name if it ever leaked into a dotted path.
const pythonSyntheticRootSentinel = "__batou_pkgroot__.py"

// readPythonProjectName extracts the package name declared in a Python
// project manifest. Returns "" when nothing parsable is found.
func readPythonProjectName(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	const maxBytes = 32 * 1024 // 32KB cap; manifests are tiny in practice.
	buf := make([]byte, 0, 4096)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4096), 1024*1024)
	read := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		read += len(line) + 1
		if read > maxBytes {
			break
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	content := string(buf)

	base := strings.ToLower(filepath.Base(path))
	switch base {
	case "pyproject.toml":
		if m := pyprojectNameRe.FindStringSubmatch(content); len(m) == 2 {
			return m[1]
		}
	case "setup.cfg":
		if m := setupcfgNameRe.FindStringSubmatch(content); len(m) == 2 {
			return m[1]
		}
	case "setup.py":
		if m := setupPyNameRe.FindStringSubmatch(content); len(m) == 2 {
			return m[1]
		}
	}
	return ""
}

// normalizePyModuleName converts a distribution name (which may use
// hyphens, e.g. "my-package") into a Python module name (underscores).
// Python's PEP 503 normalization is fuzzier than this but the
// canonical-to-importable transformation we need is: hyphens → underscores.
func normalizePyModuleName(name string) string {
	return strings.ReplaceAll(strings.TrimSpace(name), "-", "_")
}

// findSrcLayoutInit checks whether <dir>/src/<name>/__init__.py exists
// for the manifest-declared name. PEP 503 names are case-insensitive
// and treat hyphens / underscores interchangeably; the on-disk
// directory uses the canonical lowercase form (Flask → src/flask/).
//
// On a hit, returns (synthetic-manifest-path, importable-name, true).
// The synthetic path is `<dir>/src/<actual-on-disk-name>` (a directory,
// not a file) so the dispatcher's `filepath.Dir(manifest)` resolves
// to `<dir>/src/` — which is what we want as ModuleRoot. Without the
// extra path component the result would point at `<dir>/src/<name>`,
// keying every file as `<name>.X.X` (e.g. `flask.app.Flask` becomes
// `app.Flask` — losing the leading `flask.` qualifier).
//
// On case-insensitive filesystems (macOS default, Windows) Stat on
// `src/Flask/__init__.py` reports success even when the actual on-
// disk directory is `src/flask`, so we read the `src/` directory and
// look for an entry whose canonical-folded name matches our
// candidate. This matters because file paths reported by dirscan are
// the on-disk casing, and PackageIndex / ReExports keys derive from
// those paths.
func findSrcLayoutInit(dir, manifestName string) (string, string, bool) {
	if manifestName == "" {
		return "", "", false
	}
	srcDir := filepath.Join(dir, "src")
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return "", "", false
	}
	// Try the importable variants of the manifest name (raw and
	// lowercase). Python's distribution-to-import convention is
	// lowercase, so try lowercase first to mirror what `pip install`
	// places on disk.
	candidates := []string{strings.ToLower(manifestName), manifestName}
	for _, c := range candidates {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			if !strings.EqualFold(entry.Name(), c) {
				continue
			}
			actual := entry.Name()
			initPath := filepath.Join(srcDir, actual, "__init__.py")
			if info, err := os.Stat(initPath); err == nil && !info.IsDir() {
				// Synthetic manifest: point at `<srcDir>/<actual>`
				// (the package directory itself, not the __init__.py
				// inside it) so filepath.Dir(manifest) = srcDir.
				return filepath.Join(srcDir, actual), actual, true
			}
		}
	}
	return "", "", false
}

// findPackageRoot returns the topmost ancestor of start that bears an
// __init__.py file. Returns "" if none of the ancestors are packages.
func findPackageRoot(start string) string {
	cur := start
	last := ""
	for {
		if _, err := os.Stat(filepath.Join(cur, "__init__.py")); err == nil {
			last = cur
		} else if last != "" {
			// We left the __init__.py chain — last is the topmost
			// package root.
			return last
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return last
		}
		cur = parent
	}
}

// anyPythonFile reports whether dir contains at least one *.py file at
// its top level.
func anyPythonFile(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".py") {
			return true
		}
	}
	return false
}

// ExtractScope parses the Python file's imports into a FileScope.
//
// We use tree-sitter for robust handling of multi-line `from x import (a,
// b, c)` blocks, parenthesised continuations, and aliased imports. The
// fallback when tree-sitter parsing fails is an empty scope — callers
// then degrade to AST-local-edges-only.
//
// scope.Package is populated from the file's filesystem path alone (with
// no module-root context). The cross-file dispatcher in resolve.go
// re-derives Package using the per-file ModuleRoot before storing the
// scope, so relative imports anchor to the real-world dotted parent.
func (p *pythonResolver) ExtractScope(filePath string, content []byte) (FileScope, error) {
	fs := FileScope{
		FilePath: filePath,
		Imports:  map[string]string{},
		Aux:      map[string]string{},
	}
	fs.Package = filePathToModule(filePath, "")
	parsePythonImports(content, fs.Package, isInitFile(filePath), fs.Imports, &fs.StarImports)
	return fs, nil
}

// isInitFile reports whether path's basename is __init__.py — the
// package's index file. Relative-import resolution treats these
// specially: for a regular module file the file's own basename is
// stripped from thisPkg to find the enclosing package, but
// __init__.py's thisPkg IS the package already, so nothing should be
// stripped. See resolveModuleFromRelative.
func isInitFile(path string) bool {
	return filepath.Base(path) == "__init__.py"
}

// parsePythonImports walks content's top-level import statements and
// populates imports + stars using thisPkg as the anchor for relative
// imports. isInit tells relative-import resolution whether the file
// is an __init__.py (in which case thisPkg already names the package
// and shouldn't have its trailing component stripped).
func parsePythonImports(content []byte, thisPkg string, isInit bool, imports map[string]string, stars *[]string) {
	tree := tsast.Parse(content, rules.LangPython)
	if tree == nil || tree.Root() == nil {
		return
	}
	root := tree.Root()
	for i := 0; i < root.ChildCount(); i++ {
		stmt := root.Child(i)
		switch stmt.Type() {
		case "import_statement":
			collectImportStatement(stmt, imports)
		case "import_from_statement":
			collectImportFromStatement(stmt, thisPkg, isInit, imports, stars)
		}
	}
}

// rebuildPythonScopeRelative replaces a scope's Imports + StarImports
// with a fresh parse anchored to scope.Package — used by the cross-file
// dispatcher after it has set Package from the per-file ModuleRoot.
func rebuildPythonScopeRelative(scope *FileScope, content []byte) {
	if scope == nil {
		return
	}
	scope.Imports = map[string]string{}
	scope.StarImports = nil
	parsePythonImports(content, scope.Package, isInitFile(scope.FilePath), scope.Imports, &scope.StarImports)
}

// collectImportStatement handles `import X`, `import X as Y`, `import
// X.Y.Z`, `import X.Y as Z`. Python binds the leftmost component of a
// dotted import to the file's scope, unless an `as` rename appears.
func collectImportStatement(stmt *tsast.Node, imports map[string]string) {
	for _, child := range stmt.NamedChildren() {
		switch child.Type() {
		case "dotted_name":
			full := child.Text()
			leftmost := full
			if dot := strings.IndexByte(full, '.'); dot >= 0 {
				leftmost = full[:dot]
			}
			imports[leftmost] = full
		case "aliased_import":
			nameNode := child.ChildByFieldName("name")
			aliasNode := child.ChildByFieldName("alias")
			if nameNode == nil || aliasNode == nil {
				continue
			}
			full := strings.TrimSpace(nameNode.Text())
			alias := strings.TrimSpace(aliasNode.Text())
			if full != "" && alias != "" {
				imports[alias] = full
			}
		}
	}
}

// collectImportFromStatement handles `from X import Y`, `from . import
// Y`, `from ..X import Y as Z`, and `from x import *`.
//
// thisPkg is the file's own dotted module path; we use it to resolve
// relative imports ("." → thisPkg, ".." → thisPkg's parent, etc.).
// isInit is true when the file is __init__.py — relative imports in
// __init__.py already start from the package itself, so we don't
// strip a "file basename" off thisPkg.
func collectImportFromStatement(stmt *tsast.Node, thisPkg string, isInit bool, imports map[string]string, stars *[]string) {
	moduleNode := stmt.ChildByFieldName("module_name")
	module := ""
	relative := 0
	if moduleNode != nil {
		switch moduleNode.Type() {
		case "dotted_name":
			module = moduleNode.Text()
		case "relative_import":
			// relative_import contains zero or more "import_prefix"
			// (which is the dots) and optionally a dotted_name child.
			relative, module = parseRelativeImport(moduleNode)
		}
	}
	resolvedModule := resolveModuleFromRelative(thisPkg, isInit, relative, module)

	// Walk the import_list (which is just direct children with named
	// kinds dotted_name / aliased_import / wildcard_import).
	for _, child := range stmt.NamedChildren() {
		if child == moduleNode {
			continue
		}
		switch child.Type() {
		case "dotted_name":
			name := child.Text()
			full := name
			if resolvedModule != "" {
				full = resolvedModule + "." + name
			}
			imports[name] = full
		case "aliased_import":
			nameNode := child.ChildByFieldName("name")
			aliasNode := child.ChildByFieldName("alias")
			if nameNode == nil || aliasNode == nil {
				continue
			}
			name := strings.TrimSpace(nameNode.Text())
			alias := strings.TrimSpace(aliasNode.Text())
			if name == "" || alias == "" {
				continue
			}
			full := name
			if resolvedModule != "" {
				full = resolvedModule + "." + name
			}
			imports[alias] = full
		case "wildcard_import":
			if resolvedModule != "" {
				*stars = append(*stars, resolvedModule)
			}
		}
	}
}

// parseRelativeImport returns (dotCount, optionalSuffix) for a
// `relative_import` node. Examples:
//
//	from . import X        → (1, "")
//	from .. import X       → (2, "")
//	from .sub import X     → (1, "sub")
//	from ..pkg.sub import X → (2, "pkg.sub")
func parseRelativeImport(n *tsast.Node) (int, string) {
	dots := 0
	suffix := ""
	for _, child := range n.NamedChildren() {
		switch child.Type() {
		case "import_prefix":
			dots += len(strings.TrimSpace(child.Text()))
		case "dotted_name":
			suffix = strings.TrimSpace(child.Text())
		}
	}
	// Older tree-sitter Python grammars emit the dots as anonymous
	// tokens at child index 0+. Fall back to counting "." in the raw
	// text when no import_prefix children were named.
	if dots == 0 {
		text := strings.TrimSpace(n.Text())
		for i := 0; i < len(text) && text[i] == '.'; i++ {
			dots++
		}
	}
	return dots, suffix
}

// resolveModuleFromRelative converts a relative module spec into an
// absolute dotted path. dots is the number of leading dots (1 == current
// package, 2 == parent, etc.). suffix is the optional dotted name after
// the dots. thisPkg is the importing file's own dotted module path.
// isInit is true when the importing file is __init__.py — its thisPkg
// names the package itself, so `from . import X` should resolve to
// `<thisPkg>.X` rather than `<thisPkg's parent>.X`.
func resolveModuleFromRelative(thisPkg string, isInit bool, dots int, suffix string) string {
	if dots == 0 {
		// Not a relative import; suffix is the absolute module path.
		return suffix
	}
	parts := strings.Split(thisPkg, ".")
	// Strip the file's own basename (last component) so we sit at
	// the enclosing package. __init__.py is special: thisPkg IS the
	// package, so don't strip — the file has no separate basename.
	//
	// Example:
	//   regular file "myapp.handlers.api" + `from . import X`
	//     → strip last → "myapp.handlers" → "myapp.handlers.X"
	//   __init__.py "myapp.handlers" + `from . import X`
	//     → no strip → "myapp.handlers" → "myapp.handlers.X"
	if !isInit && len(parts) > 0 {
		parts = parts[:len(parts)-1]
	}
	// Then strip (dots-1) more components for parent references.
	for i := 1; i < dots && len(parts) > 0; i++ {
		parts = parts[:len(parts)-1]
	}
	base := strings.Join(parts, ".")
	if suffix == "" {
		return base
	}
	if base == "" {
		return suffix
	}
	return base + "." + suffix
}

// filePathToModule converts a filesystem path to a dotted Python module
// path relative to moduleRoot. Returns "" when moduleRoot is empty or
// when the file lies outside it. With moduleRoot="" we strip just the
// .py suffix and join path segments with dots — useful as a best-effort
// derivation when the resolver has no project anchor yet (ExtractScope
// is called before the cross-file pass populates ModuleRoots).
func filePathToModule(filePath, moduleRoot string) string {
	clean := filepath.ToSlash(filePath)
	if moduleRoot != "" {
		rel, err := filepath.Rel(moduleRoot, filePath)
		if err == nil && !strings.HasPrefix(rel, "..") {
			clean = filepath.ToSlash(rel)
		}
	}
	clean = strings.TrimSuffix(clean, ".py")
	// Drop trailing "/__init__" so a package directory's __init__.py
	// maps to the package's dotted name (not "<pkg>.__init__").
	clean = strings.TrimSuffix(clean, "/__init__")
	// Strip a leading "./" if present.
	clean = strings.TrimPrefix(clean, "./")
	// Strip leading "/" so absolute paths don't produce a leading dot.
	clean = strings.TrimPrefix(clean, "/")
	parts := strings.Split(clean, "/")
	// Drop empty segments (defensive against double slashes).
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, ".")
}

// ResolveCall resolves a Python call expression to a FuncNode ID, an
// extern symbol, or "no opinion".
//
// callee is one of:
//
//	"foo"        — bare name, possibly a top-level import or local def.
//	"pkg.bar"    — attribute call on a name (which may be an import alias,
//	               a local variable, or a class). We try the import
//	               interpretation; if "pkg" isn't in scope.Imports we
//	               return "no opinion" — Python's type system can't tell
//	               us "pkg" is a class instance vs a module without full
//	               static analysis.
func (p *pythonResolver) ResolveCall(callee string, scope FileScope, modulePath string, idx *PackageIndex) ResolveResult {
	if callee == "" {
		return ResolveResult{}
	}
	dot := strings.Index(callee, ".")

	// Bare name: look up against the import index. If a `from X import
	// foo` brought "foo" into scope, the index has "foo" → "X.foo" and
	// we can route the call. Otherwise the name is a local def and the
	// same-file pass already handled it.
	if dot < 0 {
		full, ok := scope.Imports[callee]
		if !ok {
			return ResolveResult{}
		}
		return resolvePythonFullName(full, modulePath, idx)
	}

	alias := callee[:dot]
	rest := callee[dot+1:]
	if alias == "" || rest == "" {
		return ResolveResult{}
	}

	// Attribute call: "pkg.bar". "pkg" might be an import alias OR a
	// local variable / class instance / function. Only the import case
	// is resolvable without type inference.
	importPath, ok := scope.Imports[alias]
	if !ok {
		// Unknown receiver — leave to the caller. The resolve.go
		// dispatcher already filters these out of UnresolvedCalls when
		// the prefix isn't an import alias.
		return ResolveResult{}
	}
	full := importPath + "." + rest
	return resolvePythonFullName(full, modulePath, idx)
}

// resolvePythonFullName takes a fully-qualified Python symbol name like
// "myapp.handlers.login" and decides whether it points to an in-project
// node or an extern.
//
// In-project membership is determined by PackageIndex lookup first:
// when the index has a node in the module, the call is in-project. This
// handles both the canonical layout (files under `<modulePath>/`) and
// the flat layout (files at the project root with no package wrapper).
// modulePath is consulted as a secondary signal — when set, it sharpens
// the "extern vs in-project" decision for names that don't appear in
// the index (e.g. constants and submodule names we don't node-ify).
//
// If the direct lookup doesn't hit a node, we consult the __init__.py
// re-export table on idx.PythonReExports: when pkg/__init__.py
// contains `from pkg.sub import handler`, looking up "pkg.handler"
// rewrites to "pkg.sub.handler" and retries. Single-hop only —
// chains aren't followed (documented).
func resolvePythonFullName(full, modulePath string, idx *PackageIndex) ResolveResult {
	// Direct lookup: did the name pin to an exact node ID in idx?
	if id, hit := resolvePythonNodeID(full, idx); hit {
		return ResolveResult{TargetID: id, Confidence: 0.85}
	}
	// Direct lookup missed; try one re-export hop. The re-export hop
	// covers two patterns:
	//   1. pkg/__init__.py: `from pkg.sub import handler` →
	//      "pkg.handler" rewrites to "pkg.sub.handler".
	//   2. pkg/__init__.py: `from . import sub` →
	//      "pkg.sub" rewrites to "pkg.sub" (no-op, but stops the
	//      table from re-pointing at the package itself).
	// Aliases (`as h`) are covered automatically because the importer's
	// scope already maps `h → pkg.h` and the re-export table stores
	// `h → pkg.sub.handler`.
	if rerouted, ok := followPythonReExport(full, idx); ok {
		if id, hit := resolvePythonNodeID(rerouted, idx); hit {
			return ResolveResult{TargetID: id, Confidence: 0.85}
		}
		// The rewritten target also missed; treat it as in-project
		// when its module is indexed (re-export points to a known
		// package but a name we don't node-ify) and otherwise hand
		// the rewritten name to the extern path so the dependency
		// surface records the real upstream.
		if pythonModuleIndexed(rerouted, idx) {
			return ResolveResult{}
		}
		return resolvePythonNotFound(rerouted, modulePath)
	}
	// Original module in index but name didn't match: in-project miss
	// (preserves PR-CCpy semantics — don't fall through to extern).
	if pythonModuleIndexed(full, idx) {
		return ResolveResult{}
	}
	return resolvePythonNotFound(full, modulePath)
}

// resolvePythonNodeID returns the FuncNode ID matching `full` (of the
// form module.name) in idx, or ("", false) if no matching node lives
// inside `module`. Callers use the (id, hit) tuple to distinguish
// "exact node match" from "module is indexed but name unmatched".
//
// Match precedence (mirrors the Java / PHP exact-first two-pass):
//  1. Exact `name` — a module-level function `handler` must win over a
//     method `Cls.handler` when both live in the module (first-hit
//     order would otherwise mis-bind, order-dependently).
//  2. Suffix `.<name>` — class-method fallback when no module-level
//     function with that name exists.
func resolvePythonNodeID(full string, idx *PackageIndex) (string, bool) {
	dot := strings.LastIndex(full, ".")
	if dot < 0 || idx == nil {
		return "", false
	}
	module := full[:dot]
	name := full[dot+1:]
	cands := idx.Lookup(module)
	// First pass: exact name match.
	for _, candID := range cands {
		colon := strings.LastIndexByte(candID, ':')
		if colon < 0 {
			continue
		}
		if candID[colon+1:] == name {
			return candID, true
		}
	}
	// Second pass: any node whose name ends with ".<name>".
	for _, candID := range cands {
		colon := strings.LastIndexByte(candID, ':')
		if colon < 0 {
			continue
		}
		if strings.HasSuffix(candID[colon+1:], "."+name) {
			return candID, true
		}
	}
	return "", false
}

// pythonModuleIndexed reports whether the module portion of `full`
// has any nodes in idx — used to decide whether a miss is
// "in-project (unindexed name)" or "extern".
func pythonModuleIndexed(full string, idx *PackageIndex) bool {
	if idx == nil {
		return false
	}
	dot := strings.LastIndex(full, ".")
	if dot < 0 {
		return false
	}
	return len(idx.Lookup(full[:dot])) > 0
}

// followPythonReExport checks if `full` (of the form module.name)
// names a re-export through a Python __init__.py. When pkg/__init__.py
// contains `from pkg.sub import handler` we record an entry in
// PythonReExports["pkg"]["handler"] = "pkg.sub.handler"; resolving
// "pkg.handler" hits the index and re-targets to "pkg.sub.handler".
//
// Returns (rerouted, true) when a re-export was found, (full, false)
// otherwise. The aliased shape `from pkg.sub import handler as h` is
// covered automatically because the importer's scope maps `h → pkg.h`
// and the re-export table stores `h → pkg.sub.handler`.
func followPythonReExport(full string, idx *PackageIndex) (string, bool) {
	if idx == nil || len(idx.PythonReExports) == 0 {
		return full, false
	}
	dot := strings.LastIndex(full, ".")
	if dot < 0 {
		return full, false
	}
	module := full[:dot]
	name := full[dot+1:]
	pkgTable, ok := idx.PythonReExports[module]
	if !ok {
		return full, false
	}
	actual, ok := pkgTable[name]
	if !ok || actual == "" || actual == full {
		// No entry, or the re-export points back to itself (defensive
		// guard against degenerate self-loops).
		return full, false
	}
	return actual, true
}

// resolvePythonNotFound handles the case where neither the direct
// lookup nor the re-export hop produced an in-project match.
func resolvePythonNotFound(full, modulePath string) ResolveResult {
	dot := strings.LastIndex(full, ".")
	if dot < 0 {
		return ResolveResult{Extern: full, Confidence: 0.85}
	}
	module := full[:dot]
	// If the module name *looks* like it's under the project's
	// declared modulePath, treat it as "in-project but unindexed"
	// (e.g. a re-export we didn't capture) — don't emit an extern.
	if modulePath != "" && (module == modulePath || strings.HasPrefix(module, modulePath+".")) {
		return ResolveResult{}
	}
	return ResolveResult{Extern: full, Confidence: 0.85}
}

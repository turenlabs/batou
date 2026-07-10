// Per-language adapter: JavaScript / TypeScript.
//
// Implements the LanguageResolver interface for the dominant module shapes
// found in real-world Node + TypeScript projects:
//
//   - ESM static imports:
//
//     import X from './foo'
//     import {Y, Z as W} from './bar'
//     import * as ns from './baz'
//     import './side-effect-only'
//
//   - ESM dynamic imports: `import('./dynamic')` — resolution rules
//     match the static-import path (relative specifier → file resolution
//     with the standard extension fallback chain).
//
//   - CommonJS: `const x = require('./baz')` and the variants
//     `const {y} = require('./baz')`, `const y = require('./baz').sub`.
//
// All resolution is RELATIVE-PATH-ONLY in this PR. Bare specifiers
// (`react`, `lodash`, `@scope/lib`) return empty results — `node_modules`
// is intentionally out of scope. TypeScript `paths` aliases declared in
// `tsconfig.json` are also out of scope; both are documented follow-ups.
//
// Resolution order for an extension-less relative specifier `./foo`:
//
//  1. ./foo.ts
//  2. ./foo.tsx
//  3. ./foo.js
//  4. ./foo.jsx
//  5. ./foo.mjs
//  6. ./foo.cjs
//  7. ./foo/index.ts
//  8. ./foo/index.tsx
//  9. ./foo/index.js
//  10. ./foo/index.jsx
//
// When the specifier already has an extension (e.g. `./foo.json`), we use
// it as-is — no extension fallback.
//
// The "module path" for JS in this resolver is the resolved absolute file
// path of the imported module. We key PackageIndex by absolute file path
// for JS/TS so cross-file lookups boil down to "find the file the import
// resolved to and look up the requested name in its nodes". This sidesteps
// JS's lack of a global namespace.
//
// Known limitations (deliberate scope cuts for this PR):
//
//   - Bare specifiers / node_modules: returns empty, NOT an extern entry.
//     The first JS PR doesn't try to enumerate npm dependencies; that's a
//     follow-up that needs package.json walking.
//   - `tsconfig.json` `paths` aliases: not parsed.
//   - Monorepo workspaces (`packages/*` from pnpm/yarn): not resolved.
//   - Re-export chains (`export { x } from './y'` in a barrel file):
//     not followed. The first-hop resolver lands `x` in the importer's
//     scope mapped to the barrel file, not the leaf. Follow-up PR.
package graph

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// jsResolver implements LanguageResolver for JavaScript AND TypeScript.
// We register two instances (one per language) so the framework's
// per-language dispatch picks us up for both file kinds.
type jsResolver struct {
	lang rules.Language
}

func init() {
	RegisterResolver(&jsResolver{lang: rules.LangJavaScript})
	RegisterResolver(&jsResolver{lang: rules.LangTypeScript})
}

// Language reports which language this resolver instance handles.
func (j *jsResolver) Language() rules.Language { return j.lang }

// jsResolveExtensionsInOrder is the canonical extension fallback list for
// extension-less specifiers, in the order Node + TypeScript prefer them.
// .ts comes first because TS projects typically import sibling .ts files
// using extension-less specifiers; in pure-JS projects the .ts variants
// simply don't exist on disk and we fall through.
var jsResolveExtensionsInOrder = []string{
	".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
}

// jsIndexFilenames is the index-file fallback list when the specifier
// names a directory. Same ordering rationale as jsResolveExtensionsInOrder.
var jsIndexFilenames = []string{
	"index.ts", "index.tsx", "index.js", "index.jsx",
}

// ProjectRoot walks up from scanDir looking for a package.json. When found,
// the manifestPath is the package.json itself and modulePath is the
// package's name (used as a diagnostic label only — JS cross-file
// resolution keys on absolute file paths, not module names).
//
// When no package.json is found, we still return ok=true with an empty
// modulePath and the scanDir itself as the manifest "path". This lets the
// resolver work on script-only repos (the common case for small Node
// utilities) just like the Python resolver's last-resort behavior.
func (j *jsResolver) ProjectRoot(scanDir string) (manifestPath, modulePath string, ok bool) {
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
		candidate := filepath.Join(cur, "package.json")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, readPackageJSONName(candidate), true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	// No manifest located. Anchor at scanDir so the framework still has a
	// non-empty manifest path; modulePath stays empty (script-only repo).
	return abs, "", true
}

// readPackageJSONName extracts the `"name"` field from a package.json.
// Returns "" on any read/parse failure; the manifest is still accepted
// because the path itself anchors the project root.
//
// We parse with a tiny hand-rolled scanner rather than encoding/json so
// the resolver stays dependency-free at the package level (matching the
// other resolvers' minimal-imports policy). We only need the top-level
// "name" string; we don't validate the JSON.
func readPackageJSONName(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	const maxBytes = 64 * 1024 // 64KB cap; manifests are tiny in practice.
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4096), maxBytes)
	read := 0
	for scanner.Scan() {
		line := scanner.Text()
		read += len(line) + 1
		if read > maxBytes {
			break
		}
		trimmed := strings.TrimSpace(line)
		// Look for `"name"` at the start of the line (top-level key).
		// This is a heuristic — nested objects with their own "name"
		// fields would also match — but it's good enough for the
		// diagnostic label use case here.
		if !strings.HasPrefix(trimmed, "\"name\"") {
			continue
		}
		// Find the colon, then the next quoted string after it.
		colon := strings.IndexByte(trimmed, ':')
		if colon < 0 {
			continue
		}
		rest := trimmed[colon+1:]
		// First quoted segment is the value.
		q1 := strings.IndexByte(rest, '"')
		if q1 < 0 {
			continue
		}
		q2 := strings.IndexByte(rest[q1+1:], '"')
		if q2 < 0 {
			continue
		}
		return rest[q1+1 : q1+1+q2]
	}
	return ""
}

// ExtractScope parses the imports in a JS/TS file. The returned FileScope
// uses absolute resolved file paths as the values in Imports: each local
// alias maps to the absolute path of the imported module on disk. Bare
// specifiers are dropped (not added to Imports), so ResolveCall naturally
// declines to resolve them.
//
// The file's `Package` is set to its OWN absolute path. PackageIndex
// keys on this same form, so a node lives in the "package" identified by
// its file path. This is JS's "every file is its own namespace" model.
func (j *jsResolver) ExtractScope(filePath string, content []byte) (FileScope, error) {
	fs := FileScope{
		FilePath: filePath,
		Imports:  map[string]string{},
		Aux:      map[string]string{},
	}
	abs, err := filepath.Abs(filePath)
	if err == nil {
		fs.Package = abs
	} else {
		fs.Package = filePath
	}
	parseJSImports(content, filePath, j.lang, fs.Imports, fs.Aux)
	return fs, nil
}

// jsImportNameAuxKey returns the Aux key under which an aliased named
// import records its ORIGINAL exported name. `import {runShell as doRun}`
// stores Aux["jsimportname:doRun"] = "runShell" so ResolveCall can look
// up "runShell" (the name the target file actually declares) rather than
// the local alias "doRun" (which has no node in the target). Only aliased
// imports get an entry — unaliased binds resolve under their own name.
func jsImportNameAuxKey(alias string) string {
	return "jsimportname:" + alias
}

// parseJSImports walks a JS/TS file's import / require statements and
// populates the imports map with alias → resolved absolute file path
// entries. Specifiers that don't resolve to an on-disk file (bare
// specifiers like "react", unresolvable relative paths) are skipped.
//
// We parse the JS file using tree-sitter for robustness against the
// many import shapes; the LangJavaScript grammar handles TS source
// well enough for *import statements* (the type-only import syntax
// `import type { X }` parses fine too).
func parseJSImports(content []byte, filePath string, lang rules.Language, imports, aux map[string]string) {
	tree := tsast.ParseFile(content, lang, filePath)
	if tree == nil || tree.Root() == nil {
		return
	}
	fileDir := filepath.Dir(filePath)
	if !filepath.IsAbs(fileDir) {
		if cwd, err := os.Getwd(); err == nil {
			fileDir = filepath.Join(cwd, fileDir)
		}
	}

	// TypeScript path aliases: discover the nearest tsconfig.json's
	// compilerOptions.paths once per file (cached per directory). nil
	// when there's no tsconfig — resolveJSSpecifier then behaves exactly
	// as before.
	aliases := aliasTableForDir(fileDir)

	root := tree.Root()
	for i := 0; i < root.ChildCount(); i++ {
		stmt := root.Child(i)
		switch stmt.Type() {
		case "import_statement":
			collectESMImport(stmt, fileDir, imports, aux, aliases)
		case "lexical_declaration", "variable_declaration":
			// `const x = require(...)` lives inside a lexical_declaration.
			collectCJSRequires(stmt, fileDir, imports, aliases)
		case "export_statement":
			// Barrel re-export: `export {f} from './impl'` /
			// `export {f as g} from './impl'` / `export * from './impl'`.
			collectESMReExport(stmt, fileDir, aux, aliases)
		case "expression_statement":
			// `require('./side-effect')` at top level — no alias. Also the
			// CJS barrel form `module.exports = require('./impl')`, which we
			// record as a wildcard re-export.
			collectCJSReExport(stmt, fileDir, aux, aliases)
		}
	}
}

// collectESMImport parses one `import` statement and populates imports.
// Shapes handled:
//
//	import X from './foo'             — default import
//	import {Y, Z as W} from './foo'   — named imports (with alias)
//	import * as ns from './foo'       — namespace import
//	import './foo'                    — side-effect import (no aliases)
func collectESMImport(stmt *tsast.Node, fileDir string, imports, aux map[string]string, aliases *jsAliasTable) {
	// The module specifier is the `source` field, a string literal.
	source := stmt.ChildByFieldName("source")
	if source == nil {
		return
	}
	specifier := jsTrimStringLiteral(source.Text())
	if specifier == "" {
		return
	}
	target := resolveJSSpecifier(fileDir, specifier, aliases)
	if target == "" {
		// Bare specifier (node_modules) or unresolvable relative path —
		// skip. The cross-file resolver will treat unresolved aliases
		// as "no opinion".
		return
	}

	// Walk the import_clause to extract aliases. Two top-level shapes:
	//   - default import: identifier directly under import_statement
	//     (older grammars emit this as a named child).
	//   - import_clause: contains the structured forms below.
	for _, child := range stmt.NamedChildren() {
		switch child.Type() {
		case "identifier":
			// `import X from './foo'` — default import, X is the alias.
			alias := strings.TrimSpace(child.Text())
			if alias != "" {
				imports[alias] = target
			}
		case "import_clause":
			collectImportClauseEntries(child, target, imports, aux)
		}
	}
}

// collectImportClauseEntries handles the body of an `import_clause`
// node, which contains default / namespace / named import shapes.
func collectImportClauseEntries(clause *tsast.Node, target string, imports, aux map[string]string) {
	for _, child := range clause.NamedChildren() {
		switch child.Type() {
		case "identifier":
			// Default binding inside the clause:
			//   `import X, {Y} from './foo'`
			alias := strings.TrimSpace(child.Text())
			if alias != "" {
				imports[alias] = target
			}
		case "namespace_import":
			// `import * as ns from './foo'`
			for _, c := range child.NamedChildren() {
				if c.Type() == "identifier" {
					alias := strings.TrimSpace(c.Text())
					if alias != "" {
						imports[alias] = target
					}
				}
			}
		case "named_imports":
			// `import {a, b as c} from './foo'`
			for _, spec := range child.NamedChildren() {
				if spec.Type() != "import_specifier" {
					continue
				}
				name := nodeFieldText(spec, "name")
				alias := nodeFieldText(spec, "alias")
				bind := alias
				if bind == "" {
					bind = name
				}
				if bind != "" {
					imports[bind] = target
				}
				// Aliased named import (`b as c`): record the ORIGINAL
				// exported name so ResolveCall can look up `b` (the node the
				// target file declares) instead of the local alias `c`
				// (which has no node there). Unaliased imports bind under
				// their own name and need no entry.
				if alias != "" && name != "" && alias != name && aux != nil {
					aux[jsImportNameAuxKey(alias)] = name
				}
			}
		}
	}
}

// collectCJSRequires walks a `const x = require(...)` declaration and
// extracts the binding(s). Handles:
//
//	const x = require('./baz')
//	const {y, z: w} = require('./baz')
//	const y = require('./baz').sub
func collectCJSRequires(decl *tsast.Node, fileDir string, imports map[string]string, aliases *jsAliasTable) {
	for _, child := range decl.NamedChildren() {
		if child.Type() != "variable_declarator" {
			continue
		}
		val := child.ChildByFieldName("value")
		if val == nil {
			continue
		}
		// Drill through `require('./x').sub` — the outer node is a
		// member_expression whose object is the call_expression.
		callExpr := val
		if val.Type() == "member_expression" {
			if obj := val.ChildByFieldName("object"); obj != nil {
				callExpr = obj
			}
		}
		if callExpr.Type() != "call_expression" {
			continue
		}
		fn := callExpr.ChildByFieldName("function")
		if fn == nil || strings.TrimSpace(fn.Text()) != "require" {
			continue
		}
		args := callExpr.ChildByFieldName("arguments")
		if args == nil {
			continue
		}
		var specifier string
		for k := 0; k < args.ChildCount(); k++ {
			a := args.Child(k)
			if a != nil && a.IsNamed() && a.Type() == "string" {
				specifier = jsTrimStringLiteral(a.Text())
				break
			}
		}
		if specifier == "" {
			continue
		}
		target := resolveJSSpecifier(fileDir, specifier, aliases)
		if target == "" {
			continue
		}
		// Bind LHS aliases.
		name := child.ChildByFieldName("name")
		if name == nil {
			continue
		}
		switch name.Type() {
		case "identifier":
			alias := strings.TrimSpace(name.Text())
			if alias != "" {
				imports[alias] = target
			}
		case "object_pattern":
			// `const {y, z: w} = require('./x')`
			for _, p := range name.NamedChildren() {
				switch p.Type() {
				case "shorthand_property_identifier_pattern", "shorthand_property_identifier":
					alias := strings.TrimSpace(p.Text())
					if alias != "" {
						imports[alias] = target
					}
				case "pair_pattern":
					// `z: w` — key is `z`, value is `w` (the alias).
					val := p.ChildByFieldName("value")
					if val != nil && val.Type() == "identifier" {
						alias := strings.TrimSpace(val.Text())
						if alias != "" {
							imports[alias] = target
						}
					}
				}
			}
		}
	}
}

// jsReExportAuxPrefix is the Aux key prefix under which a barrel file's
// re-exports are recorded during ExtractScope. The cross-file dispatcher
// (collectJSReExports) reads these back into PackageIndex.JSReExports.
// The value is "<leafFile>\x00<leafName>" — leafName "*" marks a wildcard
// (`export * from`) / CJS whole-module re-export.
const jsReExportAuxPrefix = "jsreexport:"

// jsReExportWildcard is the inner-key sentinel for `export * from './x'`
// and `module.exports = require('./x')` — re-exports where the leaf NAME
// isn't known at the barrel, only the leaf FILE. ResolveCall falls back
// to it when no named entry matches: the requested name is looked up in
// the wildcard leaf file directly.
const jsReExportWildcard = "*"

// collectESMReExport records `export {f} from './impl'` and
// `export {f as g} from './impl'` re-exports into aux. The barrel exposes
// `g` (or `f` when unaliased) as an alias for the LEAF symbol `f` defined
// in './impl'. `export * from './impl'` is recorded under the wildcard
// sentinel so the leaf file is searched directly at resolve time.
func collectESMReExport(stmt *tsast.Node, fileDir string, aux map[string]string, aliases *jsAliasTable) {
	if aux == nil {
		return
	}
	source := stmt.ChildByFieldName("source")
	if source == nil {
		// Not a re-export — a plain `export function f(){}` has no source.
		return
	}
	specifier := jsTrimStringLiteral(source.Text())
	if specifier == "" {
		return
	}
	leafFile := resolveJSSpecifier(fileDir, specifier, aliases)
	if leafFile == "" {
		// Bare/extern re-export target — nothing in-project to point at.
		return
	}
	hasClause := false
	for _, child := range stmt.NamedChildren() {
		if child.Type() != "export_clause" {
			continue
		}
		hasClause = true
		for _, spec := range child.NamedChildren() {
			if spec.Type() != "export_specifier" {
				continue
			}
			name := nodeFieldText(spec, "name")
			alias := nodeFieldText(spec, "alias")
			exposed := alias
			if exposed == "" {
				exposed = name
			}
			if exposed == "" || name == "" {
				continue
			}
			// The barrel exposes `exposed`; it maps to leaf symbol `name`
			// in leafFile.
			aux[jsReExportAuxPrefix+exposed] = leafFile + "\x00" + name
		}
	}
	if !hasClause {
		// `export * from './impl'` — wildcard: leaf names unknown here.
		aux[jsReExportAuxPrefix+jsReExportWildcard] = leafFile + "\x00" + jsReExportWildcard
	}
}

// collectCJSReExport records the CommonJS whole-module barrel form
// `module.exports = require('./impl')`. This re-exports everything from
// './impl' under the barrel, so we register a wildcard entry pointing at
// the leaf file. Other expression statements (plain `require('./x')`
// side-effect imports, arbitrary calls) are ignored.
func collectCJSReExport(stmt *tsast.Node, fileDir string, aux map[string]string, aliases *jsAliasTable) {
	if aux == nil {
		return
	}
	var assign *tsast.Node
	for _, c := range stmt.NamedChildren() {
		if c.Type() == "assignment_expression" {
			assign = c
			break
		}
	}
	if assign == nil {
		return
	}
	lhs := assign.ChildByFieldName("left")
	rhs := assign.ChildByFieldName("right")
	if lhs == nil || rhs == nil {
		return
	}
	// LHS must be `module.exports` or `exports`.
	lhsText := strings.TrimSpace(lhs.Text())
	if lhsText != "module.exports" && lhsText != "exports" {
		return
	}
	// RHS must be `require('./impl')`.
	if rhs.Type() != "call_expression" {
		return
	}
	fn := rhs.ChildByFieldName("function")
	if fn == nil || strings.TrimSpace(fn.Text()) != "require" {
		return
	}
	args := rhs.ChildByFieldName("arguments")
	if args == nil {
		return
	}
	var specifier string
	for k := 0; k < args.ChildCount(); k++ {
		a := args.Child(k)
		if a != nil && a.IsNamed() && a.Type() == "string" {
			specifier = jsTrimStringLiteral(a.Text())
			break
		}
	}
	if specifier == "" {
		return
	}
	leafFile := resolveJSSpecifier(fileDir, specifier, aliases)
	if leafFile == "" {
		return
	}
	aux[jsReExportAuxPrefix+jsReExportWildcard] = leafFile + "\x00" + jsReExportWildcard
}

// jsTrimStringLiteral strips the surrounding quotes from a tree-sitter
// string node's text. Returns "" if the text isn't quoted (defensive).
func jsTrimStringLiteral(text string) string {
	text = strings.TrimSpace(text)
	if len(text) < 2 {
		return ""
	}
	first := text[0]
	last := text[len(text)-1]
	if (first == '"' || first == '\'' || first == '`') && first == last {
		return text[1 : len(text)-1]
	}
	return ""
}

// resolveJSSpecifier resolves a module specifier to an absolute file path
// on disk. Returns "" when the specifier is a bare module name (not
// `./` or `../`) or when no on-disk file matches the extension fallback
// chain. fileDir is the directory of the importing file (absolute).
func resolveJSSpecifier(fileDir, specifier string, aliases *jsAliasTable) string {
	if specifier == "" {
		return ""
	}

	// TypeScript path aliases: before treating a non-relative specifier as
	// a bare npm package, check whether it matches a DECLARED tsconfig
	// `paths` alias. Only declared aliases are rewritten — npm-scoped
	// specifiers (@nestjs/common, @prisma/client) that match no `paths`
	// key fall through to the bare-specifier return below and stay extern.
	if !strings.HasPrefix(specifier, "./") && !strings.HasPrefix(specifier, "../") {
		for _, cand := range aliases.resolveAlias(specifier) {
			// cand is an absolute, extension-less (or directory) path under
			// baseUrl. Reuse the same extension-fallback chain the relative
			// path takes by resolving it from its own directory.
			if resolved := resolveJSAbsCandidate(cand); resolved != "" {
				return resolved
			}
		}
	}

	// Only relative paths. Bare specifiers (`react`, `@scope/x`, `lodash`)
	// fall through to node_modules in real Node resolution — out of scope.
	if !strings.HasPrefix(specifier, "./") && !strings.HasPrefix(specifier, "../") {
		return ""
	}

	base := filepath.Join(fileDir, specifier)
	return resolveJSBasePath(base, specifier)
}

// resolveJSBasePath applies the extension-fallback and index-file chain to
// an absolute base path. `specifier` is the original specifier text, used
// only to decide whether it already carried an extension (so we don't
// double-append). Shared by the relative-path and tsconfig-alias
// resolution paths so both honour the identical resolution order.
func resolveJSBasePath(base, specifier string) string {
	// If the specifier already has one of our recognized extensions,
	// use it as-is. (We still stat the result so a non-existent file
	// returns "" rather than a phantom path.)
	for _, ext := range jsResolveExtensionsInOrder {
		if strings.HasSuffix(specifier, ext) {
			if info, err := os.Stat(base); err == nil && !info.IsDir() {
				abs, _ := filepath.Abs(base)
				return abs
			}
			return ""
		}
	}
	// Other known but non-fallback extensions (`.json`, `.css`, …) —
	// accept the file if it exists. We don't try every weird extension;
	// this keeps the resolver focused on source-code modules.
	if ext := filepath.Ext(specifier); ext != "" && ext != "." {
		if info, err := os.Stat(base); err == nil && !info.IsDir() {
			abs, _ := filepath.Abs(base)
			return abs
		}
		// Non-source extension that doesn't exist on disk — drop it.
		return ""
	}

	// Extension-less: try the source-file fallbacks in order, then the
	// directory-with-index variants.
	for _, ext := range jsResolveExtensionsInOrder {
		candidate := base + ext
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			abs, _ := filepath.Abs(candidate)
			return abs
		}
	}
	for _, idx := range jsIndexFilenames {
		candidate := filepath.Join(base, idx)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			abs, _ := filepath.Abs(candidate)
			return abs
		}
	}
	return ""
}

// resolveJSAbsCandidate resolves an absolute candidate path produced by a
// tsconfig-alias substitution. The candidate carries the wildcard tail
// from the specifier (e.g. ".../services/runner"), which may or may not
// already have a source extension — so we delegate to resolveJSBasePath
// with the candidate's own basename as the "specifier" for the extension
// check.
func resolveJSAbsCandidate(cand string) string {
	if cand == "" {
		return ""
	}
	return resolveJSBasePath(cand, filepath.Base(cand))
}

// ResolveCall resolves a JS/TS call expression to a FuncNode ID.
//
// callee is one of:
//
//	"foo"        — bare name. Possibly an imported default/named binding
//	               or a local def in the same file. The same-file pass
//	               already handles the local case; here we only act when
//	               "foo" is in scope.Imports.
//
//	"alias.bar"  — attribute call. "alias" may be:
//	                 - a namespace-import alias (`import * as alias`),
//	                   in which case we look up "bar" inside the module
//	                   alias points to.
//	                 - a default-import alias for a module whose default
//	                   export is an object/class; "bar" is a method on it.
//	                   Without type inference we can't distinguish these,
//	                   so we route both shapes the same way.
//	                 - an unrelated local — not in scope.Imports → return
//	                   "no opinion" so the framework drops it.
func (j *jsResolver) ResolveCall(callee string, scope FileScope, modulePath string, idx *PackageIndex) ResolveResult {
	if callee == "" {
		return ResolveResult{}
	}
	dot := strings.Index(callee, ".")

	if dot < 0 {
		// Bare name. Resolve only when it's in the import index — local
		// defs are handled by the same-file builder pass.
		target, ok := scope.Imports[callee]
		if !ok {
			return ResolveResult{}
		}
		// Aliased named import (`import {runShell as doRun}`): the target
		// file declares `runShell`, not the local alias `doRun`. Look up
		// the ORIGINAL exported name recorded in Aux during scope
		// extraction, falling back to the alias when there's no rename.
		lookupName := callee
		if scope.Aux != nil {
			if orig, ok := scope.Aux[jsImportNameAuxKey(callee)]; ok && orig != "" {
				lookupName = orig
			}
		}
		// Find a node in the target file named `lookupName` (default-import
		// case: the import binds to whatever the module's default export
		// is named, which may be "default" or the export's own name).
		if id, hit := resolveJSNodeID(target, lookupName, idx); hit {
			return ResolveResult{TargetID: id, Confidence: 0.85}
		}
		// Default export anchor: try "default" too, since `export default
		// function () {}` lives under that key.
		if id, hit := resolveJSNodeID(target, "default", idx); hit {
			return ResolveResult{TargetID: id, Confidence: 0.85}
		}
		// Barrel re-export hop: the import landed on a barrel file
		// (`index.js` with `export {runShell} from './impl'`) that defines
		// no node named `lookupName` — the symbol lives in the leaf file.
		// Follow exactly ONE hop through the re-export index. The barrel
		// may expose the symbol under an alias (`export {f as g}`); the
		// index stores the leaf's own name to look up.
		if id, hit := followJSReExport(target, lookupName, idx); hit {
			return ResolveResult{TargetID: id, Confidence: 0.85}
		}
		// In-project file but the name didn't match a known node — leave
		// it for the framework's UnresolvedCalls filter to handle.
		return ResolveResult{}
	}

	alias := callee[:dot]
	rest := callee[dot+1:]
	if alias == "" || rest == "" {
		return ResolveResult{}
	}
	target, ok := scope.Imports[alias]
	if !ok {
		// Unknown receiver — not an import alias. Could be `this.method`,
		// `req.body`, or any local-variable method call. Return "no
		// opinion"; the dispatcher already filters these out.
		return ResolveResult{}
	}
	if id, hit := resolveJSNodeID(target, rest, idx); hit {
		return ResolveResult{TargetID: id, Confidence: 0.85}
	}
	return ResolveResult{}
}

// resolveJSNodeID looks up a function named `name` inside the file
// `filePath` via the PackageIndex (which is keyed by absolute file path
// for JS/TS). Returns the FuncNode ID and true on hit, ("", false)
// otherwise.
//
// We accept both an exact name match (`handler`) and a class-method-style
// suffix match (`Cls.handler`) so calls like `import {handler} from './x'
// → handler()` find a class method named "Foo.handler" in the target
// file as well.
//
// Match precedence (mirrors the Java / PHP exact-first two-pass):
//  1. Exact `name` — a free function `handler` must win over a method
//     `Cls.handler` when both live in the file (first-hit order would
//     otherwise mis-bind, order-dependently).
//  2. Suffix `.<name>` — class-method fallback when no free function
//     with that name exists.
func resolveJSNodeID(filePath, name string, idx *PackageIndex) (string, bool) {
	if idx == nil || filePath == "" || name == "" {
		return "", false
	}
	cands := idx.Lookup(filePath)
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

// followJSReExport follows ONE barrel re-export hop. When `barrelFile`
// has a re-export table and it forwards `name` to a leaf file, resolve
// the leaf symbol there. Mirrors followPythonReExport's single-hop
// semantics: we do not chase barrel → barrel → leaf chains.
//
// Two table shapes:
//   - Named: `export {runShell} from './impl'` records
//     {LeafFile: impl, LeafName: "runShell"}. The leaf's own name may
//     differ from the exposed name when aliased (`export {f as g}`).
//   - Wildcard: `export * from './impl'` / `module.exports =
//     require('./impl')` records LeafName "*". The requested `name` is
//     looked up in the leaf file directly.
func followJSReExport(barrelFile, name string, idx *PackageIndex) (string, bool) {
	if idx == nil || len(idx.JSReExports) == 0 || barrelFile == "" || name == "" {
		return "", false
	}
	table, ok := idx.JSReExports[barrelFile]
	if !ok {
		return "", false
	}
	// Named re-export of exactly this symbol.
	if re, ok := table[name]; ok && re.LeafFile != "" && re.LeafFile != barrelFile {
		leafName := re.LeafName
		if leafName == "" || leafName == jsReExportWildcard {
			leafName = name
		}
		if id, hit := resolveJSNodeID(re.LeafFile, leafName, idx); hit {
			return id, true
		}
		// Leaf may itself default-export the symbol.
		if id, hit := resolveJSNodeID(re.LeafFile, "default", idx); hit {
			return id, true
		}
	}
	// Wildcard re-export: search the leaf file for the requested name.
	if re, ok := table[jsReExportWildcard]; ok && re.LeafFile != "" && re.LeafFile != barrelFile {
		if id, hit := resolveJSNodeID(re.LeafFile, name, idx); hit {
			return id, true
		}
	}
	return "", false
}

// Per-language adapter: PHP.
//
// Implements LanguageResolver for cross-file PHP call resolution. PHP
// combines Java-style namespaces (every class has an FQN composed of
// `namespace App\Foo; class Bar` → "App\Foo\Bar") with a Composer-based
// autoload mechanism that maps namespace prefixes to filesystem dirs.
//
// Scope of this initial implementation:
//
//   - Composer PSR-4 autoload mapping. When a `composer.json` lives at the
//     module root and declares `autoload.psr-4`, those mappings drive
//     namespace-to-directory resolution exactly as Composer's autoloader
//     does at runtime. The most common dev-only mapping under
//     `autoload-dev.psr-4` is also consulted so test-only namespaces
//     resolve correctly when their files appear in the scan.
//
//   - Sensible defaults when composer.json is absent or doesn't include a
//     mapping. Two conventions dominate real-world repos:
//       Laravel : `App\` → `app/`
//       Symfony : `App\` → `src/`
//     Both fallbacks are tried in turn.
//
//   - `use` statements with optional aliases and grouped form
//     (`use App\Util\{Helper, Logger as L};`). Resolution: each alias →
//     absolute path of the .php file declaring that class.
//
//   - `require_once __DIR__ . '/../foo.php'` and similar `__DIR__`-anchored
//     includes are resolved relative to the importing file's directory.
//     Their files don't introduce names into scope (PHP `require` evaluates
//     a script, doesn't import a symbol) but the framework records them
//     in StarImports for downstream consumers.
//
//   - Standard library and dominant framework prefixes are externs:
//     `\PDO`, `\Exception`, etc. resolve to extern.
//
// Known limitations (deliberate scope cuts for this PR):
//
//   - Composer `classmap` and `files` autoload entries: not parsed.
//   - Vendor / `vendor/` autoload (third-party libs): out of scope.
//   - Composer namespace prefix conflicts: when multiple mappings could
//     match, we use the longest matching prefix (matches Composer behaviour).
//   - `require 'foo.php';` without `__DIR__`: ambiguous; we try same-dir
//     first, then a single walk-up pass. No `include_path` resolution.
//   - Anonymous classes inside `new class { ... }`: not resolved cross-file
//     (they're per-file).
//   - Trait `use TraitName;` does NOT re-route method calls — only the
//     class file is consulted. Same gap as Java's static-import.
//   - Multi-namespace files (`namespace A { ... } namespace B { ... }`):
//     only the first namespace is recorded in FileScope.Package.
package graph

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// phpResolver implements LanguageResolver for PHP.
type phpResolver struct{}

func init() {
	RegisterResolver(&phpResolver{})
}

func (p *phpResolver) Language() rules.Language { return rules.LangPHP }

// phpComposerManifest is the canonical manifest filename for PHP projects.
const phpComposerManifest = "composer.json"

// phpManifestFilenames is the precedence-ordered list of project-root
// markers. composer.json is the canonical signal; index.php / src / app
// are last-resort fallbacks for legacy projects that lack a manifest.
var phpManifestFilenames = []string{
	"composer.json",
	"composer.lock",
}

// phpDefaultPSR4Mappings is the ordered list of (namespace prefix →
// directory) fallbacks consulted when composer.json is absent or missing
// an `autoload.psr-4` section. Order matches the relative popularity of
// the two dominant PHP conventions:
//
//   - Laravel: `App\` lives under `app/`.
//   - Symfony: `App\` lives under `src/`.
//
// Both have trailing slashes on the prefix (Composer convention) so prefix
// matching is unambiguous.
var phpDefaultPSR4Mappings = []phpPSR4Entry{
	{Prefix: `App\`, Directory: "app"},
	{Prefix: `App\`, Directory: "src"},
}

// phpBuiltinClasses is the set of well-known PHP root-namespace classes
// the resolver should treat as extern (they don't live in user source).
var phpBuiltinClasses = map[string]bool{
	"PDO":             true,
	"PDOStatement":    true,
	"PDOException":    true,
	"mysqli":          true,
	"mysqli_stmt":     true,
	"mysqli_result":   true,
	"DOMDocument":     true,
	"DOMNode":         true,
	"DOMElement":      true,
	"SimpleXMLElement": true,
	"Exception":       true,
	"Error":           true,
	"Throwable":       true,
	"TypeError":       true,
	"ValueError":      true,
	"RuntimeException": true,
	"InvalidArgumentException": true,
	"LogicException":  true,
	"DateTime":        true,
	"DateTimeImmutable": true,
	"DateInterval":    true,
	"DateTimeZone":    true,
	"ArrayObject":     true,
	"ArrayIterator":   true,
	"SplObjectStorage": true,
	"SplQueue":        true,
	"SplStack":        true,
	"Closure":         true,
	"Generator":       true,
	"Iterator":        true,
	"IteratorAggregate": true,
	"Countable":       true,
	"ArrayAccess":     true,
	"Stringable":      true,
	"JsonSerializable": true,
	"ReflectionClass": true,
	"ReflectionMethod": true,
	"ReflectionFunction": true,
}

// phpPSR4Entry binds a namespace prefix to a directory under module root.
type phpPSR4Entry struct {
	Prefix    string // e.g. `App\` (always trailing backslash)
	Directory string // e.g. `app` or `src/App`
}

// ProjectRoot walks up from scanDir looking for a PHP project manifest.
// composer.json sets ModuleRoot to its own directory.
//
// When no manifest is found we still return ok=true and the scanDir itself
// as the manifest path — script-only PHP repos (small CLI scripts, legacy
// LAMP apps) are common and the resolver should still anchor somewhere.
// The empty modulePath signals "no Composer mapping available; use the
// default PSR-4 fallbacks".
func (p *phpResolver) ProjectRoot(scanDir string) (manifestPath, modulePath string, ok bool) {
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
		for _, manifest := range phpManifestFilenames {
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
	return abs, "", true
}

// findPHPModuleRoot walks up from a file's directory looking for the
// nearest composer.json. Returns the directory containing it, or "" when
// none is found.
func findPHPModuleRoot(fileAbs string) string {
	cur := filepath.Dir(fileAbs)
	for {
		for _, manifest := range phpManifestFilenames {
			candidate := filepath.Join(cur, manifest)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
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

// phpReadPSR4Mappings parses an optional composer.json at moduleRoot and
// returns the PSR-4 mappings declared inside `autoload.psr-4` (and, when
// useDev is true, `autoload-dev.psr-4`).
//
// Mappings are returned in longest-prefix-first order — Composer's
// runtime autoloader does the same so the most-specific prefix wins.
//
// Returns nil when composer.json is absent or has no PSR-4 section, in
// which case the caller should consult phpDefaultPSR4Mappings.
func phpReadPSR4Mappings(moduleRoot string, useDev bool) []phpPSR4Entry {
	if moduleRoot == "" {
		return nil
	}
	path := filepath.Join(moduleRoot, phpComposerManifest)
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	// Cap reads at 256 KB. Real composer.json files are smaller; the cap
	// keeps a runaway file from blocking the resolver.
	const maxBytes = 256 * 1024
	buf := make([]byte, 0, 8192)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(buf, maxBytes)
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		// Read the whole file in one shot — composer.json is tiny.
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		return len(data), data, nil
	})
	var content []byte
	for scanner.Scan() {
		content = append(content, scanner.Bytes()...)
	}
	if len(content) == 0 {
		return nil
	}

	type psr4Section struct {
		PSR4 map[string]json.RawMessage `json:"psr-4,omitempty"`
	}
	type composerFile struct {
		Autoload    psr4Section `json:"autoload,omitempty"`
		AutoloadDev psr4Section `json:"autoload-dev,omitempty"`
	}
	var cf composerFile
	if err := json.Unmarshal(content, &cf); err != nil {
		return nil
	}

	var out []phpPSR4Entry
	collect := func(m map[string]json.RawMessage) {
		for prefix, raw := range m {
			// Each PSR-4 value can be a string OR an array of strings.
			var single string
			if err := json.Unmarshal(raw, &single); err == nil {
				out = append(out, phpPSR4Entry{Prefix: phpNormPSR4Prefix(prefix), Directory: strings.TrimSuffix(strings.TrimSuffix(single, "/"), `\`)})
				continue
			}
			var multi []string
			if err := json.Unmarshal(raw, &multi); err == nil {
				for _, d := range multi {
					out = append(out, phpPSR4Entry{Prefix: phpNormPSR4Prefix(prefix), Directory: strings.TrimSuffix(strings.TrimSuffix(d, "/"), `\`)})
				}
			}
		}
	}
	collect(cf.Autoload.PSR4)
	if useDev {
		collect(cf.AutoloadDev.PSR4)
	}
	// Sort by prefix length descending — longest match wins.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if len(out[j].Prefix) > len(out[i].Prefix) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// phpNormPSR4Prefix normalises a PSR-4 namespace prefix:
//
//	"App\\"        → "App\\"
//	"App\\Foo\\"   → "App\\Foo\\"
//	"App"          → "App\\"  (trailing backslash added)
//
// Composer requires the trailing backslash; we add it defensively for
// hand-written manifests.
func phpNormPSR4Prefix(p string) string {
	if p == "" {
		return p
	}
	if !strings.HasSuffix(p, `\`) {
		return p + `\`
	}
	return p
}

// ExtractScope parses a PHP file's namespace and use declarations into a
// FileScope. The Imports map binds short class names to absolute file
// paths when resolvable, or to their FQN when not (so ResolveCall can
// route the unresolved case to extern).
//
// scope.Package is the file's declared namespace (e.g. "App\Controllers").
// scope.Aux carries "module_root" so ResolveCall can probe sibling files
// in the same namespace without re-walking the filesystem.
func (p *phpResolver) ExtractScope(filePath string, content []byte) (FileScope, error) {
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
	moduleRoot := findPHPModuleRoot(abs)
	if moduleRoot != "" {
		fs.Aux["module_root"] = moduleRoot
	}

	tree := tsast.Parse(content, rules.LangPHP)
	if tree == nil || tree.Root() == nil {
		return fs, nil
	}
	root := tree.Root()

	ns := extractPHPNamespace(root)
	fs.Package = ns

	mappings := phpResolveMappings(moduleRoot)

	for _, c := range root.NamedChildren() {
		switch c.Type() {
		case "namespace_use_declaration":
			collectPHPScopeUse(c, moduleRoot, mappings, fs.Imports)
		case "expression_statement":
			for _, gc := range c.NamedChildren() {
				switch gc.Type() {
				case "require_once_expression", "require_expression",
					"include_once_expression", "include_expression":
					if target := phpResolveRequire(gc, filepath.Dir(abs)); target != "" {
						fs.StarImports = append(fs.StarImports, target)
					}
				}
			}
		}
	}
	return fs, nil
}

// phpResolveMappings returns the PSR-4 mappings to use for a given module
// root: composer.json's mappings when present, else the default Laravel /
// Symfony fallbacks.
func phpResolveMappings(moduleRoot string) []phpPSR4Entry {
	if mappings := phpReadPSR4Mappings(moduleRoot, true); len(mappings) > 0 {
		return mappings
	}
	return phpDefaultPSR4Mappings
}

// collectPHPScopeUse parses one `use` declaration during ExtractScope.
// It mirrors collectPHPUseDeclaration from the extractor but resolves
// each alias to an absolute file path via the mapping list.
func collectPHPScopeUse(n *tsast.Node, moduleRoot string, mappings []phpPSR4Entry, imports map[string]string) {
	var prefix string
	var group *tsast.Node
	for _, c := range n.NamedChildren() {
		switch c.Type() {
		case "namespace_name":
			prefix = strings.TrimSpace(c.Text())
		case "namespace_use_group":
			group = c
		case "namespace_use_clause":
			fqn, alias := parsePHPUseClause(c)
			if fqn == "" {
				continue
			}
			if alias == "" {
				alias = phpShortName(fqn)
			}
			if alias != "" {
				imports[alias] = phpResolveFQNToFileOrFQN(fqn, moduleRoot, mappings)
			}
		}
	}
	if group != nil {
		for _, gc := range group.NamedChildren() {
			if gc.Type() != "namespace_use_group_clause" {
				continue
			}
			suffix, alias := parsePHPUseGroupClause(gc)
			if suffix == "" {
				continue
			}
			fqn := suffix
			if prefix != "" {
				fqn = prefix + `\` + suffix
			}
			if alias == "" {
				alias = phpShortName(suffix)
			}
			if alias != "" {
				imports[alias] = phpResolveFQNToFileOrFQN(fqn, moduleRoot, mappings)
			}
		}
	}
}

// phpResolveFQNToFileOrFQN resolves a PHP FQN to an absolute .php file
// path when on-disk, else returns the FQN itself (so ResolveCall can route
// the call to extern). Built-in classes always return the FQN.
func phpResolveFQNToFileOrFQN(fqn, moduleRoot string, mappings []phpPSR4Entry) string {
	if fqn == "" {
		return ""
	}
	// Strip a leading backslash for normalisation: `\App\Foo` → `App\Foo`.
	norm := strings.TrimPrefix(fqn, `\`)
	if phpIsBuiltinClass(norm) {
		return fqn
	}
	if path := phpResolveFQNToFile(norm, moduleRoot, mappings); path != "" {
		return path
	}
	return fqn
}

// phpResolveFQNToFile attempts to locate the .php file declaring the
// fully-qualified name `fqn` (no leading backslash) under moduleRoot. The
// mappings list is consulted longest-prefix-first; the first match whose
// resolved path exists on disk wins.
//
// For `App\Foo\Bar`:
//   - With mapping `App\` → `src/App`, look for moduleRoot/src/App/Foo/Bar.php
//   - With mapping `App\` → `app/`, look for moduleRoot/app/Foo/Bar.php
//
// Returns the absolute path when found, "" otherwise.
func phpResolveFQNToFile(fqn, moduleRoot string, mappings []phpPSR4Entry) string {
	if moduleRoot == "" || fqn == "" {
		return ""
	}
	for _, m := range mappings {
		if !strings.HasPrefix(fqn, m.Prefix) {
			continue
		}
		// Strip the prefix; the remaining path components map to directories.
		rel := strings.TrimPrefix(fqn, m.Prefix)
		rel = strings.ReplaceAll(rel, `\`, "/")
		base := m.Directory
		// PSR-4 directories are relative to module root.
		candidate := filepath.Join(moduleRoot, base, filepath.FromSlash(rel+".php"))
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			abs, err := filepath.Abs(candidate)
			if err != nil {
				return candidate
			}
			return abs
		}
	}
	return ""
}

// phpResolveRequire resolves a require/include expression to an absolute
// file path on disk, or "" when the path can't be pinned. Recognises:
//
//	require_once __DIR__ . '/../foo.php'  → fileDir + "/../foo.php"
//	require '/abs/path.php'                → absolute path (returned if exists)
//	require 'foo.php'                      → same-dir, then walk up once
//
// The expression text is parsed by walking the AST: we look for a binary
// expression whose left side is `__DIR__` and right side is a string,
// or a bare string argument.
func phpResolveRequire(expr *tsast.Node, fileDir string) string {
	if expr == nil {
		return ""
	}
	// Inspect children to find either a binary_expression (__DIR__ + str)
	// or a bare string argument.
	for _, c := range expr.NamedChildren() {
		switch c.Type() {
		case "string":
			literal := phpTrimStringLiteral(c.Text())
			if literal == "" {
				return ""
			}
			return phpResolveRequirePath(literal, fileDir)
		case "binary_expression":
			// `__DIR__ . '/foo.php'` (or `__DIR__ . '/../foo.php'`).
			path := phpResolveDirConcat(c, fileDir)
			if path != "" {
				return path
			}
		}
	}
	return ""
}

// phpResolveDirConcat handles `__DIR__ . '<suffix>'` style require args.
// Returns the absolute resolved path when both operands fit the pattern.
func phpResolveDirConcat(bin *tsast.Node, fileDir string) string {
	left := bin.ChildByFieldName("left")
	right := bin.ChildByFieldName("right")
	if left == nil || right == nil {
		return ""
	}
	leftText := strings.TrimSpace(left.Text())
	if leftText != "__DIR__" {
		return ""
	}
	if right.Type() != "string" {
		return ""
	}
	suffix := phpTrimStringLiteral(right.Text())
	if suffix == "" {
		return ""
	}
	// __DIR__ expands to the importing file's directory.
	candidate := filepath.Join(fileDir, suffix)
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		abs, err := filepath.Abs(candidate)
		if err != nil {
			return candidate
		}
		return abs
	}
	return ""
}

// phpResolveRequirePath resolves a bare-string require/include argument.
// Absolute paths are accepted as-is when the file exists; relative paths
// are tried in the importing file's dir first, then a single parent walk-up.
func phpResolveRequirePath(literal, fileDir string) string {
	if filepath.IsAbs(literal) {
		if info, err := os.Stat(literal); err == nil && !info.IsDir() {
			return literal
		}
		return ""
	}
	candidate := filepath.Join(fileDir, literal)
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		abs, _ := filepath.Abs(candidate)
		return abs
	}
	// One parent walk-up; some legacy code does `require 'config.php';`
	// expecting it to live up the tree.
	parent := filepath.Dir(fileDir)
	if parent != fileDir {
		candidate := filepath.Join(parent, literal)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			abs, _ := filepath.Abs(candidate)
			return abs
		}
	}
	return ""
}

// phpTrimStringLiteral strips quotes from a PHP string literal (single
// or double quoted). Heredoc / nowdoc are not handled — those use a
// different node type (encapsed_string / heredoc) which we ignore.
func phpTrimStringLiteral(text string) string {
	text = strings.TrimSpace(text)
	if len(text) < 2 {
		return ""
	}
	first := text[0]
	last := text[len(text)-1]
	if (first == '"' || first == '\'') && first == last {
		return text[1 : len(text)-1]
	}
	return ""
}

// phpIsBuiltinClass reports whether `fqn` (no leading backslash) names a
// PHP built-in class that's not part of user source.
func phpIsBuiltinClass(fqn string) bool {
	// Only root-namespace names can be PHP builtins.
	if strings.Contains(fqn, `\`) {
		return false
	}
	return phpBuiltinClasses[fqn]
}

// ResolveCall resolves a PHP call expression to a FuncNode ID, an extern
// symbol, or "no opinion".
//
// callee is one of:
//
//	"foo"               — bare function name. Bare-name calls usually
//	                       refer to a global or namespace-local function;
//	                       try the imports table and the same-namespace
//	                       neighbour file.
//	"Alias::bar"        — static call on an imported class. Look up Alias
//	                       in scope.Imports.
//	"Alias.bar"         — instance method (the builder normalises
//	                       `$obj->bar()` to "<obj-or-class>.bar"). When
//	                       Alias is an import alias, resolve to that file.
//	"\\Foo\\Bar::baz"   — fully-qualified call. Try direct file resolution.
func (p *phpResolver) ResolveCall(callee string, scope FileScope, modulePath string, idx *PackageIndex) ResolveResult {
	if callee == "" {
		return ResolveResult{}
	}

	// PHP uses both `::` (static / scoped) and `.` (the builder uses `.`
	// for member calls so the cross-file framework's split logic works
	// across languages). Normalise so we can split on either.
	sep := "::"
	if !strings.Contains(callee, sep) {
		sep = "."
	}
	idxSep := strings.Index(callee, sep)

	// Bare-name callee.
	if idxSep < 0 {
		// Imported function name: `use function App\Helpers\foo;`
		if target, ok := scope.Imports[callee]; ok {
			if filepath.IsAbs(target) {
				if id, hit := resolvePHPNodeID(target, "", callee, idx); hit {
					return ResolveResult{TargetID: id, Confidence: 0.85}
				}
				return ResolveResult{}
			}
			return ResolveResult{Extern: target, Confidence: 0.85}
		}
		// Same-namespace neighbour file? Probe `<nsDir>/<callee>.php`.
		if id, hit := p.resolveSameNamespace(callee, callee, scope, idx); hit {
			return ResolveResult{TargetID: id, Confidence: 0.85}
		}
		return ResolveResult{}
	}

	alias := callee[:idxSep]
	rest := callee[idxSep+len(sep):]
	if alias == "" || rest == "" {
		return ResolveResult{}
	}

	// Strip a leading backslash from the alias for FQN-style calls.
	alias = strings.TrimPrefix(alias, `\`)

	if target, ok := scope.Imports[alias]; ok {
		if filepath.IsAbs(target) {
			// Target is a resolved file path. Find the matching node by
			// looking for "<alias>::<rest>" (qualified) or any node whose
			// name ends with "::<rest>".
			if id, hit := resolvePHPNodeID(target, alias, rest, idx); hit {
				return ResolveResult{TargetID: id, Confidence: 0.85}
			}
			return ResolveResult{}
		}
		return ResolveResult{Extern: target + "::" + rest, Confidence: 0.85}
	}

	// Same-namespace class call without an explicit use.
	if id, hit := p.resolveSameNamespace(alias, rest, scope, idx); hit {
		return ResolveResult{TargetID: id, Confidence: 0.85}
	}

	return ResolveResult{}
}

// resolveSameNamespace handles two cases:
//
//   - bareName == method: a bare function call to a same-namespace function.
//     We probe for a sibling file holding the function (rare in modern PHP
//     but legal — `function helper() {}` next to the caller).
//   - bareName != method (className, method): a class call like
//     `Helper::greet()` where Helper lives in the same namespace and isn't
//     explicitly imported. Probe `<nsDir>/<Helper>.php`.
//
// nsDir is derived from the file's namespace + the file's module root via
// the PSR-4 mappings.
func (p *phpResolver) resolveSameNamespace(alias, method string, scope FileScope, idx *PackageIndex) (string, bool) {
	moduleRoot := scope.Aux["module_root"]
	if moduleRoot == "" || scope.Package == "" {
		return "", false
	}
	mappings := phpResolveMappings(moduleRoot)
	// Resolve the namespace + class to a candidate file path.
	candidateFQN := scope.Package + `\` + alias
	if path := phpResolveFQNToFile(candidateFQN, moduleRoot, mappings); path != "" {
		return resolvePHPNodeID(path, alias, method, idx)
	}
	return "", false
}

// resolvePHPNodeID looks up a method (or function) named `method` inside
// `filePath` via the PackageIndex. className is used to prefer
// `<className>::<method>` over a bare match when both exist.
//
// PackageIndex for PHP is keyed by absolute file path (mirrors Java/JS).
func resolvePHPNodeID(filePath, className, method string, idx *PackageIndex) (string, bool) {
	if idx == nil || filePath == "" || method == "" {
		return "", false
	}
	cands := idx.Lookup(filePath)
	// First pass: prefer exact "<...>\\className::method" or "::method"
	// where the class component matches.
	if className != "" {
		for _, candID := range cands {
			colon := strings.LastIndexByte(candID, ':')
			if colon < 0 {
				continue
			}
			fnPart := candID[colon+1:]
			// fnPart looks like "App\\Foo\\Cls::method" or just "App\\Foo\\func".
			if strings.HasSuffix(fnPart, `\`+className+"::"+method) ||
				fnPart == className+"::"+method {
				return candID, true
			}
		}
	}
	// Second pass: any node whose name ends with "::method" or equals
	// method (top-level function).
	for _, candID := range cands {
		colon := strings.LastIndexByte(candID, ':')
		if colon < 0 {
			continue
		}
		fnPart := candID[colon+1:]
		if fnPart == method || strings.HasSuffix(fnPart, "::"+method) {
			return candID, true
		}
		// Namespace-qualified top-level function: "App\\Helpers\\format_url"
		// matches a bare-name call to "format_url".
		if strings.HasSuffix(fnPart, `\`+method) {
			return candID, true
		}
	}
	return "", false
}

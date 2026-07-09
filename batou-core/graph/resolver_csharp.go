// Per-language adapter: C#.
//
// Implements LanguageResolver for cross-file C# call resolution. Like the
// Java resolver this is the namespace+using analog, but C# does NOT
// enforce a file=directory layout (a `namespace MyApp.Helpers` class can
// live in any .cs file anywhere under the project), so unlike Java we do
// NOT disk-probe `<pkgDir>/Type.cs`. Instead PackageIndex is keyed on the
// absolute file path of each .cs file (importPathForNode returns
// node.FilePath) and same-namespace resolution scans the index for nodes
// whose owning file declares the caller's namespace.
//
// Resolution ranking (callee "Helper.GetName"):
//
//  1. SAME-NAMESPACE, no `using` — `Helper` is a class declared in a
//     sibling .cs file whose `namespace` matches the caller's. C# makes
//     same-namespace types visible without an import, so we scan the
//     project-wide node index for "Helper.GetName" (exact) / ".GetName"
//     (suffix) in any file whose Package == the caller's namespace. This
//     is the v1 milestone shape.
//  2. EXPLICIT `using Namespace;` then `Type.Method()` — ExtractScope
//     records each `using X.Y.Z;` into StarImports; ResolveCall scans the
//     index for the node in any file declaring a used namespace.
//  3. FULLY-QUALIFIED `MyApp.Helpers.Helper.GetName()` — collapsed to the
//     last two segments "Helper.GetName" and resolved as (1)/(2).
//  4. EXTERN — System.* / Microsoft.* / Newtonsoft.* etc. are treated as
//     out-of-source and routed to ExternCalls.
//
// Known limitations (documented follow-ups, mirroring the Java cuts):
//   - `using static Type;` member binding (bare-name static calls).
//   - partial classes split across files (each part still indexes its own
//     methods, so suffix match across both files works; the cut is
//     resolving an instance through a field whose type is the partial).
//   - csproj <ProjectReference> cross-project resolution.
//   - DI / interface dispatch (field.Method() where field's declared type
//     is a service interface) — the Java resolveInterfaceFieldCall analog
//     is a later PR.
//   - multi-hop relay (A→B→C) — 1-hop only.
package graph

import (
	"os"
	"path/filepath"
	"strings"

	tsast "github.com/turenlabs/batou-core/ast"
	"github.com/turenlabs/batou-rules/rules"
)

// csharpResolver implements LanguageResolver for C#.
type csharpResolver struct{}

func init() {
	RegisterResolver(&csharpResolver{})
}

// Language reports that this resolver handles C#.
func (c *csharpResolver) Language() rules.Language { return rules.LangCSharp }

// csharpManifestFilenames are the build manifests / markers that identify
// a C# project root. .csproj / .sln are matched by suffix (the filename
// varies per project) and handled separately in the walk.
var csharpManifestFilenames = []string{
	"global.json",
	"Directory.Build.props",
	"nuget.config",
	"NuGet.config",
}

// csharpExternPrefixes lists namespace prefixes the resolver treats as
// out-of-source (BCL + dominant framework / library roots). Calls into
// these resolve to ExternCalls rather than in-project edges. Mirrors
// javaExternPrefixes — intentionally short; adding a prefix removes
// cross-file resolution for it.
var csharpExternPrefixes = []string{
	"System.",
	"Microsoft.",
	"Newtonsoft.",
	"Azure.",
	"Amazon.",
	"Google.",
	"Dapper.",
	"AutoMapper.",
	"Serilog.",
	"Polly.",
	"FluentValidation.",
	"MediatR.",
}

// ProjectRoot walks up from scanDir looking for a C# project manifest
// (.csproj / .sln / well-known marker files). modulePath is always empty
// for C# — namespaces don't carry a global path-prefix the way Go modules
// do; each file owns its `namespace` declaration directly.
func (c *csharpResolver) ProjectRoot(scanDir string) (manifestPath, modulePath string, ok bool) {
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
		if m := csharpManifestInDir(cur); m != "" {
			return m, "", true
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	// Nothing matched. Return scanDir as a synthetic manifest so cross-file
	// resolution can still anchor — same fallback shape as the JS / Java
	// resolvers' script-only-repo case.
	return abs, "", true
}

// csharpManifestInDir returns the path of a C# project manifest in dir, or
// "" when none is present. Checks well-known marker filenames plus any
// *.csproj / *.sln file.
func csharpManifestInDir(dir string) string {
	for _, manifest := range csharpManifestFilenames {
		candidate := filepath.Join(dir, manifest)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".csproj") || strings.HasSuffix(name, ".sln") {
			return filepath.Join(dir, name)
		}
	}
	return ""
}

// ExtractScope parses a C# file's namespace declaration and using
// directives into a FileScope.
//
//   - scope.Package is the file's primary namespace (the outermost
//     `namespace N { }` or file-scoped `namespace N;`). When a file
//     declares multiple namespaces we record the first; same-namespace
//     resolution still works because PackageIndex is keyed by file path
//     and the node names carry the full dotted prefix.
//   - StarImports holds each `using X.Y.Z;` namespace (the C# analog of
//     Java star imports — `using` brings every type in a namespace into
//     scope without naming them).
//   - Imports holds `using Alias = X.Y.Z;` alias bindings (alias → target
//     namespace/type FQN).
//
// scope.FilePath is the file's absolute path — PackageIndex keys nodes by
// absolute file path for C# (importPathForNode returns node.FilePath).
func (c *csharpResolver) ExtractScope(filePath string, content []byte) (FileScope, error) {
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

	tree := tsast.Parse(content, rules.LangCSharp)
	if tree == nil || tree.Root() == nil {
		return fs, nil
	}
	root := tree.Root()
	collectCSharpScope(root, &fs)
	return fs, nil
}

// collectCSharpScope walks the compilation unit recording the first
// namespace as fs.Package and every using directive into StarImports /
// Imports. Recurses into block-scoped namespace bodies so a file that
// only has `namespace N { using X; class C {} }` is still captured.
func collectCSharpScope(n *tsast.Node, fs *FileScope) {
	if n == nil {
		return
	}
	for _, child := range n.NamedChildren() {
		switch child.Type() {
		case "using_directive":
			collectCSharpUsing(child, fs)
		case "namespace_declaration", "file_scoped_namespace_declaration":
			if fs.Package == "" {
				if name := child.ChildByFieldName("name"); name != nil {
					fs.Package = strings.TrimSpace(name.Text())
				}
			}
			// Recurse into the body for nested usings / namespaces.
			if body := child.ChildByFieldName("body"); body != nil {
				collectCSharpScope(body, fs)
			} else {
				// File-scoped namespace: siblings follow it in the same
				// parent, so continue scanning the current level.
				collectCSharpScope(child, fs)
			}
		}
	}
}

// collectCSharpUsing parses one `using X.Y.Z;` / `using Alias = X.Y.Z;` /
// `using static X.Y.Z;` directive and updates fs.StarImports / fs.Imports.
func collectCSharpUsing(n *tsast.Node, fs *FileScope) {
	text := strings.TrimSpace(n.Text())
	if text == "" {
		return
	}
	text = strings.TrimPrefix(text, "using")
	text = strings.TrimSpace(text)
	text = strings.TrimSuffix(text, ";")
	text = strings.TrimSpace(text)
	if text == "" {
		return
	}
	// `using static X.Y.Z;` — out of scope for this PR (member binding).
	if strings.HasPrefix(text, "static ") || strings.HasPrefix(text, "global ") {
		// Drop the global modifier and continue for `global using X;`.
		if strings.HasPrefix(text, "global ") {
			text = strings.TrimSpace(strings.TrimPrefix(text, "global"))
			text = strings.TrimSpace(text)
			if strings.HasPrefix(text, "static ") {
				return
			}
		} else {
			return
		}
	}
	// Alias: `using Alias = Namespace.Type;`.
	if eq := strings.IndexByte(text, '='); eq >= 0 {
		alias := strings.TrimSpace(text[:eq])
		target := strings.TrimSpace(text[eq+1:])
		if alias != "" && target != "" {
			fs.Imports[alias] = target
		}
		return
	}
	// Plain namespace import: record the namespace for same-suffix probing.
	fs.StarImports = append(fs.StarImports, text)
}

// ResolveCall resolves one C# call expression to a FuncNode ID, an extern
// symbol, or "no opinion".
//
// callee is one of:
//
//	"Foo"        — bare name. A same-class self call (handled by the
//	               same-file pass) or a `using static` member (out of
//	               scope). Return "no opinion".
//
//	"Recv.Bar"   — qualified call. `Recv` may be:
//	                 - a using alias (`using R = NS.Type` → resolve in the
//	                   target namespace).
//	                 - a same-namespace class name (no using needed).
//	                 - an imported (used-namespace) class name.
//	                 - a fully-qualified prefix tail.
//	                 - a local variable / field — out of scope without type
//	                   inference; return "no opinion".
func (c *csharpResolver) ResolveCall(callee string, scope FileScope, modulePath string, idx *PackageIndex) ResolveResult {
	if callee == "" {
		return ResolveResult{}
	}
	dot := strings.Index(callee, ".")
	if dot < 0 {
		// Bare name — same-class self calls are handled by the same-file
		// pass; `using static` member calls are out of scope.
		return ResolveResult{}
	}

	// Collapse a fully-qualified receiver to its last two dotted segments
	// ("MyApp.Helpers.Helper.GetName" → class "Helper", method "GetName").
	className, method := csharpSplitClassMethod(callee)
	if className == "" || method == "" {
		return ResolveResult{}
	}

	// Using alias: `using R = NS.Type;` and the call is `R.Method()`.
	if target, ok := scope.Imports[className]; ok {
		// target is a namespace/type FQN. Strip a trailing ".Type" so we
		// search by the type's own namespace + name.
		aliasNS, aliasType := csharpSplitNamespaceType(target)
		if isCSharpExternFQN(target) {
			return ResolveResult{Extern: target + "." + method, Confidence: 0.85}
		}
		if id, hit := resolveCSharpNodeInNamespaces(aliasType, method, []string{aliasNS}, idx); hit {
			return ResolveResult{TargetID: id, Confidence: 0.85}
		}
		return ResolveResult{}
	}

	// Extern receiver (`Console.WriteLine`, `File.ReadAllText`, ...) —
	// route to extern when the receiver is a known BCL/framework root.
	if isCSharpExternReceiver(className) {
		return ResolveResult{Extern: className + "." + method, Confidence: 0.8}
	}

	// Same-namespace: `Helper.GetName()` where Helper lives in the caller's
	// own namespace, no `using` required (the v1 milestone shape).
	if id, hit := c.resolveSameNamespaceQualified(className, method, scope, idx); hit {
		return ResolveResult{TargetID: id, Confidence: 0.85}
	}

	// Imported namespaces: scan each `using`-ed namespace for the type.
	if len(scope.StarImports) > 0 {
		if id, hit := resolveCSharpNodeInNamespaces(className, method, scope.StarImports, idx); hit {
			return ResolveResult{TargetID: id, Confidence: 0.8}
		}
	}

	// Unknown receiver — local variable / field / DI dispatch, out of scope
	// without type inference. Return "no opinion" so the framework drops it.
	return ResolveResult{}
}

// resolveSameNamespaceQualified handles `Helper.GetName()` where Helper is
// a class declared in the caller's own namespace but reached without an
// explicit `using`. We scan the project-wide node index for a node named
// "Helper.GetName" (exact) or ".GetName" (suffix) declared in any file
// whose Package equals the caller's namespace.
func (c *csharpResolver) resolveSameNamespaceQualified(className, method string, scope FileScope, idx *PackageIndex) (string, bool) {
	if scope.Package == "" {
		return "", false
	}
	return resolveCSharpNodeInNamespaces(className, method, []string{scope.Package}, idx)
}

// resolveCSharpNodeInNamespaces scans the project-wide node index for a
// node whose fully-qualified name resolves "<className>.<method>" within
// one of `namespaces`. C# nodes carry the full dotted name (the builder
// emits "MyApp.Helpers.Helper.GetName"), so the namespace is a PREFIX of
// the node name rather than a separate index key. We therefore match the
// node name against "<namespace>.<className>.<method>" (exact) and, as a
// fallback, "<className>.<method>" as a suffix of any node declared under
// the namespace.
//
// The PackageIndex for C# is keyed by absolute file path (importPathForNode
// returns node.FilePath), so there is no namespace→files key; we iterate
// every indexed node once. This is O(total nodes) per call but bounded by
// the per-pass call-index cache and the existing per-rule timeout (the C#
// risk note in csharp.md accepts this for app-sized scans).
func resolveCSharpNodeInNamespaces(className, method string, namespaces []string, idx *PackageIndex) (string, bool) {
	if idx == nil || method == "" || len(namespaces) == 0 {
		return "", false
	}
	want := className + "." + method
	// First pass: exact "<namespace>.<className>.<method>" full match —
	// strongest signal, prefers the precise class in the precise namespace.
	for _, ns := range namespaces {
		if ns == "" {
			continue
		}
		fullWant := ns + "." + want
		for _, nodes := range idx.PackageToNodes {
			for _, candID := range nodes {
				if csharpNodeFuncName(candID) == fullWant {
					return candID, true
				}
			}
		}
	}
	// Second pass: a node declared under one of the namespaces (its name
	// starts with "<namespace>.") whose tail is "<className>.<method>"
	// (exact suffix) — handles nested classes / multi-segment namespaces
	// where the full prefix differs but the class+method tail matches.
	for _, ns := range namespaces {
		if ns == "" {
			continue
		}
		nsPrefix := ns + "."
		for _, nodes := range idx.PackageToNodes {
			for _, candID := range nodes {
				fnPart := csharpNodeFuncName(candID)
				if !strings.HasPrefix(fnPart, nsPrefix) {
					continue
				}
				if fnPart == ns+"."+want || strings.HasSuffix(fnPart, "."+want) {
					return candID, true
				}
			}
		}
	}
	return "", false
}

// csharpNodeFuncName returns the function-name portion of a node ID
// ("<absFilePath>:<NS.Class.Method>" → "NS.Class.Method"). FuncID joins
// the file path and name with the LAST ':' (paths may contain a drive
// letter colon on Windows, but the func name never contains ':').
func csharpNodeFuncName(nodeID string) string {
	colon := strings.LastIndexByte(nodeID, ':')
	if colon < 0 {
		return nodeID
	}
	return nodeID[colon+1:]
}

// csharpSplitClassMethod collapses a (possibly fully-qualified) callee
// into (className, method): the LAST dotted segment is the method, the
// second-to-last is the class. "Helper.GetName" → ("Helper","GetName");
// "MyApp.Helpers.Helper.GetName" → ("Helper","GetName").
func csharpSplitClassMethod(callee string) (string, string) {
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

// csharpSplitNamespaceType splits a type FQN ("NS.Sub.Type") into its
// namespace ("NS.Sub") and short type name ("Type"). When there is no dot
// the whole string is the type and the namespace is "".
func csharpSplitNamespaceType(fqn string) (string, string) {
	fqn = strings.TrimSpace(fqn)
	if dot := strings.LastIndexByte(fqn, '.'); dot >= 0 {
		return fqn[:dot], fqn[dot+1:]
	}
	return "", fqn
}

// isCSharpExternFQN reports whether fqn names a type in a BCL / known-
// framework root namespace. Prefix-based; we don't enumerate every type.
func isCSharpExternFQN(fqn string) bool {
	for _, p := range csharpExternPrefixes {
		if strings.HasPrefix(fqn, p) {
			return true
		}
	}
	return false
}

// isCSharpExternReceiver reports whether a single-segment receiver name is
// the leading segment of a known extern root (e.g. "System", "Microsoft").
// Used so `System.Console.WriteLine` collapsed to a "Console.WriteLine"
// receiver isn't mistaken for an in-project class. Conservative: only the
// top-level root tokens count.
func isCSharpExternReceiver(receiver string) bool {
	for _, p := range csharpExternPrefixes {
		root := strings.TrimSuffix(p, ".")
		if receiver == root {
			return true
		}
	}
	return false
}

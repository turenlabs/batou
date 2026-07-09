package graph

// White-box coverage tests for the cross-file resolution + persistence
// surface the existing suites leave under-exercised:
//
//   - importPathForNode: the Go (<module>/<dir>) and Python (dotted) branches,
//     the abs-path "every-file-its-own-namespace" branch (JS), and the
//     out-of-module "" branch (was 28.8%).
//   - relativeDir: empty-moduleRoot and outside-the-root (".." rel) branches
//     (was 50%).
//   - absoluteFileDir: absolute-dir vs relative-to-cwd branches (was 37.5%).
//   - fetchContent: map hit, disk read, scanDir fallback, miss (was 50%).
//   - CrossLangServiceBoundaryFindings: the exported wrapper + idempotency
//     (was 0%).
//   - ResolveCrossFileEdgesForFile: the no-cross-file-state early return and
//     a real single-file Go re-resolve restoring an outbound edge (was 63.3%).
//   - Cross-file-state persist round-trip: PackageIndex / ModulePaths /
//     ModuleRoots / FileModules / FileScopes / RoutePath / OutboundRequests
//     all survive Save→Load and the loaded graph still reports
//     HasCrossFileState (the scan→hook adoption contract).
//
// These touch unexported helpers and inspect PackageIndex internals, so they
// live in package `graph` (white-box).

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// ---------------------------------------------------------------------------
// importPathForNode: language-dispatch branches.
// ---------------------------------------------------------------------------

func TestImportPathForNode_GoModuleRelativeDir(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "")
	cg.ModulePaths = map[rules.Language]string{rules.LangGo: "example.com/app"}
	cg.ModuleRoots = map[rules.Language]string{rules.LangGo: root}

	// A file in a sub-directory becomes <module>/<reldir>.
	sub := filepath.Join(root, "services", "auth")
	node := &FuncNode{ID: filepath.Join(sub, "login.go") + ":Login", FilePath: filepath.Join(sub, "login.go"), Language: rules.LangGo}
	if got := importPathForNode(cg, node, root); got != "example.com/app/services/auth" {
		t.Errorf("Go sub-dir import path = %q, want example.com/app/services/auth", got)
	}

	// A file directly at the module root resolves to the bare module path
	// (rel == "." branch).
	rootNode := &FuncNode{ID: filepath.Join(root, "main.go") + ":main", FilePath: filepath.Join(root, "main.go"), Language: rules.LangGo}
	if got := importPathForNode(cg, rootNode, root); got != "example.com/app" {
		t.Errorf("Go root import path = %q, want example.com/app", got)
	}
}

func TestImportPathForNode_GoOutsideModule(t *testing.T) {
	cg := NewCallGraph("/p", "")
	// No ModulePaths => modulePath == "" => returns "".
	node := &FuncNode{ID: "/p/a.go:F", FilePath: "/p/a.go", Language: rules.LangGo}
	if got := importPathForNode(cg, node, "/p"); got != "" {
		t.Errorf("Go node outside any module = %q, want empty", got)
	}
}

func TestImportPathForNode_PythonDottedKey(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "")
	cg.ModulePaths = map[rules.Language]string{rules.LangPython: "myapp"}
	cg.ModuleRoots = map[rules.Language]string{rules.LangPython: root}

	path := filepath.Join(root, "myapp", "handlers", "login.py")
	node := &FuncNode{ID: path + ":login", FilePath: path, Language: rules.LangPython}
	// pythonModuleKey strips ".py" and joins dirs with dots.
	if got := importPathForNode(cg, node, root); got != "myapp.handlers.login" {
		t.Errorf("Python import path = %q, want myapp.handlers.login", got)
	}
}

func TestImportPathForNode_JSAbsolutePath(t *testing.T) {
	cg := NewCallGraph("/p", "")
	// JS keys each node by its absolute file path. An already-absolute path
	// is returned verbatim.
	abs := "/p/web/client.js"
	node := &FuncNode{ID: abs + ":handler", FilePath: abs, Language: rules.LangJavaScript}
	if got := importPathForNode(cg, node, "/p"); got != abs {
		t.Errorf("JS abs import path = %q, want %q", got, abs)
	}

	// A relative path is made absolute (filepath.Abs branch).
	relNode := &FuncNode{ID: "rel.js:h", FilePath: "rel.js", Language: rules.LangJavaScript}
	got := importPathForNode(cg, relNode, "/p")
	if !filepath.IsAbs(got) {
		t.Errorf("JS relative import path %q should be made absolute", got)
	}
}

// ---------------------------------------------------------------------------
// relativeDir: empty moduleRoot and outside-root branches.
// ---------------------------------------------------------------------------

func TestRelativeDir(t *testing.T) {
	root := t.TempDir()

	// Empty moduleRoot => "".
	if got := relativeDir(filepath.Join(root, "a"), "", root); got != "" {
		t.Errorf("empty moduleRoot should yield empty rel, got %q", got)
	}

	// Normal sub-directory.
	if got := relativeDir(filepath.Join(root, "svc", "auth"), root, root); got != filepath.Join("svc", "auth") {
		t.Errorf("rel dir = %q, want %q", got, filepath.Join("svc", "auth"))
	}

	// A directory OUTSIDE the module root yields "" (the "../" prefix guard).
	outside := filepath.Join(filepath.Dir(root), "elsewhere")
	if got := relativeDir(outside, root, root); got != "" {
		t.Errorf("dir outside module root should yield empty, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// absoluteFileDir: absolute-input vs relative-to-cwd.
// ---------------------------------------------------------------------------

func TestAbsoluteFileDir(t *testing.T) {
	// Absolute file path: returns the abs dir unchanged.
	if got := absoluteFileDir("/proj/pkg/a.go", "/scan"); got != "/proj/pkg" {
		t.Errorf("absoluteFileDir(abs) = %q, want /proj/pkg", got)
	}

	// Relative file path: joined against the cwd, with a leading "./" trimmed.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	got := absoluteFileDir("./pkg/a.go", "/scan")
	if want := filepath.Join(cwd, "pkg"); got != want {
		t.Errorf("absoluteFileDir(rel) = %q, want %q", got, want)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("relative input should produce an absolute dir, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// fetchContent: map hit, disk read, scanDir fallback, miss.
// ---------------------------------------------------------------------------

func TestFetchContent(t *testing.T) {
	root := t.TempDir()

	// 1. Map hit short-circuits before any disk access (the path need not
	//    even exist on disk).
	want := []byte("from-map")
	if got := fetchContent("ghost.go", root, map[string][]byte{"ghost.go": want}); string(got) != "from-map" {
		t.Errorf("map-hit fetchContent = %q, want from-map", got)
	}

	// 2. Direct disk read by absolute path.
	abs := filepath.Join(root, "real.go")
	if err := os.WriteFile(abs, []byte("on-disk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := fetchContent(abs, "", nil); string(got) != "on-disk" {
		t.Errorf("abs disk fetchContent = %q, want on-disk", got)
	}

	// 3. scanDir fallback: a relative path resolved against scanDir.
	if err := os.WriteFile(filepath.Join(root, "rel.go"), []byte("rel-disk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := fetchContent("rel.go", root, nil); string(got) != "rel-disk" {
		t.Errorf("scanDir fallback fetchContent = %q, want rel-disk", got)
	}

	// 4. Total miss => nil.
	if got := fetchContent("nowhere.go", root, nil); got != nil {
		t.Errorf("miss fetchContent = %q, want nil", got)
	}
}

// ---------------------------------------------------------------------------
// CrossLangServiceBoundaryFindings: exported wrapper + idempotency.
// ---------------------------------------------------------------------------

func TestCrossLangServiceBoundaryFindings_WrapperAndIdempotent(t *testing.T) {
	cg := NewCallGraph("/proj", "sess")
	caller := makeOutboundNode("/proj/web/client.js:caller", "/proj/web/client.js", "/api/items")
	handler := makeHandlerNode("/proj/api/server.py:handler", "/proj/api/server.py", "/api/items", rules.LangPython)
	cg.AddNode(caller)
	cg.AddNode(handler)

	first := CrossLangServiceBoundaryFindings(cg)
	if len(first) != 1 {
		t.Fatalf("expected 1 cross-language finding, got %d", len(first))
	}
	if first[0].RuleID != "BATOU-CROSSLANG-SQL_QUERY" {
		t.Errorf("RuleID = %q, want BATOU-CROSSLANG-SQL_QUERY", first[0].RuleID)
	}

	// Re-running on the same graph must produce the same single finding (the
	// edge add is idempotent, the finding is re-derived from node metadata).
	second := CrossLangServiceBoundaryFindings(cg)
	if len(second) != 1 {
		t.Fatalf("idempotent re-run expected 1 finding, got %d", len(second))
	}
	// And the cross-file edge must not have been duplicated.
	count := 0
	for _, c := range caller.Calls {
		if c == handler.ID {
			count++
		}
	}
	if count != 1 {
		t.Errorf("cross-file edge duplicated on re-run: caller.Calls=%v", caller.Calls)
	}
}

// An empty graph yields no findings (the len(cg.Nodes)==0 guard).
func TestCrossLangServiceBoundaryFindings_EmptyGraph(t *testing.T) {
	cg := NewCallGraph("/proj", "sess")
	if got := CrossLangServiceBoundaryFindings(cg); got != nil {
		t.Errorf("empty graph should yield no findings, got %v", got)
	}
	if got := CrossLangServiceBoundaryFindings(nil); got != nil {
		t.Errorf("nil graph should yield no findings, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// ResolveCrossFileEdgesForFile: no-state early return + a real re-resolve.
// ---------------------------------------------------------------------------

// Without scan-built cross-file state the hook lane no-ops and returns an
// empty ResolveStats (the HasCrossFileState guard).
func TestResolveCrossFileEdgesForFile_NoCrossFileState(t *testing.T) {
	cg := NewCallGraph("/p", "")
	cg.AddNode(&FuncNode{ID: "/p/a.go:F", FilePath: "/p/a.go", Name: "F", Language: rules.LangGo})
	stats := ResolveCrossFileEdgesForFile(cg, "/p", "/p/a.go", []byte("package a\nfunc F(){}\n"), nil)
	if stats != (ResolveStats{}) {
		t.Errorf("no-cross-file-state should yield zero ResolveStats, got %+v", stats)
	}
	// A nil graph must also be tolerated.
	if got := ResolveCrossFileEdgesForFile(nil, "/p", "/p/a.go", nil, nil); got != (ResolveStats{}) {
		t.Errorf("nil graph should yield zero ResolveStats, got %+v", got)
	}
}

// With scan-built state, editing a file that makes a QUALIFIED cross-package
// call (auth.Helper) into another in-project package re-resolves the outbound
// cross-file edge from the file's RawCalls. Go cross-file resolution only
// fires for qualified (import-alias.func) calls — bare same-package calls are
// already edges from the same-file pass. This drives the FileScoped path,
// reindexFileNodes, the resolver's ExtractScope (so the import alias is in
// scope), and the per-node resolveNodeRawCalls loop in the hook lane.
func TestResolveCrossFileEdgesForFile_ReResolvesOutboundEdge(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"),
		[]byte("module example.com/app\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	callerPath := filepath.Join(root, "caller.go")
	// The callee lives in a sub-package directory so it has a distinct
	// import path the caller can reference by alias.
	authDir := filepath.Join(root, "auth")
	if err := os.MkdirAll(authDir, 0o755); err != nil {
		t.Fatal(err)
	}
	calleePath := filepath.Join(authDir, "auth.go")

	cg := NewCallGraph(root, "")
	cg.ModulePaths = map[rules.Language]string{rules.LangGo: "example.com/app"}
	cg.ModuleRoots = map[rules.Language]string{rules.LangGo: root}
	cg.PackageIndex = NewPackageIndex()
	cg.FileScopes = map[string]FileScope{}

	// The callee node lives in the auth sub-package and is indexed under its
	// import path so the resolver can find it.
	callee := &FuncNode{
		ID: calleePath + ":Helper", FilePath: calleePath, Name: "Helper",
		Package: "auth", Language: rules.LangGo,
	}
	cg.AddNode(callee)
	pkg := importPathForNode(cg, callee, root)
	if pkg != "example.com/app/auth" {
		t.Fatalf("callee import path = %q, want example.com/app/auth", pkg)
	}
	cg.PackageIndex.Add(pkg, callee.ID)
	cg.FileScopes[calleePath] = FileScope{FilePath: calleePath, Package: "auth"}
	if !cg.HasCrossFileState() {
		t.Fatal("graph should carry cross-file state after indexing the callee")
	}

	// The caller node references the qualified call via RawCalls but has no
	// resolved Calls edge yet (the edit just rebuilt it).
	caller := &FuncNode{
		ID: callerPath + ":Run", FilePath: callerPath, Name: "Run",
		Package: "app", Language: rules.LangGo,
		RawCalls: []string{"auth.Helper"},
	}
	cg.AddNode(caller)

	// Real source so the Go resolver's ExtractScope binds alias auth→import.
	src := []byte("package app\n\nimport \"example.com/app/auth\"\n\nfunc Run() { auth.Helper() }\n")
	stats := ResolveCrossFileEdgesForFile(cg, root, callerPath, src, nil)

	if stats.FilesScoped != 1 {
		t.Errorf("FilesScoped = %d, want 1", stats.FilesScoped)
	}
	// The caller's scope must now be cached with the import alias bound.
	sc, ok := cg.FileScopes[callerPath]
	if !ok {
		t.Fatal("caller scope should have been extracted and cached")
	}
	if sc.Imports["auth"] != "example.com/app/auth" {
		t.Errorf("caller scope import alias not bound: %v", sc.Imports)
	}
	// The outbound cross-file edge Run→Helper must have been (re)resolved.
	if !containsStr(caller.Calls, callee.ID) {
		t.Errorf("expected resolved edge Run→Helper; caller.Calls=%v", caller.Calls)
	}
	if !containsStr(callee.CalledBy, caller.ID) {
		t.Errorf("expected back-edge Helper.CalledBy←Run; callee.CalledBy=%v", callee.CalledBy)
	}
	if stats.CrossFileEdges != 1 {
		t.Errorf("CrossFileEdges = %d, want 1", stats.CrossFileEdges)
	}
}

// ---------------------------------------------------------------------------
// Cross-file-state persist round-trip: the scan→hook adoption contract.
// The existing round-trip tests cover node taint sigs but NOT the cross-file
// fields, whose survival is what HasCrossFileState (and hook adoption) relies
// on.
// ---------------------------------------------------------------------------

func TestSaveLoadRoundTrip_CrossFileState(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "scan-session")

	// Module metadata (global + per-file).
	cg.ModulePaths = map[rules.Language]string{rules.LangGo: "example.com/app"}
	cg.ModuleRoots = map[rules.Language]string{rules.LangGo: root}
	cg.FileModules = map[string]FileModule{
		"svc/a.go": {ModulePath: "example.com/app/svc", ModuleRoot: filepath.Join(root, "svc")},
	}
	cg.FileScopes = map[string]FileScope{
		"svc/a.go": {FilePath: "svc/a.go", Package: "svc", Imports: map[string]string{"auth": "example.com/app/auth"}},
	}

	// A route-handler node and an outbound-request node — the cross-language
	// service-boundary metadata.
	handler := &FuncNode{
		ID: "svc/a.go:Handler", FilePath: "svc/a.go", Name: "Handler",
		Language: rules.LangPython, RoutePath: "/api/items", RouteMethod: "get",
		TaintSig: TaintSignature{
			SinkCalls: []SinkRef{{SinkCategory: taint.SnkSQLQuery, MethodName: "execute", Line: 9}},
		},
	}
	caller := &FuncNode{
		ID: "web/c.js:Caller", FilePath: "web/c.js", Name: "Caller",
		Language: rules.LangJavaScript,
		OutboundRequests: []OutboundRequest{
			{Path: "/api/items", Method: "get", Line: 3, TaintedArg: "req.query.q", SourceCategory: string(taint.SrcUserInput)},
		},
	}
	cg.AddNode(handler)
	cg.AddNode(caller)

	// The PackageIndex marker that HasCrossFileState keys on.
	cg.PackageIndex = NewPackageIndex()
	cg.PackageIndex.Add("example.com/app/svc", handler.ID)
	cg.PackageIndex.NodeToPackage[handler.ID] = "example.com/app/svc"

	if !cg.HasCrossFileState() {
		t.Fatal("fixture graph should carry cross-file state before save")
	}

	if err := SaveGraph(cg); err != nil {
		t.Fatalf("SaveGraph: %v", err)
	}

	// Load it back under the SAME session so LoadGraph returns the persisted
	// graph rather than a fresh one.
	loaded, err := LoadGraph(root, "scan-session")
	if err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}

	// The adoption marker must survive serialization.
	if !loaded.HasCrossFileState() {
		t.Fatal("loaded graph lost its cross-file state (PackageIndex did not survive round-trip)")
	}
	if got := loaded.PackageIndex.Lookup("example.com/app/svc"); len(got) != 1 || got[0] != handler.ID {
		t.Errorf("PackageIndex.Lookup after reload = %v, want [%s]", got, handler.ID)
	}
	if loaded.PackageIndex.NodeToPackage[handler.ID] != "example.com/app/svc" {
		t.Errorf("NodeToPackage reverse map did not survive: %v", loaded.PackageIndex.NodeToPackage)
	}

	// Module metadata.
	if loaded.ModulePaths[rules.LangGo] != "example.com/app" {
		t.Errorf("ModulePaths did not survive: %v", loaded.ModulePaths)
	}
	if fm, ok := loaded.FileModules["svc/a.go"]; !ok || fm.ModulePath != "example.com/app/svc" {
		t.Errorf("FileModules did not survive: %v", loaded.FileModules)
	}
	if sc, ok := loaded.FileScopes["svc/a.go"]; !ok || sc.Imports["auth"] != "example.com/app/auth" {
		t.Errorf("FileScopes did not survive: %v", loaded.FileScopes)
	}

	// Route-handler + outbound-request node metadata.
	lh := loaded.GetNode("svc/a.go:Handler")
	if lh == nil || lh.RoutePath != "/api/items" || lh.RouteMethod != "get" {
		t.Errorf("handler route metadata did not survive: %+v", lh)
	}
	lc := loaded.GetNode("web/c.js:Caller")
	if lc == nil || len(lc.OutboundRequests) != 1 || lc.OutboundRequests[0].TaintedArg != "req.query.q" {
		t.Errorf("caller OutboundRequests did not survive: %+v", lc)
	}

	// And the whole chain still produces the cross-language finding off the
	// reloaded graph — the end-to-end proof that a scan-built graph is fully
	// usable after a hook adopts it.
	findings := CrossLangServiceBoundaryFindings(loaded)
	if len(findings) != 1 || findings[0].RuleID != "BATOU-CROSSLANG-SQL_QUERY" {
		t.Errorf("reloaded graph should still yield the cross-language finding, got %+v", findings)
	}
}

// ---------------------------------------------------------------------------
// LoadGraphAt: the readGraphFile hard-error propagation path (a directory at
// the graph path => os.ReadFile fails with a non-IsNotExist error).
// ---------------------------------------------------------------------------

func TestLoadGraphAt_ReadErrorPropagates(t *testing.T) {
	root := t.TempDir()
	// Make the graph path a directory so os.ReadFile returns a hard error
	// (EISDIR) that is NOT os.IsNotExist — readGraphFile surfaces it.
	dirAsGraph := filepath.Join(root, "g.json")
	if err := os.MkdirAll(dirAsGraph, 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := LoadGraphAt(dirAsGraph, root, "sess")
	if err == nil {
		t.Fatalf("expected a read error for a directory graph path, got nil (graph=%+v)", got)
	}
	if got != nil {
		t.Errorf("on a hard read error the returned graph must be nil, got %+v", got)
	}
}

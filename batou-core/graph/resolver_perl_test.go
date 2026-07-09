package graph

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// writePerlProject lays down a minimal Perl distribution on disk:
//
//	root/cpanfile
//	root/lib/Lib/Helpers.pm
//
// and returns (root, absolute path of Helpers.pm). ExtractScope /
// resolvePerlModuleSpecifier stat real files, so the layout must exist.
func writePerlProject(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "cpanfile"),
		[]byte("requires 'perl', '5.30';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pmDir := filepath.Join(root, "lib", "Lib")
	if err := os.MkdirAll(pmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pmPath := filepath.Join(pmDir, "Helpers.pm")
	pmSrc := "package Lib::Helpers;\n\nsub render {\n    my ($tpl) = @_;\n    return $tpl;\n}\n\n1;\n"
	if err := os.WriteFile(pmPath, []byte(pmSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, pmPath
}

// TestPerlResolver_Registered confirms init() wired the resolver into
// the registry.
func TestPerlResolver_Registered(t *testing.T) {
	if r := GetResolver(rules.LangPerl); r == nil {
		t.Fatal("Perl resolver not registered")
	}
}

// TestPerlResolver_ProjectRoot_Cpanfile verifies the manifest walk finds
// cpanfile from a nested directory.
func TestPerlResolver_ProjectRoot_Cpanfile(t *testing.T) {
	root, _ := writePerlProject(t)
	// Walk up from a neutral subdir. (Not lib/Lib: on case-insensitive
	// filesystems Stat("lib/Lib/../lib") would match the `lib` marker dir
	// one level early.)
	sub := filepath.Join(root, "scripts")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	r := &perlResolver{}
	manifest, mod, ok := r.ProjectRoot(sub)
	if !ok {
		t.Fatalf("ProjectRoot did not find manifest from %q", sub)
	}
	if mod != "" {
		t.Errorf("modulePath = %q, want empty (Perl has no path-prefix namespace)", mod)
	}
	if filepath.Clean(manifest) != filepath.Join(root, "cpanfile") {
		t.Errorf("manifest = %q, want %q", manifest, filepath.Join(root, "cpanfile"))
	}
}

// TestPerlResolver_ProjectRoot_LibDirFallback: no manifest file, but a
// conventional lib/ tree marks the root via the synthetic __manifest__
// anchor.
func TestPerlResolver_ProjectRoot_LibDirFallback(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &perlResolver{}
	manifest, _, ok := r.ProjectRoot(root)
	if !ok {
		t.Fatal("ProjectRoot failed on lib/ layout")
	}
	if filepath.Clean(manifest) != filepath.Join(root, "__manifest__") {
		t.Errorf("manifest = %q, want synthetic %q", manifest, filepath.Join(root, "__manifest__"))
	}
}

// TestPerlResolver_ExtractScope_UseBindings covers the main import shapes:
// an in-project `use Lib::Helpers;` binds to the .pm file on disk, a
// pragma (`use strict;`) and a CPAN module (`use JSON;`) stay extern (bare
// name), and an unresolvable package records its bare name.
func TestPerlResolver_ExtractScope_UseBindings(t *testing.T) {
	root, pmPath := writePerlProject(t)
	scriptPath := filepath.Join(root, "app.pl")
	src := []byte(`use strict;
use JSON;
use Lib::Helpers;
use No::Such::Module;
`)

	r := &perlResolver{}
	scope, err := r.ExtractScope(scriptPath, src)
	if err != nil {
		t.Fatalf("ExtractScope: %v", err)
	}
	if scope.Package != scriptPath {
		t.Errorf("Package = %q, want file's own abs path %q", scope.Package, scriptPath)
	}
	if got := scope.Imports["Lib::Helpers"]; got != pmPath {
		t.Errorf("Imports[Lib::Helpers] = %q, want %q", got, pmPath)
	}
	if got := scope.Imports["strict"]; got != "strict" {
		t.Errorf("Imports[strict] = %q, want bare extern 'strict'", got)
	}
	if got := scope.Imports["JSON"]; got != "JSON" {
		t.Errorf("Imports[JSON] = %q, want bare extern 'JSON'", got)
	}
	if got := scope.Imports["No::Such::Module"]; got != "No::Such::Module" {
		t.Errorf("Imports[No::Such::Module] = %q, want bare fallback", got)
	}
	if got := scope.Aux["module_root"]; got != root {
		t.Errorf("Aux[module_root] = %q, want %q", got, root)
	}
}

// TestPerlResolver_ExtractScope_RequireForms covers both require shapes:
// the bareword `require Lib::Helpers;` and the string form
// `require "Lib/Helpers.pm";`. Both must bind the package name to the
// absolute .pm path.
func TestPerlResolver_ExtractScope_RequireForms(t *testing.T) {
	root, pmPath := writePerlProject(t)

	cases := []struct {
		name string
		src  string
	}{
		{"bareword", "require Lib::Helpers;\n"},
		{"string", "require \"Lib/Helpers.pm\";\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The string form resolves relative to the file's directory /
			// module root / lib. Put the script inside lib/ so "Lib/Helpers.pm"
			// resolves against the script's own directory.
			scriptPath := filepath.Join(root, "lib", "runner.pl")
			r := &perlResolver{}
			scope, err := r.ExtractScope(scriptPath, []byte(tc.src))
			if err != nil {
				t.Fatalf("ExtractScope: %v", err)
			}
			if got := scope.Imports["Lib::Helpers"]; got != pmPath {
				t.Errorf("Imports[Lib::Helpers] = %q, want %q (src %q)", got, pmPath, tc.src)
			}
		})
	}
}

// TestPerlResolver_ResolveCall_Qualified: a builder-normalised
// `Lib::Helpers.render` call resolves through the use-binding to the sub
// node in the bound file (suffix match on package-qualified node names).
func TestPerlResolver_ResolveCall_Qualified(t *testing.T) {
	_, pmPath := writePerlProject(t)

	idx := NewPackageIndex()
	// Perl nodes key under their own absolute file path; the builder emits
	// package-qualified names ("Lib::Helpers.render").
	nodeID := pmPath + ":Lib::Helpers.render"
	idx.Add(pmPath, nodeID)

	scope := FileScope{
		FilePath: "/srv/app/main.pl",
		Imports:  map[string]string{"Lib::Helpers": pmPath},
	}
	r := &perlResolver{}
	res := r.ResolveCall("Lib::Helpers.render", scope, "", idx)
	if res.TargetID != nodeID {
		t.Errorf("TargetID = %q, want %q", res.TargetID, nodeID)
	}
	if res.Confidence != 0.85 {
		t.Errorf("Confidence = %v, want 0.85", res.Confidence)
	}
}

// TestPerlResolver_ResolveCall_ExactFirst: a bare top-level sub node must
// win over a package-qualified node that merely suffix-matches.
func TestPerlResolver_ResolveCall_ExactFirst(t *testing.T) {
	_, pmPath := writePerlProject(t)

	idx := NewPackageIndex()
	qualified := pmPath + ":Other.render"
	bare := pmPath + ":render"
	idx.Add(pmPath, qualified)
	idx.Add(pmPath, bare)

	scope := FileScope{
		FilePath: "/srv/app/main.pl",
		Imports:  map[string]string{"Lib::Helpers": pmPath},
	}
	r := &perlResolver{}
	res := r.ResolveCall("Lib::Helpers.render", scope, "", idx)
	if res.TargetID != bare {
		t.Errorf("exact-first violated: TargetID = %q, want bare node %q", res.TargetID, bare)
	}
}

// TestPerlResolver_ResolveCall_Extern: a call through a CPAN/pragma
// binding (non-absolute import target) routes to Extern in `Pkg::method`
// form.
func TestPerlResolver_ResolveCall_Extern(t *testing.T) {
	scope := FileScope{
		FilePath: "/srv/app/main.pl",
		Imports:  map[string]string{"CGI": "CGI"},
	}
	r := &perlResolver{}
	res := r.ResolveCall("CGI.param", scope, "", NewPackageIndex())
	if res.TargetID != "" {
		t.Errorf("extern call must not have TargetID; got %q", res.TargetID)
	}
	if res.Extern != "CGI::param" {
		t.Errorf("Extern = %q, want CGI::param", res.Extern)
	}
}

// TestPerlResolver_ResolveCall_NoOpinion: unknown package prefix, empty
// callee, and an in-project file with no matching sub all yield the zero
// ResolveResult.
func TestPerlResolver_ResolveCall_NoOpinion(t *testing.T) {
	_, pmPath := writePerlProject(t)
	idx := NewPackageIndex()
	idx.Add(pmPath, pmPath+":Lib::Helpers.render")

	scope := FileScope{
		FilePath: "/srv/app/main.pl",
		Imports:  map[string]string{"Lib::Helpers": pmPath},
	}
	r := &perlResolver{}

	if res := r.ResolveCall("", scope, "", idx); res != (ResolveResult{}) {
		t.Errorf("empty callee: got %+v, want zero", res)
	}
	if res := r.ResolveCall("Unknown::Pkg.run", scope, "", idx); res != (ResolveResult{}) {
		t.Errorf("unknown package: got %+v, want zero", res)
	}
	if res := r.ResolveCall("Lib::Helpers.no_such_sub", scope, "", idx); res != (ResolveResult{}) {
		t.Errorf("missing sub in bound file: got %+v, want zero (no opinion)", res)
	}
}

// TestPerlResolver_CrossFileEdge is the end-to-end check: main.pl does
// `use Lib::Helpers;` and calls `Lib::Helpers::render(...)` (normalised by
// the builder to "Lib::Helpers.render"); the cross-file pass must add a
// Calls edge to the sub node in lib/Lib/Helpers.pm.
func TestPerlResolver_CrossFileEdge(t *testing.T) {
	root, pmPath := writePerlProject(t)
	mainPath := filepath.Join(root, "main.pl")

	cg := NewCallGraph(root, "test")
	cg.AddNode(&FuncNode{
		ID:       mainPath + ":handle_request",
		FilePath: mainPath,
		Name:     "handle_request",
		Language: rules.LangPerl,
		RawCalls: []string{"Lib::Helpers.render"},
	})
	cg.AddNode(&FuncNode{
		ID:       pmPath + ":Lib::Helpers.render",
		FilePath: pmPath,
		Name:     "Lib::Helpers.render",
		Language: rules.LangPerl,
	})

	contents := map[string][]byte{
		mainPath: []byte("use Lib::Helpers;\n\nsub handle_request {\n    return Lib::Helpers::render($_[0]);\n}\n"),
		pmPath:   []byte("package Lib::Helpers;\n\nsub render { return $_[0]; }\n\n1;\n"),
	}
	stats := ResolveCrossFileEdges(cg, root, contents)
	if stats.CrossFileEdges < 1 {
		t.Errorf("CrossFileEdges = %d, want >= 1 (stats=%+v)", stats.CrossFileEdges, stats)
	}
	caller := cg.GetNode(mainPath + ":handle_request")
	wantTarget := pmPath + ":Lib::Helpers.render"
	if !containsStr(caller.Calls, wantTarget) {
		t.Errorf("caller.Calls missing %q (got %v)", wantTarget, caller.Calls)
	}
}

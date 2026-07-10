package graph

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// fakeResolver is a minimal LanguageResolver used to exercise the
// registry and the supporting data structures.
type fakeResolver struct {
	lang     rules.Language
	manifest string
	mod      string
	calls    map[string]string // callee → in-project target ID
}

func (f *fakeResolver) Language() rules.Language { return f.lang }

func (f *fakeResolver) ProjectRoot(scanDir string) (string, string, bool) {
	return f.manifest, f.mod, f.manifest != ""
}

func (f *fakeResolver) ExtractScope(_ string, _ []byte) (FileScope, error) {
	return FileScope{}, nil
}

func (f *fakeResolver) ResolveCall(callee string, _ FileScope, _ string, _ *PackageIndex) ResolveResult {
	if id, ok := f.calls[callee]; ok {
		return ResolveResult{TargetID: id, Confidence: 0.9}
	}
	return ResolveResult{}
}

func TestRegistry_AddAndGet(t *testing.T) {
	// Save & restore registry around the test to keep us hermetic
	// against any real adapters that may have registered at package init.
	resolverMu.Lock()
	saved := resolvers
	resolvers = make(map[rules.Language]LanguageResolver)
	resolverMu.Unlock()
	t.Cleanup(func() {
		resolverMu.Lock()
		resolvers = saved
		resolverMu.Unlock()
	})

	f := &fakeResolver{lang: rules.LangGo, mod: "example.com/foo"}
	RegisterResolver(f)
	if got := GetResolver(rules.LangGo); got != f {
		t.Fatalf("GetResolver returned wrong resolver: %#v", got)
	}
	if got := GetResolver(rules.LangPython); got != nil {
		t.Errorf("GetResolver(Python) = %v, want nil", got)
	}

	langs := RegisteredLanguages()
	if len(langs) != 1 || langs[0] != rules.LangGo {
		t.Errorf("RegisteredLanguages = %v, want [go]", langs)
	}
}

func TestRegistry_ReregisterOverrides(t *testing.T) {
	resolverMu.Lock()
	saved := resolvers
	resolvers = make(map[rules.Language]LanguageResolver)
	resolverMu.Unlock()
	t.Cleanup(func() {
		resolverMu.Lock()
		resolvers = saved
		resolverMu.Unlock()
	})

	a := &fakeResolver{lang: rules.LangGo, mod: "a"}
	b := &fakeResolver{lang: rules.LangGo, mod: "b"}
	RegisterResolver(a)
	RegisterResolver(b)
	if got := GetResolver(rules.LangGo); got != b {
		t.Errorf("re-registered resolver was not adopted: got %#v", got)
	}
}

func TestRegistry_NilIgnored(t *testing.T) {
	// Must not panic.
	RegisterResolver(nil)
}

func TestPackageIndex_AddLookup(t *testing.T) {
	p := NewPackageIndex()
	p.Add("example.com/foo/svc", "svc/a.go:Foo")
	p.Add("example.com/foo/svc", "svc/b.go:Bar")
	p.Add("example.com/foo/db", "db/conn.go:Open")

	got := p.Lookup("example.com/foo/svc")
	if len(got) != 2 {
		t.Errorf("Lookup(svc) returned %d entries, want 2: %v", len(got), got)
	}

	if pkg := p.NodeToPackage["svc/a.go:Foo"]; pkg != "example.com/foo/svc" {
		t.Errorf("NodeToPackage = %q, want example.com/foo/svc", pkg)
	}

	if got := p.Lookup("does/not/exist"); got != nil {
		t.Errorf("Lookup(missing) = %v, want nil", got)
	}

	// Empty inputs are silently ignored.
	p.Add("", "skipped")
	p.Add("not-skipped", "")
	if len(p.NodeToPackage) != 3 { // only the 3 valid adds above
		t.Errorf("NodeToPackage has %d entries, want 3", len(p.NodeToPackage))
	}
}

func TestResolveResult_ZeroValue(t *testing.T) {
	// A zero ResolveResult should be the resolver's "no opinion" form.
	var r ResolveResult
	if r.TargetID != "" || r.Extern != "" || r.Confidence != 0 {
		t.Errorf("zero ResolveResult is not zero: %#v", r)
	}
}

func TestFakeResolver_RoundTrip(t *testing.T) {
	// End-to-end sanity: register, look up, call ResolveCall, expect
	// the fake's mapping back.
	resolverMu.Lock()
	saved := resolvers
	resolvers = make(map[rules.Language]LanguageResolver)
	resolverMu.Unlock()
	t.Cleanup(func() {
		resolverMu.Lock()
		resolvers = saved
		resolverMu.Unlock()
	})

	f := &fakeResolver{
		lang:     rules.LangGo,
		manifest: "/tmp/go.mod",
		mod:      "example.com/foo",
		calls:    map[string]string{"auth.Login": "auth/login.go:Login"},
	}
	RegisterResolver(f)

	r := GetResolver(rules.LangGo)
	manifest, mod, ok := r.ProjectRoot("/tmp")
	if !ok || manifest != "/tmp/go.mod" || mod != "example.com/foo" {
		t.Errorf("ProjectRoot = (%q, %q, %v), want (/tmp/go.mod, example.com/foo, true)", manifest, mod, ok)
	}

	got := r.ResolveCall("auth.Login", FileScope{}, mod, NewPackageIndex())
	if got.TargetID != "auth/login.go:Login" {
		t.Errorf("ResolveCall.TargetID = %q, want auth/login.go:Login", got.TargetID)
	}
	if got.Confidence != 0.9 {
		t.Errorf("ResolveCall.Confidence = %v, want 0.9", got.Confidence)
	}

	if miss := r.ResolveCall("unknown.Foo", FileScope{}, mod, NewPackageIndex()); miss.TargetID != "" {
		t.Errorf("ResolveCall(unknown) = %#v, want zero", miss)
	}
}

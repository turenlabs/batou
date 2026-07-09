package graph

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	"github.com/turenlabs/batou-rules/rules"
)

// TestPythonExtractor_Registered verifies the Python extractor is
// installed at init time, mirroring TestExtractorRegistry_GoRegistered.
func TestPythonExtractor_Registered(t *testing.T) {
	if !IsExtractorSupported(rules.LangPython) {
		t.Fatal("Python extractor not registered")
	}
}

// TestPythonExtractor_TopLevelFunc covers the simplest case: a bare
// `def foo(x):` with no annotations.
func TestPythonExtractor_TopLevelFunc(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "top_level_no_annotations",
			FilePath: "/app/lib.py",
			Content: `def greet(name):
    return "hello " + name
`,
			Func: "greet",
			WantParams: []ParamTaint{
				{Index: 0, Name: "name"},
			},
		},
	}
	RunHarness(t, rules.LangPython, cases)
}

// TestPythonExtractor_FlaskRequestSource verifies that an aliased Flask
// request type lands in pythonTypeCatalog and is marked as a source.
func TestPythonExtractor_FlaskRequestSource(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "flask_request_param_source",
			FilePath: "/app/views.py",
			Content: `from flask import Request

def handle(req: Request):
    return req.args.get("q")
`,
			Func: "handle",
			WantParams: []ParamTaint{
				{
					Index:          0,
					Name:           "req",
					CanonicalType:  "flask.Request",
					IsSourceType:   true,
					SourceCategory: taint.SrcUserInput,
				},
			},
		},
	}
	RunHarness(t, rules.LangPython, cases)
}

// TestPythonExtractor_ClassMethodName verifies that methods inside a
// class are emitted as "Cls.method" so FuncNode IDs match the builder.
func TestPythonExtractor_ClassMethodName(t *testing.T) {
	src := `class Service:
    def run(self, x):
        return x

    def helper(self):
        return 1
`
	ex := GetExtractor(rules.LangPython)
	if ex == nil {
		t.Fatal("no Python extractor")
	}
	sigs := ex.ExtractFunctions(&ExtractContext{
		FilePath: "/app/svc.py",
		Content:  []byte(src),
		Language: rules.LangPython,
	})

	names := map[string]bool{}
	for _, s := range sigs {
		names[s.Name] = true
	}
	for _, want := range []string{"Service.run", "Service.helper"} {
		if !names[want] {
			t.Errorf("missing signature %q in %v", want, names)
		}
	}
}

// TestPythonExtractor_NestedClassMethodName verifies nested class
// methods get dotted prefixes like "Outer.Inner.method".
func TestPythonExtractor_NestedClassMethodName(t *testing.T) {
	src := `class Outer:
    class Inner:
        def deep(self):
            return 1
`
	ex := GetExtractor(rules.LangPython)
	if ex == nil {
		t.Fatal("Python extractor not registered")
	}
	sigs := ex.ExtractFunctions(&ExtractContext{
		FilePath: "/app/n.py",
		Content:  []byte(src),
		Language: rules.LangPython,
	})
	found := false
	for _, s := range sigs {
		if s.Name == "Outer.Inner.deep" {
			found = true
			break
		}
	}
	if !found {
		names := make([]string, 0, len(sigs))
		for _, s := range sigs {
			names = append(names, s.Name)
		}
		t.Errorf("expected nested-class method 'Outer.Inner.deep', got %v", names)
	}
}

// TestPythonExtractor_DecoratedFunc verifies @decorator wrappers don't
// hide the underlying function from the extractor.
func TestPythonExtractor_DecoratedFunc(t *testing.T) {
	src := `from flask import request

@app.route("/x")
def index():
    return request.args.get("q")
`
	ex := GetExtractor(rules.LangPython)
	if ex == nil {
		t.Fatal("Python extractor not registered")
	}
	sigs := ex.ExtractFunctions(&ExtractContext{
		FilePath: "/app/v.py",
		Content:  []byte(src),
		Language: rules.LangPython,
	})
	found := false
	for _, s := range sigs {
		if s.Name == "index" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("decorated def 'index' not extracted; got %d sigs", len(sigs))
	}
}

// TestPythonExtractor_CanonicalizeType_AliasedImport verifies that an
// aliased import surfaces in canonicalized type annotations.
func TestPythonExtractor_CanonicalizeType_AliasedImport(t *testing.T) {
	src := `from flask import Request as R

def handle(req: R):
    return 1
`
	ex := GetExtractor(rules.LangPython)
	if ex == nil {
		t.Fatal("Python extractor not registered")
	}
	sigs := ex.ExtractFunctions(&ExtractContext{
		FilePath: "/app/r.py",
		Content:  []byte(src),
		Language: rules.LangPython,
	})
	var got *FuncSignature
	for i := range sigs {
		if sigs[i].Name == "handle" {
			got = &sigs[i]
			break
		}
	}
	if got == nil {
		t.Fatal("handle not extracted")
	}
	if len(got.Params) != 1 {
		t.Fatalf("expected 1 param, got %d", len(got.Params))
	}
	if got.Params[0].CanonicalType != "flask.Request" {
		t.Errorf("CanonicalType = %q, want flask.Request", got.Params[0].CanonicalType)
	}
	if !got.Params[0].IsSourceType {
		t.Error("aliased Request should be marked as source")
	}
}

// TestPythonExtractor_NoFunctionsEmptyFile verifies graceful handling of
// a file with no function definitions at all.
func TestPythonExtractor_NoFunctionsEmptyFile(t *testing.T) {
	ex := GetExtractor(rules.LangPython)
	if ex == nil {
		t.Fatal("Python extractor not registered")
	}
	sigs := ex.ExtractFunctions(&ExtractContext{
		FilePath: "/app/empty.py",
		Content:  []byte("# just a comment\nx = 1\n"),
		Language: rules.LangPython,
	})
	if len(sigs) != 0 {
		t.Errorf("expected 0 signatures for empty file, got %d", len(sigs))
	}
}

// TestPythonExtractor_NilContext is a defensive test for the panic-
// safety contract — passing nil ExtractContext must return empty.
func TestPythonExtractor_NilContext(t *testing.T) {
	ex := GetExtractor(rules.LangPython)
	if ex == nil {
		t.Fatal("Python extractor not registered")
	}
	sigs := ex.ExtractFunctions(nil)
	if len(sigs) != 0 {
		t.Errorf("expected nil-safe behavior, got %d signatures", len(sigs))
	}
}

// TestPythonTypeCatalog_FlaskRequest pins the core catalog entry that
// most other Python source detection depends on.
func TestPythonTypeCatalog_FlaskRequest(t *testing.T) {
	cat := PythonTypeCatalog()
	if cat == nil {
		t.Fatal("PythonTypeCatalog() returned nil")
	}
	got, ok := cat.LookupSource("flask.Request")
	if !ok {
		t.Fatal("flask.Request not in SourceParam map")
	}
	if got != taint.SrcUserInput {
		t.Errorf("flask.Request category = %q, want SrcUserInput", got)
	}
}

package graph

import (
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// TestRubyExtractor_TopLevelFunction verifies that a top-level `def foo(...)`
// emits a FuncSignature named "foo" with positional Params.
func TestRubyExtractor_TopLevelFunction(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "toplevel_def_with_param",
			FilePath: "/app/handler.rb",
			Content: `def handler(req)
  req.params[:id]
end
`,
			Func: "handler",
			WantParams: []ParamTaint{
				{Index: 0, Name: "req"},
			},
		},
	}
	RunHarness(t, rules.LangRuby, cases)
}

// TestRubyExtractor_InstanceMethod verifies `class Cls; def m; end` becomes
// "Cls.m" (dotted convention, mirroring Java's Outer.method).
func TestRubyExtractor_InstanceMethod(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "class_instance_method",
			FilePath: "/app/users_controller.rb",
			Content: `class UsersController < ApplicationController
  def show(id)
    User.find(id)
  end
end
`,
			Func: "UsersController.show",
			WantParams: []ParamTaint{
				{Index: 0, Name: "id"},
			},
		},
	}
	RunHarness(t, rules.LangRuby, cases)
}

// TestRubyExtractor_SingletonMethod verifies `def self.method` and `def Cls.method`
// both qualify under the enclosing class name as "Cls.method".
func TestRubyExtractor_SingletonMethod(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "self_singleton_method",
			FilePath: "/app/user.rb",
			Content: `class User
  def self.find_by(name)
    name
  end
end
`,
			Func: "User.find_by",
			WantParams: []ParamTaint{
				{Index: 0, Name: "name"},
			},
		},
	}
	RunHarness(t, rules.LangRuby, cases)
}

// TestRubyExtractor_ModuleMethod verifies a module-level singleton method
// gets the module's name as its prefix.
func TestRubyExtractor_ModuleMethod(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "module_singleton_method",
			FilePath: "/app/foo.rb",
			Content: `module Foo
  def self.bar(x)
    x
  end
end
`,
			Func: "Foo.bar",
			WantParams: []ParamTaint{
				{Index: 0, Name: "x"},
			},
		},
	}
	RunHarness(t, rules.LangRuby, cases)
}

// TestRubyExtractor_NestedClass verifies nested classes / modules thread
// through with dotted prefixes ("Outer.Inner.method").
func TestRubyExtractor_NestedClass(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "nested_class_method",
			FilePath: "/app/outer.rb",
			Content: `module Outer
  class Inner
    def hello(name)
      "hi #{name}"
    end
  end
end
`,
			Func: "Outer.Inner.hello",
			WantParams: []ParamTaint{
				{Index: 0, Name: "name"},
			},
		},
	}
	RunHarness(t, rules.LangRuby, cases)
}

// TestRubyExtractor_SinatraRouteBlock verifies that the Sinatra-style
// `get '/x' do ... end` DSL emits a synthetic FuncNode named
// "<verb>@<line>:<col>" (or "<prefix>.<verb>@..." inside a class) so
// the request handler is reachable in the call graph. Without this,
// Sinatra apps lose their dominant handler shape.
func TestRubyExtractor_SinatraRouteBlock(t *testing.T) {
	content := `get '/users/:id' do
  params[:id]
end

post '/login' do
  params[:user]
end
`
	ex := GetExtractor(rules.LangRuby)
	if ex == nil {
		t.Fatal("Ruby extractor not registered")
	}
	ctx := &ExtractContext{
		FilePath: "/app/sinatra_app.rb",
		Content:  []byte(content),
		Language: rules.LangRuby,
	}
	sigs := ex.ExtractFunctions(ctx)
	// We expect two route-block signatures, one for each verb. Names
	// carry the line:col anchor so we don't assert the literal name —
	// we assert the prefix and the IsClosure flag.
	var got []FuncSignature
	for _, s := range sigs {
		if s.Name == "" {
			continue
		}
		got = append(got, s)
	}
	if len(got) < 2 {
		t.Fatalf("expected at least 2 route signatures, got %d (%+v)", len(got), got)
	}
	foundGet, foundPost := false, false
	for _, s := range got {
		if s.IsClosure && stringStartsWith(s.Name, "get@") {
			foundGet = true
		}
		if s.IsClosure && stringStartsWith(s.Name, "post@") {
			foundPost = true
		}
	}
	if !foundGet {
		t.Errorf("expected a `get@<line>:<col>` route signature, got %+v", got)
	}
	if !foundPost {
		t.Errorf("expected a `post@<line>:<col>` route signature, got %+v", got)
	}
}

// TestRubyExtractor_SinatraRouteWithBlockParams verifies route blocks
// with `|arg|` parameter syntax extract the param.
func TestRubyExtractor_SinatraRouteWithBlockParams(t *testing.T) {
	content := `get '/echo' do |msg|
  msg
end
`
	ex := GetExtractor(rules.LangRuby)
	ctx := &ExtractContext{
		FilePath: "/app/echo.rb",
		Content:  []byte(content),
		Language: rules.LangRuby,
	}
	sigs := ex.ExtractFunctions(ctx)
	if len(sigs) == 0 {
		t.Fatal("no signatures extracted")
	}
	// Find the get route block.
	var route *FuncSignature
	for i := range sigs {
		if stringStartsWith(sigs[i].Name, "get@") {
			route = &sigs[i]
			break
		}
	}
	if route == nil {
		t.Fatalf("no get@ route block extracted; sigs=%+v", sigs)
	}
	if len(route.Params) != 1 || route.Params[0].Name != "msg" {
		t.Errorf("expected one param 'msg', got %+v", route.Params)
	}
}

// TestRubyExtractor_DefineMethod verifies `define_method(:dyn)` becomes
// a regular FuncSignature named after the symbol (no synthetic suffix).
func TestRubyExtractor_DefineMethod(t *testing.T) {
	content := `class Dyn
  define_method(:dynamic) do |arg|
    arg
  end
end
`
	ex := GetExtractor(rules.LangRuby)
	ctx := &ExtractContext{
		FilePath: "/app/dyn.rb",
		Content:  []byte(content),
		Language: rules.LangRuby,
	}
	sigs := ex.ExtractFunctions(ctx)
	got := findSignature(sigs, "Dyn.dynamic")
	if got == nil {
		t.Fatalf("expected signature 'Dyn.dynamic', got %+v", sigs)
	}
	if len(got.Params) != 1 || got.Params[0].Name != "arg" {
		t.Errorf("Params = %+v, want [{Name: arg}]", got.Params)
	}
}

// TestRubyExtractor_VariousParams verifies the parameter walker handles
// optional / splat / hash_splat / block parameters.
func TestRubyExtractor_VariousParams(t *testing.T) {
	cases := []HarnessCase{
		{
			Name:     "all_param_kinds",
			FilePath: "/app/p.rb",
			Content: `class P
  def m(a, b=1, *args, **kwargs, &blk)
    a
  end
end
`,
			Func: "P.m",
			WantParams: []ParamTaint{
				{Index: 0, Name: "a"},
				{Index: 1, Name: "b"},
				{Index: 2, Name: "args"},
				{Index: 3, Name: "kwargs"},
				{Index: 4, Name: "blk"},
			},
		},
	}
	RunHarness(t, rules.LangRuby, cases)
}

// TestRubyExtractor_NamespaceDSLRecurses verifies that Rails-style
// `namespace :api do ... end` containers don't emit a node themselves
// but recurse so routes declared inside are still extracted.
func TestRubyExtractor_NamespaceDSLRecurses(t *testing.T) {
	content := `namespace :api do
  get '/users' do
    "ok"
  end
end
`
	ex := GetExtractor(rules.LangRuby)
	ctx := &ExtractContext{
		FilePath: "/app/api.rb",
		Content:  []byte(content),
		Language: rules.LangRuby,
	}
	sigs := ex.ExtractFunctions(ctx)
	foundGet := false
	for _, s := range sigs {
		if stringStartsWith(s.Name, "get@") {
			foundGet = true
		}
		if s.Name == "namespace" {
			t.Errorf("namespace DSL should not emit a node itself")
		}
	}
	if !foundGet {
		t.Errorf("expected a `get@` route node inside namespace, got %+v", sigs)
	}
}

// TestRubyExtractor_RegisteredInRegistry confirms the init() registration
// fires and the extractor is reachable via GetExtractor.
func TestRubyExtractor_RegisteredInRegistry(t *testing.T) {
	if !IsExtractorSupported(rules.LangRuby) {
		t.Fatal("Ruby extractor not registered")
	}
	ex := GetExtractor(rules.LangRuby)
	if ex == nil {
		t.Fatal("GetExtractor returned nil for Ruby")
	}
	if ex.Language() != rules.LangRuby {
		t.Errorf("Language() = %q, want Ruby", ex.Language())
	}
}

// stringStartsWith is a tiny helper to avoid importing "strings" just
// for the prefix check (the file already pulls it in transitively, but
// keeping a local helper makes the assertions read clearer).
func stringStartsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

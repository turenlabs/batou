package graph

import (
	"path/filepath"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// TestRubyBuilder_DefineMethod_Symbol: `define_method(:name) do ... end`
// inside a class emits a "Class.name" FuncNode whose RawCalls capture the
// block body's calls (emitRubyDefineMethodNode, symbol-argument arm).
func TestRubyBuilder_DefineMethod_Symbol(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "user.rb")
	src := `class User
  define_method(:greet) do |name|
    format_greeting(name)
  end
end
`
	UpdateFile(cg, filePath, src, rules.LangRuby)

	n := cg.GetNode(filePath + ":User.greet")
	if n == nil {
		t.Fatalf("User.greet define_method node not emitted; have %v", nodeIDsInFile(cg, filePath))
	}
	if !containsStr(n.RawCalls, "format_greeting") {
		t.Errorf("User.greet RawCalls missing 'format_greeting' (got %v)", n.RawCalls)
	}
}

// TestRubyBuilder_DefineMethod_String: the string-name form
// `define_method("name") do ... end` binds the same way (string-argument
// arm of emitRubyDefineMethodNode).
func TestRubyBuilder_DefineMethod_String(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "audit.rb")
	src := `class Audit
  define_method("record") do |event|
    event
  end
end
`
	UpdateFile(cg, filePath, src, rules.LangRuby)

	if n := cg.GetNode(filePath + ":Audit.record"); n == nil {
		t.Errorf("Audit.record define_method node not emitted; have %v", nodeIDsInFile(cg, filePath))
	}
}

// TestRubyBuilder_DefineMethod_TopLevel: a top-level define_method (no
// class prefix) emits a bare-name node.
func TestRubyBuilder_DefineMethod_TopLevel(t *testing.T) {
	root := t.TempDir()
	cg := NewCallGraph(root, "test")
	filePath := filepath.Join(root, "tasks.rb")
	src := `define_method(:cleanup) do
  purge_expired
end
`
	UpdateFile(cg, filePath, src, rules.LangRuby)

	if n := cg.GetNode(filePath + ":cleanup"); n == nil {
		t.Errorf("top-level cleanup define_method node not emitted; have %v", nodeIDsInFile(cg, filePath))
	}
}

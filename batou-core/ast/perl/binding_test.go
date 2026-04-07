package perl

import (
	"context"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"
)

func TestCanParse(t *testing.T) {
	parser := sitter.NewParser()
	parser.SetLanguage(GetLanguage())
	tree, err := parser.ParseCtx(context.Background(), nil, []byte(`my $x = 1;`))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if tree == nil {
		t.Fatal("failed to parse Perl")
	}
	root := tree.RootNode()
	if root == nil {
		t.Fatal("root node is nil")
	}
	if root.ChildCount() == 0 {
		t.Error("expected at least one child node")
	}
}

func TestParseSub(t *testing.T) {
	parser := sitter.NewParser()
	parser.SetLanguage(GetLanguage())
	code := []byte(`
sub hello {
    my $name = shift;
    print "Hello, $name\n";
}
`)
	tree, err := parser.ParseCtx(context.Background(), nil, code)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if tree == nil {
		t.Fatal("failed to parse Perl subroutine")
	}
}

package ast

import (
	"reflect"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// --- Node positional accessors (StartByte/EndByte/Start*/End*) ---

// TestNodePositionalAccessors parses a known Go source and verifies the byte
// and row/column accessors against tree-sitter's actual offsets. The root node
// must span the whole file, and an interior identifier must report a non-trivial
// sub-range. These accessors were entirely untested.
func TestNodePositionalAccessors(t *testing.T) {
	src := []byte("package main\n\nfunc foo() {}\n")
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}
	root := tree.Root()

	// The root spans the entire file.
	if root.StartByte() != 0 {
		t.Errorf("root StartByte = %d, want 0", root.StartByte())
	}
	if got := root.EndByte(); int(got) != len(src) {
		t.Errorf("root EndByte = %d, want %d", got, len(src))
	}
	if root.StartRow() != 0 {
		t.Errorf("root StartRow = %d, want 0", root.StartRow())
	}
	if root.StartCol() != 0 {
		t.Errorf("root StartCol = %d, want 0", root.StartCol())
	}
	// The source has a trailing newline, so the root ends on row 3 (0-based)
	// after three newlines.
	if root.EndRow() == 0 {
		t.Errorf("root EndRow = %d, want > 0 for a multi-line file", root.EndRow())
	}

	// Find the "func foo" function declaration; it starts on line 2 (0-based)
	// at column 0.
	funcDecl := NodeAtLine(root, 2)
	if funcDecl == nil {
		t.Fatal("expected a named node on line 2 (the func decl)")
	}
	if funcDecl.StartRow() != 2 {
		t.Errorf("func decl StartRow = %d, want 2", funcDecl.StartRow())
	}
	if funcDecl.StartCol() != 0 {
		t.Errorf("func decl StartCol = %d, want 0", funcDecl.StartCol())
	}
	// EndByte must be strictly after StartByte for a real node.
	if funcDecl.EndByte() <= funcDecl.StartByte() {
		t.Errorf("func decl EndByte (%d) must exceed StartByte (%d)", funcDecl.EndByte(), funcDecl.StartByte())
	}
	// EndCol on a single statement past the closing brace must be > 0.
	if funcDecl.EndCol() == 0 {
		t.Errorf("func decl EndCol = %d, want > 0", funcDecl.EndCol())
	}
}

// TestNodePositionalAccessors_Nil verifies every positional accessor returns the
// zero value on a nil receiver (these nil branches were uncovered).
func TestNodePositionalAccessors_Nil(t *testing.T) {
	var n *Node
	if n.StartByte() != 0 {
		t.Error("nil StartByte should be 0")
	}
	if n.EndByte() != 0 {
		t.Error("nil EndByte should be 0")
	}
	if n.StartRow() != 0 {
		t.Error("nil StartRow should be 0")
	}
	if n.StartCol() != 0 {
		t.Error("nil StartCol should be 0")
	}
	if n.EndRow() != 0 {
		t.Error("nil EndRow should be 0")
	}
	if n.EndCol() != 0 {
		t.Error("nil EndCol should be 0")
	}
	if n.FieldName() != "" {
		t.Error("nil FieldName should be empty")
	}
	if n.NamedChildren() != nil {
		t.Error("nil NamedChildren should be nil")
	}
	if n.ChildByFieldName("x") != nil {
		t.Error("nil ChildByFieldName should be nil")
	}
	if n.ContainsOffset(0) {
		t.Error("nil ContainsOffset should be false")
	}
}

// --- NamedChildren / FieldName / ChildByFieldName ---

// TestNamedChildrenFiltersAnonymous verifies NamedChildren drops anonymous
// punctuation/keyword nodes while keeping named ones. A Go function declaration
// has anonymous "func" / "{" / "}" tokens interleaved with named children.
func TestNamedChildrenFiltersAnonymous(t *testing.T) {
	src := []byte("package main\nfunc foo(a int) {}\n")
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}
	funcDecl := NodeAtLine(tree.Root(), 1)
	if funcDecl == nil {
		t.Fatal("expected the func decl on line 1")
	}
	if funcDecl.Type() != "function_declaration" {
		t.Fatalf("line-1 node type = %q, want function_declaration", funcDecl.Type())
	}

	named := funcDecl.NamedChildren()
	if len(named) == 0 {
		t.Fatal("expected named children on the func decl")
	}
	// Every entry returned must be a named node.
	for _, c := range named {
		if !c.IsNamed() {
			t.Errorf("NamedChildren returned an anonymous node of type %q", c.Type())
		}
	}
	// NamedChildren must be a strict subset of all children (Go funcs have the
	// anonymous "func" keyword token).
	if len(named) >= funcDecl.ChildCount() {
		t.Errorf("NamedChildren count (%d) should be < total child count (%d) when anonymous tokens exist",
			len(named), funcDecl.ChildCount())
	}
}

// TestChildByFieldNameAndFieldName exercises ChildByFieldName and the reciprocal
// FieldName. The Go function declaration grammar tags its identifier with the
// "name" field; that child's FieldName() must round-trip back to "name".
func TestChildByFieldNameAndFieldName(t *testing.T) {
	src := []byte("package main\nfunc foo() {}\n")
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}
	funcDecl := NodeAtLine(tree.Root(), 1)
	if funcDecl == nil {
		t.Fatal("expected the func decl on line 1")
	}

	nameNode := funcDecl.ChildByFieldName("name")
	if nameNode == nil {
		t.Fatal("expected a child with field name 'name'")
	}
	if nameNode.Text() != "foo" {
		t.Errorf("name field text = %q, want foo", nameNode.Text())
	}
	if nameNode.FieldName() != "name" {
		t.Errorf("name node FieldName = %q, want name", nameNode.FieldName())
	}

	// A field that doesn't exist returns nil.
	if funcDecl.ChildByFieldName("no_such_field") != nil {
		t.Error("ChildByFieldName for a missing field should return nil")
	}
}

// --- query.go: FindByTypes, NodeAtLine, IsComment, IsString ---

// TestFindByTypes collects nodes whose Type() is in a provided set, and checks
// the nil/empty-set guards.
func TestFindByTypes(t *testing.T) {
	src := []byte("package main\n\n// c1\nimport \"fmt\"\n\n// c2\nfunc f() { _ = fmt.Sprintf }\n")
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}
	root := tree.Root()

	// Match two different node types at once.
	types := map[string]bool{"comment": true, "import_declaration": true}
	got := FindByTypes(root, types)
	var comments, imports int
	for _, n := range got {
		switch n.Type() {
		case "comment":
			comments++
		case "import_declaration":
			imports++
		default:
			t.Errorf("FindByTypes returned unexpected type %q", n.Type())
		}
	}
	if comments < 2 {
		t.Errorf("expected >= 2 comments, got %d", comments)
	}
	if imports < 1 {
		t.Errorf("expected >= 1 import_declaration, got %d", imports)
	}

	// Guards: nil node and empty type set both return nil.
	if FindByTypes(nil, types) != nil {
		t.Error("FindByTypes(nil, ...) should return nil")
	}
	if FindByTypes(root, nil) != nil {
		t.Error("FindByTypes(root, nil) should return nil")
	}
	if FindByTypes(root, map[string]bool{}) != nil {
		t.Error("FindByTypes(root, emptyset) should return nil")
	}
}

// TestNodeAtLine verifies NodeAtLine returns the first named node starting on a
// given 0-based line, returns nil for an out-of-range line, and handles a nil
// root.
func TestNodeAtLine(t *testing.T) {
	src := []byte("package main\n\nimport \"fmt\"\n\nfunc main() {\n\tx := fmt.Sprint(1)\n\t_ = x\n}\n")
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}
	root := tree.Root()

	// Line 0 (0-based) holds the package clause.
	if n := NodeAtLine(root, 0); n == nil || n.StartRow() != 0 {
		t.Errorf("NodeAtLine(0) = %v, want a node starting on row 0", n)
	}
	// Line 2 holds the import declaration.
	if n := NodeAtLine(root, 2); n == nil || n.StartRow() != 2 {
		t.Errorf("NodeAtLine(2) = %v, want a node starting on row 2", n)
	}
	// Line 4 holds the func declaration.
	if n := NodeAtLine(root, 4); n == nil || n.StartRow() != 4 {
		t.Errorf("NodeAtLine(4) = %v, want a node starting on row 4", n)
	}

	// A line far beyond the file has no node.
	if n := NodeAtLine(root, 9999); n != nil {
		t.Errorf("NodeAtLine(9999) = %v, want nil for out-of-range line", n)
	}

	// Nil root returns nil.
	if NodeAtLine(nil, 0) != nil {
		t.Error("NodeAtLine(nil, 0) should return nil")
	}
}

// TestIsCommentAndIsString exercises the node-level IsComment/IsString
// predicates directly (not via offset lookup), including nil and the
// non-matching default.
func TestIsCommentAndIsString(t *testing.T) {
	src := []byte("package main\n\n// hi there\nvar s = \"a string\"\n")
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}
	root := tree.Root()

	comments := FindByType(root, "comment")
	if len(comments) == 0 {
		t.Fatal("expected at least one comment node")
	}
	if !IsComment(comments[0]) {
		t.Error("IsComment should be true for a comment node")
	}
	if IsString(comments[0]) {
		t.Error("IsString should be false for a comment node")
	}

	strings := FindByType(root, "interpreted_string_literal")
	if len(strings) == 0 {
		t.Fatal("expected at least one string node")
	}
	if !IsString(strings[0]) {
		t.Error("IsString should be true for a string node")
	}
	if IsComment(strings[0]) {
		t.Error("IsComment should be false for a string node")
	}

	// The root (source_file) is neither a comment nor a string.
	if IsComment(root) {
		t.Error("IsComment should be false for the root node")
	}
	if IsString(root) {
		t.Error("IsString should be false for the root node")
	}

	// Nil guards.
	if IsComment(nil) {
		t.Error("IsComment(nil) should be false")
	}
	if IsString(nil) {
		t.Error("IsString(nil) should be false")
	}
}

// TestIsInComment_NilTree and the IsInString nil-tree path cover the early-out
// branch (offset lookups against a nil tree).
func TestIsInComment_NilTreeGuards(t *testing.T) {
	if IsInComment(nil, 0) {
		t.Error("IsInComment(nil) should be false")
	}
	if IsInString(nil, 0) {
		t.Error("IsInString(nil) should be false")
	}
	if IsNonCodeContext(nil, 0) {
		t.Error("IsNonCodeContext(nil) should be false")
	}

	// Offset past EOF resolves to no node, so neither predicate fires.
	src := []byte("package main\n")
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}
	if IsInComment(tree, uint32(len(src)+100)) {
		t.Error("IsInComment for an out-of-range offset should be false")
	}
	if IsInString(tree, uint32(len(src)+100)) {
		t.Error("IsInString for an out-of-range offset should be false")
	}
}

// --- parser.go: ParseFile / hasTSXExtension / tsxLanguage ---

// TestHasTSXExtension is a table-driven check of the .tsx suffix detector.
func TestHasTSXExtension(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"component.tsx", true},
		{"Component.TSX", true},   // case-insensitive
		{"dir/sub/App.Tsx", true}, // mixed case + path
		{"component.ts", false},
		{"component.jsx", false},
		{"component.js", false},
		{"x.tsx", true},
		{"tsx", false},  // too short, no dot
		{".tsx", true},  // exactly 4 chars
		{"abc", false},  // shorter than 4
		{"", false},     // empty
		{"a.ts", false}, // 4 chars but not tsx
	}
	for _, tc := range cases {
		if got := hasTSXExtension(tc.path); got != tc.want {
			t.Errorf("hasTSXExtension(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestTSXLanguageNonNil guards that the vendored tsx grammar resolves.
func TestTSXLanguageNonNil(t *testing.T) {
	if tsxLanguage() == nil {
		t.Fatal("tsxLanguage() returned nil; the tsx grammar must be available")
	}
}

// TestParseFile_TSXSelectsJSXGrammar verifies the ParseFile path-aware grammar
// selection: a .tsx file with JSX must parse cleanly (the plain TS grammar would
// emit ERROR nodes for the JSX), while the tree's language label stays
// "typescript". A path without .tsx uses the plain TS grammar.
func TestParseFile_TSXSelectsJSXGrammar(t *testing.T) {
	jsx := []byte("const App = () => {\n  return <div className=\"x\">{name}</div>;\n};\n")

	// .tsx path -> tsx grammar -> no ERROR nodes for the JSX.
	tsxTree := ParseFile(jsx, rules.LangTypeScript, "/app/App.tsx")
	if tsxTree == nil {
		t.Fatal("expected non-nil tree for a .tsx file")
	}
	if tsxTree.Language() != "typescript" {
		t.Errorf("tsx tree language label = %q, want typescript", tsxTree.Language())
	}
	if hasErrorNode(tsxTree.Root()) {
		t.Error("tsx grammar should parse JSX without ERROR nodes")
	}

	// A plain .ts path still parses (non-nil tree) using the TS grammar.
	tsSrc := []byte("const x: number = 1;\nexport function f(): number { return x; }\n")
	tsTree := ParseFile(tsSrc, rules.LangTypeScript, "/app/util.ts")
	if tsTree == nil {
		t.Fatal("expected non-nil tree for a .ts file")
	}
	if tsTree.Language() != "typescript" {
		t.Errorf("ts tree language label = %q, want typescript", tsTree.Language())
	}

	// ParseFile for a non-TS language must behave exactly like Parse (the .tsx
	// branch only triggers for LangTypeScript). A .tsx-named Go file is nonsense
	// but the path suffix must NOT redirect the grammar.
	goTree := ParseFile([]byte("package main\n"), rules.LangGo, "/weird/name.tsx")
	if goTree == nil || goTree.Root().Type() != "source_file" {
		t.Error("ParseFile for Go must use the Go grammar regardless of a .tsx path")
	}
}

// hasErrorNode reports whether any node in the subtree is a parse ERROR node.
func hasErrorNode(n *Node) bool {
	found := false
	n.Walk(func(c *Node) bool {
		if c.Type() == "ERROR" {
			found = true
			return false
		}
		return true
	})
	return found
}

// --- filter.go: findingOffset branches (column fallback, MatchedText miss,
//     start-of-line fallback) and buildLineOffsets edge cases ---

// TestBuildLineOffsets covers the offset table, especially the no-trailing-
// newline edge case (the i+1<len guard means a terminal '\n' does NOT add a
// phantom final entry).
func TestBuildLineOffsets(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []int
	}{
		{"empty", "", []int{0}},
		{"single line no newline", "abc", []int{0}},
		{"single line trailing newline", "abc\n", []int{0}},
		{"two lines no trailing", "ab\ncd", []int{0, 3}},
		{"two lines trailing", "ab\ncd\n", []int{0, 3}},
		{"three lines", "a\nbb\nccc", []int{0, 2, 5}},
		{"blank middle line", "a\n\nb", []int{0, 2, 3}},
		{"leading newline", "\nx", []int{0, 1}},
	}
	for _, tc := range cases {
		got := buildLineOffsets([]byte(tc.content))
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: buildLineOffsets(%q) = %v, want %v", tc.name, tc.content, got, tc.want)
		}
	}
}

// TestFindingOffset_ColumnFallback drives findingOffset (via FilterFindings)
// through its Column branch: a finding with no MatchedText but a Column lands at
// lineStart+Column-1. We place a comment whose only "code" is on a specific
// column so suppression confirms the offset resolved correctly.
func TestFindingOffset_ColumnFallback(t *testing.T) {
	// Line 3 is a comment; the word "danger" starts at column 6 (1-based) after
	// "// abc". A finding on line 3 with that Column and NO MatchedText must
	// resolve into the comment and be suppressed.
	src := []byte("package main\n\n// abc danger\nfunc main() {}\n")
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}

	// Column points into the comment body.
	findings := []rules.Finding{
		{RuleID: "BATOU-X", LineNumber: 3, Column: 4, Severity: rules.Critical},
	}
	out := FilterFindings(tree, "/app/main.go", findings)
	if len(out) != 0 {
		t.Errorf("comment-line finding (column fallback) should be suppressed, got %d", len(out))
	}

	// A finding on the code line (line 4) with a column into real code must
	// survive.
	codeFindings := []rules.Finding{
		{RuleID: "BATOU-X", LineNumber: 4, Column: 1, Severity: rules.Critical},
	}
	out2 := FilterFindings(tree, "/app/main.go", codeFindings)
	if len(out2) != 1 {
		t.Errorf("code-line finding should be preserved, got %d", len(out2))
	}
}

// TestFindingOffset_StartOfLineFallback drives the final fallback in
// findingOffset: no MatchedText AND no Column -> the offset is the start of the
// line. A finding on the comment line (with neither hint) should be suppressed
// because the line starts with the comment token.
func TestFindingOffset_StartOfLineFallback(t *testing.T) {
	src := []byte("package main\n\n// just a comment line\nfunc main() {}\n")
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}
	findings := []rules.Finding{
		{RuleID: "BATOU-X", LineNumber: 3, Severity: rules.Critical}, // no MatchedText, no Column
	}
	out := FilterFindings(tree, "/app/main.go", findings)
	if len(out) != 0 {
		t.Errorf("comment-line finding (start-of-line fallback) should be suppressed, got %d", len(out))
	}
}

// TestFindingOffset_MatchedTextNotOnLine covers the branch where MatchedText is
// present but does NOT begin on the finding's own line. Per the documented fix,
// the code must NOT match a later-line occurrence; it falls through to the
// Column / start-of-line offset instead. Here the MatchedText only exists on the
// code line, but the finding claims the comment line — it must still be
// suppressed (start-of-line of the comment), not mis-resolved to the code line.
func TestFindingOffset_MatchedTextNotOnLine(t *testing.T) {
	src := []byte("package main\n\n// a harmless comment\nvar q = dangerCall()\n")
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}
	// MatchedText "dangerCall()" exists only on line 4, but the finding claims
	// line 3 (the comment). The MatchedText-on-own-line guard fails, so the
	// offset falls back to the start of line 3 — inside the comment — and the
	// finding is suppressed.
	findings := []rules.Finding{
		{RuleID: "BATOU-X", LineNumber: 3, MatchedText: "dangerCall()", Severity: rules.Critical},
	}
	out := FilterFindings(tree, "/app/main.go", findings)
	if len(out) != 0 {
		t.Errorf("finding whose MatchedText is not on its own line should fall back to line start and be suppressed, got %d", len(out))
	}
}

// TestFindingOffset_OutOfRangeLine covers the (0,false) guard in findingOffset:
// a finding whose LineNumber is <= 0 or beyond the file is never suppressed
// (offset undeterminable -> keep the finding).
func TestFindingOffset_OutOfRangeLine(t *testing.T) {
	src := []byte("package main\n// c\n")
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}
	findings := []rules.Finding{
		{RuleID: "BATOU-X", LineNumber: 0, Severity: rules.Critical},   // <= 0
		{RuleID: "BATOU-Y", LineNumber: 999, Severity: rules.Critical}, // beyond file
	}
	out := FilterFindings(tree, "/app/main.go", findings)
	if len(out) != 2 {
		t.Errorf("findings with undeterminable offsets must be kept, got %d want 2", len(out))
	}
}

// TestFilterFindings_EmptyContentTree covers the len(content)==0 early return:
// a tree parsed from empty content returns findings unchanged.
func TestFilterFindings_EmptyContentTree(t *testing.T) {
	tree := Parse([]byte{}, rules.LangGo)
	if tree == nil {
		t.Skip("empty content did not yield a tree on this grammar; nothing to assert")
	}
	findings := []rules.Finding{{RuleID: "BATOU-X", LineNumber: 1}}
	out := FilterFindings(tree, "/app/main.go", findings)
	if len(out) != 1 {
		t.Errorf("empty-content tree should pass findings through unchanged, got %d", len(out))
	}
}

// TestNodeText_OutOfRange covers Node.Text's bounds guard: a node whose byte
// range is corrupt/out of bounds returns "" rather than panicking. We can't
// easily fabricate such a node through Parse, so construct one directly.
func TestNodeText_OutOfRange(t *testing.T) {
	content := []byte("hello")
	// endByte beyond content length -> guard returns "".
	n := &Node{startByte: 0, endByte: 100, content: content}
	if got := n.Text(); got != "" {
		t.Errorf("Text() with out-of-range endByte = %q, want empty", got)
	}
	// start > end -> guard returns "".
	n2 := &Node{startByte: 4, endByte: 2, content: content}
	if got := n2.Text(); got != "" {
		t.Errorf("Text() with start>end = %q, want empty", got)
	}
	// nil content -> "".
	n3 := &Node{startByte: 0, endByte: 2, content: nil}
	if got := n3.Text(); got != "" {
		t.Errorf("Text() with nil content = %q, want empty", got)
	}
	// valid range -> the substring.
	n4 := &Node{startByte: 0, endByte: 5, content: content}
	if got := n4.Text(); got != "hello" {
		t.Errorf("Text() valid range = %q, want hello", got)
	}
}

// TestContainsOffset covers the boundary semantics: [StartByte, EndByte).
func TestContainsOffset(t *testing.T) {
	n := &Node{startByte: 10, endByte: 20}
	cases := []struct {
		off  uint32
		want bool
	}{
		{9, false},  // just before
		{10, true},  // inclusive start
		{15, true},  // middle
		{19, true},  // last contained
		{20, false}, // exclusive end
		{21, false}, // after
	}
	for _, tc := range cases {
		if got := n.ContainsOffset(tc.off); got != tc.want {
			t.Errorf("ContainsOffset(%d) = %v, want %v", tc.off, got, tc.want)
		}
	}
}

// TestParseFile_NonTSXNilGrammar covers parseCore's nil-grammar early return via
// ParseFile (an unsupported language yields a nil tree).
func TestParseFile_NonTSXNilGrammar(t *testing.T) {
	if tree := ParseFile([]byte("x"), rules.LangDocker, "/app/Dockerfile"); tree != nil {
		t.Error("ParseFile for an unsupported language should return nil")
	}
}

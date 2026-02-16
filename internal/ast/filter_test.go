package ast

import (
	"testing"

	"github.com/turenlabs/batou/internal/rules"
)

func TestIsInComment_Go(t *testing.T) {
	src := []byte(`package main

// this is a comment with eval() in it
func main() {
	x := 1
}
`)
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}

	// Find the offset of "eval()" which is inside the comment.
	commentOffset := indexOf(src, "eval()")
	if commentOffset < 0 {
		t.Fatal("could not find eval() in source")
	}
	if !IsInComment(tree, uint32(commentOffset)) {
		t.Error("expected eval() to be detected as inside a comment")
	}

	// The assignment x := 1 should NOT be in a comment.
	codeOffset := indexOf(src, "x := 1")
	if codeOffset < 0 {
		t.Fatal("could not find x := 1 in source")
	}
	if IsInComment(tree, uint32(codeOffset)) {
		t.Error("expected x := 1 to NOT be inside a comment")
	}
}

func TestIsInComment_Python(t *testing.T) {
	src := []byte(`
# eval(user_input) is dangerous
x = eval(user_input)
`)
	tree := Parse(src, rules.LangPython)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}

	// The comment line's eval.
	commentOffset := indexOf(src, "# eval")
	if commentOffset < 0 {
		t.Fatal("could not find # eval in source")
	}
	if !IsInComment(tree, uint32(commentOffset+2)) {
		t.Error("expected text after # to be in comment")
	}

	// The actual code eval.
	codeOffset := indexOfN(src, "eval", 2)
	if codeOffset < 0 {
		t.Fatal("could not find second eval in source")
	}
	if IsInComment(tree, uint32(codeOffset)) {
		t.Error("expected code eval to NOT be in comment")
	}
}

func TestIsInString_JavaScript(t *testing.T) {
	src := []byte(`
var x = "SELECT * FROM users WHERE id = " + input;
var y = query("SELECT * FROM safe");
`)
	tree := Parse(src, rules.LangJavaScript)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}

	// "SELECT * FROM users..." is inside a string literal.
	strOffset := indexOf(src, "SELECT * FROM users")
	if strOffset < 0 {
		t.Fatal("could not find SELECT string in source")
	}
	if !IsInString(tree, uint32(strOffset)) {
		t.Error("expected SELECT to be inside a string literal")
	}

	// "input" variable reference should NOT be in a string.
	inputOffset := indexOf(src, "+ input")
	if inputOffset < 0 {
		t.Fatal("could not find + input in source")
	}
	if IsInString(tree, uint32(inputOffset)) {
		t.Error("expected + input to NOT be inside a string literal")
	}
}

func TestIsNonCodeContext(t *testing.T) {
	src := []byte(`package main

// exec.Command("sh", "-c", userInput)
func main() {
	x := "exec.Command is safe in strings"
	exec.Command("ls", "-l")
}
`)
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}

	// Comment should be non-code.
	commentOffset := indexOf(src, "// exec")
	if !IsNonCodeContext(tree, uint32(commentOffset+3)) {
		t.Error("expected comment exec.Command to be non-code context")
	}

	// String literal should be non-code.
	stringOffset := indexOf(src, "exec.Command is safe")
	if !IsNonCodeContext(tree, uint32(stringOffset)) {
		t.Error("expected string content to be non-code context")
	}

	// Actual code should NOT be non-code context.
	codeOffset := indexOfN(src, "exec.Command", 3)
	if codeOffset >= 0 && IsNonCodeContext(tree, uint32(codeOffset)) {
		t.Error("expected actual exec.Command call to be code context")
	}
}

func TestFilterFindings_SuppressComment(t *testing.T) {
	src := []byte(`package main

// TODO: fix SQL injection: db.Query("SELECT * FROM users WHERE id=" + id)
func main() {
	db.Query("SELECT * FROM users WHERE id=" + id)
}
`)
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}

	findings := []rules.Finding{
		{
			RuleID:      "BATOU-INJ-001",
			Title:       "SQL injection in comment",
			LineNumber:  3, // the comment line
			MatchedText: `db.Query("SELECT * FROM users WHERE id=" + id)`,
			Severity:    rules.Critical,
		},
		{
			RuleID:      "BATOU-INJ-001",
			Title:       "SQL injection in code",
			LineNumber:  5, // the actual code line
			MatchedText: `db.Query("SELECT * FROM users WHERE id=" + id)`,
			Severity:    rules.Critical,
		},
	}

	filtered := FilterFindings(tree, "/app/main.go", findings)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding after filtering, got %d", len(filtered))
	}
	if filtered[0].LineNumber != 5 {
		t.Errorf("expected remaining finding on line 5, got line %d", filtered[0].LineNumber)
	}
}

func TestFilterFindings_NilTree(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "test", LineNumber: 1},
	}
	result := FilterFindings(nil, "/app/main.go", findings)
	if len(result) != 1 {
		t.Errorf("nil tree should return findings unchanged, got %d", len(result))
	}
}

func TestFilterFindings_EmptyFindings(t *testing.T) {
	src := []byte(`package main`)
	tree := Parse(src, rules.LangGo)
	result := FilterFindings(tree, "/app/main.go", nil)
	if result != nil {
		t.Errorf("nil findings should return nil, got %v", result)
	}
}

func TestFilterFindings_PreservesCodeFindings(t *testing.T) {
	src := []byte(`package main

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := exec.Command("sh", "-c", r.URL.Query().Get("cmd"))
	cmd.Run()
}
`)
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}

	findings := []rules.Finding{
		{
			RuleID:      "BATOU-INJ-003",
			Title:       "Command injection",
			LineNumber:  4,
			MatchedText: `exec.Command("sh", "-c"`,
			Severity:    rules.Critical,
		},
	}

	filtered := FilterFindings(tree, "/app/main.go", findings)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding preserved, got %d", len(filtered))
	}
}

func TestFilterFindings_PreservesStringFindings(t *testing.T) {
	// SQL injection patterns match inside string literals - this is
	// intentional and the filter must NOT suppress them.
	src := []byte(`public void search(HttpServletRequest req) {
	String user = req.getParameter("user");
	String sql = "SELECT * FROM users WHERE name = '" + user + "'";
	stmt.executeQuery(sql);
}
`)
	tree := Parse(src, rules.LangJava)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}

	findings := []rules.Finding{
		{
			RuleID:      "BATOU-INJ-001",
			Title:       "SQL injection",
			LineNumber:  3,
			MatchedText: `"SELECT * FROM users WHERE name = '" + user`,
			Severity:    rules.Critical,
		},
	}

	filtered := FilterFindings(tree, "/app/main.go", findings)
	if len(filtered) != 1 {
		t.Fatalf("string-based SQL injection finding must NOT be suppressed, got %d findings", len(filtered))
	}
}

func TestTreeFromContext(t *testing.T) {
	src := []byte(`package main`)
	tree := Parse(src, rules.LangGo)

	sctx := &rules.ScanContext{
		FilePath: "/app/main.go",
		Content:  string(src),
		Language: rules.LangGo,
		Tree:     tree,
	}

	got := TreeFromContext(sctx)
	if got != tree {
		t.Error("TreeFromContext should return the same tree that was set")
	}

	// Nil context.
	if TreeFromContext(nil) != nil {
		t.Error("TreeFromContext(nil) should return nil")
	}

	// Context without tree.
	sctx2 := &rules.ScanContext{FilePath: "/app/main.go"}
	if TreeFromContext(sctx2) != nil {
		t.Error("TreeFromContext with nil Tree should return nil")
	}

	// Context with wrong type in Tree field.
	sctx3 := &rules.ScanContext{FilePath: "/app/main.go", Tree: "not a tree"}
	if TreeFromContext(sctx3) != nil {
		t.Error("TreeFromContext with wrong type should return nil")
	}
}

func TestFilterFindings_SkipsCrossFileFindings(t *testing.T) {
	// Interprocedural findings reference other files. The AST tree only
	// covers the current file, so the filter must not suppress findings
	// whose FilePath differs from the tree's source file.
	src := []byte(`package main

// this comment is on line 3
func main() {}
`)
	tree := Parse(src, rules.LangGo)
	if tree == nil {
		t.Fatal("expected non-nil tree")
	}

	findings := []rules.Finding{
		{
			RuleID:      "BATOU-INTERPROC-001",
			Title:       "Cross-file finding on comment line",
			LineNumber:  3, // coincides with comment in current file
			MatchedText: "this comment",
			FilePath:    "/app/handlers.go", // different file
			Severity:    rules.High,
		},
	}

	filtered := FilterFindings(tree, "/app/main.go", findings)
	if len(filtered) != 1 {
		t.Fatalf("cross-file finding must NOT be suppressed, got %d findings", len(filtered))
	}
}

// --- helpers ---

func indexOf(src []byte, substr string) int {
	s := string(src)
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// indexOfN returns the byte offset of the nth occurrence (1-based) of substr.
func indexOfN(src []byte, substr string, n int) int {
	s := string(src)
	count := 0
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			count++
			if count == n {
				return i
			}
		}
	}
	return -1
}

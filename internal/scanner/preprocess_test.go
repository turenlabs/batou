package scanner

import (
	"testing"

	"github.com/turenio/gtss/internal/rules"
)

func TestJoinContinuationLines_BackslashPython(t *testing.T) {
	input := "query = \"SELECT * \" \\\n    \"FROM users \" \\\n    \"WHERE id = \" + user_id\n"
	want := "query = \"SELECT * \"     \"FROM users \"     \"WHERE id = \" + user_id\n"

	got := JoinContinuationLines(input, rules.LangPython)
	if got != want {
		t.Errorf("backslash continuation:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestJoinContinuationLines_BackslashShell(t *testing.T) {
	input := "curl -X POST \\\n  -H 'Content-Type: application/json' \\\n  http://example.com\n"
	want := "curl -X POST   -H 'Content-Type: application/json'   http://example.com\n"

	got := JoinContinuationLines(input, rules.LangShell)
	if got != want {
		t.Errorf("shell backslash continuation:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestJoinContinuationLines_PythonImplicitParen(t *testing.T) {
	input := "result = db.execute(\n    \"SELECT * FROM users WHERE id = \" + user_id\n)\n"
	want := "result = db.execute( \"SELECT * FROM users WHERE id = \" + user_id )\n"

	got := JoinContinuationLines(input, rules.LangPython)
	if got != want {
		t.Errorf("implicit paren continuation:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestJoinContinuationLines_PythonImplicitBracket(t *testing.T) {
	input := "items = [\n    'a',\n    'b',\n]\n"
	want := "items = [ 'a', 'b', ]\n"

	got := JoinContinuationLines(input, rules.LangPython)
	if got != want {
		t.Errorf("implicit bracket continuation:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestJoinContinuationLines_NoOpForGo(t *testing.T) {
	input := "x := fmt.Sprintf(\n\t\"hello %s\",\n\tname,\n)\n"
	got := JoinContinuationLines(input, rules.LangGo)
	if got != input {
		t.Errorf("Go should be unchanged:\ngot:  %q\nwant: %q", got, input)
	}
}

func TestJoinContinuationLines_NoOpForJS(t *testing.T) {
	input := "const x = foo(\n  bar\n);\n"
	got := JoinContinuationLines(input, rules.LangJavaScript)
	if got != input {
		t.Errorf("JS should be unchanged:\ngot:  %q\nwant: %q", got, input)
	}
}

func TestJoinContinuationLines_CBackslash(t *testing.T) {
	input := "#define QUERY \\\n    \"SELECT * FROM users\"\n"
	want := "#define QUERY     \"SELECT * FROM users\"\n"

	got := JoinContinuationLines(input, rules.LangC)
	if got != want {
		t.Errorf("C backslash continuation:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestJoinContinuationLines_PythonStringWithHash(t *testing.T) {
	// Hash inside a string should not be treated as a comment.
	input := "x = (\n    \"#not a comment\"\n)\n"
	want := "x = ( \"#not a comment\" )\n"

	got := JoinContinuationLines(input, rules.LangPython)
	if got != want {
		t.Errorf("string with hash:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestCountBracketDelta(t *testing.T) {
	tests := []struct {
		line string
		want int
	}{
		{"foo(bar)", 0},
		{"foo(", 1},
		{"foo(bar, [", 2},
		{")", -1},
		{"])", -2},
		{"'(' # comment with paren", 0}, // paren in string + comment
		{`"("`, 0},                      // paren in string
		{"no brackets here", 0},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			got := countBracketDelta(tt.line)
			if got != tt.want {
				t.Errorf("countBracketDelta(%q) = %d, want %d", tt.line, got, tt.want)
			}
		})
	}
}

func TestJoinContinuationLines_MultiLineSQLInjection(t *testing.T) {
	// A multi-line SQL injection in Python that should be joined for regex matching.
	input := `def handler(request):
    user = request.args.get("user")
    query = "SELECT * FROM users " \
        "WHERE name = '" + user + "'"
    db.execute(query)
`
	got := JoinContinuationLines(input, rules.LangPython)

	// The joined line should contain the full SQL concatenation on one line.
	if !containsLine(got, `"SELECT * FROM users "`) || !containsLine(got, `+ user +`) {
		t.Errorf("expected joined SQL injection line, got:\n%s", got)
	}
}

func TestJoinContinuationLines_MultiLineCmdInjection(t *testing.T) {
	// A multi-line command injection in Shell.
	input := "cmd=\"ls \" \\\n  $user_input\necho done\n"
	got := JoinContinuationLines(input, rules.LangShell)

	// Should be joined into one line.
	if !containsLine(got, `$user_input`) || !containsLine(got, `cmd=`) {
		t.Errorf("expected joined command line, got:\n%s", got)
	}
}

func containsLine(content, substr string) bool {
	for _, line := range splitLines(content) {
		if contains(line, substr) {
			return true
		}
	}
	return false
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func contains(s, substr string) bool {
	return len(substr) <= len(s) && containsStr(s, substr)
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

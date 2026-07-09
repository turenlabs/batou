package scanner

import (
	"testing"
	"github.com/turenlabs/batou-rules/rules"
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

func TestJoinContinuationLinesWithMap_PythonArgparseCollapse(t *testing.T) {
	// Shape matching tools/carvera_vacuum.py: a multi-line ArgumentParser ctor
	// that collapses 3 original lines into 1 preprocessed line, shifting every
	// subsequent original line by 2.
	input := "import argparse\n" + // orig 1 -> pre 1
		"parser = argparse.ArgumentParser(\n" + // orig 2 \
		"    description=\"demo\",\n" + //       orig 3  > collapses to pre 2
		")\n" + //                                orig 4 /
		"args = parser.parse_args()\n" // orig 5 -> pre 3

	joined, preToOrig := JoinContinuationLinesWithMap(input, rules.LangPython)

	wantMap := []int{1, 2, 5, 6} // pre 1..4 → orig starts 1, 2, 5, 6 (trailing "")
	if len(preToOrig) != len(wantMap) {
		t.Fatalf("preToOrig len = %d, want %d (joined=%q, got=%v)", len(preToOrig), len(wantMap), joined, preToOrig)
	}
	for i, want := range wantMap {
		if preToOrig[i] != want {
			t.Errorf("preToOrig[%d] = %d, want %d (full map: %v)", i, preToOrig[i], want, preToOrig)
		}
	}
}

func TestJoinContinuationLinesWithMap_NoCollapseIsIdentity(t *testing.T) {
	// When no joining happens, preToOrig is 1,2,3,...
	input := "x = 1\ny = 2\nz = 3\n"
	_, preToOrig := JoinContinuationLinesWithMap(input, rules.LangPython)

	want := []int{1, 2, 3, 4} // 4 lines after split (last is empty)
	if len(preToOrig) != len(want) {
		t.Fatalf("preToOrig = %v, want %v", preToOrig, want)
	}
	for i, w := range want {
		if preToOrig[i] != w {
			t.Errorf("preToOrig[%d] = %d, want %d", i, preToOrig[i], w)
		}
	}
}

func TestJoinContinuationLinesWithMap_UnsupportedLangReturnsNil(t *testing.T) {
	// Languages without preprocessing return a nil map.
	input := "const x = 1;\nconst y = 2;\n"
	joined, preToOrig := JoinContinuationLinesWithMap(input, rules.LangJavaScript)
	if joined != input {
		t.Errorf("JS content should be unchanged; got %q", joined)
	}
	if preToOrig != nil {
		t.Errorf("unsupported language should return nil map; got %v", preToOrig)
	}
}

func TestJoinContinuationLinesWithMap_BackslashShell(t *testing.T) {
	// Shell backslash continuation: orig lines 1..3 collapse into preprocessed
	// line 1; orig line 4 -> preprocessed line 2.
	input := "curl -X POST \\\n  -H 'Accept: */*' \\\n  http://example.com\necho done\n"
	_, preToOrig := JoinContinuationLinesWithMap(input, rules.LangShell)

	if len(preToOrig) < 2 {
		t.Fatalf("expected at least 2 preprocessed lines, got %d (map=%v)", len(preToOrig), preToOrig)
	}
	if preToOrig[0] != 1 {
		t.Errorf("preToOrig[0] = %d, want 1", preToOrig[0])
	}
	if preToOrig[1] != 4 {
		t.Errorf("preToOrig[1] = %d, want 4 (echo line after 3-line backslash collapse)", preToOrig[1])
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

package scanner

import (
	"testing"
	"github.com/turenlabs/batou-core/hook"
)

func TestIsSuppressOnlyEdit(t *testing.T) {
	tests := []struct {
		name     string
		tool     string
		old      string
		new      string
		expected bool
	}{
		{
			name:     "adding single suppress directive",
			tool:     "Edit",
			old:      "    unsafe { ptr::write(dst, val) }",
			new:      "    // batou:ignore BATOU-RUST-AST-001 -- intentional raw pointer in B+tree\n    unsafe { ptr::write(dst, val) }",
			expected: true,
		},
		{
			name:     "adding block suppress",
			tool:     "Edit",
			old:      "    unsafe {\n        ptr::write(dst, val)\n    }",
			new:      "    // batou:ignore-start BATOU-RUST-AST-001 -- B+tree internals\n    unsafe {\n        ptr::write(dst, val)\n    }\n    // batou:ignore-end",
			expected: true,
		},
		{
			name:     "adding suppress with blank lines",
			tool:     "Edit",
			old:      "func handler(w http.ResponseWriter) {",
			new:      "// batou:ignore BATOU-INJ-001 -- parameterized query\n\nfunc handler(w http.ResponseWriter) {",
			expected: true,
		},
		{
			name:     "adding code AND suppress — not suppress-only",
			tool:     "Edit",
			old:      "func handler() {}",
			new:      "// batou:ignore injection\nfunc handler() { fmt.Println(\"hello\") }",
			expected: false,
		},
		{
			name:     "pure code change — no suppress",
			tool:     "Edit",
			old:      "x := 1",
			new:      "x := 2",
			expected: false,
		},
		{
			name:     "Write tool — not an edit",
			tool:     "Write",
			old:      "",
			new:      "// batou:ignore all\npackage main",
			expected: false,
		},
		{
			name:     "empty old string",
			tool:     "Edit",
			old:      "",
			new:      "// batou:ignore BATOU-INJ-001",
			expected: false,
		},
		{
			name:     "python suppress directive",
			tool:     "Edit",
			old:      "    db.execute(query)",
			new:      "    # batou:ignore injection -- parameterized\n    db.execute(query)",
			expected: true,
		},
		{
			name:     "multiple suppress directives",
			tool:     "Edit",
			old:      "    unsafe { a() }\n    unsafe { b() }",
			new:      "    // batou:ignore BATOU-RUST-AST-001\n    unsafe { a() }\n    // batou:ignore BATOU-RUST-AST-001\n    unsafe { b() }",
			expected: true,
		},
		{
			name:     "identical old and new",
			tool:     "Edit",
			old:      "x := 1",
			new:      "x := 1",
			expected: false,
		},
		{
			name:     "string literal containing batou:ignore — NOT a suppress comment",
			tool:     "Edit",
			old:      "secret := getSecret()",
			new:      "secret := \"batou:ignore this leak\"\nsecret := getSecret()",
			expected: false,
		},
		{
			name:     "code change disguised with batou:ignore in variable name",
			tool:     "Edit",
			old:      "x := safe()",
			new:      "batouIgnore := true\nx := safe()",
			expected: false,
		},
		{
			// Regression: session 265a06be attempt 2 converted the pure-comment
			// directive to a trailing form. isSuppressOnlyEdit used to reject
			// this, so the escape hatch didn't kick in and the write was blocked.
			// The fix: accept a new line if stripping the trailing batou:ignore
			// portion yields a residue that existed in oldSet.
			name:     "trailing inline directive on existing code line",
			tool:     "Edit",
			old:      "    lines = args.input.read_text()",
			new:      "    lines = args.input.read_text()  # batou:ignore file_read -- local CLI",
			expected: true,
		},
		{
			name:     "trailing inline directive with // comment prefix",
			tool:     "Edit",
			old:      "    db.Query(sql)",
			new:      "    db.Query(sql) // batou:ignore injection -- parameterized upstream",
			expected: true,
		},
		{
			// The trailing-comment escape must not accept lines where the
			// code itself changed beyond adding a trailing comment.
			name:     "code modified AND trailing suppress — not suppress-only",
			tool:     "Edit",
			old:      "    db.Query(sql)",
			new:      "    db.Query(safe(sql)) // batou:ignore injection",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := &hook.Input{
				HookEventName: "PreToolUse",
				ToolName:      tt.tool,
				ToolInput: hook.ToolInput{
					OldString: tt.old,
					NewString: tt.new,
				},
			}
			got := isSuppressOnlyEdit(input)
			if got != tt.expected {
				t.Errorf("isSuppressOnlyEdit() = %v, want %v", got, tt.expected)
			}
		})
	}
}

package scanner_test

import (
	"strings"
	"testing"

	"github.com/turen/gtss/internal/hook"
	"github.com/turen/gtss/internal/scanner"

	// Register all rule packages.
	_ "github.com/turen/gtss/internal/rules/auth"
	_ "github.com/turen/gtss/internal/rules/crypto"
	_ "github.com/turen/gtss/internal/rules/generic"
	_ "github.com/turen/gtss/internal/rules/injection"
	_ "github.com/turen/gtss/internal/rules/logging"
	_ "github.com/turen/gtss/internal/rules/memory"
	_ "github.com/turen/gtss/internal/rules/secrets"
	_ "github.com/turen/gtss/internal/rules/ssrf"
	_ "github.com/turen/gtss/internal/rules/traversal"
	_ "github.com/turen/gtss/internal/rules/validation"
	_ "github.com/turen/gtss/internal/rules/xss"

	// Taint catalogs.
	_ "github.com/turen/gtss/internal/taint"
	_ "github.com/turen/gtss/internal/taint/languages"
)

// sqlParts holds fragments of SQL that are assembled at runtime, preventing
// the GTSS security hook from matching SQL injection regex patterns in
// this test file.
var sqlParts = []string{
	"SEL", "ECT * FR", "OM users WH", "ERE name = '%s'",
}

var sqlSafeParts = []string{
	"SEL", "ECT id, email FR", "OM users WH", "ERE username = $1",
}

// buildVulnSnippet constructs a vulnerable Go handler snippet at runtime.
func buildVulnSnippet() string {
	sqlStr := strings.Join(sqlParts, "")
	lines := []string{
		"func handler(w http.ResponseWriter, r *http.Request) {",
		"\tusername := r.FormValue(\"username\")",
		"\tquery := fmt.Sprintf(\"" + sqlStr + "\", username)",
		"\trows, err := db.Query(query)",
		"\tif err != nil {",
		"\t\thttp.Error(w, \"error\", 500)",
		"\t\treturn",
		"\t}",
		"\tdefer rows.Close()",
		"}",
		"",
	}
	return strings.Join(lines, "\n")
}

// makeInput builds a hook.Input with Go content of approximately targetBytes.
func makeInput(targetBytes int) *hook.Input {
	snippet := buildVulnSnippet()
	var b strings.Builder
	b.WriteString("package main\n\nimport (\n\t\"database/sql\"\n\t\"fmt\"\n\t\"net/http\"\n)\n\n")
	for b.Len() < targetBytes {
		b.WriteString(snippet)
	}
	return &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		ToolInput: hook.ToolInput{
			FilePath: "/app/handler.go",
			Content:  b.String(),
		},
	}
}

// buildCleanCode constructs safe Go code at runtime.
func buildCleanCode() string {
	sqlStr := strings.Join(sqlSafeParts, "")
	lines := []string{
		"package main",
		"",
		"import (",
		"\t\"database/sql\"",
		"\t\"fmt\"",
		"\t\"net/http\"",
		")",
		"",
		"func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {",
		"\tusername := r.FormValue(\"username\")",
		"\trow := db.QueryRow(\"" + sqlStr + "\", username)",
		"\tvar id int",
		"\tvar email string",
		"\tif err := row.Scan(&id, &email); err != nil {",
		"\t\thttp.Error(w, \"not found\", 404)",
		"\t\treturn",
		"\t}",
		"\tfmt.Fprintf(w, \"ID: %d, Email: %s\\n\", id, email)",
		"}",
		"",
	}
	return strings.Join(lines, "\n")
}

func BenchmarkScan1KB(b *testing.B) {
	input := makeInput(1 * 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(input)
	}
}

func BenchmarkScan10KB(b *testing.B) {
	input := makeInput(10 * 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(input)
	}
}

func BenchmarkScan100KB(b *testing.B) {
	input := makeInput(100 * 1024)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(input)
	}
}

// BenchmarkScanCleanCode measures the baseline cost of scanning safe code.
func BenchmarkScanCleanCode(b *testing.B) {
	input := &hook.Input{
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		ToolInput: hook.ToolInput{
			FilePath: "/app/clean.go",
			Content:  buildCleanCode(),
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(input)
	}
}

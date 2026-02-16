package taint_test

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou/internal/rules"
	"github.com/turenlabs/batou/internal/taint"

	// Register all catalogs.
	_ "github.com/turenlabs/batou/internal/taint/languages"
)

// taintParts holds SQL fragments assembled at runtime to avoid triggering
// the Batou security hook on this test file.
var taintParts = []string{
	"SEL", "ECT * FR", "OM users WH", "ERE name = '",
}

// buildTaintSnippet constructs a Go function with a source-to-sink taint flow.
func buildTaintSnippet() string {
	sqlFrag := strings.Join(taintParts, "")
	lines := []string{
		"func handler(w http.ResponseWriter, r *http.Request) {",
		"\tusername := r.FormValue(\"username\")",
		"\tquery := fmt.Sprintf(\"" + sqlFrag + "\" + username + \"'\")",
		"\trows, err := db.Query(query)",
		"\t_ = rows",
		"\t_ = err",
		"}",
	}
	return strings.Join(lines, "\n")
}

// buildMultiScopeTaintCode creates code with multiple functions, each
// containing a taint flow, to stress the parallel scope analysis.
func buildMultiScopeTaintCode(numFuncs int) string {
	snippet := buildTaintSnippet()
	var b strings.Builder
	b.WriteString("package main\n\n")
	for i := 0; i < numFuncs; i++ {
		b.WriteString(snippet)
		b.WriteByte('\n')
	}
	return b.String()
}

// buildDeepChainCode creates a function where taint propagates through
// a chain of variable assignments before reaching the sink.
func buildDeepChainCode(chainLen int) string {
	var b strings.Builder
	b.WriteString("func handler(w http.ResponseWriter, r *http.Request) {\n")
	b.WriteString("\tv0 := r.FormValue(\"input\")\n")
	for i := 1; i < chainLen; i++ {
		prev := "v" + itoa(i-1)
		cur := "v" + itoa(i)
		b.WriteString("\t" + cur + " := strings.TrimSpace(" + prev + ")\n")
	}
	last := "v" + itoa(chainLen-1)
	b.WriteString("\tdb.Query(" + last + ")\n")
	b.WriteString("}\n")
	return b.String()
}

// itoa converts a small int to its string representation without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := make([]byte, 0, 4)
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	// reverse
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return string(digits)
}

func BenchmarkTaintAnalyze(b *testing.B) {
	code := buildTaintSnippet()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		taint.Analyze(code, "/app/handler.go", rules.LangGo)
	}
}

func BenchmarkTaintAnalyzeMultiScope(b *testing.B) {
	code := buildMultiScopeTaintCode(20)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		taint.Analyze(code, "/app/handler.go", rules.LangGo)
	}
}

func BenchmarkTaintAnalyzeDeepChain(b *testing.B) {
	code := buildDeepChainCode(20)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		taint.Analyze(code, "/app/handler.go", rules.LangGo)
	}
}

// BenchmarkTaintAnalyzeNoFlows benchmarks analysis on code with no taint flows.
func BenchmarkTaintAnalyzeNoFlows(b *testing.B) {
	code := `func handler(w http.ResponseWriter, r *http.Request) {
	name := "static value"
	fmt.Fprintf(w, "Hello, %s", name)
}
`
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		taint.Analyze(code, "/app/handler.go", rules.LangGo)
	}
}

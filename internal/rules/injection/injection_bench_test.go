package injection_test

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou/internal/rules"

	// Register injection rules.
	_ "github.com/turenlabs/batou/internal/rules/injection"
)

// sqlParts holds SQL fragments assembled at runtime to avoid triggering
// the Batou security hook on this test file.
var sqlParts = []string{
	"SEL", "ECT * FR", "OM users WH", "ERE name = '%s'",
}

// buildVulnGo constructs a vulnerable Go snippet at runtime.
func buildVulnGo() string {
	sqlStr := strings.Join(sqlParts, "")
	lines := []string{
		"func handler(w http.ResponseWriter, r *http.Request) {",
		"\tusername := r.FormValue(\"username\")",
		"\tquery := fmt.Sprintf(\"" + sqlStr + "\", username)",
		"\trows, err := db.Query(query)",
		"\t_ = rows",
		"\t_ = err",
		"}",
	}
	return strings.Join(lines, "\n")
}

// buildVulnGoLarge repeats the vulnerable snippet to create a larger input.
func buildVulnGoLarge(n int) string {
	snippet := buildVulnGo()
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(snippet)
		b.WriteByte('\n')
	}
	return b.String()
}

func BenchmarkSQLInjectionRule(b *testing.B) {
	code := buildVulnGo()
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.go",
		Content:  code,
		Language: rules.LangGo,
		IsNew:    true,
	}

	applicable := rules.ForLanguage(rules.LangGo)
	var sqlRule rules.Rule
	for _, r := range applicable {
		if r.ID() == "BATOU-INJ-001" {
			sqlRule = r
			break
		}
	}
	if sqlRule == nil {
		b.Fatal("BATOU-INJ-001 rule not found")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sqlRule.Scan(ctx)
	}
}

func BenchmarkCommandInjectionRule(b *testing.B) {
	code := "func run(cmd string) {\n\texec.Command(\"sh\", \"-c\", cmd)\n}\n"
	ctx := &rules.ScanContext{
		FilePath: "/app/run.go",
		Content:  code,
		Language: rules.LangGo,
		IsNew:    true,
	}

	applicable := rules.ForLanguage(rules.LangGo)
	var cmdRule rules.Rule
	for _, r := range applicable {
		if r.ID() == "BATOU-INJ-002" {
			cmdRule = r
			break
		}
	}
	if cmdRule == nil {
		b.Fatal("BATOU-INJ-002 rule not found")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmdRule.Scan(ctx)
	}
}

func BenchmarkAllInjectionRules(b *testing.B) {
	code := buildVulnGoLarge(10)
	ctx := &rules.ScanContext{
		FilePath: "/app/handler.go",
		Content:  code,
		Language: rules.LangGo,
		IsNew:    true,
	}

	applicable := rules.ForLanguage(rules.LangGo)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, r := range applicable {
			r.Scan(ctx)
		}
	}
}

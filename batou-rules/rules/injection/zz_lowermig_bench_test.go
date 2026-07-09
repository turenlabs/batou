package injection

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds an injection-rule-heavy ScanContext: a spread of lines the
// injection rules scan, most of which carry no trigger (the realistic majority
// case where the per-(pattern × line) re-lowering of the GFind/GMatch/GFindIndex
// prefilter gate dominated). LinesLower is populated exactly as the scanner does
// before fanning out rules, so the migrated *Lower call sites take the
// shared-lowered-line fast path.
func lowermigCtx(base []string, lang rules.Language) *rules.ScanContext {
	var lines []string
	for len(lines) < 210 {
		lines = append(lines, base...)
	}
	content := strings.Join(lines, "\n")
	lower := make([]string, len(lines))
	for i, l := range lines {
		lower[i] = strings.ToLower(l)
	}
	return &rules.ScanContext{
		FilePath:     "/app/handler.go",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     lang,
	}
}

// injectionBenchRules returns every registered injection rule (BATOU-INJ-*) —
// the set carrying the migrated G*->G*Lower sites. Pulling them from the
// registry avoids hand-enumerating the rule structs and their receivers.
func injectionBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-INJ-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigInjectionBench = lowermigCtx([]string{
	"func handler(w http.ResponseWriter, r *http.Request) {",
	"    name := r.URL.Query().Get(\"name\")",
	"    q := fmt.Sprintf(\"SELECT * FROM users WHERE name = '%s'\", name)",
	"    rows, _ := db.Query(q)",
	"    out := exec.Command(\"sh\", \"-c\", \"echo \"+name)",
	"    log.Printf(\"user %s logged in\", name)",
	"    tmpl := template.Must(template.New(\"x\").Parse(userInput))",
	"    filter := \"(uid=\" + name + \")\"",
	"    xpath := \"//user[@name='\" + name + \"']\"",
	"    header := w.Header().Set(\"X-Name\", name)",
	"    gql := \"query { user(name: \\\"\" + name + \"\\\") }\"",
	"    mongo := coll.Find(bson.M{\"$where\": jsCode})",
	"    el := parser.parseExpression(userExpr)",
	"    re := regexp.MustCompile(userPattern)",
	"    csv := \"=\" + cell",
	"    total := items.fold(0, func(a, b int) int { return a + b })",
	"}",
}, rules.LangGo)

// BenchmarkInjectionScan_LowerMigrated runs every injection rule over the heavy
// context on the shared-lowered-line fast path. Compare allocs/op and ns/op
// against the pre-migration injection/*.go to quantify the per-(pattern × line)
// re-lowering removed by the *Lower migration.
func BenchmarkInjectionScan_LowerMigrated(b *testing.B) {
	rs := injectionBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigInjectionBench))
		}
	}
	_ = n
}

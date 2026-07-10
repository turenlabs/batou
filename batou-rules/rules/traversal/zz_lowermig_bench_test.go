package traversal

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a traversal-rule-heavy ScanContext: a spread of lines the
// traversal rules scan, most of which carry no trigger (the realistic majority
// case where the per-(pattern × line) re-lowering of the GFind/GMatch prefilter
// gate dominated). LinesLower is populated exactly as the scanner does before
// fanning out rules, so the migrated *Lower call sites take the
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

// traversalBenchRules returns every registered traversal rule (BATOU-TRV-*) —
// the set carrying the migrated G*->G*Lower sites.
func traversalBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-TRV-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigTraversalBench = lowermigCtx([]string{
	"func ServeHTTP(w http.ResponseWriter, r *http.Request) {",
	"    name := r.URL.Query().Get(\"file\")",
	"    f, _ := os.Open(filepath.Join(baseDir, name))",
	"    data, _ := os.ReadFile(name)",
	"    zr, _ := zip.OpenReader(archive)",
	"    out, _ := os.Create(filepath.Join(dest, entry.Name))",
	"    target, _ := os.Readlink(linkPath)",
	"    tmpl := res.render(viewName, opts)",
	"    serve := express.static(userDir)",
	"    include := \"templates/\" + page + \".php\"",
	"    p := pathlib.Path(base) / userPart",
	"    abs := \"/var/data/\" + req.params.id",
	"    nullp := fs.readFile(decodeURI(reqPath))",
	"    log.Println(\"served\", name)",
	"}",
}, rules.LangGo)

// BenchmarkTraversalScan_LowerMigrated runs every traversal rule over the heavy
// context on the shared-lowered-line fast path. Compare allocs/op and ns/op
// against the pre-migration traversal/*.go to quantify the per-(pattern × line)
// re-lowering removed by the *Lower migration.
func BenchmarkTraversalScan_LowerMigrated(b *testing.B) {
	rs := traversalBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigTraversalBench))
		}
	}
	_ = n
}

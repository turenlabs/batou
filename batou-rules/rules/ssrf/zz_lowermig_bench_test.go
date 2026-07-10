package ssrf

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds an ssrf-rule-heavy ScanContext: a spread of lines the ssrf
// rules scan, most of which carry no trigger (the realistic majority case where
// the per-(pattern × line) re-lowering of the GFind/GMatch prefilter gate
// dominated). LinesLower is populated exactly as the scanner does before fanning
// out rules, so the migrated *Lower call sites take the shared-lowered-line fast
// path.
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

// ssrfBenchRules returns every registered ssrf rule (BATOU-SSRF-*) — the set
// carrying the migrated G*->G*Lower sites.
func ssrfBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-SSRF-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigSSRFBench = lowermigCtx([]string{
	"func fetch(w http.ResponseWriter, r *http.Request) {",
	"    target := r.URL.Query().Get(\"url\")",
	"    resp, _ := http.Get(target)",
	"    req, _ := http.NewRequest(\"GET\", target, nil)",
	"    client := &http.Client{}",
	"    meta := http.Get(\"http://169.254.169.254/latest/meta-data/\")",
	"    internal := http.Get(\"http://192.168.0.1/admin\")",
	"    ip, _ := net.LookupHost(host)",
	"    webhook := requests.post(hookURL, json=payload)",
	"    pdf := wkhtmltopdf.from_url(userURL)",
	"    svg := rsvg.render(svgData)",
	"    parsed := url.Parse(userURL)",
	"    file := requests.get(\"file:///etc/passwd\")",
	"    log.Println(\"fetched\", target)",
	"}",
}, rules.LangGo)

// BenchmarkSSRFScan_LowerMigrated runs every ssrf rule over the heavy context on
// the shared-lowered-line fast path. Compare allocs/op and ns/op against the
// pre-migration ssrf/*.go to quantify the per-(pattern × line) re-lowering
// removed by the *Lower migration.
func BenchmarkSSRFScan_LowerMigrated(b *testing.B) {
	rs := ssrfBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigSSRFBench))
		}
	}
	_ = n
}

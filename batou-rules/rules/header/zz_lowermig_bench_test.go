package header

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a header-rule-heavy ScanContext: a spread of lines the
// header rules scan, most of which carry no trigger (the realistic majority
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
		FilePath:     "/app/server.js",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     lang,
	}
}

// headerBenchRules returns every registered header rule (BATOU-HDR-*) — the set
// carrying the migrated G*->G*Lower sites. Pulling them from the registry
// avoids hand-enumerating the rule structs and their receivers.
func headerBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-HDR-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigHeaderBench = lowermigCtx([]string{
	"const http = require('http');",
	"function loginHandler(req, response) {",
	"    response.setHeader('Content-Type', 'application/json');",
	"    response.setHeader('Cache-Control', 'public, max-age=3600');",
	"    response.setHeader('Server', 'MyServer/1.0');",
	"    response.setHeader('X-Powered-By', 'Express');",
	"    response.setHeader('X-Custom', req.query.value);",
	"    response.set('Content-Security-Policy', \"default-src 'unsafe-inline'\");",
	"    res.header('X-Auth', request.body.user);",
	"    const x = compute(value);",
	"    const y = helper(x);",
	"    response.send(payload);",
	"}",
	"http.createServer(loginHandler).listen(8080);",
}, rules.LangJavaScript)

// BenchmarkHeaderScan_LowerMigrated runs every header rule over the heavy
// context on the shared-lowered-line fast path. Compare allocs/op and ns/op
// against the pre-migration header/header.go to quantify the per-(pattern × line)
// re-lowering removed by the *Lower migration.
func BenchmarkHeaderScan_LowerMigrated(b *testing.B) {
	rs := headerBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigHeaderBench))
		}
	}
	_ = n
}

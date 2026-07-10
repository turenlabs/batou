package redirect

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a redirect-rule-heavy ScanContext: a spread of lines the
// redirect rules scan, most of which carry no trigger (the realistic majority
// case where the per-(pattern × line) re-lowering of the GFind prefilter gate
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
		FilePath:     "/app/handler.js",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     lang,
	}
}

// redirectBenchRules returns every registered redirect rule (BATOU-REDIR-*) —
// the set carrying the migrated G*->G*Lower sites.
func redirectBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-REDIR-") {
			out = append(out, r)
		}
	}
	return out
}

// The migrated redirect sites live in REDIR-002..008 (redirect_ext.go + the
// BypassableURLAllowlist loop). Use a JS/TS context with a redirect marker so
// the file-level gate in BypassableURLAllowlist is satisfied and every rule
// walks the per-line loop.
var lowermigRedirectBench = lowermigCtx([]string{
	"function handler(req, res) {",
	"  const next = req.query.next;",
	"  res.redirect(next);",
	"  window.location = req.query.url;",
	"  location.href = location.search;",
	"  document.location.href = params.get('to');",
	"  const ok = url.includes('allowed.com');",
	"  const ok2 = url.indexOf('safe.com') !== -1;",
	"  const ok3 = url.startsWith('https');",
	"  res.setHeader('Location', req.headers.host);",
	"  form.action = req.body.dest;",
	"  redirect = '//evil.com';",
	"  console.log('redirecting to', next);",
	"}",
}, rules.LangJavaScript)

// BenchmarkRedirectScan_LowerMigrated runs every redirect rule over the heavy
// context on the shared-lowered-line fast path. Compare allocs/op and ns/op
// against the pre-migration redirect/*.go to quantify the per-(pattern × line)
// re-lowering removed by the *Lower migration.
func BenchmarkRedirectScan_LowerMigrated(b *testing.B) {
	rs := redirectBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigRedirectBench))
		}
	}
	_ = n
}

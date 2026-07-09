package auth

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds an auth-rule-heavy ScanContext: a spread of lines the auth
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
		FilePath:     "/app/auth.js",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     lang,
	}
}

// authBenchRules returns every registered auth rule (BATOU-AUTH-*) — the set
// carrying the migrated G*->G*Lower sites. Pulling them from the registry
// avoids hand-enumerating the rule structs and their receivers.
func authBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-AUTH-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigAuthBench = lowermigCtx([]string{
	"function login(req, res) {",
	"    if (password === 'secret123') {",
	"    if (username === 'admin') {",
	"    res.header('Access-Control-Allow-Origin', '*');",
	"    cors({ origin: '*' });",
	"    if (pwd == userInput) {",
	"    const admin = 'admin:password';",
	"    res.cookie('session', token);",
	"    app.post('/login', handler);",
	"    isAdmin = req.body.isAdmin;",
	"    app.get('/admin', adminHandler);",
	"    const token = Math.random();",
	"    if (minLength = 6) {}",
	"    transfer(amount);",
	"    const x = compute(value);",
	"    const y = helper(x);",
	"    return res.json({ ok: true });",
	"}",
}, rules.LangJavaScript)

// BenchmarkAuthScan_LowerMigrated runs every auth rule over the heavy context on
// the shared-lowered-line fast path. Compare allocs/op and ns/op against the
// pre-migration auth/*.go to quantify the per-(pattern × line) re-lowering
// removed by the *Lower migration.
func BenchmarkAuthScan_LowerMigrated(b *testing.B) {
	rs := authBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigAuthBench))
		}
	}
	_ = n
}

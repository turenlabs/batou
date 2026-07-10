package misconfig

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a misconfig-rule-heavy ScanContext: a spread of lines the
// misconfig rules scan, most of which carry no trigger (the realistic majority
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
		FilePath:     "/app/config.py",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     lang,
	}
}

// misconfigBenchRules returns every registered misconfig rule (BATOU-MISC-*) —
// the set carrying the migrated G*->G*Lower sites. Pulling them from the
// registry avoids hand-enumerating the rule structs and their receivers.
func misconfigBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-MISC-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigMisconfigBench = lowermigCtx([]string{
	"import os",
	"DEBUG = True",
	"app.debug = True",
	"display_errors = On",
	"error_reporting(E_ALL)",
	"DEBUG_MODE = true",
	"response.write(traceback.format_exc())",
	"return jsonify({'error': str(e)})",
	"os.chmod(path, 0o777)",
	"password = 'changeme'",
	"admin_panel = '/admin'",
	"http.createServer(handler)",
	"autoindex on",
	"includeStackTrace = true",
	"x = compute(value)",
	"y = helper(x)",
	"NODE_ENV = 'development'",
}, rules.LangPython)

// BenchmarkMisconfigScan_LowerMigrated runs every misconfig rule over the heavy
// context on the shared-lowered-line fast path. Compare allocs/op and ns/op
// against the pre-migration misconfig/*.go to quantify the per-(pattern × line)
// re-lowering removed by the *Lower migration.
func BenchmarkMisconfigScan_LowerMigrated(b *testing.B) {
	rs := misconfigBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigMisconfigBench))
		}
	}
	_ = n
}

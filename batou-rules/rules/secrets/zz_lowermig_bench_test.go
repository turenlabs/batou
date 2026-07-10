package secrets

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a secrets-rule-heavy ScanContext: a spread of lines the
// secrets rules scan, most of which carry no trigger (the realistic majority
// case where the per-(pattern × line) re-lowering of the GFind/GMatch prefilter
// gate dominated). LinesLower is populated exactly as the scanner does before
// fanning out rules, so the migrated *Lower call sites take the
// shared-lowered-line fast path. The FilePath deliberately avoids the
// isTestFile() substrings (test/spec/mock/fixture/example) so the secrets rules
// actually run.
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

// secretsBenchRules returns every registered secrets rule (BATOU-SEC-*) — the
// set carrying the migrated G*->G*Lower sites. Pulling them from the registry
// avoids hand-enumerating the rule structs and their receivers.
func secretsBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-SEC-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigSecretsBench = lowermigCtx([]string{
	"import os",
	"config = load_settings()",
	"timeout = 30",
	"host = '127.0.0.1'",
	"port = 8080",
	"username = 'service'",
	"retries = 5",
	"log_level = 'info'",
	"x = compute(value)",
	"y = helper(x)",
	"pool_size = 16",
	"region = 'us-east-1'",
	"enabled = True",
	"path = os.path.join(base, name)",
	"headers = {'Accept': 'application/json'}",
	"buffer = bytearray(1024)",
	"label = 'production'",
}, rules.LangPython)

// BenchmarkSecretsScan_LowerMigrated runs every secrets rule over the heavy
// context on the shared-lowered-line fast path. Compare allocs/op and ns/op
// against the pre-migration secrets/*.go to quantify the per-(pattern × line)
// re-lowering removed by the *Lower migration.
func BenchmarkSecretsScan_LowerMigrated(b *testing.B) {
	rs := secretsBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigSecretsBench))
		}
	}
	_ = n
}

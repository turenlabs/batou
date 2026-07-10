package generic

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a generic-rule-heavy ScanContext: a spread of lines the
// generic rules scan, most of which carry no trigger (the realistic majority case
// where the per-(pattern × line) re-lowering of the GFind/GMatch prefilter gate
// dominated). LinesLower is populated exactly as the scanner does before fanning
// out rules, so the migrated *Lower call sites take the shared-lowered-line fast
// path. The generic rules switch on ctx.Language, so the body mixes Python/JS
// idioms and the context is tagged Python (one of the heaviest switch arms).
func lowermigCtx(base []string) *rules.ScanContext {
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
		FilePath:     "/app/handler.py",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     rules.LangPython,
	}
}

// genBenchRules returns every registered generic rule (BATOU-GEN-*) — the set
// carrying the migrated G*->G*Lower sites. Pulling them from the registry avoids
// hand-enumerating the rule structs and their receivers.
func genBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-GEN-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigGENBench = lowermigCtx([]string{
	"import xml.etree.ElementTree as ET",
	"import yaml, pickle, os",
	"def handler(request):",
	"    name = request.GET.get('name')",
	"    data = pickle.loads(blob)",
	"    cfg = yaml.load(stream)",
	"    tree = ET.parse(path)",
	"    obj = yaml.unsafe_load(text)",
	"    DEBUG = True",
	"    os.chmod(path, 0o777)",
	"    eval(expr)",
	"    redirect(request.GET.get('next'))",
	"    # TODO: fix security issue here",
	"    password_in_url = 'http://u:secret@host/path'",
	"    try:",
	"        risky()",
	"    except Exception:",
	"        pass",
	"    tmp = '/tmp/insecure.dat'",
	"    total = sum(it.amount for it in items)",
	"    for it in lst:",
	"        acc.append(it.name)",
	"    if cfg.enabled and cfg.timeout > 0:",
	"        retry()",
	"    logger.info('processed %d records', count)",
	"    return render('index', model)",
})

// BenchmarkGenericScan_LowerMigrated runs every generic rule over the heavy
// context on the shared-lowered-line fast path. Compare allocs/op and ns/op
// against the pre-migration generic/*.go to quantify the per-(pattern × line)
// re-lowering removed by the *Lower migration.
func BenchmarkGenericScan_LowerMigrated(b *testing.B) {
	rs := genBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigGENBench))
		}
	}
	_ = n
}

package python

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a Python-rule-heavy ScanContext: a spread of lines the
// Python rules scan, most of which carry no trigger (the realistic majority case
// where the per-(pattern × line) re-lowering of the GFind/GMatch prefilter gate
// dominated). LinesLower is populated exactly as the scanner does before fanning
// out rules, so the migrated *Lower call sites take the shared-lowered-line path.
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
		FilePath:     "/app/views.py",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     rules.LangPython,
	}
}

// pyBenchRules returns every registered Python rule (BATOU-PY-*) — the set
// carrying the migrated G*->G*Lower sites. Pulling them from the registry avoids
// hand-enumerating the rule structs and their receivers.
func pyBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-PY-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigPyBench = lowermigCtx([]string{
	"def handle(request):",
	"    name = request.GET.get('name')",
	"    subprocess.call('ls ' + name, shell=True)",
	"    path = os.path.join(root, name)",
	"    tmpl = jinja2.Environment(autoescape=False)",
	"    data = yaml.load(payload)",
	"    obj = pickle.loads(blob)",
	"    cursor.execute('SELECT * FROM u WHERE n=' + name)",
	"    app.secret_key = 'hardcoded-secret-value'",
	"    requests.get(url, verify=False)",
	"    pat = re.compile(name)",
	"    tar.extractall(dest)",
	"    logging.info(f'processed {name}')",
	"    jwt.decode(token, verify=False)",
	"    app.run(debug=True)",
	"    total = sum(it.amount for it in items)",
	"    for it in items:",
	"        acc.append(it.name)",
	"    if cfg.enabled and cfg.timeout > 0:",
	"        retry()",
	"    return render(request, 'page.html', ctx)",
})

// BenchmarkPythonScan_LowerMigrated runs every Python rule over the heavy context
// on the shared-lowered-line fast path. Compare allocs/op and ns/op against the
// pre-migration python/*.go to quantify the per-(pattern × line) re-lowering
// removed by the *Lower migration.
func BenchmarkPythonScan_LowerMigrated(b *testing.B) {
	rs := pyBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigPyBench))
		}
	}
	_ = n
}

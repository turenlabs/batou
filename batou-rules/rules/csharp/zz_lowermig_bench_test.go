package csharp

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a C#-rule-heavy ScanContext: a spread of lines the C# rules
// scan, most of which carry no trigger (the realistic majority case where the
// per-(pattern × line) re-lowering of the GFind/GMatch prefilter gate dominated).
// LinesLower is populated exactly as the scanner does before fanning out rules,
// so the migrated *Lower call sites take the shared-lowered-line fast path.
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
		FilePath:     "/app/Controller.cs",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     rules.LangCSharp,
	}
}

// csBenchRules returns every registered C# rule (BATOU-CS-*) — the set carrying
// the migrated G*->G*Lower sites. Pulling them from the registry avoids
// hand-enumerating the rule structs and their receivers.
func csBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-CS-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigCSBench = lowermigCtx([]string{
	"public class UserController : Controller {",
	"  public IActionResult Get(string name) {",
	"    var q = \"SELECT * FROM users WHERE name = '\" + name + \"'\";",
	"    db.Database.ExecuteSqlRaw(q);",
	"    var p = Process.Start(\"cmd\", name);",
	"    var path = Path.Combine(root, name);",
	"    var f = new BinaryFormatter().Deserialize(stream);",
	"    Response.Write(\"<div>\" + name + \"</div>\");",
	"    var html = Html.Raw(model.Body);",
	"    var rng = new Random();",
	"    var hc = new HttpClient().GetAsync(url);",
	"    var conn = \"Server=db;User=sa;Password=hunter2;\";",
	"    Response.Redirect(name);",
	"    var total = items.Sum(it => it.Amount);",
	"    foreach (var it in list) { acc.Add(it.Name); }",
	"    if (cfg.Enabled && cfg.Timeout > 0) { Retry(); }",
	"    logger.LogInformation(\"processed {Count} records\", count);",
	"    return View(model);",
	"  }",
	"}",
})

// BenchmarkCSharpScan_LowerMigrated runs every C# rule over the heavy context on
// the shared-lowered-line fast path. Compare allocs/op and ns/op against the
// pre-migration csharp/*.go to quantify the per-(pattern × line) re-lowering
// removed by the *Lower migration.
func BenchmarkCSharpScan_LowerMigrated(b *testing.B) {
	rs := csBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigCSBench))
		}
	}
	_ = n
}

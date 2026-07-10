package kotlin

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a Kotlin-rule-heavy ScanContext: a spread of lines the
// Kotlin rules scan, most of which carry no trigger (the realistic majority case
// where the per-(pattern × line) re-lowering of the GFind/GMatch prefilter gate
// dominated). LinesLower is populated exactly as the scanner does before fanning
// out rules, so the migrated *Lower call sites take the shared-lowered-line fast
// path.
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
		FilePath:     "/app/MainActivity.kt",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     rules.LangKotlin,
	}
}

// ktBenchRules returns every registered Kotlin rule (BATOU-KT-*) — the set
// carrying the migrated G*->G*Lower sites. Pulling them from the registry avoids
// hand-enumerating the rule structs and their receivers.
func ktBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-KT-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigKTBench = lowermigCtx([]string{
	"class MainActivity : AppCompatActivity() {",
	"  fun onCreate(savedInstanceState: Bundle?) {",
	"    val name = intent.getStringExtra(\"name\")",
	"    val q = \"SELECT * FROM users WHERE name = '$name'\"",
	"    db.rawQuery(\"SELECT * FROM t WHERE x = \" + name, null)",
	"    Runtime.getRuntime().exec(\"sh -c \" + cmd)",
	"    webView.loadUrl(\"javascript:\" + payload)",
	"    webView.addJavascriptInterface(JsBridge(), \"bridge\")",
	"    val intent2 = Intent()",
	"    sendBroadcast(intent2)",
	"    val f = File(dir, name)",
	"    prefs.edit().putString(\"token\", token).apply()",
	"    Log.d(\"TAG\", \"password=$password\")",
	"    GlobalScope.launch { doWork() }",
	"    val obj = Json.decodeFromString<User>(body)",
	"    Class.forName(className)",
	"    contentResolver.query(uri, null, sel, args, null)",
	"    call.respondText(html, ContentType.Text.Html)",
	"    call.respondRedirect(target)",
	"    val total = items.sumOf { it.amount }",
	"    for (it in list) { acc.add(it.name) }",
	"    if (cfg.enabled && cfg.timeout > 0) { retry() }",
	"    logger.info(\"processed {} records\", count)",
	"    return setContentView(R.layout.main)",
	"  }",
	"}",
})

// BenchmarkKotlinScan_LowerMigrated runs every Kotlin rule over the heavy context
// on the shared-lowered-line fast path. Compare allocs/op and ns/op against the
// pre-migration kotlin/*.go to quantify the per-(pattern × line) re-lowering
// removed by the *Lower migration.
func BenchmarkKotlinScan_LowerMigrated(b *testing.B) {
	rs := ktBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigKTBench))
		}
	}
	_ = n
}

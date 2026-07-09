package rust

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a Rust-rule-heavy ScanContext: a spread of lines the Rust
// rules scan, most of which carry no trigger (the realistic majority case where
// the per-(pattern × line) re-lowering of the GFind/GMatch prefilter gate
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
		FilePath:     "/app/src/handler.rs",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     rules.LangRust,
	}
}

// rustBenchRules returns every registered Rust rule (BATOU-RS-*) — the set
// carrying the migrated G*->G*Lower sites. Pulling them from the registry avoids
// hand-enumerating the rule structs and their receivers.
func rustBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-RS-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigRustBench = lowermigCtx([]string{
	"use actix_web::{web, App, HttpServer};",
	"async fn handler(req: web::Query<Params>) -> impl Responder {",
	"    let name = req.name.clone();",
	"    let q = format!(\"SELECT * FROM users WHERE name = '{}'\", name);",
	"    sqlx::query(&q).execute(&pool).await.unwrap();",
	"    let out = Command::new(\"sh\").arg(\"-c\").arg(&name).output();",
	"    let path = std::path::Path::new(&name);",
	"    let data = tokio::fs::read(path).await.unwrap();",
	"    let decoded: User = bincode::deserialize(&bytes).unwrap();",
	"    let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build();",
	"    let mut rng = rand::thread_rng();",
	"    unsafe {",
	"        let p = ptr as *const u8;",
	"        let v = *p.offset(3);",
	"        let s = std::slice::from_raw_parts(p, len);",
	"        let t: u64 = std::mem::transmute(x);",
	"    }",
	"    extern \"C\" {",
	"        fn c_fn(buf: *mut u8, len: usize) -> i32;",
	"    }",
	"    let cs = CStr::from_ptr(raw);",
	"    let re = regex::Regex::new(&user_pattern).unwrap();",
	"    let cors = Cors::permissive();",
	"    let total = items.iter().fold(0, |a, b| a + b.amount);",
	"    log::info!(\"processed {} records\", count);",
	"}",
})

// BenchmarkRustScan_LowerMigrated runs every Rust rule over the heavy context on
// the shared-lowered-line fast path. Compare allocs/op and ns/op against the
// pre-migration rust/*.go to quantify the per-(pattern × line) re-lowering removed
// by the *Lower migration.
func BenchmarkRustScan_LowerMigrated(b *testing.B) {
	rs := rustBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigRustBench))
		}
	}
	_ = n
}

package zig

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a zig-rule-heavy ScanContext: a spread of lines the zig
// rules scan, most of which carry no trigger (the realistic majority case where
// the per-(pattern × line) re-lowering of the GMatch prefilter gate dominated).
// LinesLower is populated exactly as the scanner does before fanning out rules,
// so the migrated *Lower call sites take the shared-lowered-line fast path.
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
		FilePath:     "/app/main.zig",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     lang,
	}
}

// zigBenchRules returns every registered zig rule (BATOU-ZIG-*) — the set
// carrying the migrated G*->G*Lower sites. Pulling them from the registry
// avoids hand-enumerating the rule structs and their receivers.
func zigBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-ZIG-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigZigBench = lowermigCtx([]string{
	"const std = @import(\"std\");",
	"pub fn main() !void {",
	"    const allocator = std.heap.page_allocator;",
	"    var list = std.ArrayList(u8).init(allocator);",
	"    defer list.deinit();",
	"    const n: usize = 42;",
	"    var sum: u32 = 0;",
	"    for (items) |item| sum += item;",
	"    const slice = buffer[0..len];",
	"    try writer.print(\"value={d}\\n\", .{sum});",
	"    const result = try compute(value);",
	"    if (n > 0) return n;",
	"    const name = config.name;",
	"    var map = std.AutoHashMap(u32, u32).init(allocator);",
	"    const total = a + b;",
	"    std.debug.print(\"done\\n\", .{});",
	"}",
}, rules.LangZig)

// BenchmarkZigScan_LowerMigrated runs every zig rule over the heavy context on
// the shared-lowered-line fast path. Compare allocs/op and ns/op against the
// pre-migration zig/zig.go to quantify the per-(pattern × line) re-lowering
// removed by the *Lower migration.
func BenchmarkZigScan_LowerMigrated(b *testing.B) {
	rs := zigBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigZigBench))
		}
	}
	_ = n
}

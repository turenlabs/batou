package lua

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a Lua-rule-heavy ScanContext: a spread of lines the Lua
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
		FilePath:     "/app/lua/handler.lua",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     rules.LangLua,
	}
}

// luaBenchRules returns every registered Lua rule (BATOU-LUA-*) — the set
// carrying the migrated G*->G*Lower sites. Pulling them from the registry avoids
// hand-enumerating the rule structs and their receivers.
func luaBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-LUA-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigLuaBench = lowermigCtx([]string{
	"local cjson = require(\"cjson\")",
	"local name = ngx.var.arg_name",
	"local q = \"SELECT * FROM users WHERE name = '\" .. name .. \"'\"",
	"local res = db:query(q)",
	"os.execute(\"ls \" .. name)",
	"local h = io.popen(\"cat \" .. name)",
	"local f = io.open(path .. name, \"r\")",
	"local fn = loadstring(user_code)",
	"local g = load(\"return \" .. expr)",
	"dofile(name)",
	"loadfile(user_path)",
	"ngx.say(\"<div>\" .. name .. \"</div>\")",
	"ngx.print(body)",
	"ngx.redirect(target)",
	"local payload = serpent.load(blob)",
	"local d = require(\"debug\")",
	"local total = 0",
	"for _, v in ipairs(items) do total = total + v.amount end",
	"ngx.log(ngx.INFO, \"processed \", count, \" records\")",
	"return { status = 200 }",
})

// BenchmarkLuaScan_LowerMigrated runs every Lua rule over the heavy context on
// the shared-lowered-line fast path. Compare allocs/op and ns/op against the
// pre-migration lua/*.go to quantify the per-(pattern × line) re-lowering removed
// by the *Lower migration.
func BenchmarkLuaScan_LowerMigrated(b *testing.B) {
	rs := luaBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigLuaBench))
		}
	}
	_ = n
}

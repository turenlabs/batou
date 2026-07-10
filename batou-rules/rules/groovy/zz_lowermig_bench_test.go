package groovy

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a groovy-rule-heavy ScanContext: a spread of lines the
// groovy rules scan, most of which carry no trigger (the realistic majority
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
		FilePath:     "/app/Build.groovy",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     lang,
	}
}

// groovyBenchRules returns every registered groovy rule (BATOU-GVY-*) — the set
// carrying the migrated G*->G*Lower sites. Pulling them from the registry
// avoids hand-enumerating the rule structs and their receivers.
func groovyBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-GVY-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigGroovyBench = lowermigCtx([]string{
	"package com.example.app",
	"import groovy.transform.CompileStatic",
	"def name = params.name",
	"def total = items.size()",
	"println \"processing ${total} items\"",
	"def result = service.compute(value)",
	"list.each { item -> handle(item) }",
	"def config = new ConfigSlurper().parse(text)",
	"return [status: 'ok', count: total]",
	"def x = a + b",
	"model.attribute('user', currentUser)",
	"def sum = nums.inject(0) { acc, n -> acc + n }",
	"task build(type: Copy) { from 'src' }",
	"def headers = [Accept: 'application/json']",
	"logger.info('request handled')",
	"def parsed = json.parse(body)",
	"def trimmed = input?.trim()",
}, rules.LangGroovy)

// BenchmarkGroovyScan_LowerMigrated runs every groovy rule over the heavy
// context on the shared-lowered-line fast path. Compare allocs/op and ns/op
// against the pre-migration groovy/*.go to quantify the per-(pattern × line)
// re-lowering removed by the *Lower migration.
func BenchmarkGroovyScan_LowerMigrated(b *testing.B) {
	rs := groovyBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigGroovyBench))
		}
	}
	_ = n
}

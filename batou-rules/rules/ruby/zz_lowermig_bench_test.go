package ruby

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a Ruby-rule-heavy ScanContext: a spread of lines the Ruby
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
		FilePath:     "/app/app.rb",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     rules.LangRuby,
	}
}

// rbBenchRules returns every registered Ruby rule (BATOU-RB-*) — the set carrying
// the migrated G*->G*Lower sites. Pulling them from the registry avoids
// hand-enumerating the rule structs and their receivers.
func rbBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-RB-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigRBBench = lowermigCtx([]string{
	"class UsersController < ApplicationController",
	"  def show",
	"    name = params[:name]",
	"    User.where(\"name = '#{name}'\")",
	"    system(\"ls #{name}\")",
	"    out = `grep #{name} log.txt`",
	"    eval(params[:code])",
	"    Kernel.open(\"| #{name}\")",
	"    obj.send(params[:method])",
	"    Regexp.new(params[:pattern])",
	"    YAML.load(request.body.read)",
	"    Marshal.load(cookies[:data])",
	"    redirect_to params[:url]",
	"    render html: raw(params[:html])",
	"    @comment = user_input.html_safe",
	"    cookies[:session] = { value: token }",
	"    http.verify_mode = OpenSSL::SSL::VERIFY_NONE",
	"    User.update_attributes(params[:user])",
	"    JWT.decode(token, nil, false)",
	"    key = OpenSSL::PKey::RSA.new(1024)",
	"    erb = ERB.new(params[:tmpl])",
	"    File.read(params[:path])",
	"    @result = items.sum { |x| x.amount }",
	"    logger.info(\"processed #{count} records\")",
	"    respond_to do |format|",
	"      format.html",
	"    end",
	"  end",
	"end",
})

// BenchmarkRubyScan_LowerMigrated runs every Ruby rule over the heavy context on
// the shared-lowered-line fast path. Compare allocs/op and ns/op against the
// pre-migration ruby/*.go to quantify the per-(pattern × line) re-lowering removed
// by the *Lower migration.
func BenchmarkRubyScan_LowerMigrated(b *testing.B) {
	rs := rbBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigRBBench))
		}
	}
	_ = n
}

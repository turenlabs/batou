package framework

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds a framework-rule-heavy ScanContext for the given language: a
// spread of lines the framework rules scan, most of which carry no framework
// trigger (the realistic majority case where the per-(pattern × line) re-lowering
// dominated). LinesLower is populated exactly as the scanner does before fanning
// out rules, so the *Lower call sites take the shared-lowered-line fast path.
func lowermigCtx(lang rules.Language, path string, base []string) *rules.ScanContext {
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
		FilePath:     path,
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     lang,
	}
}

// fwBenchRules returns every registered framework rule (BATOU-FW-*), which is the
// set carrying the migrated G*->G*Lower sites. Pulling them from the registry
// avoids hand-enumerating ~190 rule structs (and their pointer/value receivers).
func fwBenchRules() []rules.Rule {
	var out []rules.Rule
	for _, r := range rules.All() {
		if strings.HasPrefix(r.ID(), "BATOU-FW-") {
			out = append(out, r)
		}
	}
	return out
}

var lowermigJavaBench = lowermigCtx(rules.LangJava, "/app/src/main/java/Controller.java", []string{
	"@RestController",
	"public class UserController {",
	"  @GetMapping(\"/u\")",
	"  public String get(@RequestParam String name, HttpServletRequest request) {",
	"    String q = \"SELECT * FROM users WHERE name = '\" + name + \"'\";",
	"    jdbcTemplate.queryForObject(q, String.class);",
	"    ModelAndView mv = new ModelAndView(name);",
	"    response.addHeader(\"X-Thing\", request.getHeader(\"X\"));",
	"    return \"redirect:\" + request.getParameter(\"next\");",
	"  }",
	"  private int total(List<Item> items) { return items.stream().mapToInt(Item::amount).sum(); }",
	"  for (Item it : list) { acc.add(it.getName()); }",
	"  if (cfg.isEnabled() && cfg.getTimeout() > 0) { retry(); }",
})

var lowermigJSBench = lowermigCtx(rules.LangJavaScript, "/app/routes/index.js", []string{
	"const app = express();",
	"app.get('/u', (req, res) => {",
	"  res.send('<html>' + req.query.name + '</html>');",
	"  res.redirect(req.query.next);",
	"  const r = require(req.body.mod);",
	"  app.use(cors({ origin: '*' }));",
	"  res.cookie('s', token, { httpOnly: false });",
	"  db.query('SELECT * FROM u WHERE id = ' + req.params.id);",
	"  const sum = items.reduce((a, b) => a + b, 0);",
	"  for (const it of list) { acc.push(it.name); }",
	"  if (cfg.enabled && cfg.timeout > 0) retry();",
	"  logger.info('processed ' + count + ' records');",
})

var lowermigPyBench = lowermigCtx(rules.LangPython, "/app/views.py", []string{
	"from django.shortcuts import render",
	"DEBUG = True",
	"ALLOWED_HOSTS = ['*']",
	"@csrf_exempt",
	"def view(request):",
	"    q = User.objects.raw(f\"SELECT * FROM u WHERE n = {request.GET['n']}\")",
	"    cursor.execute(f\"SELECT * FROM t WHERE id = {uid}\")",
	"    html = mark_safe(request.GET['x'])",
	"    return render(request, 't.html', {'h': html})",
	"    total = sum(it.amount for it in items)",
	"    for it in items: acc.append(it.name)",
	"    if cfg.enabled and cfg.timeout > 0: retry()",
	"    logger.info('processed %d records', count)",
})

var lowermigPHPBench = lowermigCtx(rules.LangPHP, "/app/Http/Controllers/UserController.php", []string{
	"<?php",
	"class UserController extends Controller {",
	"  public function show(Request $request) {",
	"    $name = $request->input('name');",
	"    $user = User::whereRaw(\"name = '\" . $name . \"'\")->first();",
	"    DB::statement(\"UPDATE u SET n = '$name'\");",
	"    return redirect($request->input('next'));",
	"    return view('profile')->with('html', $request->input('bio'));",
	"    $total = array_sum(array_map(fn($i) => $i->amount, $items));",
	"    foreach ($list as $it) { $acc[] = $it->name; }",
	"    if ($cfg->enabled && $cfg->timeout > 0) { retry(); }",
	"  }",
	"}",
})

var lowermigRubyBench = lowermigCtx(rules.LangRuby, "/app/controllers/users_controller.rb", []string{
	"class UsersController < ApplicationController",
	"  skip_before_action :verify_authenticity_token",
	"  def show",
	"    @user = User.where(\"name = '#{params[:name]}'\").first",
	"    User.find_by_sql(\"SELECT * FROM users WHERE id = #{params[:id]}\")",
	"    redirect_to params[:next]",
	"    render html: params[:bio].html_safe",
	"    render inline: params[:tpl]",
	"    total = items.sum { |i| i.amount }",
	"    list.each { |it| acc << it.name }",
	"    retry if cfg.enabled && cfg.timeout > 0",
	"  end",
	"end",
})

func benchFW(b *testing.B, ctx *rules.ScanContext) {
	rs := fwBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(ctx))
		}
	}
	_ = n
}

// BenchmarkFWScan_LowerMigrated_* run the framework rules over a per-language
// context on the shared-lowered-line path. Compare allocs/op against the
// pre-migration framework files to quantify the per-(pattern × line) re-lowering
// removed by the G*->G*Lower migration.
func BenchmarkFWScan_LowerMigrated_Java(b *testing.B) { benchFW(b, lowermigJavaBench) }
func BenchmarkFWScan_LowerMigrated_JS(b *testing.B)   { benchFW(b, lowermigJSBench) }
func BenchmarkFWScan_LowerMigrated_Py(b *testing.B)   { benchFW(b, lowermigPyBench) }
func BenchmarkFWScan_LowerMigrated_PHP(b *testing.B)  { benchFW(b, lowermigPHPBench) }
func BenchmarkFWScan_LowerMigrated_Ruby(b *testing.B) { benchFW(b, lowermigRubyBench) }

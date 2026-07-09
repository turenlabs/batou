package xss

import (
	"strings"
	"testing"

	"github.com/turenlabs/batou-rules/rules"
)

// lowermigCtx builds an XSS-rule-heavy ScanContext for the given language: a
// spread of lines the XSS rules scan, most of which carry no XSS trigger (the
// realistic majority case where the per-(pattern x line) re-lowering dominated).
// LinesLower is populated exactly as the scanner does before fanning out rules,
// so the *Lower call sites take the shared-lowered-line fast path.
func lowermigCtx(lang rules.Language, base []string) *rules.ScanContext {
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
		FilePath:     "/app/view.src",
		Content:      content,
		Lines:        lines,
		LinesLower:   lower,
		ContentLower: strings.ToLower(content),
		Language:     lang,
	}
}

var lowermigJSBench = lowermigCtx(rules.LangJavaScript, []string{
	"function render(req, res) {",
	"  el.innerHTML = data;",
	"  node.insertAdjacentHTML('beforeend', html);",
	"  $('#x').html(userInput);",
	"  document.write('<div>' + name + '</div>');",
	"  eval(expr);",
	"  window.location = req.query.next;",
	"  window.open(url);",
	"  el.setAttribute('onclick', handler);",
	"  res.setHeader('X-Thing', req.headers.x);",
	"  const a = '<a href=\"javascript:' + cmd + '\">';",
	"  res.send('<html>' + body + '</html>');",
	"  res.json({ ok: true, value: total });",
	"  const sum = items.reduce((a, b) => a + b, 0);",
	"  for (const it of list) { acc.push(it.name); }",
	"  if (cfg.enabled && cfg.timeout > 0) retry();",
	"  logger.info('processed ' + count + ' records');",
	"  return template`<p>${escape(text)}</p>`;",
})

var lowermigJavaBench = lowermigCtx(rules.LangJava, []string{
	"public String handle(HttpServletRequest request) {",
	"  String name = request.getParameter(\"name\");",
	"  response.getWriter().println(\"<h1>\" + name + \"</h1>\");",
	"  out.print(\"<div>\" + userData + \"</div>\");",
	"  String html = \"<span>\" + value + \"</span>\";",
	"  resp.setHeader(\"X-Custom\", header);",
	"  PrintWriter w = response.getWriter();",
	"  int total = items.stream().mapToInt(Item::amount).sum();",
	"  for (Item it : list) { acc.add(it.getName()); }",
	"  if (cfg.isEnabled() && cfg.getTimeout() > 0) { retry(); }",
	"  log.info(\"processed {} records\", count);",
	"  return new ResponseEntity<>(body, HttpStatus.OK);",
})

// xssBenchRules are all XSS rules carrying the migrated G* sites.
func xssBenchRules() []rules.Rule {
	return []rules.Rule{
		&InnerHTMLUsage{}, &DangerouslySetInnerHTML{}, &DocumentWrite{},
		&UnescapedTemplateOutput{}, &DOMManipulation{}, &ResponseHeaderInjection{},
		&URLSchemeInjection{}, &ServerSideRenderingXSS{}, &MissingContentType{},
		&JSONContentTypeXSS{}, &ReflectedXSS{}, &PythonFStringHTML{},
		&JavaHTMLStringConcat{}, &JavaResponseWriterXSS{}, &JavaServletReflectedXSS{},
	}
}

// BenchmarkXSSScan_LowerMigrated_JS runs the XSS rules over a JS context on the
// shared-lowered-line path. Compare allocs/op against the pre-migration xss.go
// to quantify the per-(pattern x line) re-lowering removed by the *Lower migration.
func BenchmarkXSSScan_LowerMigrated_JS(b *testing.B) {
	rs := xssBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigJSBench))
		}
	}
	_ = n
}

// BenchmarkXSSScan_LowerMigrated_Java runs the XSS rules over a Java context.
func BenchmarkXSSScan_LowerMigrated_Java(b *testing.B) {
	rs := xssBenchRules()
	b.ReportAllocs()
	b.ResetTimer()
	var n int
	for i := 0; i < b.N; i++ {
		for _, r := range rs {
			n += len(r.Scan(lowermigJavaBench))
		}
	}
	_ = n
}

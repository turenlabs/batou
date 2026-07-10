package tsflow

import (
	"testing"

	"github.com/turenlabs/batou-core/taint"
	_ "github.com/turenlabs/batou-core/taint/languages"
	"github.com/turenlabs/batou-rules/rules"
)

// Coverage tests for the cov/jsts additions: mssql/tedious SQLi, reverse-proxy
// SSRF, and the util.format CWE-134 format-string sink. Each asserts the
// specific new sink ID fires when fed a request-tainted value, and a near-miss
// (constant value / parameterized form / different receiver) does not.
//
// Flows are exercised through the supported propagation shape (a request source
// assigned to a local, then passed to the sink) and the inline source-at-sink
// shape, both of which tsflow resolves for member-access sources.

func jsFlowHasSinkID(flows []taint.TaintFlow, sinkID string) bool {
	for _, f := range flows {
		if f.Sink.ID == sinkID {
			return true
		}
	}
	return false
}

func TestJSCoverage_MssqlBatch(t *testing.T) {
	// Tainted T-SQL into mssql Request.batch() — raw batch, no params API.
	vuln := `function h(req) {
  const request = new sql.Request();
  const q = req.query.name;
  request.batch(q);
}`
	flows := Analyze(vuln, "/app/h.js", rules.LangJavaScript)
	if !jsFlowHasSinkID(flows, "js.mssql.request.batch") {
		t.Errorf("expected js.mssql.request.batch to fire on tainted .batch()")
	}

	// Parameterized form: .input() binding clears the SQL taint, and the batch
	// argument is a constant string.
	safe := `function h(req) {
  const request = new sql.Request();
  request.input('name', sql.NVarChar, req.query.name);
  request.batch('SELECT * FROM users WHERE name = @name');
}`
	if jsFlowHasSinkID(Analyze(safe, "/app/h.js", rules.LangJavaScript), "js.mssql.request.batch") {
		t.Errorf("js.mssql.request.batch should not fire on a constant @name batch")
	}
}

func TestJSCoverage_ProxySSRF(t *testing.T) {
	// createProxyServer({ target }) with a request-derived target.
	v1 := `const httpProxy = require('http-proxy');
function h(req) {
  const url = req.query.url;
  const proxy = httpProxy.createProxyServer({ target: url });
  return proxy;
}`
	if !jsFlowHasSinkID(Analyze(v1, "/app/h.js", rules.LangJavaScript), "js.httpproxy.createproxyserver") {
		t.Errorf("expected js.httpproxy.createproxyserver to fire on tainted target")
	}

	// proxy.web(req, res, { target }) per-request forward.
	v2 := `function h(req, res) {
  const target = req.body.upstream;
  proxy.web(req, res, { target: target });
}`
	if !jsFlowHasSinkID(Analyze(v2, "/app/h.js", rules.LangJavaScript), "js.httpproxy.web") {
		t.Errorf("expected js.httpproxy.web to fire on tainted target option")
	}

	// createProxyMiddleware({ target }) bare call.
	v3 := `const { createProxyMiddleware } = require('http-proxy-middleware');
function h(req) {
  const t = req.query.dest;
  return createProxyMiddleware({ target: t });
}`
	if !jsFlowHasSinkID(Analyze(v3, "/app/h.js", rules.LangJavaScript), "js.httpproxymiddleware.create") {
		t.Errorf("expected js.httpproxymiddleware.create to fire on tainted target")
	}

	// Static config target — no taint, must not fire.
	safe := `const httpProxy = require('http-proxy');
function h() {
  const proxy = httpProxy.createProxyServer({ target: 'http://localhost:9000' });
  return proxy;
}`
	if jsFlowHasSinkID(Analyze(safe, "/app/h.js", rules.LangJavaScript), "js.httpproxy.createproxyserver") {
		t.Errorf("js.httpproxy.createproxyserver should not fire on a constant target")
	}
}

func TestJSCoverage_UtilFormat(t *testing.T) {
	// Tainted format string (arg 0) into util.format.
	vuln := `const util = require('util');
function h(req) {
  const fmt = req.query.fmt;
  return util.format(fmt, data);
}`
	if !jsFlowHasSinkID(Analyze(vuln, "/app/h.js", rules.LangJavaScript), "js.util.format") {
		t.Errorf("expected js.util.format to fire on a tainted format string")
	}

	// Constant format string with user data only in the value slot — safe.
	safe := `const util = require('util');
function h(req) {
  return util.format('user %s logged in', req.query.name);
}`
	if jsFlowHasSinkID(Analyze(safe, "/app/h.js", rules.LangJavaScript), "js.util.format") {
		t.Errorf("js.util.format should not fire when only the value slot is tainted")
	}
}
